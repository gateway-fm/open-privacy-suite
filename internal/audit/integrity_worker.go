package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"privacy-proxy/internal/netguard"

	"github.com/prometheus/client_golang/prometheus"
)

// IntegrityWorker is the in-process scheduler that runs the audit
// hash-chain Verifier on a fixed cadence and fires a Notifier on
// mismatch. The Verifier itself is read-only; the worker is the bit
// that turns "verifiable in principle" into "we'd actually find out"
// (RD-858).
//
// One worker covers both audit chains (access_logs, rbac_audit_log).
// Each chain is verified independently per tick, in sequence, so a
// long access_logs walk doesn't block the rbac_audit_log walk past
// the next tick.
type IntegrityWorker struct {
	verifier *Verifier
	notifier Notifier
	chains   []ChainName
	interval time.Duration

	// Prometheus counter; nil disables metric emission.
	violations *prometheus.CounterVec

	stop chan struct{}
	done chan struct{}
}

// IntegrityWorkerConfig configures the scheduled verifier. Zero
// values are filled with sensible defaults (15-minute interval, both
// chains).
type IntegrityWorkerConfig struct {
	// Interval between full passes over every configured chain. The
	// default (15 minutes) keeps the verification cost a rounding
	// error against the row-write rate while still giving sub-hour
	// detection. Set to 0 to use the default.
	Interval time.Duration
	// Chains lists which chains to verify. Empty = both.
	Chains []ChainName
	// Violations is the Prometheus counter incremented once per
	// detected violation, labelled by chain and reason. Nil disables
	// the metric.
	Violations *prometheus.CounterVec
}

// NewIntegrityWorker wires the verifier, notifier, and schedule. Call
// Start to begin running and Stop to drain.
func NewIntegrityWorker(verifier *Verifier, notifier Notifier, cfg IntegrityWorkerConfig) *IntegrityWorker {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	chains := cfg.Chains
	if len(chains) == 0 {
		chains = []ChainName{ChainAccessLogs, ChainRBACAuditLog}
	}
	return &IntegrityWorker{
		verifier:   verifier,
		notifier:   notifier,
		chains:     chains,
		interval:   interval,
		violations: cfg.Violations,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// Start launches the verifier loop. ctx cancels the loop and any
// in-flight verify pass. Safe to call once per worker instance.
func (w *IntegrityWorker) Start(ctx context.Context) {
	go w.run(ctx)
}

// Stop signals the loop to exit and waits for the current pass to
// finish.
func (w *IntegrityWorker) Stop() {
	close(w.stop)
	<-w.done
}

func (w *IntegrityWorker) run(ctx context.Context) {
	defer close(w.done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// First pass happens immediately so a freshly-started instance
	// reports a status without waiting for the first tick. Subsequent
	// passes run on the ticker.
	w.pass(ctx)
	for {
		select {
		case <-w.stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pass(ctx)
		}
	}
}

func (w *IntegrityWorker) pass(ctx context.Context) {
	for _, chain := range w.chains {
		passCtx, cancel := context.WithTimeout(ctx, w.interval-time.Second)
		res, err := w.verifier.Verify(passCtx, chain)
		cancel()
		if err != nil {
			slog.Error("audit chain verify failed",
				"chain", chain,
				"err", err)
			if w.violations != nil {
				w.violations.WithLabelValues(string(chain), "verify_error").Inc()
			}
			continue
		}
		if !res.OK {
			slog.Error("audit chain integrity violation detected",
				"chain", chain,
				"reason", res.FirstMismatchReason,
				"row_id", res.FirstMismatchID,
				"row_time", res.FirstMismatchTime,
				"scanned_rows", res.ScannedRows,
				"null_hash_rows", res.NullHashRows)
			if w.violations != nil {
				w.violations.WithLabelValues(string(chain), res.FirstMismatchReason).Inc()
			}
			if w.notifier != nil {
				w.notifier.Notify(ctx, res)
			}
			continue
		}
		slog.Debug("audit chain verified intact",
			"chain", chain,
			"scanned_rows", res.ScannedRows)
	}
}

// Notifier is invoked by IntegrityWorker each time a chain fails
// verification. Multiple notifiers can be combined via MultiNotifier.
//
// Implementations must NOT block for long — the worker's verify
// budget is consumed inside Notify. A best-effort enqueue (e.g.
// pushing onto a buffered channel) is appropriate.
type Notifier interface {
	Notify(ctx context.Context, result *Result)
}

// MultiNotifier fans a violation event out to every wrapped notifier.
// Failures in one don't suppress the others.
type MultiNotifier struct {
	Notifiers []Notifier
}

func (m *MultiNotifier) Notify(ctx context.Context, result *Result) {
	for _, n := range m.Notifiers {
		if n != nil {
			n.Notify(ctx, result)
		}
	}
}

// SIEMNotifier emits a violation as a SIEMEvent so it rides the same
// audit pipeline the rest of the proxy uses. Customers who route SIEM
// to PagerDuty / Slack / Datadog get the alert via that channel
// without any additional plumbing — this is the **preferred**
// notification path per RD-858 because it reuses the SIEM trust
// boundary the customer already operates.
type SIEMNotifier struct {
	Forwarder *SIEMForwarder
}

func (s *SIEMNotifier) Notify(_ context.Context, result *Result) {
	if s == nil || s.Forwarder == nil {
		return
	}
	s.Forwarder.Send(SIEMEvent{
		Timestamp: time.Now().UTC(),
		EventType: "audit.chain.tamper_detected",
		Action:    "audit.chain.verify",
		Outcome:   "violation",
		Details: fmt.Sprintf("chain=%s reason=%s row_id=%d",
			result.Chain, result.FirstMismatchReason, result.FirstMismatchID),
		EntryHash: result.FirstMismatchHash,
	})
}

// WebhookNotifier POSTs a JSON payload to a customer-supplied URL on
// every violation. Used when no SIEM is configured (smaller customers
// often wire this to Slack incoming webhooks, Discord, or a generic
// alerting bus). The destination URL is validated via
// netguard.ValidateWebhookURL — the same SSRF guard applied to the
// SIEM forwarder.
//
// The notifier sends a single attempt with a short timeout and logs
// failure. Retries are intentionally NOT implemented here — the
// scheduled worker will run the verifier again at its next tick and
// fire a fresh notification, which is the natural retry surface.
type WebhookNotifier struct {
	URL    string
	Client *http.Client
}

// NewWebhookNotifier validates the URL via the existing SSRF guard
// (netguard.ValidateWebhookURL — denies loopback, RFC-1918, link-local,
// cloud metadata IPs) and returns a configured notifier. Pass an empty
// string to disable webhook notification entirely.
func NewWebhookNotifier(rawURL string) (*WebhookNotifier, error) {
	return newWebhookNotifierForEnv(rawURL, false)
}

// newWebhookNotifierForEnv is NewWebhookNotifier with the SSRF guard's
// relaxation exposed. It stays unexported deliberately: the tamper webhook is
// strict in every deployment (config.Validate applies the strict URL guard to
// AUDIT_TAMPER_WEBHOOK_URL regardless of environment), so production callers
// must not be able to ask for the relaxed variant. Tests in this package use
// it to point a notifier at a loopback httptest server.
func newWebhookNotifierForEnv(rawURL string, allowPrivate bool) (*WebhookNotifier, error) {
	if rawURL == "" {
		return nil, nil
	}
	if err := netguard.ValidateWebhookURLForEnv(rawURL, allowPrivate); err != nil {
		return nil, err
	}
	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}
	return &WebhookNotifier{
		URL: rawURL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
			// Refuse private/loopback destinations at dial time, after DNS
			// resolution (RD-1266): the URL guard above only sees a hostname,
			// so a name resolving or rebinding to an internal address would
			// otherwise slip through.
			Transport: netguard.GuardedTransport(allowPrivate),
			// Disallow redirects: a redirect could lead to a private/internal
			// address even when the original URL was validated (open-redirect
			// SSRF) — same guard as the SIEM forwarder's client.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("redirects not permitted for audit tamper webhook")
			},
		},
	}, nil
}

// webhookPayload is the JSON shape POSTed to the customer URL on
// violation. Fields are stable across versions; new ones added by
// appending.
type webhookPayload struct {
	Type        string    `json:"type"`
	Chain       string    `json:"chain"`
	Reason      string    `json:"reason"`
	RowID       int64     `json:"row_id"`
	RowTime     time.Time `json:"row_time"`
	StoredHash  string    `json:"stored_hash,omitempty"`
	ExpectHash  string    `json:"expected_hash,omitempty"`
	ScannedRows int64     `json:"scanned_rows"`
	NullHash    int64     `json:"null_hash_rows"`
	DetectedAt  time.Time `json:"detected_at"`
}

func (w *WebhookNotifier) Notify(ctx context.Context, result *Result) {
	if w == nil || w.URL == "" {
		return
	}
	payload := webhookPayload{
		Type:        "audit.chain.tamper_detected",
		Chain:       string(result.Chain),
		Reason:      result.FirstMismatchReason,
		RowID:       result.FirstMismatchID,
		RowTime:     result.FirstMismatchTime,
		StoredHash:  result.FirstMismatchHash,
		ExpectHash:  result.FirstMismatchExpect,
		ScannedRows: result.ScannedRows,
		NullHash:    result.NullHashRows,
		DetectedAt:  time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("audit tamper webhook: marshal failed", "err", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		slog.Error("audit tamper webhook: build request failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "privacy-proxy/audit-integrity")
	resp, err := w.Client.Do(req)
	if err != nil {
		slog.Error("audit tamper webhook: POST failed", "url", w.URL, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Error("audit tamper webhook: non-success status",
			"url", w.URL, "status", resp.StatusCode)
	}
}
