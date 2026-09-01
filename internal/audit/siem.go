package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"privacy-proxy/internal/netguard"

	"github.com/prometheus/client_golang/prometheus"
)

// SIEMConfig configures the SIEM webhook forwarder.
type SIEMConfig struct {
	WebhookURL      string
	AuthHeader      string
	BatchSize       int
	FlushInterval   time.Duration
	FallbackLogPath string // If set, failed batches are appended here as JSON lines.
	// AllowInsecure relaxes the SSRF guard so HTTP (not just HTTPS) and
	// loopback/private destinations are accepted. Intended for tests and
	// local development only — production callers MUST leave this false so
	// netguard.ValidateWebhookURL (strict mode) is applied.
	AllowInsecure bool
}

// SIEMEvent represents an audit event to forward to a SIEM system.
type SIEMEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	ActorID       string    `json:"actor_id,omitempty"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Details       string    `json:"details,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	EntryHash     string    `json:"entry_hash,omitempty"`
	// MatchedVia is "wildcard" when the action method passed the allowlist
	// via a chain-namespace wildcard rather than an explicit entry.
	MatchedVia    string    `json:"matched_via,omitempty"`
	// MatchedPrefix is the wildcard prefix that allowed the method (e.g. "linea_").
	MatchedPrefix string    `json:"matched_prefix,omitempty"`
}

// SIEMForwarder batches audit events and forwards them to a SIEM webhook.
type SIEMForwarder struct {
	cfg    SIEMConfig
	client *http.Client

	mu    sync.Mutex
	batch []SIEMEvent
	stop  chan struct{}
	done  chan struct{}

	// Prometheus metrics (optional, set via SetMetrics)
	batchesTotal       *prometheus.CounterVec
	eventsDroppedTotal prometheus.Counter
}

// SetMetrics configures Prometheus metrics for the SIEM forwarder.
func (s *SIEMForwarder) SetMetrics(batches *prometheus.CounterVec, dropped prometheus.Counter) {
	s.batchesTotal = batches
	s.eventsDroppedTotal = dropped
}

// NewSIEMForwarder creates a new SIEM forwarder. Call Start() to begin flushing.
//
// The WebhookURL is validated at construction time via
// netguard.ValidateWebhookURLForEnv (RD-950) — a malformed or SSRF-prone destination
// makes the forwarder fail fast at startup rather than at the first flush.
// Callers in production must leave SIEMConfig.AllowInsecure=false so HTTPS
// is required and loopback/RFC-1918/link-local destinations are rejected.
func NewSIEMForwarder(cfg SIEMConfig) (*SIEMForwarder, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	if err := netguard.ValidateWebhookURLForEnv(cfg.WebhookURL, cfg.AllowInsecure); err != nil {
		return nil, err
	}

	return &SIEMForwarder{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Disallow redirects: a redirect could lead to a private/internal
			// address even when the original URL was validated (open-redirect SSRF).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("redirects not permitted for SIEM webhook")
			},
		},
		batch: make([]SIEMEvent, 0, cfg.BatchSize),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}, nil
}

// Send queues an event for the next batch. If the batch is full, an immediate flush is triggered.
func (s *SIEMForwarder) Send(event SIEMEvent) {
	s.mu.Lock()
	s.batch = append(s.batch, event)
	full := len(s.batch) >= s.cfg.BatchSize
	s.mu.Unlock()

	if full {
		s.flush()
	}
}

// Start begins the periodic flush loop.
func (s *SIEMForwarder) Start() {
	go s.run()
}

// Stop flushes remaining events and stops the forwarder.
func (s *SIEMForwarder) Stop() {
	close(s.stop)
	<-s.done
}

func (s *SIEMForwarder) run() {
	defer close(s.done)

	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			s.flush()
			return
		case <-ticker.C:
			s.flush()
		}
	}
}

func (s *SIEMForwarder) flush() {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return
	}
	events := s.batch
	s.batch = make([]SIEMEvent, 0, s.cfg.BatchSize)
	s.mu.Unlock()

	if err := s.send(events); err != nil {
		s.handleFailedBatch(events, err)
	} else if s.batchesTotal != nil {
		s.batchesTotal.WithLabelValues("success").Inc()
	}
}

const maxRetries = 3

func (s *SIEMForwarder) send(events []SIEMEvent) error {
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	// RD-950: defence-in-depth re-validation immediately before the outbound
	// request. NewSIEMForwarder already validates the URL at startup, but
	// re-checking here means any future code that mutates s.cfg.WebhookURL
	// (or any new flush path that constructs SIEMForwarder by hand) still
	// has to clear the SSRF guard before reaching net/http. The check is
	// cheap (no DNS, no network) and runs once per batch, not per event.
	if err := netguard.ValidateWebhookURLForEnv(s.cfg.WebhookURL, s.cfg.AllowInsecure); err != nil {
		return fmt.Errorf("SIEM webhook URL failed SSRF guard: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest(http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if s.cfg.AuthHeader != "" {
			req.Header.Set("Authorization", s.cfg.AuthHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("SIEM webhook returned status %d", resp.StatusCode)
	}

	return fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}

// handleFailedBatch handles events that could not be sent after all retries.
// M4 fix: if FallbackLogPath is configured, write events to a local file so
// operators can recover them manually. The batch is always dropped from memory
// (no infinite retry) regardless of fallback success.
func (s *SIEMForwarder) handleFailedBatch(events []SIEMEvent, sendErr error) {
	if s.batchesTotal != nil {
		s.batchesTotal.WithLabelValues("error").Inc()
	}
	if s.eventsDroppedTotal != nil {
		s.eventsDroppedTotal.Add(float64(len(events)))
	}

	if s.cfg.FallbackLogPath != "" {
		if err := s.writeFallback(events); err != nil {
			slog.Error("SIEM flush failed and fallback write also failed, dropping events", "send_error", sendErr, "fallback_error", err, "count", len(events))
		} else {
			slog.Warn("SIEM flush failed, wrote events to fallback log", "error", sendErr, "count", len(events), "fallback_path", s.cfg.FallbackLogPath)
		}
		return
	}

	// No fallback configured - log at ERROR level with count.
	slog.Error("SIEM flush failed, dropping events (no fallback path configured)", "error", sendErr, "count", len(events))
}

// writeFallback appends events as JSON lines to the fallback log file.
func (s *SIEMForwarder) writeFallback(events []SIEMEvent) error {
	f, err := os.OpenFile(s.cfg.FallbackLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open fallback log: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("write event to fallback log: %w", err)
		}
	}
	return nil
}
