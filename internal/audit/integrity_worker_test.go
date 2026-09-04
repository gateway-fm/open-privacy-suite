package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestWebhookNotifier_DoesNotFollowRedirects locks the open-redirect SSRF
// guard on the tamper-webhook client: a destination that passed the startup
// SSRF validation must not be able to bounce the POST (with its body) to a
// private/metadata address via a 307/308 at request time. Same contract as
// the SIEM forwarder's client.
func TestWebhookNotifier_DoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		// 307 preserves the method and body — the worst case for a
		// redirect-based SSRF of a POSTed audit payload.
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	// Construct through the real constructor so the test exercises the client
	// it builds. The relaxed variant is required because the dial-time SSRF
	// guard (RD-1266) refuses loopback destinations in strict mode — swapping
	// a public URL for a 127.0.0.1 one, as this test used to, is exactly the
	// rebinding shape that guard exists to stop.
	n, err := newWebhookNotifierForEnv(origin.URL, true)
	if err != nil {
		t.Fatalf("newWebhookNotifierForEnv: %v", err)
	}

	n.Notify(context.Background(), &Result{})

	if got := originHits.Load(); got != 1 {
		t.Fatalf("origin hits = %d, want 1", got)
	}
	if got := redirectTargetHits.Load(); got != 0 {
		t.Fatalf("redirect target hits = %d, want 0 — the notifier followed a redirect", got)
	}
}

// TestWebhookNotifier_StrictClientRefusesPrivateAtDial locks the RD-1266
// property on the tamper-webhook client: the destination is refused when the
// address it actually reaches is private, even though the URL itself passed
// validation. Constructed strict, as production does, then pointed at a
// loopback server — the shape a DNS rebind produces.
func TestWebhookNotifier_StrictClientRefusesPrivateAtDial(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := NewWebhookNotifier("https://tamper.example.com/hook")
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	n.URL = srv.URL

	n.Notify(context.Background(), &Result{})

	if got := hits.Load(); got != 0 {
		t.Fatalf("loopback server hits = %d, want 0 — the dial guard must refuse before connect", got)
	}
}
