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

	// Construct through the real constructor so the test exercises the
	// client it builds; the validated public URL is then swapped for the
	// local origin (the URL check itself is covered in netguard's tests).
	n, err := NewWebhookNotifier("https://tamper.example.com/hook")
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	n.URL = origin.URL

	n.Notify(context.Background(), &Result{})

	if got := originHits.Load(); got != 1 {
		t.Fatalf("origin hits = %d, want 1", got)
	}
	if got := redirectTargetHits.Load(); got != 0 {
		t.Fatalf("redirect target hits = %d, want 0 — the notifier followed a redirect", got)
	}
}
