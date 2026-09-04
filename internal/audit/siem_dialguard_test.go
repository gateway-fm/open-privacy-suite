package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestSIEM_StrictClientRefusesLoopbackServer locks the end-to-end property the
// RD-1266 review found untested: every other test in siem_test.go builds
// forwarders with AllowInsecure=true, so a strict forwarder — the production
// shape — never reached a loopback destination in any assertion. Nothing here
// may connect to the test server.
func TestSIEM_StrictClientRefusesLoopbackServer(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Constructed strict, as production does, with a URL that passes the guard.
	fwd, err := NewSIEMForwarder(SIEMConfig{
		WebhookURL: "https://siem.example.com/ingest",
		BatchSize:  1,
	})
	if err != nil {
		t.Fatalf("NewSIEMForwarder: %v", err)
	}

	// Repoint at the loopback server — the shape a DNS rebind or a later
	// config mutation produces.
	fwd.cfg.WebhookURL = srv.URL

	fwd.Send(SIEMEvent{EventType: "test"})
	fwd.flush()

	if got := hits.Load(); got != 0 {
		t.Fatalf("loopback server hits = %d, want 0 — a strict forwarder must never reach it", got)
	}
}

// TestSIEM_DialGuardIsWiredOnTheClient isolates the dial-time half on the SIEM
// client. The end-to-end test above is satisfied by the pre-flush URL
// re-validation alone, so on its own it would not notice the guarded transport
// being dropped; this drives the client's own transport at a blocked literal.
func TestSIEM_DialGuardIsWiredOnTheClient(t *testing.T) {
	strict, err := NewSIEMForwarder(SIEMConfig{
		WebhookURL: "https://siem.example.com/ingest", BatchSize: 1,
	})
	if err != nil {
		t.Fatalf("NewSIEMForwarder(strict): %v", err)
	}
	tr, ok := strict.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("strict client Transport is %T, want *http.Transport carrying the dial guard", strict.client.Transport)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("strict client dialed loopback — the RD-1266 guard is not wired on the SIEM transport")
	} else if !strings.Contains(err.Error(), "blocked outbound dial") {
		t.Fatalf("strict dial error = %q, want the dial guard's refusal", err)
	}

	// Relaxed keeps local collectors reachable, but still refuses metadata.
	relaxed := mustNewForwarder(t, SIEMConfig{
		WebhookURL: "http://127.0.0.1:1/ingest", BatchSize: 1,
	})
	rtr, ok := relaxed.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("relaxed client Transport is %T, want *http.Transport", relaxed.client.Transport)
	}
	if _, err := rtr.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("relaxed client dialed cloud metadata — must stay blocked in every mode")
	}
}
