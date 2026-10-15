package nodeapproval

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The connection is opened at start-up, before any approval exists; every new connection is
// asked for the producer's Status, and so is a live one, periodically. A lost connection is
// re-opened without waiting for a batch to need it.
func TestStatusOnEveryConnectionAndWhileConnected(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitUntil(t, 2*time.Second, "Status on the first connection", func() bool { return p.statusCalls() >= 1 })
	waitUntil(t, 2*time.Second, "Status again on the live connection", func() bool { return p.statusCalls() >= 3 })
	p.restart("boot-a")
	statuses := p.statusCalls()
	waitUntil(t, 3*time.Second, "Status on the new connection", func() bool { return p.statusCalls() > statuses })
	p.mu.Lock()
	dials := p.dials
	p.mu.Unlock()
	if dials < 2 {
		t.Fatalf("%d connections; the lost one was not re-opened", dials)
	}
	if len(p.received()) != 0 || len(s.queue) != 0 {
		t.Fatal("an approval appeared without Enqueue")
	}
}

func TestDeliverySettings(t *testing.T) {
	unset := func(t *testing.T) {
		for _, name := range []string{"OPS_APPROVAL_DELIVERY_TIMEOUT", "OPS_APPROVAL_MAX_IN_FLIGHT", "OPS_APPROVAL_RETAIN_MAX"} {
			t.Setenv(name, "")
		}
	}
	t.Run("targets", func(t *testing.T) {
		for in, want := range map[string][]string{
			"sequencer:50051":            {"sequencer:50051"},
			" a:1 , b:2 ":                {"a:1", "b:2"},
			"[::1]:50051,10.0.0.7:50051": {"[::1]:50051", "10.0.0.7:50051"},
		} {
			got, err := parseTargets(in)
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("parseTargets(%q) = %v, %v; want %v", in, got, err, want)
			}
		}
		for _, in := range []string{"", " ", ",", "a:1,", "a:1,,b:2", "a", "a:", ":1", "a:0", "a:65536", "a:x", "a:+1", "http://a:1", "a:1,a:1"} {
			if _, err := parseTargets(in); err == nil || !strings.Contains(err.Error(), "OPS_APPROVAL_TARGETS") {
				t.Fatalf("parseTargets(%q) accepted or unclear: %v", in, err)
			}
		}
	})
	t.Run("defaults", func(t *testing.T) {
		unset(t)
		cfg, err := configuredDelivery("a:1")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.timeout != 2*time.Second || cfg.maxInFlight != 8 || cfg.retainMax != 100_000 {
			t.Fatalf("defaults: timeout %v, in flight %d, retained %d", cfg.timeout, cfg.maxInFlight, cfg.retainMax)
		}
		if cfg.statusEvery != time.Second || cfg.readyWindow != 5*time.Second || cfg.drain != 2*time.Second {
			t.Fatalf("fixed intervals: status %v, ready %v, drain %v", cfg.statusEvery, cfg.readyWindow, cfg.drain)
		}
	})
	t.Run("values", func(t *testing.T) {
		unset(t)
		t.Setenv("OPS_APPROVAL_DELIVERY_TIMEOUT", "500ms")
		t.Setenv("OPS_APPROVAL_MAX_IN_FLIGHT", "1024")
		t.Setenv("OPS_APPROVAL_RETAIN_MAX", "32")
		cfg, err := configuredDelivery("a:1,b:2")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.timeout != 500*time.Millisecond || cfg.maxInFlight != 1024 || cfg.retainMax != 32 || len(cfg.targets) != 2 {
			t.Fatalf("parsed %+v", cfg)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		for name, values := range map[string][]string{
			"OPS_APPROVAL_DELIVERY_TIMEOUT": {"0", "-1s", "2 seconds", "2m"},
			"OPS_APPROVAL_MAX_IN_FLIGHT":    {"0", "-1", "1025", "eight"},
			"OPS_APPROVAL_RETAIN_MAX":       {"31", "0", "-5", "many"},
		} {
			for _, v := range values {
				unset(t)
				t.Setenv(name, v)
				if _, err := configuredDelivery("a:1"); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("%s=%q accepted or unclear: %v", name, v, err)
				}
			}
		}
	})
	t.Run("New refuses an empty target list", func(t *testing.T) {
		unset(t)
		if _, err := New("http://127.0.0.1:1", "", testSeed); err == nil || !strings.Contains(err.Error(), "OPS_APPROVAL_TARGETS") {
			t.Fatalf("New with no targets: %v", err)
		}
	})
}
