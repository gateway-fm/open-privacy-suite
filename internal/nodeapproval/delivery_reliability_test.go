package nodeapproval

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// An approval whose call dies with its connection must still reach the producer once the
// connection is back. The call's status is the confirmation; a call lost with its connection
// has none, so the batch stays OPS's to deliver.
func TestApprovalSurvivesABrokenConnection(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	p.set(func(p *producer) { p.gate = make(chan struct{}) }) // the first call hangs at the producer
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	h := txHashes(1, 1)[0]
	enqueue(t, s, h)
	waitUntil(t, 2*time.Second, "the call reaches the producer", func() bool { return len(p.received()) == 1 })
	p.set(func(p *producer) { p.gate = nil })
	p.restart("boot-a") // the connection drops mid-call; the same process answers again
	waitUntil(t, 3*time.Second, "the approval arrives after the reconnect", func() bool { return p.holds("boot-a", h) })
	if got := value(t, s.metrics.redeliveries.WithLabelValues(p.name)); got != 0 {
		t.Fatalf("%v redeliveries for an unchanged boot id", got)
	}
}

// A peer that accepts and immediately resets (a producer at its connection limit, a proxy, a
// half-started node) must not turn OPS into a dial storm, even with a batch waiting for it.
func TestLostConnectionBacksOffBeforeRedialing(t *testing.T) {
	var dials atomic.Int64
	cfg := testDelivery()
	cfg.targets = []string{"resetting-peer:1"}
	cfg.dialer = func(context.Context, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		server.Close()
		return client, nil
	}
	s := startDelivery(t, time.Minute, cfg)
	s.publish(signedBatch(t, time.Minute, txHashes(1, 1)...))
	time.Sleep(700 * time.Millisecond)
	if n := dials.Load(); n > 10 {
		t.Fatalf("%d connections in 700 ms: reconnecting without backoff", n)
	} else if n == 0 {
		t.Fatal("never connected")
	}
}

// Every approval accepted by Enqueue belongs to a transaction that is about to be forwarded.
// A graceful stop (a rolling restart) must deliver what it has already accepted. This goes
// through New and gRPC's own dialer to a loopback port: the production path end to end.
func TestCloseDeliversEverythingAlreadyAccepted(t *testing.T) {
	p := newTCPProducer(t, "boot-a")
	s, err := New("http://127.0.0.1:1", p.name, testSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitReady(t, s)
	hashes := txHashes(1, 200)
	enqueue(t, s, hashes...)
	s.Close() // immediately: nothing has necessarily been signed yet
	if !p.holds("boot-a", hashes...) {
		t.Fatalf("close delivered %d of %d accepted approvals", len(p.storedIn("boot-a")), len(hashes))
	}
}

// The drain is bounded: a producer that stopped answering cannot hold a rolling restart hostage.
func TestCloseIsBoundedWhenNoProducerAnswers(t *testing.T) {
	p := newProducer(t, "producer-a:1", "boot-a")
	s := startDelivery(t, time.Minute, testDelivery(p))
	waitReady(t, s)
	p.stop()
	s.publish(signedBatch(t, time.Minute, txHashes(1, 1)...))
	started := time.Now()
	s.Close()
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Close took %v with a drain of 500 ms", elapsed)
	}
}
