package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"

	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
)

type fixtureReceiver struct {
	approvalpb.UnimplementedApprovalDeliveryServer
	mu       sync.Mutex
	boot     string
	received chan []byte
	ack      <-chan struct{}
}

func (r *fixtureReceiver) Status(context.Context, *approvalpb.StatusRequest) (*approvalpb.StatusResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &approvalpb.StatusResponse{BootId: r.boot, ChainId: 31337, TrustedKeyIds: []string{"default"}, MaxTtlMs: 20_000}, nil
}

func (r *fixtureReceiver) Deliver(_ context.Context, q *approvalpb.DeliverRequest) (*approvalpb.DeliverResponse, error) {
	r.mu.Lock()
	boot := r.boot
	r.mu.Unlock()
	r.received <- bytes.Clone(q.Batch)
	if r.ack != nil {
		<-r.ack
	}
	count := binary.BigEndian.Uint32(q.Batch[39+int(q.Batch[22]):])
	return &approvalpb.DeliverResponse{BootId: boot, Stored: count}, nil
}

func TestConfirmationBarrierCountsMembersAcrossRealOPSBatches(t *testing.T) {
	t.Setenv("OPS_APPROVAL_KEY_ID", "default")
	t.Setenv("OPS_APPROVAL_NODE", "reth")
	t.Setenv("OPS_APPROVAL_MAX_BATCH", "32")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ack := make(chan struct{})
	var release sync.Once
	receiver := &fixtureReceiver{boot: "11111111111111111111111111111111", received: make(chan []byte, 128), ack: ack}
	server := grpc.NewServer()
	approvalpb.RegisterApprovalDeliveryServer(server, receiver)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	c, err := newClient("http://127.0.0.1:1", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	t.Cleanup(func() { release.Do(func() { close(ack) }) })
	approvals := make([]nodeapproval.Approval, 70)
	for i := range approvals {
		approvals[i] = nodeapproval.Approval{ChainID: 31337, TxHash: common.BytesToHash([]byte{byte(i + 1)})}
	}
	// Enqueue must return while receiver acknowledgements are blocked. Waiting belongs to the
	// Python fixture's payload setup, never to the production sender's request path.
	done := make(chan error, 1)
	go func() { _, err := c.handle(request{Enqueue: approvals}); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue waited for receiver acknowledgement")
	}
	select {
	case <-receiver.received:
	case <-time.After(5 * time.Second):
		t.Fatal("OPS did not deliver a batch")
	}
	metrics := func() map[string]float64 {
		t.Helper()
		reply, err := c.handle(request{Metrics: true})
		if err != nil {
			t.Fatal(err)
		}
		return reply.(map[string]float64)
	}
	const confirmed = "privacyproxy_approval_confirmed_total"
	if got := metrics()[confirmed]; got != 0 {
		t.Fatalf("counted unacknowledged approvals: %v", got)
	}
	release.Do(func() { close(ack) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		m := metrics()
		if m[confirmed] == 70 {
			if m["privacyproxy_approval_batches_total/OK"] < 3 {
				t.Fatal("70 approvals did not split into bounded batches")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("confirmation barrier did not observe all 70 approvals: %v", m)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNormalClientUsesOPSSigningTTLAndAutomaticBootRedelivery(t *testing.T) {
	t.Setenv("OPS_APPROVAL_TTL", "10m")
	t.Setenv("OPS_APPROVAL_KEY_ID", "default")
	t.Setenv("OPS_APPROVAL_NODE", "reth")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	receiver := &fixtureReceiver{boot: "11111111111111111111111111111111", received: make(chan []byte, 16)}
	server := grpc.NewServer()
	approvalpb.RegisterApprovalDeliveryServer(server, receiver)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	c, err := newClient("http://127.0.0.1:1", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	// Exercise the same JSON command the Python harness uses. No raw Deliver, fixture signer,
	// preflight RPC or second Enqueue participates in recovery.
	a := nodeapproval.Approval{ChainID: 31337, TxHash: common.HexToHash("0x01"), Fingerprint: common.HexToHash("0x02"), Principal: common.HexToHash("0xff")}
	encoded, _ := json.Marshal(map[string]any{"enqueue": []nodeapproval.Approval{a}})
	var q request
	if err := json.Unmarshal(encoded, &q); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handle(q); err != nil {
		t.Fatal(err)
	}
	await := func() []byte {
		t.Helper()
		select {
		case b := <-receiver.received:
			return b
		case <-time.After(5 * time.Second):
			t.Fatal("OPS did not deliver the retained approval")
			return nil
		}
	}
	first := await()
	if len(first) != 43+len("default")+120+ed25519.SignatureSize {
		t.Fatalf("unexpected envelope length %d", len(first))
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), first[:len(first)-64], first[len(first)-64:]) {
		t.Fatal("OPS signature did not verify")
	}
	issuedAt := binary.BigEndian.Uint64(first[30:38])
	expiresAt := binary.BigEndian.Uint64(first[38:46])
	if expiresAt-issuedAt != 20_000 {
		t.Fatalf("sender ignored receiver TTL: %d", expiresAt-issuedAt)
	}
	if !bytes.Equal(first[50+88:50+120], make([]byte, 32)) {
		t.Fatal("sender did not clear the reserved principal")
	}
	receiver.mu.Lock()
	receiver.boot = "22222222222222222222222222222222"
	receiver.mu.Unlock()
	if again := await(); !bytes.Equal(first, again) {
		t.Fatal("automatic redelivery changed the retained signed envelope")
	}
	metrics, err := c.handle(request{Metrics: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := metrics.(map[string]float64)["privacyproxy_approval_redeliveries_total"]; got != 1 {
		t.Fatalf("redelivery was not triggered by the OPS lane observing boot id: %v", metrics)
	}
}
