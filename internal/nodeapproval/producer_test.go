package nodeapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"privacy-proxy/internal/nodeapproval/approvalpb"
)

// testSeed signs every batch in the delivery tests; the fake producer trusts its public key.
var testSeed = bytes.Repeat([]byte{7}, 32)

var testPublicKey = ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)

// Script entries beyond the gRPC codes: how a producer answers besides a plain status.
const (
	// answerStoreFull is a full store: UNAVAILABLE with the store-full trailer (contract §3, check 8).
	answerStoreFull codes.Code = 1000 + iota
	// answerStall holds the call until the caller gives up, so the caller sees its own deadline.
	answerStall
)

// producer is an in-process block producer for delivery tests. It serves the approval gRPC
// contract, verifies every envelope under the test key, answers from a script and remembers what
// each of its process lifetimes (boot ids) stored, so a test can make it refuse, stall, restart
// or disappear.
type producer struct {
	approvalpb.UnimplementedApprovalDeliveryServer
	t    *testing.T
	name string // the host:port OPS is configured with
	tcp  bool   // serves on a loopback port instead of an in-memory listener

	mu        sync.Mutex
	lis       net.Listener // nil while the producer is down
	srv       *grpc.Server
	boot      string
	chain     uint64
	keys      []string
	maxTTLms  uint64
	script    []codes.Code  // answers to the next Deliver calls
	always    codes.Code    // the answer once the script is used up
	statusErr codes.Code    // when not OK, Status answers with it
	gate      chan struct{} // while set, Deliver waits for it to close before answering
	calls     []delivered
	statuses  int
	stored    map[string][]common.Hash // per boot id, in arrival order
	active    int
	peak      int
	dials     int
}

// delivered is one Deliver call as the producer saw it.
type delivered struct {
	boot     string
	envelope envelope
	at       time.Time
	answer   codes.Code
}

func newProducer(t *testing.T, name, boot string) *producer {
	t.Helper()
	p := &producer{t: t, name: name, boot: boot, chain: 31337, keys: []string{"default"},
		maxTTLms: uint64(time.Hour.Milliseconds()), stored: map[string][]common.Hash{}}
	p.start()
	t.Cleanup(p.stop)
	return p
}

// newTCPProducer serves on a loopback port, for tests that go through New and gRPC's own dialer.
func newTCPProducer(t *testing.T, boot string) *producer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &producer{t: t, name: lis.Addr().String(), tcp: true, boot: boot, chain: 31337, keys: []string{"default"},
		maxTTLms: uint64(time.Hour.Milliseconds()), stored: map[string][]common.Hash{}}
	p.serve(lis)
	t.Cleanup(p.stop)
	return p
}

func (p *producer) start() {
	var lis net.Listener = bufconn.Listen(1 << 16)
	if p.tcp {
		var err error
		if lis, err = net.Listen("tcp", p.name); err != nil {
			p.t.Fatalf("producer %s cannot listen again: %v", p.name, err)
		}
	}
	p.serve(lis)
}

func (p *producer) serve(lis net.Listener) {
	// The contract asks receivers to permit OPS's keepalive pings (every 20 s, also idle).
	srv := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}))
	approvalpb.RegisterApprovalDeliveryServer(srv, p)
	p.mu.Lock()
	p.lis, p.srv = lis, srv
	p.mu.Unlock()
	go func() { _ = srv.Serve(lis) }()
}

// stop takes the producer down: open connections and calls end, new dials are refused.
func (p *producer) stop() {
	p.mu.Lock()
	srv := p.srv
	p.lis, p.srv = nil, nil
	p.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

// restart is a process restart: the store is empty and the boot id is the one given.
func (p *producer) restart(boot string) {
	p.stop()
	p.mu.Lock()
	p.boot = boot
	p.mu.Unlock()
	p.start()
}

func (p *producer) dial(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	p.dials++
	lis, _ := p.lis.(*bufconn.Listener)
	p.mu.Unlock()
	if lis == nil {
		return nil, errors.New("connection refused")
	}
	return lis.DialContext(ctx)
}

func (p *producer) set(change func(p *producer)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

func (p *producer) Deliver(ctx context.Context, req *approvalpb.DeliverRequest) (*approvalpb.DeliverResponse, error) {
	env, err := openEnvelope(req.GetBatch())
	if err != nil {
		p.t.Errorf("%s received an envelope it cannot verify: %v", p.name, err)
		return nil, status.Error(codes.InvalidArgument, "malformed batch")
	}
	p.mu.Lock()
	answer := p.always
	if len(p.script) > 0 {
		answer, p.script = p.script[0], p.script[1:]
	}
	gate, boot := p.gate, p.boot
	p.calls = append(p.calls, delivered{boot: boot, envelope: env, at: time.Now(), answer: answer})
	p.active++
	p.peak = max(p.peak, p.active)
	p.mu.Unlock()
	defer p.set(func(p *producer) { p.active-- })
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	switch answer {
	case codes.OK:
		p.set(func(p *producer) { p.stored[boot] = append(p.stored[boot], env.hashes...) })
		return &approvalpb.DeliverResponse{BootId: boot, Stored: uint32(len(env.hashes))}, nil
	case answerStall:
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	case answerStoreFull:
		_ = grpc.SetTrailer(ctx, metadata.Pairs("ops-approval-reason", "store-full"))
		return nil, status.Error(codes.Unavailable, "approval store full")
	default:
		return nil, status.Error(answer, "scripted refusal")
	}
}

func (p *producer) Status(context.Context, *approvalpb.StatusRequest) (*approvalpb.StatusResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses++
	if p.statusErr != codes.OK {
		return nil, status.Error(p.statusErr, "scripted status refusal")
	}
	return &approvalpb.StatusResponse{BootId: p.boot, ChainId: p.chain, TrustedKeyIds: p.keys,
		MaxTtlMs: p.maxTTLms, Capacity: 100_000, WaitMs: 5000}, nil
}

// storedIn is what the process with this boot id stored, in arrival order.
func (p *producer) storedIn(boot string) []common.Hash {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]common.Hash(nil), p.stored[boot]...)
}

func (p *producer) holds(boot string, hashes ...common.Hash) bool {
	stored := map[common.Hash]bool{}
	for _, h := range p.storedIn(boot) {
		stored[h] = true
	}
	for _, h := range hashes {
		if !stored[h] {
			return false
		}
	}
	return true
}

func (p *producer) received() []delivered {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]delivered(nil), p.calls...)
}

func (p *producer) statusCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.statuses
}

// envelope is a decoded, verified DeliverRequest.batch (contract §2).
type envelope struct {
	keyID           string
	issued, expires time.Time
	hashes          []common.Hash
	reserved        []common.Hash
}

func openEnvelope(raw []byte) (envelope, error) {
	const domain = "OPS_APPROVAL_BATCH_V2\x00"
	if len(raw) < len(domain)+1+ed25519.SignatureSize || !bytes.HasPrefix(raw, []byte(domain)) {
		return envelope{}, errors.New("not a version 2 envelope")
	}
	message, signature := raw[:len(raw)-ed25519.SignatureSize], raw[len(raw)-ed25519.SignatureSize:]
	if !ed25519.Verify(testPublicKey, message, signature) {
		return envelope{}, errors.New("signature does not verify under the test key")
	}
	header := len(domain) + 1 + int(message[len(domain)])
	if len(message) < header+20 {
		return envelope{}, errors.New("header cut short")
	}
	env := envelope{keyID: string(message[len(domain)+1 : header]),
		issued:  time.UnixMilli(int64(binary.BigEndian.Uint64(message[header:]))),
		expires: time.UnixMilli(int64(binary.BigEndian.Uint64(message[header+8:])))}
	count := int(binary.BigEndian.Uint32(message[header+16:]))
	items := message[header+20:]
	if len(items) != count*120 {
		return envelope{}, fmt.Errorf("%d bytes of approvals for a count of %d", len(items), count)
	}
	for i := 0; i < count; i++ {
		item := items[i*120 : (i+1)*120]
		env.hashes = append(env.hashes, common.BytesToHash(item[24:56]))
		env.reserved = append(env.reserved, common.BytesToHash(item[88:120]))
	}
	return env, nil
}

// testDelivery is a deliveryConfig for in-process producers, with Status polling, the ready
// window and the drain shortened so tests take milliseconds instead of seconds.
func testDelivery(producers ...*producer) deliveryConfig {
	cfg := deliveryConfig{timeout: 500 * time.Millisecond, maxInFlight: defaultMaxInFlight, retainMax: defaultRetainMax,
		statusEvery: 50 * time.Millisecond, readyWindow: 500 * time.Millisecond, drain: 500 * time.Millisecond}
	byName := map[string]*producer{}
	for _, p := range producers {
		cfg.targets = append(cfg.targets, p.name)
		byName[p.name] = p
	}
	cfg.dialer = func(ctx context.Context, addr string) (net.Conn, error) {
		p, ok := byName[addr]
		if !ok {
			return nil, fmt.Errorf("no producer at %s", addr)
		}
		return p.dial(ctx)
	}
	return cfg
}

// startDelivery runs a Service's signer and delivery lanes without a preflight node.
func startDelivery(t *testing.T, ttl time.Duration, cfg deliveryConfig) *Service {
	t.Helper()
	s := &Service{signer: NewEd25519Signer("default", testSeed), ttl: ttl, maxBatch: MaxBatchApprovals, hops: newHops()}
	if err := s.startDelivery(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func txHashes(from, n int) []common.Hash {
	hashes := make([]common.Hash, n)
	for i := range hashes {
		hashes[i] = common.BigToHash(big.NewInt(int64(from + i)))
	}
	return hashes
}

func approvalFor(hash common.Hash) *Prepared {
	return &Prepared{Approval: Approval{HashMode: HashCalls, ChainID: 31337, TxHash: hash, Fingerprint: common.HexToHash("0x5678")}}
}

func enqueue(t *testing.T, s *Service, hashes ...common.Hash) {
	t.Helper()
	for _, h := range hashes {
		if err := s.Enqueue(approvalFor(h)); err != nil {
			t.Fatalf("enqueue %s: %v", h, err)
		}
	}
}

// signedBatch signs approvals for hashes under the test key with the given lifetime.
func signedBatch(t *testing.T, ttl time.Duration, hashes ...common.Hash) Batch {
	t.Helper()
	approvals := make([]Approval, len(hashes))
	for i, h := range hashes {
		approvals[i] = approvalFor(h).Approval
	}
	b, err := NewEd25519Signer("default", testSeed).SignBatch(approvals, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitUntil(t *testing.T, within time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting until %s", within, what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitReady(t *testing.T, s *Service) {
	t.Helper()
	waitUntil(t, 3*time.Second, "a producer is ready", func() bool { return s.ready(31337, time.Now()) })
}

// value reads a counter, a gauge, or a histogram's sample count.
func value(t *testing.T, metric any) float64 {
	t.Helper()
	m, ok := metric.(prometheus.Metric)
	if !ok {
		t.Fatalf("%T is not a single metric", metric)
	}
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		t.Fatal(err)
	}
	switch {
	case d.Counter != nil:
		return d.GetCounter().GetValue()
	case d.Gauge != nil:
		return d.GetGauge().GetValue()
	case d.Histogram != nil:
		return float64(d.GetHistogram().GetSampleCount())
	}
	t.Fatalf("unsupported metric %v", &d)
	return 0
}

// readyLane is a lane without a connection that counts as ready for chain, for tests of the
// signer and the queue that need Enqueue to accept.
func readyLane(chain uint64) *lane {
	l := &lane{}
	l.readyChain.Store(chain)
	l.readyUntil.Store(time.Now().Add(time.Hour).UnixNano())
	return l
}
