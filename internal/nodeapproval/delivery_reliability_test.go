package nodeapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// brokenConn is a connection whose first write fails the way a stalled or reset
// socket does. Reads block until Close so the connection watcher behaves as it
// would on a live socket.
type brokenConn struct {
	mu     sync.Mutex
	closed chan struct{}
	once   sync.Once
	writes int
}

func newBrokenConn() *brokenConn { return &brokenConn{closed: make(chan struct{})} }
func (c *brokenConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}
func (c *brokenConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return 0, errors.New("connection reset by peer")
}
func (c *brokenConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *brokenConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *brokenConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *brokenConn) SetDeadline(time.Time) error      { return nil }
func (c *brokenConn) SetReadDeadline(time.Time) error  { return nil }
func (c *brokenConn) SetWriteDeadline(time.Time) error { return nil }

// readApprovalHashes reads length-prefixed batches from c until every wanted hash
// has been seen or the deadline passes, and returns the hashes it saw.
func readApprovalHashes(t *testing.T, c net.Conn, want int, deadline time.Time) map[common.Hash]bool {
	t.Helper()
	seen := map[common.Hash]bool{}
	_ = c.SetReadDeadline(deadline)
	for len(seen) < want {
		var n uint32
		if err := binary.Read(c, binary.BigEndian, &n); err != nil {
			return seen
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(c, frame); err != nil {
			return seen
		}
		message := frame[:len(frame)-ed25519.SignatureSize]
		if !bytes.HasPrefix(message, []byte("OPS_APPROVAL_BATCH_V1\x00")) {
			t.Fatalf("unexpected frame %q", message[:min(len(message), 24)])
		}
		count := binary.BigEndian.Uint32(message[22:26])
		body := message[26:]
		for i := uint32(0); i < count; i++ {
			// Each item: domain (16) | chain (8) | tx hash (32) | fingerprint (32) | principal (32) = 120 bytes.
			item := body[i*120 : (i+1)*120]
			seen[common.BytesToHash(item[24:56])] = true
		}
	}
	return seen
}

// An approval whose delivery fails must still reach the producer once the
// connection is back. Today the batch is dropped on the write error and the
// transaction times out in the pool with nobody told; production needs the
// approval to survive the connection, not the connection to survive the approval.
func TestApprovalSurvivesAFailedWrite(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	seed := bytes.Repeat([]byte{7}, 32)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{key: ed25519.NewKeyFromSeed(seed), address: listener.Addr().String(),
		queue: make(chan Approval, 4096), signed: make(chan Batch, 128), maxBatch: MaxBatchApprovals,
		sign: SignBatch, cancel: cancel, done: make(chan struct{}), signDone: make(chan struct{})}
	first := newBrokenConn()
	go s.signLoop(ctx)
	go s.deliver(ctx, first)
	defer s.Close()

	hash := common.HexToHash("0xfeed")
	p := &Prepared{Approval: Approval{ChainID: 31337, TxHash: hash, Fingerprint: common.HexToHash("0x5678")}}
	if err := s.Enqueue(p, "did:fixture"); err != nil {
		t.Fatal(err)
	}
	// The first write fails; OPS reconnects to the listener. The approval must arrive there.
	if l, ok := listener.(*net.TCPListener); ok {
		_ = l.SetDeadline(time.Now().Add(3 * time.Second))
	}
	replacement, err := listener.Accept()
	if err != nil {
		t.Fatalf("no reconnect after the failed write: %v", err)
	}
	defer replacement.Close()
	seen := readApprovalHashes(t, replacement, 1, time.Now().Add(2*time.Second))
	first.mu.Lock()
	writes := first.writes
	first.mu.Unlock()
	if writes == 0 {
		t.Fatal("the broken connection was never written to; the test did not exercise the failure")
	}
	if !seen[hash] {
		t.Fatalf("approval %s was lost with the failed write: it never reached the reconnected producer", hash)
	}
}
