package nodeapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func batchFixtures(n int) []Approval {
	a := make([]Approval, n)
	for i := range a {
		a[i] = Approval{ChainID: 31337, TxHash: common.BigToHash(common.Big1), Fingerprint: common.HexToHash(fmt.Sprintf("0x%x", i+2)), Principal: common.HexToHash("0x03")}
	}
	return a
}

func TestBatchGolden(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	batch, err := goldenSigner(key).SignBatch(batchFixtures(3))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(batch, "", "  ")
	data = append(data, '\n')
	// Explicit regeneration only; the fixture is also independently verified by Rust.
	if os.Getenv("OPS_UPDATE_BATCH_GOLDEN") == "1" {
		if err := os.WriteFile("testdata/batch.json", data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile("testdata/batch.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, golden) {
		t.Fatal("batch protocol changed")
	}
	message, _ := batch.Message()
	sig, _ := hex.DecodeString(batch.Signature)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, sig) {
		t.Fatal("invalid signature")
	}
	for _, n := range []int{0, 33} {
		if _, err := SignBatch(key, batchFixtures(n)); err == nil {
			t.Fatal("accepted invalid batch size", n)
		}
	}
	b32, err := SignBatch(key, batchFixtures(32))
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := json.Marshal(b32)
	if len(frame) > MaxBatchFrame {
		t.Fatal("valid batch exceeds ingress limit")
	}
}

func nextBatch(t *testing.T, ch <-chan Batch) Batch {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(time.Second):
		t.Fatal("signer waited for more approvals")
		return Batch{}
	}
}

func TestSignerSnapshotIndependentOfDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan []Approval, 4)
	release := make(chan struct{})
	hook := &hookSigner{Signer: NewEd25519Signer("default", make([]byte, 32)), entered: entered, release: release}
	s := &Service{signer: hook, queue: make(chan Approval, 64), signed: make(chan Batch, 4), maxBatch: 32, signDone: make(chan struct{}), done: make(chan struct{})}
	s.queue <- batchFixtures(1)[0]
	go s.signLoop(ctx)
	defer func() { cancel(); <-s.signDone }()
	first := <-entered
	if len(first) != 1 {
		t.Fatal("first snapshot", len(first))
	}
	// Blocked crypto must not block Enqueue. These 33 arrive during the first signature.
	for i := 0; i < 33; i++ {
		if err := s.Enqueue(&Prepared{}, "principal"); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	// There is deliberately no delivery worker. Signing can run ahead independently.
	for _, want := range []int{1, 32, 1} {
		b := nextBatch(t, s.signed)
		if len(b.Approvals) != want {
			t.Fatalf("got %d, want %d", len(b.Approvals), want)
		}
	}
}

func BenchmarkBatchSigning(b *testing.B) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	for _, n := range []int{1, 3, 32} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			a := batchFixtures(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				batch, err := SignBatch(key, a)
				if err != nil || batch.Signature == "" {
					b.Fatal(err)
				}
			}
		})
	}
}

// hookSigner reports each batch it is asked to sign and blocks the first one until released,
// so a test can observe what the signer snapshotted while crypto is "slow".
type hookSigner struct {
	Signer
	entered chan []Approval
	release chan struct{}
	calls   int
}

func (h *hookSigner) SignBatch(a []Approval) (Batch, error) {
	h.calls++
	h.entered <- a
	if h.calls == 1 {
		<-h.release
	}
	return h.Signer.SignBatch(a)
}
