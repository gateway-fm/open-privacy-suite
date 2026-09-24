package nodeapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// goldenIssued is the fixed signing instant of the golden vectors.
var goldenIssued = time.UnixMilli(1790000000000).UTC()

// goldenSigner signs at goldenIssued so golden vectors are reproducible.
func goldenSigner(key ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{keyID: "default", key: key, now: func() time.Time { return goldenIssued }}
}

func TestBatchCarriesItsExpiry(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	batch, err := goldenSigner(key).SignBatch(batchFixtures(2), 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if batch.IssuedAt != uint64(goldenIssued.UnixMilli()) || batch.ExpiresAt != batch.IssuedAt+90_000 {
		t.Fatalf("issued_at %d, expires_at %d", batch.IssuedAt, batch.ExpiresAt)
	}
	message, err := batch.Message()
	if err != nil {
		t.Fatal(err)
	}
	// domain | u8 key id length | key id | u64 issued_at | u64 expires_at | u32 count | items
	header := len(batchDomain) + 1 + len("default")
	if got := binary.BigEndian.Uint64(message[header:]); got != batch.IssuedAt {
		t.Fatalf("issued_at on the wire %d", got)
	}
	if got := binary.BigEndian.Uint64(message[header+8:]); got != batch.ExpiresAt {
		t.Fatalf("expires_at on the wire %d", got)
	}
	if got := binary.BigEndian.Uint32(message[header+16:]); got != 2 {
		t.Fatalf("count on the wire %d", got)
	}
	sig, _ := hex.DecodeString(batch.Signature)
	if !bytes.Equal(batch.Encoded(), append(append([]byte{}, message...), sig...)) {
		t.Fatal("the encoded batch is not message || signature")
	}
	tampered := batch
	tampered.ExpiresAt++
	changed, _ := tampered.Message()
	if ed25519.Verify(key.Public().(ed25519.PublicKey), changed, sig) {
		t.Fatal("the expiry is not covered by the signature")
	}
}

func TestBatchRefusesAnExpiryNotAfterIssue(t *testing.T) {
	for _, expires := range []uint64{1000, 999} {
		b := Batch{Version: BatchVersion, KeyID: "default", IssuedAt: 1000, ExpiresAt: expires, Approvals: batchFixtures(1)}
		if _, err := b.Message(); err == nil {
			t.Fatalf("accepted expires_at %d for issued_at 1000", expires)
		}
	}
	if _, err := goldenSigner(ed25519.NewKeyFromSeed(make([]byte, 32))).SignBatch(batchFixtures(1), 0); err == nil {
		t.Fatal("signed with a zero TTL")
	}
}

func TestApprovalTTLSetting(t *testing.T) {
	for value, want := range map[string]time.Duration{"": DefaultApprovalTTL, "10s": 10 * time.Second, "90s": 90 * time.Second, "1h": time.Hour} {
		t.Setenv("OPS_APPROVAL_TTL", value)
		if got, err := configuredApprovalTTL(); err != nil || got != want {
			t.Fatalf("OPS_APPROVAL_TTL=%q: got %v, %v; want %v", value, got, err, want)
		}
	}
	// The minimum leaves room for a producer's wait window plus a block (wire contract §5).
	for _, value := range []string{"9s", "0", "-1s", "61m", "ten minutes"} {
		t.Setenv("OPS_APPROVAL_TTL", value)
		if _, err := configuredApprovalTTL(); err == nil {
			t.Fatalf("accepted OPS_APPROVAL_TTL=%q", value)
		}
	}
}
