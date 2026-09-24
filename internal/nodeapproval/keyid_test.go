package nodeapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// A batch names the key that signed it, so a producer can hold several trusted keys and a
// rotation is add-then-switch instead of a simultaneous restart of every node and OPS.
func TestBatchNamesItsSigningKey(t *testing.T) {
	signer := NewEd25519Signer("ops-2026-09", bytes.Repeat([]byte{7}, 32))
	batch, err := signer.SignBatch(batchFixtures(2), DefaultApprovalTTL)
	if err != nil {
		t.Fatal(err)
	}
	if batch.KeyID != "ops-2026-09" || batch.Version != 2 {
		t.Fatalf("batch = version %d key %q", batch.Version, batch.KeyID)
	}
	message, err := batch.Message()
	if err != nil {
		t.Fatal(err)
	}
	// OPS_APPROVAL_BATCH_V2\0 | u8 key id length | key id | u32 count | items
	domain := []byte("OPS_APPROVAL_BATCH_V2\x00")
	if !bytes.HasPrefix(message, domain) {
		t.Fatalf("domain %q", message[:22])
	}
	if int(message[len(domain)]) != len("ops-2026-09") || string(message[len(domain)+1:len(domain)+1+11]) != "ops-2026-09" {
		t.Fatal("key id not carried in the signed bytes")
	}
	sig, _ := hex.DecodeString(batch.Signature)
	if !ed25519.Verify(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey), message, sig) {
		t.Fatal("signature does not cover the key id")
	}
	// The envelope on the wire is the message plus the signature.
	if got := batch.Encoded(); len(got) != len(message)+ed25519.SignatureSize {
		t.Fatalf("encoded length %d", len(got))
	}
	for _, id := range []string{"", "has space", string(make([]byte, 65))} {
		if _, err := NewEd25519Signer(id, bytes.Repeat([]byte{7}, 32)).SignBatch(batchFixtures(1), DefaultApprovalTTL); err == nil {
			t.Fatalf("accepted key id %q", id)
		}
	}
}
