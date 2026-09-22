package nodeapproval

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const MaxBatchApprovals = 32
const MaxBatchFrame = 16384

// Batch signs complete approvals, including their individual hash-mode domain, in order.
// A batch is only a delivery unit; transactions execute independently. Version 2 names the
// key that signed it, so a producer can hold several trusted keys and a rotation is
// add-then-switch instead of a simultaneous restart of every node and OPS.
type Batch struct {
	frame     []byte
	Version   uint32     `json:"version"`
	KeyID     string     `json:"key_id"`
	Approvals []Approval `json:"approvals"`
	Signature string     `json:"signature"`
}

const BatchVersion = 2
const batchDomain = "OPS_APPROVAL_BATCH_V2\x00"

// ValidKeyID accepts the identifiers a key set on the producer is keyed by: 1–64 characters
// from [A-Za-z0-9._:-]. The identifier is signed with the batch, so it cannot be swapped.
func ValidKeyID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == ':' || r == '-') {
			return false
		}
	}
	return true
}

// Message is the signed bytes:
// OPS_APPROVAL_BATCH_V2\0 | u8 key id length | key id | u32 count | count × 120-byte items.
func (b Batch) Message() ([]byte, error) {
	if b.Version != BatchVersion || len(b.Approvals) == 0 || len(b.Approvals) > MaxBatchApprovals || !ValidKeyID(b.KeyID) {
		return nil, errors.New("unsupported or invalid approval batch")
	}
	message := []byte(batchDomain)
	message = append(message, byte(len(b.KeyID)))
	message = append(message, b.KeyID...)
	message = binary.BigEndian.AppendUint32(message, uint32(len(b.Approvals)))
	for _, a := range b.Approvals {
		if !validHashMode(a.HashMode) {
			return nil, errors.New("unknown approval hash mode")
		}
		if a.Signature != "" {
			return nil, errors.New("batch members must not have individual signatures")
		}
		message = append(message, a.Message()...)
	}
	return message, nil
}

// Frame is the length-prefixed wire encoding produced by SignBatch (test fixtures deliver it directly).
func (b Batch) Frame() []byte { return b.frame }

// Signer produces the batch signature. The interface is the seam for a KMS- or HSM-backed
// signer later; the producer only ever sees a key id and a signature.
type Signer interface {
	KeyID() string
	SignBatch(approvals []Approval) (Batch, error)
}

// Ed25519Signer signs with a software key held by OPS. The seed arrives like every other OPS
// secret — environment or a Secrets Manager–mounted file — never from a config file.
type Ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

func NewEd25519Signer(keyID string, seed []byte) *Ed25519Signer {
	if len(seed) != ed25519.SeedSize {
		return &Ed25519Signer{keyID: keyID}
	}
	return &Ed25519Signer{keyID: keyID, key: ed25519.NewKeyFromSeed(seed)}
}

func (s *Ed25519Signer) KeyID() string { return s.keyID }

// PublicKey is what the producer must be configured with, under this signer's key id.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	if s.key == nil {
		return nil
	}
	return s.key.Public().(ed25519.PublicKey)
}

func (s *Ed25519Signer) SignBatch(approvals []Approval) (Batch, error) {
	if s.key == nil {
		return Batch{}, errors.New("approval signer has no key")
	}
	b := Batch{Version: BatchVersion, KeyID: s.keyID, Approvals: append([]Approval(nil), approvals...)}
	message, err := b.Message()
	if err != nil {
		return Batch{}, err
	}
	signature := ed25519.Sign(s.key, message)
	b.Signature = hex.EncodeToString(signature)
	b.frame = binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(message)+len(signature)), uint32(len(message)+len(signature)))
	b.frame = append(b.frame, message...)
	b.frame = append(b.frame, signature...)
	return b, nil
}

// SignBatch signs under the key id "default"; fixtures and the harness client use it.
func SignBatch(key ed25519.PrivateKey, approvals []Approval) (Batch, error) {
	return (&Ed25519Signer{keyID: "default", key: key}).SignBatch(approvals)
}
