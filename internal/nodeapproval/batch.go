package nodeapproval

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"time"
)

const MaxBatchApprovals = 32
const MaxBatchFrame = 16384

// Batch signs complete approvals, including their individual hash-mode domain, in order.
// A batch is only a delivery unit; transactions execute independently. Version 2 names the
// key that signed it, so a producer can hold several trusted keys and a rotation is
// add-then-switch instead of a simultaneous restart of every node and OPS.
type Batch struct {
	frame   []byte
	encoded []byte
	Version uint32 `json:"version"`
	KeyID   string `json:"key_id"`
	// IssuedAt and ExpiresAt are Unix milliseconds and part of the signed bytes. A
	// producer uses the batch's approvals only before ExpiresAt, which bounds how
	// long a decision outlives a policy change and how long a producer keeps it.
	IssuedAt  uint64     `json:"issued_at"`
	ExpiresAt uint64     `json:"expires_at"`
	Approvals []Approval `json:"approvals"`
	Signature string     `json:"signature"`
}

// DefaultApprovalTTL is how long a signed approval stays usable unless OPS_APPROVAL_TTL says
// otherwise. MinApprovalTTL leaves room for a producer's wait window plus a block;
// MaxApprovalTTL is the longest OPS will sign.
const (
	DefaultApprovalTTL = 10 * time.Minute
	MinApprovalTTL     = 10 * time.Second
	MaxApprovalTTL     = time.Hour
)

// configuredApprovalTTL reads OPS_APPROVAL_TTL (a Go duration, 10s to 1h).
func configuredApprovalTTL() (time.Duration, error) {
	value := os.Getenv("OPS_APPROVAL_TTL")
	if value == "" {
		return DefaultApprovalTTL, nil
	}
	ttl, err := time.ParseDuration(value)
	if err != nil || ttl < MinApprovalTTL || ttl > MaxApprovalTTL {
		return 0, errors.New("OPS_APPROVAL_TTL must be a duration between 10s and 1h")
	}
	return ttl, nil
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
	if b.ExpiresAt <= b.IssuedAt {
		return nil, errors.New("approval batch must expire after it is issued")
	}
	message := []byte(batchDomain)
	message = append(message, byte(len(b.KeyID)))
	message = append(message, b.KeyID...)
	message = binary.BigEndian.AppendUint64(message, b.IssuedAt)
	message = binary.BigEndian.AppendUint64(message, b.ExpiresAt)
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

// Encoded is the signed envelope as it travels: the signed message followed by
// the 64-byte Ed25519 signature (docs/implementation/approvals-wire-contract.md).
func (b Batch) Encoded() []byte { return b.encoded }

// Signer produces the batch signature. The interface is the seam for a KMS- or HSM-backed
// signer later; the producer only ever sees a key id and a signature. The lifetime is chosen
// per batch, because it depends on what the producers accept (wire contract §5).
type Signer interface {
	KeyID() string
	SignBatch(approvals []Approval, ttl time.Duration) (Batch, error)
}

// Ed25519Signer signs with a software key held by OPS. The seed arrives like every other OPS
// secret — environment or a Secrets Manager–mounted file — never from a config file.
type Ed25519Signer struct {
	keyID string
	key   ed25519.PrivateKey
	now   func() time.Time
}

func NewEd25519Signer(keyID string, seed []byte) *Ed25519Signer {
	s := &Ed25519Signer{keyID: keyID, now: time.Now}
	if len(seed) == ed25519.SeedSize {
		s.key = ed25519.NewKeyFromSeed(seed)
	}
	return s
}

func (s *Ed25519Signer) KeyID() string { return s.keyID }

// PublicKey is what the producer must be configured with, under this signer's key id.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	if s.key == nil {
		return nil
	}
	return s.key.Public().(ed25519.PublicKey)
}

// SignBatch signs approvals that stay usable for ttl from now.
func (s *Ed25519Signer) SignBatch(approvals []Approval, ttl time.Duration) (Batch, error) {
	if s.key == nil {
		return Batch{}, errors.New("approval signer has no key")
	}
	if ttl < time.Millisecond {
		return Batch{}, errors.New("approval TTL must be positive")
	}
	issued := uint64(s.now().UnixMilli())
	b := Batch{Version: BatchVersion, KeyID: s.keyID, IssuedAt: issued, ExpiresAt: issued + uint64(ttl.Milliseconds()), Approvals: append([]Approval(nil), approvals...)}
	message, err := b.Message()
	if err != nil {
		return Batch{}, err
	}
	signature := ed25519.Sign(s.key, message)
	b.Signature = hex.EncodeToString(signature)
	b.encoded = append(append(make([]byte, 0, len(message)+len(signature)), message...), signature...)
	b.frame = binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b.encoded)), uint32(len(b.encoded)))
	b.frame = append(b.frame, b.encoded...)
	return b, nil
}

// SignBatch signs under the key id "default" with the default TTL; fixtures and the harness
// client use it.
func SignBatch(key ed25519.PrivateKey, approvals []Approval) (Batch, error) {
	return (&Ed25519Signer{keyID: "default", key: key, now: time.Now}).SignBatch(approvals, DefaultApprovalTTL)
}
