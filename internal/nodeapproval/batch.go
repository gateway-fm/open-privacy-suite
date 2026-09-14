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
// A batch is only a delivery unit; transactions execute independently.
type Batch struct {
	frame     []byte
	Version   uint32     `json:"version"`
	Approvals []Approval `json:"approvals"`
	Signature string     `json:"signature"`
}

func (b Batch) Message() ([]byte, error) {
	if b.Version != 1 || len(b.Approvals) == 0 || len(b.Approvals) > MaxBatchApprovals {
		return nil, errors.New("unsupported or invalid approval batch")
	}
	message := []byte("OPS_APPROVAL_BATCH_V1\x00")
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

func SignBatch(key ed25519.PrivateKey, approvals []Approval) (Batch, error) {
	b := Batch{Version: 1, Approvals: append([]Approval(nil), approvals...)}
	message, err := b.Message()
	if err != nil {
		return Batch{}, err
	}
	signature := ed25519.Sign(key, message)
	b.Signature = hex.EncodeToString(signature)
	b.frame = binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(message)+len(signature)), uint32(len(message)+len(signature)))
	b.frame = append(b.frame, message...)
	b.frame = append(b.frame, signature...)
	return b, nil
}
