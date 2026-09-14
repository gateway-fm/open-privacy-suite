package nodeapproval

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Opt-in diagnostics, buffered until shutdown. No per-approval logging or disk
// writes in the live path. Unix timestamps are comparable only on the same host.
type Hop struct {
	Hash          common.Hash `json:"hash"`
	Queued        int64       `json:"queued"`
	SignStart     int64       `json:"sign_start"`
	SignEnd       int64       `json:"sign_end"`
	DeliveryStart int64       `json:"delivery_start"`
	Encoded       int64       `json:"encoded"`
	ConnectStart  int64       `json:"connect_start"`
	Connected     int64       `json:"connected"`
	WriteStart    int64       `json:"write_start"`
	Written       int64       `json:"written"`
	ForwardStart  int64       `json:"forward_start"`
}
type hops struct {
	path string
	mu   sync.Mutex
	rows []*Hop
}

func newHops() *hops {
	if path := os.Getenv("OPS_APPROVAL_HOPS_FILE"); path != "" {
		return &hops{path: path}
	}
	return nil
}
func (h *hops) add(hash common.Hash) *Hop {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.rows) >= 8192 {
		return nil
	}
	r := &Hop{Hash: hash, Queued: time.Now().UnixNano()}
	h.rows = append(h.rows, r)
	return r
}
func (h *hops) flush() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	data, err := json.Marshal(h.rows)
	if err == nil {
		err = os.WriteFile(h.path, data, 0600)
	}
	if err != nil {
		slog.Error("approval diagnostics write failed", "error", err)
	}
}
func mark(approvals []Approval, field func(*Hop, int64)) {
	if len(approvals) == 0 || approvals[0].hop == nil {
		return
	}
	now := time.Now().UnixNano()
	for _, a := range approvals {
		if a.hop != nil {
			field(a.hop, now)
		}
	}
}
func (s *Service) TraceForward(p *Prepared) {
	if p.Approval.hop != nil {
		p.Approval.hop.ForwardStart = time.Now().UnixNano()
	}
}
