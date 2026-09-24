package nodeapproval

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Opt-in diagnostics, buffered until shutdown. No per-approval logging or disk
// writes in the live path. Unix timestamps are comparable only on the same host.
// The delivery marks follow the first target's first delivery of the batch.
type Hop struct {
	Hash      common.Hash `json:"hash"`
	Queued    int64       `json:"queued"`
	SignStart int64       `json:"sign_start"`
	SignEnd   int64       `json:"sign_end"`
	// CallStart is when the first Deliver call for the batch began; Stored is when the producer
	// answered OK, retries included.
	CallStart    int64 `json:"call_start"`
	Stored       int64 `json:"stored"`
	ForwardStart int64 `json:"forward_start"`
}
type hops struct {
	path  string
	limit int
	mu    sync.Mutex
	rows  []*Hop
}

// defaultHopLimit bounds memory when the recorder is on; OPS_APPROVAL_HOPS_LIMIT
// raises it for a load run, so a sample covers the whole run and not its start.
const defaultHopLimit = 8192

func newHops() *hops {
	path := os.Getenv("OPS_APPROVAL_HOPS_FILE")
	if path == "" {
		return nil
	}
	limit := defaultHopLimit
	if value := os.Getenv("OPS_APPROVAL_HOPS_LIMIT"); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			limit = n
		}
	}
	return &hops{path: path, limit: limit}
}
func (h *hops) add(hash common.Hash) *Hop {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.rows) >= h.limit {
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
