// Test fixture: runs the real OPS preflight (nodeapproval.Service in Besu mode) and signs approvals
// with the fixture key, so the harness exercises internal/nodeapproval exactly as OPS would.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/nodeapproval"
)

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: client <node-rpc-url>")
	}
	seed := bytes.Repeat([]byte{7}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	s, err := nodeapproval.NewPreflight(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer s.Close()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1<<20)
	out := json.NewEncoder(os.Stdout)
	emit := func(v any) {
		if err := out.Encode(v); err != nil {
			log.Fatal(err)
		}
	}
	for scan.Scan() {
		var q struct {
			Approvals   []nodeapproval.Approval `json:"approvals"`
			Raw         string                  `json:"raw"`
			Principal   string                  `json:"principal"`
			Fingerprint map[string]any          `json:"fingerprint"` // {calls, pre}: Go encoder over a geth trace
		}
		if err := json.Unmarshal(scan.Bytes(), &q); err != nil {
			panic(err)
		}
		switch {
		case q.Fingerprint != nil:
			calls, _ := q.Fingerprint["calls"].(map[string]any)
			pre, _ := q.Fingerprint["pre"].(map[string]any)
			h, _, err := nodeapproval.CallFingerprint(calls, pre)
			if err != nil {
				emit(map[string]any{"error": err.Error()})
			} else {
				emit(map[string]any{"fingerprint": h.Hex()})
			}
		case q.Approvals != nil:
			for i := range q.Approvals {
				q.Approvals[i].Signature = ""
			}
			b, err := nodeapproval.SignBatch(key, q.Approvals)
			if err != nil {
				emit(map[string]any{"error": err.Error()})
			} else {
				emit(map[string]any{"batch": b, "frame": hex.EncodeToString(b.Frame())})
			}
		default:
			p, err := s.Prepare(context.Background(), q.Raw)
			if err != nil {
				emit(map[string]any{"error": err.Error()})
				continue
			}
			p.Approval.Principal = crypto.Keccak256Hash([]byte(q.Principal))
			// Delivery signs batches; the harness re-signs through the batch path, so no per-item signature.
			// The creation sets drive OPS's contract registration, so the harness asserts them.
			emit(map[string]any{
				"Approval":           p.Approval,
				"Trace":              p.Trace,
				"surviving":          keys(p.SurvivingCreations),
				"fresh":              keys(p.FreshCreations),
				"plainValueTransfer": p.PlainValueTransfer,
			})
		}
	}
}
