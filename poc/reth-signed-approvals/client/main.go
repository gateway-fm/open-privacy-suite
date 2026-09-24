// Test fixture: prepares/signs approved benchmark transactions outside the timed Reth path.
// Authorization itself is exercised separately through the real OPS processor + PostgreSQL.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"os"
	"privacy-proxy/internal/nodeapproval"
)

func main() {
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
	for scan.Scan() {
		var q struct {
			Approvals []nodeapproval.Approval `json:"approvals"`
			Raw       string                  `json:"raw"`
			Principal string                  `json:"principal"`
		}
		if err := json.Unmarshal(scan.Bytes(), &q); err != nil {
			panic(err)
		}
		if q.Approvals != nil {
			for i := range q.Approvals {
				q.Approvals[i].Signature = ""
			}
			b, err := nodeapproval.SignBatch(key, q.Approvals)
			if err != nil {
				out.Encode(map[string]any{"error": err.Error()})
			} else {
				out.Encode(b)
			}
			continue
		}
		p, err := s.Prepare(context.Background(), q.Raw)
		if err != nil {
			out.Encode(map[string]any{"error": err.Error()})
			continue
		}
		p.Approval.Principal = crypto.Keccak256Hash([]byte(q.Principal))
		p.Approval.Signature = hex.EncodeToString(ed25519.Sign(key, p.Approval.Message()))
		out.Encode(p)
	}
}
