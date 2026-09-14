package server

import (
	"encoding/hex"
	"fmt"
	"os"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodehttp"
	"strings"
)

// Opt-in PoC. Default deployments retain the existing path.
func (p *JSONRPCProcessor) configureNodeApprovals(nodeURL string, tc nodehttp.TransportConfig) error {
	address := os.Getenv("OPS_APPROVAL_TARGET")
	if address == "" {
		return nil
	}
	bytes, err := os.ReadFile(os.Getenv("OPS_APPROVAL_SEED_FILE"))
	if err != nil {
		return fmt.Errorf("read approval signing seed: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(bytes)))
	if err != nil {
		return fmt.Errorf("decode approval signing seed: %w", err)
	}
	p.nodeApprovals, err = nodeapproval.NewWithTransport(nodeURL, address, seed, tc)
	return err
}
