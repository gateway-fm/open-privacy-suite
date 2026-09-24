package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodehttp"
	"strings"
)

// configureNodeApprovals turns the signed-approval gate on when OPS_APPROVAL_TARGETS names the
// producers to deliver to. Default deployments retain the existing path.
func (p *JSONRPCProcessor) configureNodeApprovals(nodeURL string, tc nodehttp.TransportConfig) error {
	if os.Getenv("OPS_APPROVAL_TARGET") != "" {
		// Ignoring the retired setting would switch the gate off without a word.
		return errors.New("OPS_APPROVAL_TARGET is replaced by OPS_APPROVAL_TARGETS, a comma-separated host:port list")
	}
	targets := os.Getenv("OPS_APPROVAL_TARGETS")
	if targets == "" {
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
	p.nodeApprovals, err = nodeapproval.NewWithTransport(nodeURL, targets, seed, tc)
	return err
}
