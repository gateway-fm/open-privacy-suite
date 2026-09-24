package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodehttp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// registerNodeApprovalMetrics registers the gate's delivery collector on reg, so
// /metrics serves it next to the server's own metrics. With the gate off there is
// nothing to register.
func (p *JSONRPCProcessor) registerNodeApprovalMetrics(reg prometheus.Registerer) error {
	if p.nodeApprovals == nil {
		return nil
	}
	return reg.Register(p.nodeApprovals)
}

// refuseApprovalDelivery answers a transaction no producer can take an approval
// for: 503, logged like every other refusal, and never forwarded.
func (p *JSONRPCProcessor) refuseApprovalDelivery(ctx context.Context, req *ProcessRequest, start time.Time) *ProcessResult {
	p.recordRPCOutcome(req.Method, "approval_delivery_unavailable", start)
	req.denialReason = ReasonUpstreamError
	p.logAccess(ctx, req, http.StatusServiceUnavailable)
	return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusServiceUnavailable, Message: "approval delivery unavailable", Reason: ReasonUpstreamError}}
}

// closeNodeApprovals stops approval delivery, if it was started, when the server fails to start
// after configuring it.
func (p *JSONRPCProcessor) closeNodeApprovals() {
	if p.nodeApprovals != nil {
		p.nodeApprovals.Close()
	}
}
