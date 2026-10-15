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

// nodeApprovalsFromEnv turns the signed-approval gate on when OPS_APPROVAL_TARGETS names the
// producers to deliver to. Default deployments retain the existing path.
func nodeApprovalsFromEnv(nodeURL string, tc nodehttp.TransportConfig) (*nodeapproval.Service, error) {
	if os.Getenv("OPS_APPROVAL_TARGET") != "" {
		// Ignoring the retired setting would switch the gate off without a word.
		return nil, errors.New("OPS_APPROVAL_TARGET is replaced by OPS_APPROVAL_TARGETS, a comma-separated host:port list")
	}
	targets := os.Getenv("OPS_APPROVAL_TARGETS")
	if targets == "" {
		return nil, nil
	}
	bytes, err := os.ReadFile(os.Getenv("OPS_APPROVAL_SEED_FILE"))
	if err != nil {
		return nil, fmt.Errorf("read approval signing seed: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(bytes)))
	if err != nil {
		return nil, fmt.Errorf("decode approval signing seed: %w", err)
	}
	return nodeapproval.NewWithTransport(nodeURL, targets, seed, tc)
}

// registerNodeApprovalMetrics registers the gate's delivery collector on reg, so
// /metrics serves it next to the server's own metrics. With the gate off there is
// nothing to register.
func registerNodeApprovalMetrics(approvals *nodeapproval.Service, reg prometheus.Registerer) error {
	if approvals == nil {
		return nil
	}
	return reg.Register(approvals)
}

// refuseApprovalDelivery answers a transaction no producer can take an approval
// for: 503, logged like every other refusal, and never forwarded.
func (p *JSONRPCProcessor) refuseApprovalDelivery(ctx context.Context, req *ProcessRequest, start time.Time) *ProcessResult {
	p.recordRPCOutcome(req.Method, "approval_delivery_unavailable", start)
	req.denialReason = ReasonUpstreamError
	p.logAccess(ctx, req, http.StatusServiceUnavailable)
	return &ProcessResult{Error: &ProcessError{StatusCode: http.StatusServiceUnavailable, Message: "approval delivery unavailable", Reason: ReasonUpstreamError}}
}
