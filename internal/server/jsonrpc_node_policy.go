package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

// NodeExecutionIdentityRequest carries identity and an exact execution binding.
// It never carries group membership, operational claims or permission decisions.
type NodeExecutionIdentityRequest struct {
	Scope, PrincipalID, OrgID, Signer, BindingHash string
}

type NodeSubmissionMetadata struct {
	SenderDID string
	VisibleTo []string
}

// NodeExecutionService prepares a short-lived signed identity only after reading
// the current database fact version and checking the private node's readiness,
// network, protocol and required capabilities at that minimum version.
type NodeExecutionService interface {
	PrepareIdentity(context.Context, NodeExecutionIdentityRequest) ([]byte, error)
	SubmitTransaction(context.Context, []byte, string, NodeSubmissionMetadata) (nodepolicy.Submission, error)
	Simulate(context.Context, []byte, []byte) (json.RawMessage, error)
}

func nodeExecutionMethod(method string) bool {
	switch rbac.ResolveMethodAlias(method) {
	case "eth_sendRawTransaction", "eth_sendTransaction", "eth_call", "eth_estimateGas", "debug_traceCall", "debug_traceTransaction", "eth_createAccessList":
		return true
	default:
		return false
	}
}

// processNodeExecution is a separate execution path. Once selected it never
// falls back to the legacy upstream or preflight trace authorization.
func (p *JSONRPCProcessor) processNodeExecution(ctx context.Context, req *ProcessRequest) *ProcessResult {
	start := time.Now()
	method := rbac.ResolveMethodAlias(req.Method)
	if method == "debug_traceTransaction" || method == "eth_createAccessList" {
		return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "method is unavailable in Reth policy mode", ReasonInvalidRequestShape)
	}
	if method == "eth_sendTransaction" {
		return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "eth_sendTransaction is unavailable; sign locally and use eth_sendRawTransaction", "")
	}
	if p.rbacAccessCtrl == nil || p.nodeExecution == nil {
		return p.nodeExecutionError(ctx, req, http.StatusServiceUnavailable, "execution service unavailable", ReasonTracingUnavailable)
	}
	var transaction *types.Transaction
	var raw, from, to, data, value string
	var params []any
	if method == "eth_sendRawTransaction" {
		var err error
		raw, err = extractRawTxHex(req.Params)
		if err != nil {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid raw transaction", "")
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X"))
		if err != nil {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid raw transaction", "")
		}
		transaction = new(types.Transaction)
		if err = transaction.UnmarshalBinary(decoded); err != nil {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid raw transaction", "")
		}
		from, to, data, value, _, err = decodeRawTransaction(raw)
		if err != nil {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid raw transaction", "")
		}
		raw = "0x" + hex.EncodeToString(decoded)
		params = buildTxParams(from, to, data, value)
	} else {
		// Own the map before adding a default sender, so a concurrent observer
		// of the caller's request cannot alter the exact signed simulation.
		encoded, err := json.Marshal(req.Params)
		if err != nil || json.Unmarshal(encoded, &params) != nil || len(params) < 1 || len(params) > 3 {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid simulation request", "")
		}
		if _, ok := params[0].(map[string]any); !ok {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid simulation request", "")
		}
		from, to, data, value = extractTxParams(params)
	}
	allowlistMethod := req.Method
	if transaction != nil {
		allowlistMethod = "eth_sendTransaction"
	} // Existing raw-tx method equivalence.
	admission, err := p.rbacAccessCtrl.CheckExecutionAdmission(ctx, &rbac.AccessCheckRequest{UserExternalID: req.UserID, OrgID: req.OrgID, Method: allowlistMethod, AccessMethod: method, Params: params, TargetAddress: to, BypassCache: req.BypassPermsCache})
	if err != nil || admission == nil {
		slog.Warn("node execution admission unavailable", "method", req.Method, "error", err)
		return p.nodeExecutionError(ctx, req, http.StatusNotFound, "method not found", ReasonMethodNotAllowed)
	}
	req.resolvedOrgID = admission.OrgID
	if !admission.Allowed {
		p.recordRBACDecision("denied")
		if admission.Reason == rbac.ExecutionSenderRequired {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, rbac.ExecutionSenderRequired, ReasonSenderNotLinked)
		}
		if admission.Reason == rbac.ExecutionSenderNotLinked {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid sender: from address is not linked to your account", ReasonSenderNotLinked)
		}
		reason := ReasonMethodNotAllowed
		if admission.AuthRequired {
			reason = ReasonAuthRequired
		}
		return p.nodeExecutionError(ctx, req, http.StatusNotFound, "method not found", reason)
	}
	p.recordRBACDecision("allowed")
	if method == "debug_traceCall" {
		if p.rateLimiter == nil {
			return p.nodeExecutionError(ctx, req, http.StatusServiceUnavailable, "trace service unavailable", ReasonTracingUnavailable)
		}
		rps, daily := 1, 100
		if allowed, _ := p.rateLimiter.CheckAndIncrement(req.UserID, &rps, &daily); !allowed {
			return p.nodeExecutionError(ctx, req, http.StatusTooManyRequests, "trace request limit reached", ReasonRateLimited)
		}
	}
	if p.concurrencyLimiter != nil {
		if !p.concurrencyLimiter.TryAcquire(req.UserID) {
			return p.nodeExecutionError(ctx, req, http.StatusTooManyRequests, "too many concurrent requests", ReasonConcurrencyLimited)
		}
		defer p.concurrencyLimiter.Release(req.UserID)
	}
	apiKey := admission.RPCAPIKey
	if apiKey == "" {
		apiKey = p.defaultRPCAPIKey
	}
	if p.circuitBreaker != nil && p.circuitBreaker.IsOpen(apiKey) {
		return p.nodeExecutionError(ctx, req, http.StatusTooManyRequests, "upstream rate limited, retry in 1s", ReasonRateLimited)
	}
	var visibleTo []string
	if transaction != nil {
		if denied := p.checkCompliance(ctx, req, admission.OrgID, admission.UserID, admission.Signer, to, data, value); denied != nil {
			return denied
		}
		top := extractAndStripTopLevelVisibleTo(req)
		param := extractAndStripRawTxVisibleTo(req)
		var resolver ethAddressResolver
		if candidate, ok := p.rbacAccessCtrl.Store().(ethAddressResolver); ok {
			resolver = candidate
		}
		resolved, invalid := resolveTopLevelVisibleTo(ctx, resolver, top)
		if invalid != nil {
			return p.nodeExecutionError(ctx, req, invalid.StatusCode, invalid.Message, invalid.Reason)
		}
		visibleTo = unionVisibleToDIDs(param, resolved)
		if len(visibleTo) > visibleToMaxSize {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "visibleTo list exceeds maximum size", "")
		}
		if len(visibleTo) > 0 && (isSimpleValueTransfer(data) || to == "") {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "visibleTo is only supported for contract calls that emit event logs", "")
		}
	}
	identityRequest := NodeExecutionIdentityRequest{PrincipalID: admission.UserID, OrgID: admission.OrgID, Signer: admission.Signer}
	var request []byte
	if transaction != nil {
		identityRequest.Scope = "transaction"
		identityRequest.BindingHash = strings.ToLower(transaction.Hash().Hex())
	} else {
		params[0].(map[string]any)["from"] = admission.Signer
		payload, err := json.Marshal(params)
		if err != nil {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid simulation request", "")
		}
		request, err = nodepolicy.EncodeSimulation(nodepolicy.SimulationRequest{Method: method, Params: payload})
		if err != nil {
			return p.nodeExecutionError(ctx, req, http.StatusBadRequest, "invalid simulation request", "")
		}
		identityRequest.Scope = "simulation"
		identityRequest.BindingHash = nodepolicy.SimulationHash(request)
	}
	identity, err := p.nodeExecution.PrepareIdentity(ctx, identityRequest)
	if err != nil {
		return p.nodeExecutionFailure(ctx, req, err)
	}
	var result json.RawMessage
	if transaction != nil {
		submission, err := p.nodeExecution.SubmitTransaction(ctx, identity, raw, NodeSubmissionMetadata{SenderDID: req.UserID, VisibleTo: visibleTo})
		if err != nil {
			return p.nodeExecutionFailure(ctx, req, err)
		}
		if submission.TransactionHash != identityRequest.BindingHash || submission.Status != "accepted" {
			return p.nodeExecutionFailure(ctx, req, nodepolicy.ErrNodeResponse)
		}
		result, _ = json.Marshal(submission.TransactionHash)
		// The execution service saves visibility and deployment intent before
		// submission. Canonical node outcomes reconcile actual CREATE/CREATE2
		// results and visibility atomically, including after process restart.
	} else {
		result, err = p.nodeExecution.Simulate(ctx, identity, request)
		if err != nil {
			return p.nodeExecutionFailure(ctx, req, err)
		}
		if !json.Valid(result) {
			return p.nodeExecutionFailure(ctx, req, nodepolicy.ErrNodeResponse)
		}
	}
	if p.circuitBreaker != nil {
		p.circuitBreaker.Reset(apiKey)
	}
	p.recordRPCOutcome(req.Method, "success", start)
	p.nodeExecutionLog(ctx, req, http.StatusOK)
	var input struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(req.Body, &input)
	if len(input.ID) == 0 {
		input.ID = json.RawMessage("null")
	}
	body, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{"2.0", input.ID, result})
	if err != nil {
		return p.nodeExecutionFailure(ctx, req, nodepolicy.ErrNodeResponse)
	}
	return &ProcessResult{StatusCode: http.StatusOK, ResponseBody: body}
}

func (p *JSONRPCProcessor) nodeExecutionFailure(ctx context.Context, req *ProcessRequest, err error) *ProcessResult {
	slog.Warn("private node execution failed", "method", req.Method, "error", err)
	if errors.Is(err, nodepolicy.ErrNodeRejected) {
		return p.nodeExecutionError(ctx, req, http.StatusForbidden, "request rejected by execution node", ReasonNodeRejected)
	}
	return p.nodeExecutionError(ctx, req, http.StatusServiceUnavailable, "execution service unavailable", ReasonExecutionUnavailable)
}
func (p *JSONRPCProcessor) nodeExecutionError(ctx context.Context, req *ProcessRequest, status int, message, reason string) *ProcessResult {
	req.denialReason = reason
	p.nodeExecutionLog(ctx, req, status)
	return &ProcessResult{Error: &ProcessError{StatusCode: status, Message: message, Reason: reason}}
}
func (p *JSONRPCProcessor) nodeExecutionLog(ctx context.Context, req *ProcessRequest, status int) {
	if p.accessLogger != nil || p.enhancedLogger != nil || p.auditBuffer != nil {
		p.logAccess(ctx, req, status)
	}
}
