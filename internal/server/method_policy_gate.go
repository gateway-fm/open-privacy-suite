package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// Compile-time guard (final-audit M1): the concrete store MUST satisfy the
// capture-store capability. Without this, a future signature change on *db.DB
// would silently flip the runtime type assertion in methodPolicyStore() to
// ok=false and fail OPEN (gated reads served unfiltered). Keep it a build error.
var _ methodPolicyCaptureStore = (*db.DB)(nil)

// Method access policy request-path wiring (RD-1206). The read gate runs inside
// applyResponseFilter (post-forward), so it decodes the caller's OWN already-
// fetched eth_call response — never a second upstream call, and allow/deny share
// the timing profile. The capture hook runs on the send methods, enqueuing the
// pre-decoded capture payload to the receipt-confirmed outbox.

// methodPolicyCaptureStore is the optional capability the processor needs for
// capture read/enqueue. Satisfied by *db.DB; absent in lightweight test
// harnesses (the gate then behaves as pre-feature for reads, and skips capture).
type methodPolicyCaptureStore interface {
	GetRecordCaptures(ctx context.Context, orgID, contractAddr, recordType, recordKey string) ([]rbac.CapturedField, error)
	EnqueuePendingRecordCaptures(ctx context.Context, txHash, orgID, contractAddr, senderDID string, writes []rbac.CapturedWrite) error
}

func (p *JSONRPCProcessor) methodPolicyStore() (methodPolicyCaptureStore, bool) {
	s, ok := p.rbacAccessCtrl.Store().(methodPolicyCaptureStore)
	return s, ok
}

// errMethodPolicyOrgUnresolved: a policy-bearing contract was found by the
// global address lookup but the request has no resolved org to attribute it to,
// so we cannot safely apply (or skip) it. Callers fail closed.
var errMethodPolicyOrgUnresolved = errors.New("method policy: contract org unresolved")

// methodPolicyContract resolves the gate's target contract, scoped to the
// request's resolved org. Addresses are unique only PER ORG, so a global lookup
// can return a different org's row for a dual-registered address — which would
// non-deterministically skip or misapply a policy (C1). eth_call/eth_sendTransaction
// both resolve the org via CheckAccess before this runs, so resolvedOrgID is
// normally set. If it is empty we fall back to the global lookup only to DETECT
// a policy: finding one we cannot attribute to an org returns an error so the
// caller fails closed rather than guessing.
func (p *JSONRPCProcessor) methodPolicyContract(ctx context.Context, req *ProcessRequest, to string) (*rbac.Contract, error) {
	if req.resolvedOrgID != "" {
		return p.rbacAccessCtrl.Store().GetContractByAddress(ctx, req.resolvedOrgID, to)
	}
	contract, err := p.rbacAccessCtrl.Store().GetContractByAddressGlobal(ctx, to)
	if err != nil {
		return nil, err
	}
	if contract != nil && len(contract.MethodPolicies) > 0 {
		return nil, errMethodPolicyOrgUnresolved
	}
	return nil, nil
}

// ethCallHasStateOverride reports whether an eth_call carries a state- or
// block-override object (params[2]/[3]). Such overrides make the node compute
// the return against caller-supplied state, so the returned address fields are
// forgeable and must not be trusted by the return-address resolver (MED).
func ethCallHasStateOverride(params []any) bool {
	for i := 2; i < len(params); i++ {
		if m, ok := params[i].(map[string]any); ok && len(m) > 0 {
			return true
		}
	}
	return false
}

// methodPolicyDecision evaluates the target contract's per-record method policy
// for the current request against the provided return bytes (may be nil). It is
// the shared core for every execution surface that runs a reader (eth_call and
// its trace twin debug_traceCall). It returns whether the call is gated and, if
// so, whether it is DENIED — it does NOT shape a response or log, so each caller
// can deny in its own idiom. When overridden is true the return-address resolver
// is neutralized (the return was computed against caller-supplied state and is
// forgeable). Every fail-closed condition (capability wired but DB error, corrupt
// policy, unresolved org, eval error) returns gated=true, denied=true.
func (p *JSONRPCProcessor) methodPolicyDecision(ctx context.Context, req *ProcessRequest, to, data string, returnData []byte, overridden bool) (gated, denied bool) {
	to = strings.ToLower(strings.TrimSpace(to))
	if to == "" || data == "" {
		return false, false
	}
	store, ok := p.methodPolicyStore()
	if !ok {
		return false, false // capability not wired — no policy enforcement possible
	}
	contract, err := p.methodPolicyContract(ctx, req, to)
	if err != nil {
		return true, true // DB error, or a policy we can't attribute to the resolved org → fail closed
	}
	if contract == nil || len(contract.MethodPolicies) == 0 {
		return false, false // no policy configured
	}
	doc, perr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies)
	if perr != nil {
		return true, true // corrupt policy → deny (M1)
	}
	calldata := common.FromHex(data)
	caller := rbac.NewCallerIdentity(req.UserID, p.linkedAddresses(ctx, req.UserID))
	ownerOrg := contract.OrgID
	loadCaptures := func(recordType, recordKey string) ([]rbac.CapturedField, error) {
		return store.GetRecordCaptures(ctx, ownerOrg, to, recordType, recordKey)
	}
	paths := doc.ReturnAddressPaths(calldata, contract.ABI)
	resolveReturn := func() ([]common.Address, error) {
		if overridden || len(paths) == 0 || len(returnData) == 0 {
			return nil, nil
		}
		return rbac.DecodeReturnAddresses(returnData, calldata, paths, contract.ABI)
	}
	g, dec, evalErr := doc.EvaluateReader(calldata, caller, loadCaptures, resolveReturn, contract.ABI)
	if evalErr != nil {
		return true, true
	}
	if !g {
		return false, false
	}
	return true, !dec.Allow
}

// applyMethodPolicyGate gates an eth_call response by the target contract's
// per-record method policy. Not-gated calls pass through unchanged; a policy
// denial or any fail-closed condition returns an opaque error and stamps the
// access log as a denial (RD-1137).
func (p *JSONRPCProcessor) applyMethodPolicyGate(ctx context.Context, req *ProcessRequest, responseBody []byte) []byte {
	_, to, data, _ := extractTxParams(req.Params)
	returnData := extractEthCallResultBytes(responseBody)
	// A state override makes the node compute the return against caller-supplied
	// state, so its address fields are forgeable — neutralize the return resolver
	// (capture-based rules, which read the DB, are unaffected).
	overridden := ethCallHasStateOverride(req.Params)
	gated, denied := p.methodPolicyDecision(ctx, req, to, data, returnData, overridden)
	if gated && denied {
		req.methodPolicyDenied = true
		req.denialReason = ReasonMethodPolicyDenied
		return denyMethodPolicy(responseBody)
	}
	return responseBody
}

// extractTraceCallOutputBytes returns the decoded bytes of a debug_traceCall
// response's top-level frame output (the getter's return data), or nil when the
// response is an error / has no output / is a non-callTracer format.
func extractTraceCallOutputBytes(responseBody []byte) []byte {
	var resp struct {
		Result *struct {
			Output string `json:"output"`
		} `json:"result"`
		Error *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nil
	}
	if resp.Error != nil || resp.Result == nil {
		return nil
	}
	s := strings.TrimSpace(resp.Result.Output)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil
	}
	return common.FromHex(s)
}

// debugTraceCallHasStateOverride reports whether a debug_traceCall trace config
// (params[2]) carries a state override, which would make the traced return
// forgeable for the return-address resolver (same concern as eth_call overrides).
func debugTraceCallHasStateOverride(params []any) bool {
	if len(params) < 3 {
		return false
	}
	cfg, ok := params[2].(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"stateOverrides", "stateOverride", "overrides"} {
		if m, ok := cfg[k].(map[string]any); ok && len(m) > 0 {
			return true
		}
	}
	return false
}

// enqueueMethodPolicyCaptures decodes a send's calldata against the target
// contract's policy and enqueues the capture payload to the outbox. Best-effort
// (logs on failure) — mirrors the visibleTo outbox enqueue.
func (p *JSONRPCProcessor) enqueueMethodPolicyCaptures(ctx context.Context, req *ProcessRequest, toHex, dataHex string, visibleTo []string, txHash string) {
	toHex = strings.ToLower(strings.TrimSpace(toHex))
	if toHex == "" || dataHex == "" || txHash == "" {
		return
	}
	store, ok := p.methodPolicyStore()
	if !ok {
		return
	}
	// Org-scoped (C1): never capture under another org's row for a dual-registered
	// address. On the unresolved-org fallback the helper returns an error → skip.
	contract, err := p.methodPolicyContract(ctx, req, toHex)
	if err != nil || contract == nil || len(contract.MethodPolicies) == 0 {
		return
	}
	doc, perr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies)
	if perr != nil {
		return
	}
	writes, derr := doc.DecodeCaptures(common.FromHex(dataHex), req.UserID, visibleTo, contract.ABI)
	if derr != nil || len(writes) == 0 {
		return
	}
	if err := store.EnqueuePendingRecordCaptures(ctx, txHash, contract.OrgID, toHex, req.UserID, writes); err != nil {
		slog.Error("method-policy capture enqueue failed; tx is on-chain but the record's parties won't be captured",
			"tx", txHash, "contract", toHex, "sender", req.UserID, "org", contract.OrgID, "error", err)
	}
}

// linkedAddresses returns the caller's linked ETH addresses, or nil on error.
func (p *JSONRPCProcessor) linkedAddresses(ctx context.Context, did string) []string {
	addrs, err := p.rbacAccessCtrl.Store().GetLinkedEthAddresses(ctx, did)
	if err != nil {
		return nil
	}
	return addrs
}

// nodeForwarder is the subset of *proxy.Proxy the receipt checker needs.
type nodeForwarder interface {
	Forward(reqBody []byte) ([]byte, int, error)
}

// makeReceiptStatusFunc builds the reconciler's receipt checker backed by an
// upstream eth_getTransactionReceipt call (RD-1206 capture promotion).
func makeReceiptStatusFunc(fwd nodeForwarder) ReceiptStatusFunc {
	return func(ctx context.Context, txHash string) (mined bool, success bool, err error) {
		body, mErr := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"method": "eth_getTransactionReceipt",
			"params": []any{txHash}, // marshaled, never string-concatenated
		})
		if mErr != nil {
			return false, false, mErr
		}
		resp, _, fErr := fwd.Forward(body)
		if fErr != nil {
			return false, false, fErr
		}
		var r struct {
			Result *struct {
				Status string `json:"status"`
			} `json:"result"`
			Error *json.RawMessage `json:"error"`
		}
		if e := json.Unmarshal(resp, &r); e != nil {
			return false, false, e
		}
		if r.Error != nil {
			return false, false, nil // treat as transient — retry
		}
		if r.Result == nil {
			return false, false, nil // not yet mined
		}
		return true, strings.EqualFold(r.Result.Status, "0x1"), nil
	}
}

// denyMethodPolicy returns an opaque JSON-RPC error preserving the request id.
// The message carries no record detail (no existence oracle).
func denyMethodPolicy(responseBody []byte) []byte {
	id := rpcResponseID(responseBody)
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32000,"message":"not authorized to read this record"}}`)
}

// extractEthCallResultBytes returns the decoded bytes of an eth_call response's
// result hex, or nil when the response is an error / null / non-hex.
func extractEthCallResultBytes(responseBody []byte) []byte {
	var resp struct {
		Result *string          `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return nil
	}
	if resp.Error != nil || resp.Result == nil {
		return nil
	}
	s := strings.TrimSpace(*resp.Result)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil
	}
	return common.FromHex(s)
}
