package server

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/rbac"
)

// recordAudienceGate is the request-scoped implementation of
// rbac.RecordAudienceGate (RD-1206 rule 71). It loads a contract's method policy
// + captures and delegates the decision to MethodPolicyDocument.EventAudienceAdmits
// — the SAME decision the explorer redactor uses (see explorer wiring), so the
// two surfaces cannot drift. Per-request caches keep the hot getLogs path from
// re-parsing the policy/ABI or re-querying captures for logs that share a
// contract or record key. Not safe for concurrent use; one gate per request.
type recordAudienceGate struct {
	ctx    context.Context
	store  rbac.Store               // GetContractByAddressGlobal
	caps   methodPolicyCaptureStore // GetRecordCaptures
	caller rbac.CallerIdentity

	policyByContract map[string]*contractPolicyABI   // addr → parsed policy+ABI (nil = none/unusable)
	captureCache     map[string][]rbac.CapturedField // addr|recordType|recordKey → captures
}

type contractPolicyABI struct {
	doc    *rbac.MethodPolicyDocument
	orgID  string
	parsed abi.ABI
}

// buildRecordAudienceGate constructs the concrete gate for a viewer, or nil when
// it can't apply (no capture-store capability, or an anonymous viewer with no
// identity). Cheap; the real work is lazy + cached per contract/record on first
// use.
func (p *JSONRPCProcessor) buildRecordAudienceGate(ctx context.Context, viewerDID string, viewerAddrs []string) *recordAudienceGate {
	capStore, ok := p.methodPolicyStore()
	if !ok {
		return nil // capability not wired → no gating (fail-safe: baseline only)
	}
	return newRecordAudienceGate(ctx, p.rbacAccessCtrl.Store(), capStore, viewerDID, viewerAddrs)
}

// newRecordAudienceGate is the SINGLE constructor for the request-scoped gate,
// shared by the RPC path (JSONRPCProcessor.buildRecordAudienceGate) and the
// explorer resolver (dbCapturedAudienceResolver). Both surfaces therefore build
// the identical decision object over the same policy+captures — the anti-drift
// seam. Returns nil for an anonymous viewer with no identity (matches nothing).
func newRecordAudienceGate(ctx context.Context, store rbac.Store, caps methodPolicyCaptureStore, viewerDID string, viewerAddrs []string) *recordAudienceGate {
	if viewerDID == "" && len(viewerAddrs) == 0 {
		return nil // no caller identity → matches nothing anyway
	}
	return &recordAudienceGate{
		ctx:              ctx,
		store:            store,
		caps:             caps,
		caller:           rbac.NewCallerIdentity(viewerDID, viewerAddrs),
		policyByContract: map[string]*contractPolicyABI{},
		captureCache:     map[string][]rbac.CapturedField{},
	}
}

// newRecordAudienceGate returns the gate as an rbac.RecordAudienceGate (for
// TxVisibilityContext.RecordAudience). Returns a true interface-nil when the gate
// can't apply (never a non-nil interface wrapping a nil pointer).
func (p *JSONRPCProcessor) newRecordAudienceGate(ctx context.Context, viewerDID string, viewerAddrs []string) rbac.RecordAudienceGate {
	if g := p.buildRecordAudienceGate(ctx, viewerDID, viewerAddrs); g != nil {
		return g
	}
	return nil
}

// captureLoader returns the (cached) capture loader for a resolved contract.
func (g *recordAudienceGate) captureLoader(pa *contractPolicyABI, contractAddr string) func(string, string) ([]rbac.CapturedField, error) {
	return func(recordType, recordKey string) ([]rbac.CapturedField, error) {
		ck := contractAddr + "|" + recordType + "|" + recordKey
		if c, ok := g.captureCache[ck]; ok {
			return c, nil
		}
		c, err := g.caps.GetRecordCaptures(g.ctx, pa.orgID, contractAddr, recordType, recordKey)
		if err != nil {
			return nil, err
		}
		g.captureCache[ck] = c
		return c, nil
	}
}

// resolve loads + caches the parsed policy and ABI for a contract. Returns nil
// (cached) when the contract has no policy or the policy/ABI is unusable.
//
// Cross-org (audit F4): the audience is looked up under contract.OrgID from the
// GLOBAL address lookup — this is safe ONLY because migration 035 makes
// LOWER(address) globally unique, so exactly one org owns a given address and
// GetContractByAddressGlobal returns that org's row. Unlike the reader gate
// (method_policy_gate.go's methodPolicyContract, which also cross-checks
// req.resolvedOrgID as belt-and-braces), the event/tx path relies solely on the
// 035 invariant + the caller's eligibility (grant/Full) on that unique address.
// If 035 were ever weakened, this lookup would need the resolvedOrgID cross-check.
func (g *recordAudienceGate) resolve(contractAddr, contractABI string) *contractPolicyABI {
	if pa, seen := g.policyByContract[contractAddr]; seen {
		return pa
	}
	var out *contractPolicyABI
	contract, err := g.store.GetContractByAddressGlobal(g.ctx, contractAddr)
	if err == nil && contract != nil && len(contract.MethodPolicies) > 0 && contractABI != "" {
		if doc, derr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies); derr == nil {
			if parsed, perr := abi.JSON(strings.NewReader(contractABI)); perr == nil {
				out = &contractPolicyABI{doc: doc, orgID: contract.OrgID, parsed: parsed}
			}
		}
	}
	g.policyByContract[contractAddr] = out // negative-cache too
	return out
}

// EventLogAdmits implements rbac.RecordAudienceGate. Fail-safe: any miss returns
// false so the log falls through to the baseline.
func (g *recordAudienceGate) EventLogAdmits(contractAddr, contractABI string, topics []string, data string) bool {
	pa := g.resolve(strings.ToLower(contractAddr), contractABI)
	if pa == nil {
		return false
	}
	return pa.doc.EventAudienceAdmits(topics, common.FromHex(data), g.caller, pa.parsed, g.captureLoader(pa, strings.ToLower(contractAddr)))
}

// TxInputAdmits reports whether the caller is in the captured record audience for
// a transaction, keyed by a parameter of its own calldata (RD-1206 rule 72).
// Additive/fail-safe. inputHex is the tx's 0x-prefixed calldata.
func (g *recordAudienceGate) TxInputAdmits(contractAddr, contractABI, inputHex string) bool {
	addr := strings.ToLower(contractAddr)
	pa := g.resolve(addr, contractABI)
	if pa == nil {
		return false
	}
	return pa.doc.TxAudienceAdmits(common.FromHex(inputHex), g.caller, pa.parsed, g.captureLoader(pa, addr))
}

// txResponseRecordAudienceAdmits reports whether the viewer is in the captured
// record audience of the transaction in a getTransactionByHash-style response
// (RD-1206 rule 72). It decodes the record key from the tx's OWN calldata — no
// upstream call. Additive/fail-safe: false on any missing field or lookup error.
func (p *JSONRPCProcessor) txResponseRecordAudienceAdmits(ctx context.Context, viewerDID string, viewerAddrs []string, result *rbac.AccessCheckResult, responseBody []byte) bool {
	to, input, ok := extractTxToInput(responseBody)
	if !ok || to == "" || input == "" {
		return false
	}
	// Bound by contract eligibility, exactly like the event path (FilterEventLogs
	// `access != nil`) and the design invariant (§5): the record gate only ADDS
	// viewers who already hold a grant on the tx's `to` contract — it never widens
	// past the grant. (Audit F2: without this, a no-grant audience member could
	// read the full tx via getTransactionByHash.)
	perms := p.resolvePermsForFilter(ctx, result)
	if perms == nil || perms.GetContractAccess(strings.ToLower(to)) == nil {
		return false
	}
	gate := p.buildRecordAudienceGate(ctx, viewerDID, viewerAddrs)
	if gate == nil {
		return false
	}
	contractABI := p.contractABIProvider(ctx).GetContractABI(strings.ToLower(to))
	if contractABI == "" {
		return false
	}
	return gate.TxInputAdmits(to, contractABI, input)
}

// extractTxToInput pulls the `to` and `input` (calldata) fields from a
// transaction JSON-RPC response's result object.
func extractTxToInput(responseBody []byte) (to, input string, ok bool) {
	var resp struct {
		Result *struct {
			To    string `json:"to"`
			Input string `json:"input"`
		} `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Result == nil {
		return "", "", false
	}
	return resp.Result.To, resp.Result.Input, true
}
