package server

import (
	"context"
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

// recordAudienceGate builds the gate for a viewer, or nil when it can't apply
// (no capture-store capability, or an anonymous viewer with no identity). Cheap;
// the real work is lazy + cached per contract/record on first use.
func (p *JSONRPCProcessor) newRecordAudienceGate(ctx context.Context, viewerDID string, viewerAddrs []string) rbac.RecordAudienceGate {
	capStore, ok := p.methodPolicyStore()
	if !ok {
		return nil // capability not wired → no event-audience gating (fail-safe: baseline only)
	}
	if viewerDID == "" && len(viewerAddrs) == 0 {
		return nil // no caller identity → matches nothing anyway
	}
	return &recordAudienceGate{
		ctx:              ctx,
		store:            p.rbacAccessCtrl.Store(),
		caps:             capStore,
		caller:           rbac.NewCallerIdentity(viewerDID, viewerAddrs),
		policyByContract: map[string]*contractPolicyABI{},
		captureCache:     map[string][]rbac.CapturedField{},
	}
}

// resolve loads + caches the parsed policy and ABI for a contract. Returns nil
// (cached) when the contract has no policy or the policy/ABI is unusable.
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
	load := func(recordType, recordKey string) ([]rbac.CapturedField, error) {
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
	return pa.doc.EventAudienceAdmits(topics, common.FromHex(data), g.caller, pa.parsed, load)
}
