package server

import (
	"context"
	"strings"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// resolveViewerInternalID translates a viewer DID (external ID) into
// the internal user UUID used by user_memberships and the rbac
// resolver. Returns "" when the DID is empty, the user doesn't exist,
// or any DB error occurs — callers should treat "" as "no
// permissions" (deny). The function is the join point between the
// explorer's DID-keyed inputs (everything in eth_address_links) and
// the rbac resolver's UUID-keyed lookups (everything in
// user_memberships, contract_grants).
func resolveViewerInternalID(ctx context.Context, store rbac.Store, viewerDID string) string {
	if store == nil || viewerDID == "" {
		return ""
	}
	user, err := store.GetUserByExternalID(ctx, viewerDID)
	if err != nil || user == nil {
		return ""
	}
	return user.ID
}

// wireExplorerRedactor connects every resolver the RedactionEngine
// needs to behave correctly in production. **Both** server startup
// sites (initial constructor + explorerReconnectLoop) MUST funnel
// through this single helper — splitting the wiring across multiple
// inline call sites is how the RD-888 EventRuleChecker gap shipped
// undetected (the unit tests injected stubs; production silently
// skipped the check).
//
// The helper is a no-op when redactor is nil (explorer disabled). Each
// individual Set* call requires its own dependency to be non-nil
// (store for ABI, accessCtrl for admin + event rules, explorerBackend
// for log-participant detection); a missing dependency leaves *that*
// resolver unset rather than panicking, so an in-progress test rig
// can still exercise RedactionEngine.
//
// If you find yourself adding a fourth resolver to RedactionEngine,
// add it here too. The companion test
// (TestExplorerRedactorWiring_FullStack in
// explorer_redactor_wiring_integration_test.go) loops over the public
// Set*Resolver methods via reflection to detect any new resolver that
// wasn't wired here.
// explorerChainData is the chain data the redactor reads beyond RBAC: the
// log-participant index (RD-939) and parent-transaction data for the strict
// read profile (RD-1299). The explorer backend satisfies both.
type explorerChainData interface {
	explorer.LogParticipantStore
	explorer.TxDataResolver
}

func wireExplorerRedactor(redactor *explorer.RedactionEngine, store rbac.Store, accessCtrl *rbac.AccessController, chainData explorerChainData, pseudonymKey []byte) {
	if redactor == nil {
		return
	}
	// RD-1164 #8: key the address pseudonyms so they are non-reversible and,
	// with a configured key, non-enumerable.
	redactor.SetPseudonymKey(pseudonymKey)
	if store != nil {
		redactor.SetABIResolver(newDBABIResolver(store))
		redactor.SetDynamicPayloadAllowedResolver(newDBDynamicPayloadAllowedResolver(store))
	}
	if accessCtrl != nil {
		redactor.SetAdminContractsResolver(newDBAdminContractsResolver(accessCtrl))
		redactor.SetEventRuleChecker(newDBEventRuleChecker(accessCtrl))
		redactor.SetVisibleToUnlockResolver(newDBVisibleToUnlockResolver(accessCtrl))
	}
	if chainData != nil {
		// RD-939 Stage A. In production this is the explorer backend
		// itself — FindLogParticipantTxs is on the ExplorerBackend
		// interface so the gRPC client and SQL store both satisfy
		// LogParticipantStore. Accepting the narrower interface here
		// lets tests substitute a minimal stub without re-implementing
		// the full backend surface.
		redactor.SetLogParticipantStore(chainData)
		// RD-1299: parent-transaction data for the strict profile's
		// token-transfer and internal-call decisions.
		redactor.SetTxDataResolver(chainData)
	}
}

// dbEventRuleChecker implements explorer.EventRuleChecker by resolving
// the viewer's effective permissions against the contract's owning org
// and reading the EventRulesField off the matching ContractAccess.
//
// Its sole purpose is closing the wiring gap that made RD-888 a no-op
// in production: the explorer's RedactionEngine carries an
// EventRuleChecker field that was only ever set by tests, so Phase 4's
// tri-state event-rule check (wildcard / allowlist / deny-all) was
// skipped at runtime. After this resolver is wired into the engine via
// SetEventRuleChecker (server.go) the explorer mirrors the RPC layer's
// rbac.FilterEventLogs decisions for every (viewer, contract, topic0)
// tuple — required by the access/visibility symmetry invariant in
// REDACTION_SPEC.md.
//
// Algorithm (per call, single contract address):
//  1. Look up the contract's owning org. Unregistered or lookup error
//     ⇒ deny (zero-value EventRulesResolution).
//  2. Confirm the viewer is a member of that org. Cross-org viewers
//     get deny; defense-in-depth on top of the migration-035 unique
//     address constraint and consistent with the RPC layer's
//     org-scoping in viewerAdminContracts (RD-849).
//  3. Resolve the viewer's effective permissions against the owning
//     org. Read EventRulesField off ContractAccess[contractAddr].
//     Map the three database states to the explorer tri-state:
//     - nil, IsDeny()         ⇒ deny (zero value)
//     - IsWildcard()          ⇒ Wildcard:true
//     - allowlist with rules  ⇒ Wildcard:false, Rules:[...] including
//     ParamRules so the redactor can enforce them via
//     rbac.MatchesEventParamRules.
//
// Error handling is strictly fail-closed — any DB error or missing
// row returns the zero-value resolution (deny-all). The explorer
// never sees a nil pointer.
type dbEventRuleChecker struct {
	access *rbac.AccessController
}

func newDBEventRuleChecker(access *rbac.AccessController) *dbEventRuleChecker {
	return &dbEventRuleChecker{access: access}
}

// GetEventRulesForContract returns the viewer's tri-state event-rule
// resolution for one contract. See explorer.EventRuleChecker for the
// full contract.
func (r *dbEventRuleChecker) GetEventRulesForContract(ctx context.Context, viewerDID string, contractAddress string) explorer.EventRulesResolution {
	deny := explorer.EventRulesResolution{}
	if r.access == nil || viewerDID == "" || contractAddress == "" {
		return deny
	}
	addr := strings.ToLower(contractAddress)

	// Translate DID → internal user UUID. The explorer hands us a DID
	// (eth_address_links keyspace); user_memberships and the rbac
	// resolver are keyed by internal UUIDs, so we have to resolve here.
	// Empty result ⇒ user doesn't exist or DB error ⇒ deny.
	userID := resolveViewerInternalID(ctx, r.access.Store(), viewerDID)
	if userID == "" {
		return deny
	}

	ownerOrgID, err := r.access.Store().GetContractOwnerOrgID(ctx, addr)
	if err != nil || ownerOrgID == "" {
		return deny // unregistered or lookup error
	}

	userOrgIDs, err := r.access.GetUserOrgIDs(ctx, userID)
	if err != nil || len(userOrgIDs) == 0 {
		return deny
	}
	memberOfOwningOrg := false
	for _, o := range userOrgIDs {
		if o == ownerOrgID {
			memberOfOwningOrg = true
			break
		}
	}
	if !memberOfOwningOrg {
		return deny
	}

	perms, err := r.access.GetEffectivePermissionsByIDs(ctx, userID, ownerOrgID)
	if err != nil || perms == nil {
		return deny
	}

	// Admin bypass: tier-2 (org admin) and tier-3 (per-contract admin
	// claim) viewers see ALL events, mirroring the RPC layer's
	// rbac.FilterEventLogs admin short-circuit (event_filter.go:117).
	// Without this branch the explorer would resolve admin viewers
	// down to "no event_rules grant ⇒ deny-all" because the
	// computeOrgAdminPermissions resolver doesn't populate EventRules
	// on synthesised ContractAccess entries — fail-closed asymmetry
	// vs. RPC.
	if perms.HasAdminOnContract(addr) {
		return explorer.EventRulesResolution{Wildcard: true}
	}

	rules := perms.GetEventRules(addr)
	if rules == nil || rules.IsDeny() {
		return deny
	}
	if rules.IsWildcard() {
		return explorer.EventRulesResolution{Wildcard: true}
	}

	out := explorer.EventRulesResolution{
		Rules: make([]explorer.EventRuleInfo, 0, len(rules.Rules)),
	}
	for _, rule := range rules.Rules {
		out.Rules = append(out.Rules, explorer.EventRuleInfo{
			Topic0:     strings.ToLower(rule.Topic0),
			ParamRules: rule.ParamRules,
		})
	}
	return out
}

// Compile-time assertion that *dbEventRuleChecker satisfies explorer.EventRuleChecker.
var _ explorer.EventRuleChecker = (*dbEventRuleChecker)(nil)
