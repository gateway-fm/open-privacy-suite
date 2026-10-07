package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"privacy-proxy/internal/rbac"
)

// resolvePermsForFilter resolves the user's effective permissions across ALL
// their orgs for response filtering. This is necessary because receipts and
// logs may reference contracts from any org the user belongs to — the RBAC
// access check resolves a single org from the request target, but receipt
// logs can contain events from contracts in different orgs.
//
// Under an impersonation scope (RD-1308, withViewerOrgScope) only the scope
// org's permissions are resolved, and nil is returned when the viewer is not a
// member of it (fail closed).
func (p *JSONRPCProcessor) resolvePermsForFilter(ctx context.Context, result *rbac.AccessCheckResult) *rbac.EffectivePermissions {
	if result == nil || result.UserID == "" {
		return nil
	}

	// Get all org IDs the user belongs to
	orgIDs, err := p.rbacAccessCtrl.GetUserOrgIDs(ctx, result.UserID)
	if err != nil {
		return nil
	}
	orgIDs = restrictToViewerOrgScope(ctx, orgIDs)
	if len(orgIDs) == 0 {
		return nil
	}

	// Resolve permissions for each org and merge contract access
	var merged *rbac.EffectivePermissions
	for _, orgID := range orgIDs {
		perms, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, result.UserID, orgID)
		if err != nil {
			continue
		}
		if merged == nil {
			merged = perms
			continue
		}
		// Merge ContractAccess from this org into the merged result
		for addr, ca := range perms.ContractAccess {
			if merged.ContractAccess == nil {
				merged.ContractAccess = make(map[string]rbac.ContractAccess)
			}
			if _, exists := merged.ContractAccess[addr]; !exists {
				merged.ContractAccess[addr] = ca
			}
		}
	}
	return merged
}

// contractABIProvider returns an ABIProvider backed by the RBAC store.
func (p *JSONRPCProcessor) contractABIProvider(ctx context.Context) rbac.ABIProvider {
	return newStoreABIProvider(ctx, p.rbacAccessCtrl.Store())
}

// viewerAdminContracts is the ORG-SCOPED admin-bypass resolver used by
// response filters. It returns a map (address → true) listing contract
// addresses on which the viewer holds the admin claim IN THAT
// CONTRACT'S OWNING ORG (not merged across all orgs the viewer belongs
// to). Addresses absent from the map — or present with false — must
// NOT be treated as admin-accessible by the caller.
//
// This is belt-and-braces on top of the schema-level unique-address
// constraint (migration 035): even if two orgs ever ended up holding
// the same address, the runtime check here denies cross-org admin by
// inspecting the contract's actual owning org first. See the
// threat-model justification in the spec:
//
//	site/src/app/docs/rbac/page.mdx — "Registered (other org) → Denied"
//
// The function de-duplicates addresses, caches per-org permission
// lookups within a single call, and returns an empty map on any error.
//
// Contracts whose owning org the viewer is not a member of are silently
// omitted from the result (admin = false). Unregistered addresses
// (owner_org_id = "" or lookup error) are also omitted — the spec says
// unregistered is denied, and admin on an unregistered address is
// undefined.
func (p *JSONRPCProcessor) viewerAdminContracts(ctx context.Context, userID string, contractAddrs []string) map[string]bool {
	result := make(map[string]bool)
	if userID == "" || len(contractAddrs) == 0 {
		return result
	}

	// De-dupe (addresses arrive lowercased; callers should pass lowercase,
	// but normalize here too for defense in depth).
	seen := make(map[string]struct{}, len(contractAddrs))
	unique := make([]string, 0, len(contractAddrs))
	for _, a := range contractAddrs {
		if a == "" {
			continue
		}
		al := strings.ToLower(a)
		if _, ok := seen[al]; ok {
			continue
		}
		seen[al] = struct{}{}
		unique = append(unique, al)
	}
	if len(unique) == 0 {
		return result
	}

	userOrgIDs, err := p.rbacAccessCtrl.GetUserOrgIDs(ctx, userID)
	if err != nil {
		return result
	}
	// RD-1308: under an impersonation scope, only contracts owned by the
	// scope org can confer the admin exemption.
	userOrgIDs = restrictToViewerOrgScope(ctx, userOrgIDs)
	if len(userOrgIDs) == 0 {
		return result
	}
	userOrgSet := make(map[string]struct{}, len(userOrgIDs))
	for _, o := range userOrgIDs {
		userOrgSet[o] = struct{}{}
	}

	// Cache per-(user, owning-org) permissions within this call.
	permsByOrg := make(map[string]*rbac.EffectivePermissions)

	for _, addr := range unique {
		ownerOrgID, err := p.rbacAccessCtrl.Store().GetContractOwnerOrgID(ctx, addr)
		if err != nil || ownerOrgID == "" {
			continue // unregistered or lookup error — no admin (spec: deny)
		}
		if _, member := userOrgSet[ownerOrgID]; !member {
			continue // viewer not a member of contract's owning org
		}
		orgPerms, cached := permsByOrg[ownerOrgID]
		if !cached {
			op, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, userID, ownerOrgID)
			if err != nil {
				permsByOrg[ownerOrgID] = nil
				continue
			}
			permsByOrg[ownerOrgID] = op
			orgPerms = op
		}
		if orgPerms != nil && orgPerms.HasAdminOnContract(addr) {
			result[addr] = true
		}
	}
	return result
}

// isResponseTxVisibleTo checks if the transaction in the response body has been
// shared with the viewer via the visibleTo param. Extracts the tx hash from the
// response and checks tx_visible_to.
func (p *JSONRPCProcessor) isResponseTxVisibleTo(ctx context.Context, viewerDID string, responseBody []byte) bool {
	if p.txVisibilityStore == nil || viewerDID == "" {
		return false
	}
	txHashes := extractTxHashesFromResponse(responseBody)
	if len(txHashes) == 0 {
		return false
	}
	visibility, err := p.txVisibilityForViewer(ctx, txHashes)
	if err != nil || len(visibility) == 0 {
		return false
	}
	for _, dids := range visibility {
		for _, did := range dids {
			if strings.EqualFold(did, viewerDID) {
				return true
			}
		}
	}
	return false
}

// isNullResult checks if a JSON-RPC response has a null result.
func isNullResult(body []byte) bool {
	var resp struct {
		Result *json.RawMessage `json:"result"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return false
	}
	return resp.Result == nil || string(*resp.Result) == "null"
}

// buildTxVisibilityContext builds a TxVisibilityContext for the given response.
// It extracts tx hashes from the response body, batch-queries visibleTo rules,
// resolves the per-contract visibleTo unlock map (RD-874), and returns a
// context the filter can use. Returns nil if the visibleTo feature is not
// configured or if no rules are found.
func (p *JSONRPCProcessor) buildTxVisibilityContext(ctx context.Context, userDID string, responseBody []byte) *rbac.TxVisibilityContext {
	if p.txVisibilityStore == nil || userDID == "" {
		return nil
	}

	txHashes := extractTxHashesFromResponse(responseBody)
	if len(txHashes) == 0 {
		return nil
	}

	visibility, err := p.txVisibilityForViewer(ctx, txHashes)
	if err != nil {
		slog.Warn("failed to query visibleTo rules", "error", err)
		return nil
	}
	if len(visibility) == 0 {
		return nil
	}

	// RD-874: pre-resolve the per-contract unlock map so the filter pass
	// stays O(1) per log. Both `allow_visibleto_unlock` (DB) and viewer
	// eligibility (rbac.IsViewerEligibleForVisibleToUnlock) must hold.
	contractAddrs := extractContractAddressesFromResponse(responseBody)
	unlockable := p.buildVisibleToUnlockableMap(ctx, userDID, contractAddrs)

	return &rbac.TxVisibilityContext{
		ViewerDID:           userDID,
		TxVisibility:        visibility,
		UnlockableContracts: unlockable,
	}
}

// buildVisibleToUnlockableMap returns the (lowercased address → true) map
// of contracts where the per-contract `allow_visibleto_unlock` flag is
// set AND the viewer holds an eligible group membership on the contract
// (rbac.IsViewerEligibleForVisibleToUnlock). Both gates are required;
// missing either omits the contract from the map. The caller is expected
// to combine the result with a per-tx visibleTo membership check before
// granting access — see TxVisibilityContext doc for the full sequence.
//
// Returns an empty (non-nil) map on no-op inputs so callers don't need
// to nil-check before lookup.
func (p *JSONRPCProcessor) buildVisibleToUnlockableMap(ctx context.Context, viewerDID string, contractAddrs []string) map[string]bool {
	out := make(map[string]bool)
	if p.rbacAccessCtrl == nil || viewerDID == "" || len(contractAddrs) == 0 {
		return out
	}
	store := p.rbacAccessCtrl.Store()
	if store == nil {
		return out
	}
	seen := make(map[string]struct{}, len(contractAddrs))
	for _, addr := range contractAddrs {
		addrLower := strings.ToLower(addr)
		if _, dup := seen[addrLower]; dup || addrLower == "" {
			continue
		}
		seen[addrLower] = struct{}{}

		contract, err := store.GetContractByAddressGlobal(ctx, addrLower)
		if err != nil || contract == nil || !contract.AllowVisibleToUnlock {
			continue
		}
		// RD-1308: under an impersonation scope, only the scope org's
		// contracts can unlock.
		if scope, scoped := viewerOrgScope(ctx); scoped && (scope == "" || contract.OrgID != scope) {
			continue
		}
		if rbac.IsViewerEligibleForVisibleToUnlock(ctx, p.rbacAccessCtrl, viewerDID, addrLower) {
			out[addrLower] = true
		}
	}
	return out
}

// participantResolveMaxTxs caps how many unique transactions an eth_getLogs
// response may reference before RD-1162 participant admission is skipped for
// that response. Resolving senders costs one batched upstream round trip whose
// payload grows with the unique-tx count; beyond the cap we fall back to
// pre-RD-1162 behaviour (address/event-rule/visibleTo only) rather than issue an
// unbounded batch. Skips are logged.
const participantResolveMaxTxs = 256

// buildParticipantTxHashes resolves, for an eth_getLogs response, the set of the
// response's transaction hashes (lowercase) that the caller participated in —
// their linked address is the tx `from` or `to` (RD-1162). FilterEventLogs uses
// this to admit logs of the caller's own transactions even when the event
// carries no address of theirs, bounded there by contract-grant access.
//
// Log entries do not carry the sender, so each unique tx hash is resolved via a
// single batched eth_getTransactionByHash call to the upstream node (bypassing
// the client-facing batch rejection — this is a proxy→node call). Returns an
// empty map (never nil-panics on lookup) when the caller has no linked
// addresses, there are no tx hashes, the unique-tx count exceeds
// participantResolveMaxTxs, or the upstream resolution fails — all fail toward
// the pre-RD-1162 filtering, never toward over-exposure.
func (p *JSONRPCProcessor) buildParticipantTxHashes(addrs []string, responseBody []byte) map[string]bool {
	out := map[string]bool{}
	if len(addrs) == 0 || p.proxy == nil {
		return out
	}
	hashes := extractTxHashesFromResponse(responseBody)
	if len(hashes) == 0 {
		return out
	}
	if len(hashes) > participantResolveMaxTxs {
		slog.Warn("RD-1162: getLogs response references too many txs to resolve senders; skipping participant admission",
			"unique_txs", len(hashes), "cap", participantResolveMaxTxs)
		return out
	}

	addrSet := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		addrSet[strings.ToLower(a)] = true
	}

	// One batched eth_getTransactionByHash for all unique hashes. Results are
	// matched by the returned tx's own hash, so batch ordering is irrelevant.
	batch := make([]map[string]any, 0, len(hashes))
	for i, h := range hashes {
		batch = append(batch, map[string]any{
			"jsonrpc": "2.0",
			"method":  "eth_getTransactionByHash",
			"params":  []any{h},
			"id":      i,
		})
	}
	reqBody, err := json.Marshal(batch)
	if err != nil {
		return out
	}
	respBody, _, err := p.proxy.Forward(reqBody)
	if err != nil {
		slog.Warn("RD-1162: failed to resolve tx senders for participant admission", "error", err)
		return out
	}

	var results []struct {
		Result *struct {
			Hash string `json:"hash"`
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &results); err != nil {
		slog.Warn("RD-1162: failed to parse tx-sender batch response", "error", err)
		return out
	}
	for _, r := range results {
		if r.Result == nil {
			continue
		}
		from := strings.ToLower(r.Result.From)
		to := strings.ToLower(r.Result.To)
		if addrSet[from] || (to != "" && addrSet[to]) {
			out[strings.ToLower(r.Result.Hash)] = true
		}
	}
	return out
}

// extractTxHashesFromResponse extracts unique transaction hashes from a JSON-RPC
// response body. Handles three shapes:
//
//   - eth_getLogs — array of log objects (hash field: "transactionHash")
//   - eth_getTransactionReceipt — single receipt (hash field: "transactionHash")
//   - eth_getTransactionByHash / ...ByBlockHashAndIndex / ...ByBlockNumberAndIndex —
//     single transaction object (hash field: "hash", per the Ethereum JSON-RPC spec)
//
// All three shapes are attempted independently because Go's json.Unmarshal silently
// tolerates missing fields — e.g. unmarshaling a tx body into the receipt struct
// succeeds but produces an empty TransactionHash, so the tx-object branch is
// required as an additional attempt (not a fallback). The seen map dedupes.
func extractTxHashesFromResponse(responseBody []byte) []string {
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Result == nil {
		return nil
	}

	seen := make(map[string]bool)
	addHash := func(h string) {
		h = strings.ToLower(h)
		if h != "" && !seen[h] {
			seen[h] = true
		}
	}

	// Try as array of logs (eth_getLogs response).
	var logs []struct {
		TransactionHash string `json:"transactionHash"`
	}
	if err := json.Unmarshal(resp.Result, &logs); err == nil {
		for _, log := range logs {
			addHash(log.TransactionHash)
		}
	}

	// Try as a single receipt (eth_getTransactionReceipt response).
	var receipt struct {
		TransactionHash string `json:"transactionHash"`
		Logs            []struct {
			TransactionHash string `json:"transactionHash"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(resp.Result, &receipt); err == nil {
		addHash(receipt.TransactionHash)
		for _, log := range receipt.Logs {
			addHash(log.TransactionHash)
		}
	}

	// Try as a single transaction object (eth_getTransactionByHash et al.).
	// Transaction objects use "hash", not "transactionHash" — this branch is why
	// the others can't be an if/else chain.
	var tx struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(resp.Result, &tx); err == nil {
		addHash(tx.Hash)
	}

	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for h := range seen {
		result = append(result, h)
	}
	return result
}

// extractContractAddressesFromResponse pulls unique lowercased contract
// addresses from a JSON-RPC response body. Handles three response
// shapes so it can be used for eth_getLogs, eth_getTransactionReceipt,
// and eth_getTransactionByHash (plus block-index variants):
//
//   - array of logs (eth_getLogs) — each log's "address" is collected
//   - single receipt (eth_getTransactionReceipt) — the receipt's "to"
//     plus every log.address inside "logs"
//   - single transaction (eth_getTransactionByHash etc.) — the tx's "to"
//
// Empty addresses ("", null, missing) are skipped. The returned slice
// is ready to pass to viewerAdminContracts.
func extractContractAddressesFromResponse(responseBody []byte) []string {
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil || resp.Result == nil {
		return nil
	}

	seen := make(map[string]struct{})
	add := func(a string) {
		a = strings.ToLower(a)
		if a == "" {
			return
		}
		seen[a] = struct{}{}
	}

	// Try as array of logs.
	var logs []struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(resp.Result, &logs); err == nil {
		for _, l := range logs {
			add(l.Address)
		}
	}

	// Try as a receipt (has "to" and a "logs" array whose entries have
	// "address").
	var receipt struct {
		To   string `json:"to"`
		Logs []struct {
			Address string `json:"address"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(resp.Result, &receipt); err == nil {
		add(receipt.To)
		for _, l := range receipt.Logs {
			add(l.Address)
		}
	}

	// Try as a single transaction object (has "to", no "logs").
	var tx struct {
		To string `json:"to"`
	}
	if err := json.Unmarshal(resp.Result, &tx); err == nil {
		add(tx.To)
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	return out
}
