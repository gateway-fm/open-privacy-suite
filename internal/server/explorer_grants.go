package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
)

// getViewableAddresses returns all addresses the authenticated viewer can view.
// GET /api/v1/explorer/viewable-addresses
// SECURITY (RD-1164 #7): the viewer identity comes ONLY from the validated JWT
// (or the impersonation override) via getViewerDIDFromRequest — never from a
// ?wallet= lookup, which would be a deanonymization oracle. A ?wallet= value is
// only echoed back for display; with no JWT the response is the empty set.
//
// @Summary      Addresses viewable by the resolved viewer
// @Description  Lists the viewer's own linked addresses plus addresses disclosed to them via active disclosure grants. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: the viewer DID comes from a validated JWT (or the impersonation override) — never from a query param — and for non-full grants the disclosed address is a pseudonym or "[PRIVATE]", never the real address. Fail-closed: with no resolvable viewer, only empty lists are returned.
// @Tags         Explorer
// @Produce      json
// @Param        wallet query string false "Viewer wallet address (0x-prefixed hex), echoed back for display only. The viewer identity is resolved solely from the JWT — a wallet value never resolves a DID (RD-1164 #7)." example(0x0000000000000000000000000000000000000001)
// @Success      200 {object} apimodels.ViewableAddressesResponse
// @Failure      400 {object} apimodels.APIError "neither a wallet nor JWT authentication was supplied"
// @Failure      500 {object} apimodels.APIError "lookup failed"
// @Router       /api/v1/explorer/viewable-addresses [get]
func (s *Server) getViewableAddresses(c *gin.Context) {
	wallet := c.Query("wallet")

	// SECURITY: Resolve viewer DID from JWT (validated) or wallet (DB-verified).
	// DID is never accepted directly from query params.
	viewerDID := s.getViewerDIDFromRequest(c)

	if wallet == "" && viewerDID == "" {
		respondBadRequest(c, "either wallet or JWT authentication is required")
		return
	}

	// Normalize wallet address if provided
	if wallet != "" {
		wallet = strings.ToLower(wallet)
	}

	ctx := c.Request.Context()
	response := apimodels.ViewableAddressesResponse{
		ViewerWallet:       wallet,
		OwnAddresses:       []apimodels.OwnAddress{},
		DisclosedAddresses: []apimodels.DisclosedAddress{},
	}

	// RD-1164 #7: identity is resolved ONLY from the validated JWT
	// (getViewerDIDFromRequest, above). The previous ?wallet= →
	// GetDIDByEthAddress fallback let an unauthenticated caller resolve any
	// wallet's DID and enumerate every address linked to that identity — a
	// deanonymization/clustering oracle. The equivalent wallet-viewer path was
	// already removed from the other explorer handlers (see the getViewerIdentity
	// removal note below); this closes it here too. A caller with no valid JWT
	// gets the anonymous empty response regardless of any ?wallet= value.
	if viewerDID == "" {
		c.JSON(http.StatusOK, response)
		return
	}

	response.ViewerDID = viewerDID

	// 2. Get viewer's own addresses
	ownLinks, err := s.db.GetEthAddressesByDID(ctx, viewerDID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get own addresses",
			"explorer: GetEthAddressesByDID failed",
			"viewer_did", viewerDID, "err", err)
		return
	}

	for _, link := range ownLinks {
		response.OwnAddresses = append(response.OwnAddresses, apimodels.OwnAddress{
			Address: link.EthAddress,
			ENSName: link.ENSName,
		})
	}

	// 3. Get disclosure grants where the viewer is the requester
	// We need to find all grants where requester_did = viewerDID
	grants, err := s.getDisclosedAddressesForViewer(ctx, viewerDID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get disclosed addresses",
			"explorer: getDisclosedAddressesForViewer failed",
			"viewer_did", viewerDID, "err", err)
		return
	}
	response.DisclosedAddresses = grants

	c.JSON(http.StatusOK, response)
}

// getDisclosedAddressesForViewer returns all addresses disclosed to a viewer via grants
func (s *Server) getDisclosedAddressesForViewer(ctx context.Context, viewerDID string) ([]apimodels.DisclosedAddress, error) {
	// Query for all active grants where the viewer is the requester
	query := `SELECT g.id, g.scope, g.expires_at, r.requester_did, u.external_id as target_did
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		JOIN users u ON r.target_user_id = u.id
		WHERE r.requester_did = $1
		AND g.revoked_at IS NULL
		AND g.expires_at > NOW()`

	rows, err := s.db.Conn().QueryContext(ctx, query, viewerDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Preserve the API contract: an authenticated viewer with no grants gets
	// an empty JSON array, never null. The explorer frontend and acceptance
	// suite rely on this distinction for exact disclosure counters.
	result := make([]apimodels.DisclosedAddress, 0)

	for rows.Next() {
		var grantID string
		var scope []byte
		var expiresAt time.Time
		var requesterDID, targetDID string

		if err := rows.Scan(&grantID, &scope, &expiresAt, &requesterDID, &targetDID); err != nil {
			return nil, err
		}

		// Get all addresses owned by the target DID
		targetAddresses, err := s.db.GetEthAddressesByDID(ctx, targetDID)
		if err != nil {
			return nil, err
		}

		// Parse scope JSON to determine disclosure level
		var scopeData disclosure.Scope
		disclosureLevel := "full" // Default to full
		if err := json.Unmarshal(scope, &scopeData); err == nil {
			if scopeData.DisclosureLevel != "" {
				disclosureLevel = string(scopeData.DisclosureLevel)
			}
		}

		for _, addr := range targetAddresses {
			// Generate opaque address ID for routing (hash-based)
			addressID := explorer.GenerateAddressID(addr.EthAddress, grantID)

			disclosed := apimodels.DisclosedAddress{
				AddressID:       addressID,
				OwnerDID:        targetDID,
				DisclosureLevel: disclosureLevel,
				GrantID:         grantID,
				ExpiresAt:       &expiresAt,
			}

			// SECURITY: Only include real address for full disclosure
			switch disclosureLevel {
			case "full":
				disclosed.Address = addr.EthAddress
				disclosed.ENSName = addr.ENSName
			case "pseudonymous":
				disclosed.Address = s.pseudonym(addr.EthAddress)
				// Don't include ENS name - it could reveal identity
			case "redacted":
				disclosed.Address = "[PRIVATE]"
				// Don't include ENS name
			default:
				// SECURITY: Fail-safe - treat unknown disclosure levels as redacted
				disclosed.Address = "[PRIVATE]"
			}

			result = append(result, disclosed)
		}
	}

	return result, nil
}

// resolveAddressID resolves an opaque address_id back to the real address
// GET /api/v1/explorer/grant/:grant_id/resolve/:address_id
// This is an internal API for the explorer backend to fetch data for disclosed addresses.
// SECURITY: This endpoint is localhost-only and returns the real address for backend use.
// The explorer backend must apply appropriate redaction before sending to the frontend.
//
// @Summary      Resolve a grant-scoped address_id
// @Description  Resolves an opaque address_id (issued by viewable-addresses) back to grant-scoped disclosure data for the explorer backend. Private network only (serves the explorer backend); not reachable through the public ingress. The response is scoped to the grant's disclosure level: the real address is returned ONLY for a "full" grant; a "pseudonymous" grant returns a stable pseudonym and no real address; other levels return neither. Fail-closed: a revoked or expired grant, or an address_id that does not belong to the grant, yields 403/404.
// @Tags         Explorer
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        address_id path string true "Opaque address identifier from viewable-addresses"
// @Success      200 {object} apimodels.ResolveAddressResponse
// @Failure      400 {object} apimodels.APIError "grant_id and address_id are required"
// @Failure      401 {object} apimodels.APIError "authentication required"
// @Failure      403 {object} apimodels.APIError "grant has been revoked or has expired"
// @Failure      404 {object} apimodels.APIError "grant or address not found for this grant"
// @Failure      500 {object} apimodels.APIError "lookup failed"
// @Router       /api/v1/explorer/grant/{grant_id}/resolve/{address_id} [get]
func (s *Server) resolveAddressID(c *gin.Context) {
	grantID := c.Param("grant_id")
	addressID := c.Param("address_id")

	if grantID == "" || addressID == "" {
		respondBadRequest(c, "grant_id and address_id are required")
		return
	}

	// Look up the grant with its request
	grantWithRequest, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil || grantWithRequest == nil {
		respondNotFound(c, "grant not found")
		return
	}

	grant := grantWithRequest.Grant
	request := grantWithRequest.Request

	// SECURITY (RD-1164 #10): grantee verification — the viewer's DID must match
	// the grant's requester_did. Without it, any caller who knows a grant_id +
	// address_id could resolve the real address of a `full` grant they do not
	// hold. Mirrors getGrantActivityLogs; uniform 404 avoids grant enumeration.
	viewerDID := s.getViewerDIDFromRequest(c)
	if viewerDID == "" {
		respondUnauthorized(c, "authentication required")
		return
	}
	if request.RequesterDID != viewerDID {
		respondNotFound(c, "grant not found")
		return
	}

	// Check grant is still valid
	if grant.RevokedAt != nil {
		respondForbidden(c, "grant has been revoked")
		return
	}
	if grant.ExpiresAt.Before(time.Now()) {
		respondForbidden(c, "grant has expired")
		return
	}

	// Get target DID from the request
	targetUser, err := s.db.GetUser(c.Request.Context(), request.TargetUserID)
	if err != nil || targetUser == nil {
		respondInternalError(c, "failed to get target user")
		return
	}
	targetDID := targetUser.ExternalID

	// Get all addresses for the target DID
	addresses, err := s.db.GetEthAddressesByDID(c.Request.Context(), targetDID)
	if err != nil {
		respondInternalError(c, "failed to get addresses")
		return
	}

	// Find the address matching the address_id
	var realAddress string
	for _, addr := range addresses {
		computedID := explorer.GenerateAddressID(addr.EthAddress, grantID)
		if computedID == addressID {
			realAddress = addr.EthAddress
			break
		}
	}

	if realAddress == "" {
		respondNotFound(c, "address not found for this grant")
		return
	}

	// Get disclosure level from grant scope
	disclosureLevel := "full"
	if grant.Scope.DisclosureLevel != "" {
		disclosureLevel = string(grant.Scope.DisclosureLevel)
	}

	response := apimodels.ResolveAddressResponse{
		DisclosureLevel: disclosureLevel,
		GrantID:         grantID,
		ScopeMethods:    grant.Scope.Methods,
	}

	// SECURITY: Only include real address for full disclosure.
	// The explorer backend is an untrusted client and must not see real addresses
	// for pseudonymous or redacted grants.
	if disclosureLevel == "full" {
		response.RealAddress = &realAddress
	}

	// Include pseudonym for pseudonymous disclosures
	if disclosureLevel == "pseudonymous" {
		response.Pseudonym = s.pseudonym(realAddress)
	}

	c.JSON(http.StatusOK, response)
}

// generateExternalPseudonym creates a deterministic pseudonym for an external address
// in the context of a specific grant. The pseudonym is derived from the address and grant ID
// so it is consistent within a grant but cannot be correlated across grants.
func generateExternalPseudonym(address, grantID string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(address)))
	h.Write([]byte(":"))
	h.Write([]byte(grantID))
	sum := h.Sum(nil)
	return fmt.Sprintf("External-%X", sum[:2])
}

// pseudonym returns the keyed, non-reversible display pseudonym for an address
// (RD-1164 #8), keyed by EXPLORER_PSEUDONYM_KEY when configured. All explorer
// handlers use this rather than calling explorer.GeneratePseudonym directly so
// the key is applied uniformly.
func (s *Server) pseudonym(address string) string {
	var key []byte
	if s.config != nil {
		key = s.config.ExplorerPseudonymKey
	}
	return explorer.GeneratePseudonym(address, key)
}

// filterTxsByGrantScope drops disclosed transactions that fall outside the
// grant's own scope (RD-1164 #9): a grant scoped to a DateRange or a set of
// contract addresses must not disclose transactions beyond it. An unset scope
// dimension imposes no restriction. It fail-closes: a tx with a missing (0)
// or out-of-range timestamp, or whose from/to is not in the address scope, is
// excluded — never over-discloses. collectGrantScopeTxs applies it per raw
// page while walking the feed cursor (RD-1149/RD-1167), so in-scope rows
// beyond the first page are reachable.
func filterTxsByGrantScope(txs []explorer.Transaction, scope disclosure.Scope) []explorer.Transaction {
	if scope.DateRange == nil && len(scope.Addresses) == 0 {
		return txs
	}

	var scopeAddrs map[string]bool
	if len(scope.Addresses) > 0 {
		scopeAddrs = make(map[string]bool, len(scope.Addresses))
		for _, a := range scope.Addresses {
			scopeAddrs[strings.ToLower(a)] = true
		}
	}

	var start, end int64
	if scope.DateRange != nil {
		start = scope.DateRange.Start.Unix()
		end = scope.DateRange.End.Unix()
	}

	out := make([]explorer.Transaction, 0, len(txs))
	for _, tx := range txs {
		if scope.DateRange != nil {
			// Fail closed: a tx with a missing (0) or out-of-range block
			// timestamp is excluded rather than disclosed.
			ts := int64(tx.BlockTimestamp)
			if ts == 0 || ts < start || ts > end {
				continue
			}
		}
		if scopeAddrs != nil {
			from := strings.ToLower(tx.From)
			to := ""
			if tx.To != nil {
				to = strings.ToLower(*tx.To)
			}
			if !scopeAddrs[from] && !scopeAddrs[to] {
				continue
			}
		}
		out = append(out, tx)
	}
	return out
}

// collectGrantScopeTxs walks an address's tx feed on the backend's opaque
// continuation cursor (RD-1149), applying the grant's scope filter per fetch,
// until it has exactly `want` in-scope txs, the feed is exhausted, or a scan
// bound is hit. Each iteration fetches only the rows still missing
// (want − len(inScope)), so the result never exceeds `want` and is never
// trimmed — trimming would drop rows behind the resume cursor, which always
// positions after the last FETCHED row. Returns the in-scope txs and the
// resume cursor ("" = feed exhausted, non-empty = advanceable). At the scan
// bounds the result may be short — even empty — with a non-empty cursor: the
// caller can always page forward, so a narrowly-scoped grant over a busy
// address never dead-ends (RD-1167).
func (s *Server) collectGrantScopeTxs(ctx context.Context, address string, scope disclosure.Scope, want int, page explorer.AddressPage) ([]explorer.Transaction, string, error) {
	const (
		maxScan  = 10000 // bound on raw rows fetched (matches the count walkers)
		maxFetch = 100   // bound on sequential backend calls per request
	)
	var inScope []explorer.Transaction
	cur := page
	for scanned, fetches := 0, 0; scanned < maxScan && fetches < maxFetch; fetches++ {
		txs, next, err := s.explorerStore.GetTransactionsByAddress(ctx, address, want-len(inScope), cur)
		if err != nil {
			return nil, "", err
		}
		// A non-advancing cursor means the backend re-served the previous
		// page: discard this fetch (appending it would double-serve rows on a
		// resumed request) and terminate with what was legitimately gathered.
		if next != "" && next == cur.Cursor {
			return inScope, "", nil
		}
		scanned += len(txs)
		inScope = append(inScope, filterTxsByGrantScope(txs, scope)...)
		if next == "" {
			return inScope, "", nil // feed exhausted — nothing left to resume
		}
		cur = explorer.AddressPage{Cursor: next}
		if len(inScope) >= want {
			return inScope, next, nil
		}
	}
	return inScope, cur.Cursor, nil // scan bound hit — resumable
}

// getGrantTransactions returns transactions for a disclosed address, pseudonymized
// according to the grant's disclosure level.
// GET /api/v1/explorer/grant/:grant_id/:address_id/transactions
// SECURITY: This endpoint never exposes real addresses for non-full grants.
// The explorer backend receives pre-pseudonymized data and cannot reverse it.
//
// @Summary      Grant-scoped transactions for a disclosed address
// @Description  Returns transactions for a disclosed address, rendered at the grant's disclosure level. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the grant: "full" reveals real addresses, hashes and values; "pseudonymous" replaces addresses with stable pseudonyms and hides values and hashes; "redacted" (or any unknown level) shows only direction, gas, status and timing with "[PRIVATE]" counterparties. Fail-closed: a revoked or expired grant, or an address_id that does not belong to the grant, yields 403/404.
// @Tags         Explorer
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        address_id path string true "Opaque address identifier from viewable-addresses"
// @Param        limit query int false "Max rows to return (1-100). At the scan bounds a page may come back short — even empty — with a next_cursor to continue from (present ⇒ more pages)" default(25)
// @Param        cursor query string false "Opaque continuation cursor from the previous response's next_cursor (RD-1149); takes precedence over before"
// @Param        before query int false "Legacy: return rows strictly older than this block number (may skip rows of the boundary block — prefer cursor)"
// @Success      200 {object} apimodels.GrantTransactionsResponse
// @Failure      400 {object} apimodels.APIError "grant_id and address_id are required, or the pagination cursor is malformed"
// @Failure      401 {object} apimodels.APIError "authentication required"
// @Failure      403 {object} apimodels.APIError "grant has been revoked or has expired"
// @Failure      404 {object} apimodels.APIError "grant or address not found for this grant"
// @Failure      500 {object} apimodels.APIError "explorer store not configured or lookup failed"
// @Router       /api/v1/explorer/grant/{grant_id}/{address_id}/transactions [get]
func (s *Server) getGrantTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondInternalError(c, "explorer store not configured")
		return
	}

	grantID := c.Param("grant_id")
	addressID := c.Param("address_id")

	if grantID == "" || addressID == "" {
		respondBadRequest(c, "grant_id and address_id are required")
		return
	}

	// Look up the grant with its request
	grantWithRequest, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil || grantWithRequest == nil {
		respondNotFound(c, "grant not found")
		return
	}

	grant := grantWithRequest.Grant
	request := grantWithRequest.Request

	// SECURITY (RD-1164 #10): grantee verification FIRST — the viewer's DID must
	// match the grant's requester_did, else any caller with a grant_id +
	// address_id could read a `full` grant's real transactions. Checked before
	// revoked/expired so grant state is never revealed to a non-grantee. Mirrors
	// getGrantActivityLogs.
	viewerDID := s.getViewerDIDFromRequest(c)
	if viewerDID == "" {
		respondUnauthorized(c, "authentication required")
		return
	}
	if request.RequesterDID != viewerDID {
		respondNotFound(c, "grant not found")
		return
	}

	// Check grant is still valid
	if grant.RevokedAt != nil {
		respondForbidden(c, "grant has been revoked")
		return
	}
	if grant.ExpiresAt.Before(time.Now()) {
		respondForbidden(c, "grant has expired")
		return
	}

	// Get disclosure level
	disclosureLevel := "full"
	if grant.Scope.DisclosureLevel != "" {
		disclosureLevel = string(grant.Scope.DisclosureLevel)
	}

	// Get target user and their addresses
	targetUser, err := s.db.GetUser(c.Request.Context(), request.TargetUserID)
	if err != nil || targetUser == nil {
		respondInternalError(c, "failed to get target user")
		return
	}
	targetDID := targetUser.ExternalID

	addresses, err := s.db.GetEthAddressesByDID(c.Request.Context(), targetDID)
	if err != nil {
		respondInternalError(c, "failed to get addresses")
		return
	}

	// Find the real address by matching address_id
	var realAddress string
	for _, addr := range addresses {
		computedID := explorer.GenerateAddressID(addr.EthAddress, grantID)
		if computedID == addressID {
			realAddress = addr.EthAddress
			break
		}
	}

	if realAddress == "" {
		respondNotFound(c, "address not found for this grant")
		return
	}

	// Parse pagination params
	limit := 25
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	page := explorer.AddressPage{Cursor: c.Query("cursor")}
	if beforeStr := c.Query("before"); beforeStr != "" {
		if parsed, err := strconv.ParseUint(beforeStr, 10, 64); err == nil {
			page.BeforeBlock = &parsed
		}
	}

	// RD-1149/RD-1167: walk the address feed on the backend's real
	// continuation cursor, applying the grant's scope filter (RD-1164 #9) per
	// fetch, until `limit` in-scope txs are found, the feed is exhausted, or
	// a scan bound is hit. The old single limit+1 fetch made in-scope txs
	// deeper than the first page unreachable and derived the continuation from
	// the pre-filter page size.
	txs, resumeCursor, err := s.collectGrantScopeTxs(c.Request.Context(), realAddress, grant.Scope, limit, page)
	if err != nil {
		if isBadCursorErr(err) {
			respondBadRequest(c, "invalid pagination cursor")
			return
		}
		respondInternalError(c, "failed to get transactions")
		return
	}

	realAddrLower := strings.ToLower(realAddress)
	labels := make(map[string]string)

	// Resolve viewer's own addresses so we can label them "mine" on the grant page.
	// viewerDID was resolved and grantee-verified above (RD-1164 #10).
	viewerAddrs := make(map[string]bool)
	if viewerDID != "" {
		linked, err := s.db.GetLinkedAddresses(c.Request.Context(), viewerDID)
		if err == nil {
			for _, a := range linked {
				viewerAddrs[strings.ToLower(a)] = true
			}
		}
	}

	var grantTxs []apimodels.GrantTransaction
	for _, tx := range txs {
		gt := apimodels.GrantTransaction{
			BlockNumber:    tx.BlockNumber,
			BlockTimestamp: tx.BlockTimestamp,
			GasUsed:        tx.GasUsed,
			Status:         tx.Status,
		}

		fromLower := strings.ToLower(tx.From)
		var toLower string
		if tx.HasRecipient() {
			toLower = strings.ToLower(*tx.To)
		}

		// Determine direction
		fromIsDisclosed := fromLower == realAddrLower
		toIsDisclosed := toLower == realAddrLower
		if fromIsDisclosed && toIsDisclosed {
			gt.Direction = "self"
		} else if fromIsDisclosed {
			gt.Direction = "out"
		} else {
			gt.Direction = "in"
		}

		switch disclosureLevel {
		case "full":
			hash := tx.Hash
			gt.TxHash = &hash
			gt.From = tx.From
			if tx.HasRecipient() {
				gt.To = *tx.To
			}
			gt.Value = string(tx.Value)

		case "pseudonymous":
			disclosedPseudonym := s.pseudonym(realAddress)
			labels[disclosedPseudonym] = "disclosed"

			if fromIsDisclosed {
				gt.From = disclosedPseudonym
			} else if viewerAddrs[fromLower] {
				gt.From = "Mine"
				labels["Mine"] = "mine"
			} else {
				ext := generateExternalPseudonym(tx.From, grantID)
				gt.From = ext
				labels[ext] = "external"
			}

			if tx.HasRecipient() {
				if toIsDisclosed {
					gt.To = disclosedPseudonym
				} else if viewerAddrs[toLower] {
					gt.To = "Mine"
					labels["Mine"] = "mine"
				} else {
					ext := generateExternalPseudonym(*tx.To, grantID)
					gt.To = ext
					labels[ext] = "external"
				}
			}

			gt.Value = "hidden"
			// tx hash intentionally omitted for pseudonymous

		case "redacted":
			// Every address renders as the same opaque placeholder. Unlike
			// pseudonymous, no per-address stable token is emitted — the
			// auditor cannot correlate counterparties across txs. Value and
			// tx hash are also withheld so the auditor learns timing, gas,
			// status, and direction only ("proof of activity" without graph
			// or financial pattern correlation).
			gt.From = "[PRIVATE]"
			if tx.HasRecipient() {
				gt.To = "[PRIVATE]"
			}
			gt.Value = "hidden"
		}

		grantTxs = append(grantTxs, gt)
	}

	// Ensure non-nil slices in JSON
	if grantTxs == nil {
		grantTxs = []apimodels.GrantTransaction{}
	}

	c.JSON(http.StatusOK, apimodels.GrantTransactionsResponse{
		Transactions:    grantTxs,
		DisclosureLevel: disclosureLevel,
		AddressLabels:   labels,
		NextCursor:      resumeCursor,
	})
}

// getGrantActivityLogs returns activity logs scoped to a disclosure grant.
// GET /api/v1/explorer/grant/:grant_id/activity
//
// SECURITY:
//   - JWT required -- anonymous requests are rejected.
//   - Grant holder verification: the viewer's DID must match the grant's requester_did.
//   - Scope check: grant must include "activity_logs" or "full_disclosure".
//   - Time-bounded: only logs within the grant's validity period are returned.
//   - Stripped response: only method, status_code, and timestamp are returned.
//   - Uniform 404 for "not found" and "not your grant" to prevent enumeration.
//
// @Summary      Grant-scoped activity logs
// @Description  Returns activity-log entries (method, status code, timestamp only) for a disclosure grant the caller holds. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered: a valid JWT is required, the viewer DID must match the grant's requester, the grant scope must include activity_logs or full_disclosure, and only entries inside the grant's validity window are returned. Fail-closed: anonymous callers are rejected, and "grant missing"/"not your grant"/"expired" all return the same 404 to prevent enumeration.
// @Tags         Explorer
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} apimodels.GrantActivityLogsResponse
// @Failure      400 {object} apimodels.APIError "grant_id is required"
// @Failure      401 {object} apimodels.APIError "authentication required"
// @Failure      403 {object} apimodels.APIError "grant scope does not include activity_logs"
// @Failure      404 {object} apimodels.APIError "grant not found (also returned for a grant that is not yours or has expired)"
// @Failure      500 {object} apimodels.APIError "lookup failed"
// @Router       /api/v1/explorer/grant/{grant_id}/activity [get]
func (s *Server) getGrantActivityLogs(c *gin.Context) {
	grantID := c.Param("grant_id")
	if grantID == "" {
		respondBadRequest(c, "grant_id is required")
		return
	}

	// 1. JWT required -- reject anonymous
	viewerDID := s.getViewerDIDFromRequest(c)
	if viewerDID == "" {
		respondUnauthorized(c, "authentication required")
		return
	}

	// 2. Look up the grant with its request
	grantWithRequest, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil || grantWithRequest == nil {
		// Uniform 404 prevents enumeration
		respondNotFound(c, "grant not found")
		return
	}

	grant := grantWithRequest.Grant
	request := grantWithRequest.Request

	// 3. Grant holder verification: viewer DID must match requester_did
	if request.RequesterDID != viewerDID {
		// Same 404 -- do not reveal that the grant exists
		respondNotFound(c, "grant not found")
		return
	}

	// 4. Check grant is still active (not expired, not revoked)
	if grant.RevokedAt != nil || grant.ExpiresAt.Before(time.Now()) {
		respondNotFound(c, "grant not found")
		return
	}

	// 5. Scope check: must include "activity_logs" or "full_disclosure"
	hasScope := false
	for _, m := range grant.Scope.Methods {
		if m == "activity_logs" || m == "full_disclosure" {
			hasScope = true
			break
		}
	}
	if !hasScope {
		respondForbidden(c, "grant scope does not include activity_logs")
		return
	}

	// 6. Parse pagination
	limit := 25
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	offset := 0
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// 7. Query activity logs scoped to grant time bounds.
	// RD-1147: resolve the grant's target + time window from the main DB, then
	// read access_logs from the audit DB (they may be different databases now).
	logs, total, err := s.getActivityLogsForGrant(c.Request.Context(), grantID, limit, offset)
	if err != nil {
		respondInternalError(c, "failed to get activity logs")
		return
	}

	// 8. Build stripped response
	entries := make([]apimodels.GrantActivityLogEntry, 0, len(logs))
	for _, log := range logs {
		entries = append(entries, apimodels.GrantActivityLogEntry{
			Method:     log.Method,
			StatusCode: log.StatusCode,
			Timestamp:  log.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, apimodels.GrantActivityLogsResponse{
		Logs:   entries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}
