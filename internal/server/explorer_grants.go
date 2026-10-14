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
// @Description  Lists the viewer's own linked addresses plus addresses disclosed to them via active disclosure grants. The requester must remain a current member of the grant's organization. Grant scope is enforced on the server, and successful reads are audited. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: the viewer DID comes from a validated JWT (or the impersonation override) — never from a query param — and for non-full grants the disclosed address is a pseudonym or "[PRIVATE]", never the real address. Fail-closed: with no resolvable viewer, only empty lists are returned. Under the View-as mirror no disclosed addresses are listed: the target's grants are not available to the admin viewing as them.
// @Tags         Explorer
// @Produce      json
// @Param        wallet query string false "Viewer wallet address (0x-prefixed hex), echoed back for display only. The viewer identity is resolved solely from the JWT — a wallet value never resolves a DID (RD-1164 #7)." example(0x0000000000000000000000000000000000000001)
// @Success      200 {object} apimodels.ViewableAddressesResponse
// @Failure      400 {object} apimodels.APIError "neither a wallet nor JWT authentication was supplied"
// @Failure      500 {object} apimodels.APIError "lookup failed"
// @Router       /api/v1/explorer/viewable-addresses [get]
func (s *Server) getViewableAddresses(c *gin.Context) {
	wallet := c.Query("wallet")

	// SECURITY: Resolve viewer DID only from validated authentication.
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
	// We need to find all grants where requester_did = viewerDID.
	// RD-1318: under View-as the grants are the target's, not the admin's —
	// none are listed (getDisclosedAddressesForViewer returns an empty list).
	grants, err := s.getDisclosedAddressesForViewer(ctx, viewerDID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get disclosed addresses",
			"explorer: getDisclosedAddressesForViewer failed",
			"viewer_did", viewerDID, "err", err)
		return
	}
	response.DisclosedAddresses = grants
	counts := make(map[string]int)
	for _, address := range grants {
		counts[address.GrantID]++
	}
	for grantID, count := range counts {
		s.recordGrantRead(c, grantID, disclosure.ActionListAddresses, disclosure.ResourceAddresses, count)
	}

	c.JSON(http.StatusOK, response)
}

// getDisclosedAddressesForViewer returns all addresses disclosed to a viewer via grants
//
// Under an impersonation (disclosure.WithoutViewerGrants) it returns an empty
// list: the grants belong to the viewer, not to the admin viewing as them.
func (s *Server) getDisclosedAddressesForViewer(ctx context.Context, viewerDID string) ([]apimodels.DisclosedAddress, error) {
	if disclosure.ViewerGrantsSuppressed(ctx) {
		return make([]apimodels.DisclosedAddress, 0), nil
	}
	// Query for all active grants where the viewer is the requester
	query := `SELECT g.id, g.scope, g.expires_at, r.requester_did, u.external_id as target_did
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		JOIN users u ON r.target_user_id = u.id
		WHERE r.requester_did = $1
		AND g.revoked_at IS NULL
		AND g.expires_at > NOW()
		AND r.status = 'approved'
		AND EXISTS (
			SELECT 1 FROM users viewer
			JOIN user_memberships m ON m.user_id = viewer.id
			JOIN groups gr ON gr.id = m.group_id
			WHERE viewer.external_id = $1 AND gr.org_id = r.org_id
			AND (m.expires_at IS NULL OR m.expires_at > NOW())
		)`
	args := []any{viewerDID}
	if org, pinned := viewerOrgScope(ctx); pinned {
		query += " AND r.org_id::text = $2"
		args = append(args, org)
	}

	rows, err := s.db.Conn().QueryContext(ctx, query, args...)
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

		// Invalid legacy scope dimensions never widen consent. Empty/unknown
		// levels render as redacted rather than the former Full default.
		var scopeData disclosure.Scope
		if err := json.Unmarshal(scope, &scopeData); err != nil {
			continue
		}
		scopeData, err = scopeData.ForRead()
		if err != nil {
			continue
		}
		disclosureLevel := string(scopeData.EffectiveLevel())

		for _, addr := range targetAddresses {
			// Generate opaque address ID for routing (hash-based)
			addressID := s.grantAddressID(addr.EthAddress, grantID)

			disclosed := apimodels.DisclosedAddress{
				AddressID:       addressID,
				DisclosureLevel: disclosureLevel,
				GrantID:         grantID,
				ExpiresAt:       &expiresAt,
			}

			// SECURITY: Only include real address for full disclosure
			switch disclosureLevel {
			case "full":
				disclosed.OwnerDID = targetDID
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

	return result, rows.Err()
}

// resolveAddressID resolves an opaque address_id back to the real address
// GET /api/v1/explorer/grant/:grant_id/resolve/:address_id
// This is an internal API for the explorer backend to fetch data for disclosed addresses.
// SECURITY: Only a Full grant returns the real address; all rendering is enforced here.
//
// @Summary      Resolve a grant-scoped address_id
// @Description  Resolves an opaque address_id (issued by viewable-addresses) back to grant-scoped disclosure data for the explorer backend. The requester must remain a current member of the grant's organization. Grant scope is enforced on the server, and successful reads are audited. Private network only (serves the explorer backend); not reachable through the public ingress. The response is scoped to the grant's disclosure level: the real address is returned ONLY for a "full" grant; a "pseudonymous" grant returns a stable pseudonym and no real address; other levels return neither. Fail-closed: a revoked or expired grant, or an address_id that does not belong to the grant, yields 403/404. Under the View-as mirror it always returns 404: the target's grants are not available to the admin viewing as them.
// @Tags         Explorer
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        address_id path string true "Opaque address identifier from viewable-addresses"
// @Success      200 {object} apimodels.ResolveAddressResponse
// @Failure      400 {object} apimodels.APIError "grant_id and address_id are required"
// @Failure      401 {object} apimodels.APIError "authentication required"
// @Failure      403 {object} apimodels.APIError "grant is inactive or its scope does not permit this data"
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

	gw, ok := s.explorerGrant(c, false)
	if !ok {
		return
	}
	grant := gw.Grant
	realAddress, err := s.grantSubjectAddress(c.Request.Context(), gw, addressID)
	if err != nil {
		respondInternalError(c, "failed to resolve address")
		return
	}
	if realAddress == "" {
		respondNotFound(c, "address not found for this grant")
		return
	}
	disclosureLevel := string(grant.Scope.EffectiveLevel())

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

	s.recordGrantRead(c, grantID, disclosure.ActionResolveAddress, disclosure.ResourceAddresses, 1)
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
	out := make([]explorer.Transaction, 0, len(txs))
	for _, tx := range txs {
		to := ""
		if tx.HasRecipient() {
			to = *tx.To
		}
		if scope.CoversTransaction(tx.From, to, int64(tx.BlockTimestamp)) {
			out = append(out, tx)
		}
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
		// The indexer's address feed also includes parents of Transfer events.
		// A grant discloses only transactions whose from/to is the subject,
		// matching the detail endpoint. Keep the raw cursor and scan count so
		// skipped transfer-only parents never prevent reaching eligible rows.
		subjectTxs := make([]explorer.Transaction, 0, len(txs))
		for _, tx := range txs {
			if strings.EqualFold(tx.From, address) || (tx.HasRecipient() && strings.EqualFold(*tx.To, address)) {
				subjectTxs = append(subjectTxs, tx)
			}
		}
		inScope = append(inScope, filterTxsByGrantScope(subjectTxs, scope)...)
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
// @Description  Returns transactions for a disclosed address, rendered at the grant's disclosure level. The requester must remain a current member of the grant's organization. Grant scope is enforced on the server, and successful reads are audited. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the grant: "full" reveals real addresses, hashes and values; "pseudonymous" replaces addresses with stable pseudonyms and hides values and hashes; "redacted" (including an empty or unknown stored level) shows only direction, gas, status and timing with "[PRIVATE]" counterparties. Fail-closed: a revoked or expired grant, or an address_id that does not belong to the grant, yields 403/404. Under the View-as mirror it always returns 404: the target's grants are not available to the admin viewing as them.
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
// @Failure      403 {object} apimodels.APIError "grant is inactive or its scope does not permit this data"
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

	gw, ok := s.explorerGrant(c, false)
	if !ok {
		return
	}
	grant := gw.Grant
	if !grant.Scope.AllowsTransactionHistory() {
		respondForbidden(c, "grant scope does not include transaction_history")
		return
	}
	disclosureLevel := string(grant.Scope.EffectiveLevel())
	viewerDID := s.getViewerDIDFromRequest(c)
	realAddress, err := s.grantSubjectAddress(c.Request.Context(), gw, addressID)
	if err != nil {
		respondInternalError(c, "failed to resolve address")
		return
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
			TxIndex:        tx.TxIndex,
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
				ext := s.externalPseudonym(tx.From, grantID)
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
					ext := s.externalPseudonym(*tx.To, grantID)
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

	s.recordGrantRead(c, grantID, disclosure.ActionViewTransactions, disclosure.ResourceTransactions, len(grantTxs))
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
// @Description  Returns activity-log entries (method, status code, timestamp only) for a disclosure grant the caller holds. The requester must remain a current member of the grant's organization. Grant scope is enforced on the server, and successful reads are audited. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered: a valid JWT is required, the viewer DID must match the grant's requester, the grant scope must include activity_logs or full_disclosure, and only entries inside the grant's validity window are returned. Fail-closed: anonymous callers are rejected, and "grant missing"/"not your grant"/"expired" all return the same 404 to prevent enumeration. Under the View-as mirror it always returns 404: the target's grants are not available to the admin viewing as them.
// @Tags         Explorer
// @Produce      json
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} apimodels.GrantActivityLogsResponse
// @Failure      400 {object} apimodels.APIError "grant_id is required"
// @Failure      401 {object} apimodels.APIError "authentication required"
// @Failure      403 {object} apimodels.APIError "grant scope does not permit activity logs or restricts addresses"
// @Failure      404 {object} apimodels.APIError "grant not found (also returned for a grant that is not yours or has expired)"
// @Failure      500 {object} apimodels.APIError "lookup failed"
// @Router       /api/v1/explorer/grant/{grant_id}/activity [get]
func (s *Server) getGrantActivityLogs(c *gin.Context) {
	grantID := c.Param("grant_id")
	if grantID == "" {
		respondBadRequest(c, "grant_id is required")
		return
	}

	gw, ok := s.explorerGrant(c, true)
	if !ok {
		return
	}
	if !gw.Grant.Scope.AllowsActivityLogs() || len(gw.Grant.Scope.Addresses) != 0 {
		respondForbidden(c, "grant scope does not permit these activity logs")
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

	s.recordGrantRead(c, grantID, disclosure.ActionViewLogs, disclosure.ResourceAccessLogs, len(entries))
	c.JSON(http.StatusOK, apimodels.GrantActivityLogsResponse{
		Logs:   entries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}
