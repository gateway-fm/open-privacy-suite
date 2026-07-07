package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
)

// Explorer API Response Types

// OwnAddress represents an address owned by the viewer
type OwnAddress struct {
	Address string  `json:"address"`
	ENSName *string `json:"ens_name,omitempty"`
}

// DisclosedAddress represents an address disclosed to the viewer via a grant
// SECURITY: For non-full disclosures, Address contains the pseudonym or placeholder, NOT the real address
type DisclosedAddress struct {
	Address         string     `json:"address"`    // Pseudonym for pseudonymous, "[PRIVATE]" for redacted, real for full
	AddressID       string     `json:"address_id"` // Opaque identifier for routing (hash of real address)
	OwnerDID        string     `json:"owner_did"`
	DisclosureLevel string     `json:"disclosure_level"`
	GrantID         string     `json:"grant_id"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ENSName         *string    `json:"ens_name,omitempty"` // Only included for full disclosure
}

// ViewableAddressesResponse is the response for GET /api/v1/explorer/viewable-addresses
type ViewableAddressesResponse struct {
	ViewerWallet       string             `json:"viewer_wallet"`
	ViewerDID          string             `json:"viewer_did,omitempty"`
	OwnAddresses       []OwnAddress       `json:"own_addresses"`
	DisclosedAddresses []DisclosedAddress `json:"disclosed_addresses"`
}

// Type aliases for explorer visibility types — the canonical definitions live in
// the explorer package. API handlers and the RedactionEngine share the same types.
type VisibilityLevel = explorer.VisibilityLevel
type VisibilityReason = explorer.VisibilityReason
type AddressVisibility = explorer.AddressVisibility

// Re-export visibility constants so existing handler/test code compiles unchanged.
const (
	VisibilityFull         = explorer.VisibilityFull
	VisibilityPseudonymous = explorer.VisibilityPseudonymous
	VisibilityRedacted     = explorer.VisibilityRedacted
	VisibilityHidden       = explorer.VisibilityHidden

	ReasonOwnAddress      = explorer.ReasonOwnAddress
	ReasonDisclosureGrant = explorer.ReasonDisclosureGrant
	ReasonPublicAddress   = explorer.ReasonPublicAddress
	ReasonNoAccess        = explorer.ReasonNoAccess
	ReasonRBACGroupMember = explorer.ReasonRBACGroupMember
	ReasonVisibleToGrant  = explorer.ReasonVisibleToGrant
)

// transferParticipantUnionLimit caps the number of tx hashes that
// buildVisibilityFilter unions in from FindTransferParticipantTxs (RD-1009).
// Generous enough to cover the most-recent matches a tx feed would render,
// bounded enough to keep the join scan-safe on chains with millions of
// historical transfers. Tune via empirical query plans rather than guesswork.
const transferParticipantUnionLimit = 10000

// ResolveAddressResponse is returned when resolving an address_id.
// SECURITY: RealAddress is only populated for "full" disclosure level.
type ResolveAddressResponse struct {
	RealAddress     *string  `json:"real_address,omitempty"`
	DisclosureLevel string   `json:"disclosure_level"`
	GrantID         string   `json:"grant_id"`
	Pseudonym       string   `json:"pseudonym,omitempty"`     // For pseudonymous, the display name to use
	ScopeMethods    []string `json:"scope_methods,omitempty"` // Methods from grant scope (e.g. "transaction_history", "activity_logs")
}

// GrantTransactionsResponse is the response for GET /api/v1/explorer/grant/:grant_id/:address_id/transactions
type GrantTransactionsResponse struct {
	Transactions    []GrantTransaction `json:"transactions"`
	DisclosureLevel string             `json:"disclosure_level"`
	AddressLabels   map[string]string  `json:"address_labels"`
	HasMore         bool               `json:"has_more"`
}

// GrantTransaction represents a transaction in the context of a disclosure grant.
// For pseudonymous grants, addresses are replaced with pseudonyms and financial data is hidden.
type GrantTransaction struct {
	TxHash         *string `json:"tx_hash,omitempty"` // only for full disclosure
	BlockNumber    uint64  `json:"block_number"`
	BlockTimestamp uint64  `json:"block_timestamp,omitempty"`
	Direction      string  `json:"direction"` // "in", "out", "self"
	From           string  `json:"from"`
	To             string  `json:"to,omitempty"`
	Value          string  `json:"value"`
	GasUsed        uint64  `json:"gas_used"`
	Status         int     `json:"status"`
}

// registerExplorerRoutes registers the explorer API endpoints
// These endpoints are designed to be called by the explorer backend (internal).
// Network boundary: localhost-only. JWT: optional — if present it is validated and the
// viewer DID is extracted from it; if absent the request is treated as anonymous.
//
// Security measures:
// - G15: explorerLogRedactionMiddleware strips Ethereum addresses from logged request paths.
func (s *Server) registerExplorerRoutes(router *gin.Engine) {
	explorer := router.Group("/api/v1/explorer")
	explorer.Use(s.localhostOnlyMiddleware())
	explorer.Use(auth.OptionalJWTAuthMiddleware(s.jwtService, s.db))
	// G15: Redact Ethereum addresses from access log paths
	explorer.Use(explorerLogRedactionMiddleware())
	s.bindExplorerEndpoints(explorer)
}

// bindExplorerEndpoints attaches every explorer handler to the given route
// group. Factored out of registerExplorerRoutes so the impersonation surface
// (RD-928 / RD-994) can re-mount the same endpoint set under
// /api/v1/admin/impersonate/:target_did/in/:org_id/api/v1/explorer with a
// different middleware chain (tier-2 admin gate + viewer-DID override). Keep
// parametric-vs-specific ordering identical to the production tree to avoid
// Gin route-precedence surprises.
func (s *Server) bindExplorerEndpoints(rg *gin.RouterGroup) {
	rg.GET("/viewable-addresses", s.getViewableAddresses)

	// Resolve address_id to real address (for explorer backend internal use)
	rg.GET("/grant/:grant_id/resolve/:address_id", s.resolveAddressID)
	// Grant-scoped transactions for a disclosed address
	rg.GET("/grant/:grant_id/:address_id/transactions", s.getGrantTransactions)
	// Grant-scoped activity logs (user-facing, JWT required)
	rg.GET("/grant/:grant_id/activity", s.getGrantActivityLogs)

	// Data Retrieval Endpoints
	rg.GET("/chain-id", s.getExplorerChainID)
	rg.GET("/stats", s.getExplorerStats)
	rg.GET("/stats/tx-history", s.getExplorerTransactionHistory)

	// Blocks — register specific routes before parameterized ones
	rg.GET("/blocks", s.getExplorerBlocks)
	rg.GET("/blocks/latest/number", s.getExplorerLatestBlockNumber)
	rg.GET("/blocks/hash/:hash", s.getExplorerBlockByHash)
	rg.GET("/blocks/:number", s.getExplorerBlock)
	rg.GET("/blocks/:number/transactions", s.getExplorerBlockTransactions)
	rg.GET("/blocks/:number/internal", s.getExplorerBlockInternalTxs)

	// Transactions — register specific routes before parameterized ones
	rg.GET("/transactions/paginated", s.getExplorerTransactionsPaginated)
	rg.GET("/transactions", s.getExplorerTransactions)
	rg.GET("/transactions/:hash", s.getExplorerTransaction)
	rg.GET("/transactions/:hash/internal", s.getExplorerTransactionInternal)
	rg.GET("/transactions/:hash/transfers", s.getExplorerTransactionTransfers)
	rg.GET("/transactions/:hash/logs", s.getExplorerTransactionLogs)
	rg.GET("/transactions/:hash/op-deposit", s.getExplorerTransactionOPDeposit)

	// Addresses
	rg.GET("/addresses/:address/stats", s.getExplorerAddressStats)
	rg.GET("/addresses/:address/transactions", s.getExplorerAddressTransactions)
	rg.GET("/addresses/:address/balance", s.getExplorerAddressBalance)
	rg.GET("/addresses/:address/code", s.getExplorerAddressCode)
	rg.GET("/addresses/:address/balances", s.getExplorerAddressTokenBalances)
	rg.GET("/addresses/:address/transfers", s.getExplorerAddressTransfers)
	rg.GET("/addresses/:address/internal", s.getExplorerAddressInternal)
	rg.GET("/addresses/:address/logs", s.getExplorerAddressLogs)
	rg.GET("/addresses/:address/contract", s.getExplorerAddressContract)
	rg.GET("/addresses/:address/is-contract", s.getExplorerAddressIsContract)
	rg.POST("/addresses/:address/abi", s.updateExplorerAddressABI)

	// Logs
	rg.GET("/logs", s.getExplorerLogs)

	// Tokens
	rg.GET("/tokens", s.getExplorerTokens)
	rg.GET("/tokens/:address", s.getExplorerToken)
	rg.GET("/tokens/:address/holders", s.getExplorerTokenHolders)
	rg.GET("/tokens/:address/transfers", s.getExplorerTokenTransfers)

	// Transfers
	rg.GET("/transfers", s.getExplorerAllTransfers)

	// Accounts
	rg.GET("/accounts", s.getExplorerAccounts)

	// Search
	rg.GET("/search/suggestions", s.getExplorerSearchSuggestions)

	// Sync
	rg.GET("/sync/status", s.getExplorerSyncStatus)
	rg.GET("/sync/indexer-progress", s.getExplorerIndexerProgress)
	rg.GET("/sync/catchup", s.getExplorerCatchupProgress)

	// Indexing
	rg.POST("/index/block/:number", s.indexExplorerBlock)
}

// getViewableAddresses returns all addresses the wallet owner can view
// GET /api/v1/explorer/viewable-addresses?wallet=0x1234...&did=did:example:123
// Either wallet or did (or both) can be provided. If did is provided, it is used directly.
// If only wallet is provided, the DID is looked up from the wallet address.
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
	response := ViewableAddressesResponse{
		ViewerWallet:       wallet,
		OwnAddresses:       []OwnAddress{},
		DisclosedAddresses: []DisclosedAddress{},
	}

	var err error

	// If no DID from JWT, look up from wallet
	if viewerDID == "" && wallet != "" {
		viewerDID, err = s.db.GetDIDByEthAddress(ctx, wallet)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to look up DID",
				"explorer: GetDIDByEthAddress failed",
				"wallet", wallet, "err", err)
			return
		}
	}

	if viewerDID == "" {
		// Viewer is anonymous - no DID linked to this wallet
		// Return empty lists
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
		response.OwnAddresses = append(response.OwnAddresses, OwnAddress{
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
func (s *Server) getDisclosedAddressesForViewer(ctx context.Context, viewerDID string) ([]DisclosedAddress, error) {
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

	var result []DisclosedAddress

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

			disclosed := DisclosedAddress{
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
				disclosed.Address = explorer.GeneratePseudonym(addr.EthAddress)
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
	request := grantWithRequest.Request
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

	response := ResolveAddressResponse{
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
		response.Pseudonym = explorer.GeneratePseudonym(realAddress)
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

// getGrantTransactions returns transactions for a disclosed address, pseudonymized
// according to the grant's disclosure level.
// GET /api/v1/explorer/grant/:grant_id/:address_id/transactions
// SECURITY: This endpoint never exposes real addresses for non-full grants.
// The explorer backend receives pre-pseudonymized data and cannot reverse it.
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
	request := grantWithRequest.Request
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

	var beforeBlock *uint64
	if beforeStr := c.Query("before"); beforeStr != "" {
		if parsed, err := strconv.ParseUint(beforeStr, 10, 64); err == nil {
			beforeBlock = &parsed
		}
	}

	// Fetch one extra to detect has_more
	txs, err := s.explorerStore.GetTransactionsByAddress(c.Request.Context(), realAddress, limit+1, beforeBlock)
	if err != nil {
		respondInternalError(c, "failed to get transactions")
		return
	}

	hasMore := len(txs) > limit
	if hasMore {
		txs = txs[:limit]
	}

	realAddrLower := strings.ToLower(realAddress)
	labels := make(map[string]string)

	// Resolve viewer's own addresses so we can label them "mine" on the grant page
	viewerAddrs := make(map[string]bool)
	viewerDID := s.getViewerDIDFromRequest(c)
	if viewerDID != "" {
		linked, err := s.db.GetLinkedAddresses(c.Request.Context(), viewerDID)
		if err == nil {
			for _, a := range linked {
				viewerAddrs[strings.ToLower(a)] = true
			}
		}
	}

	var grantTxs []GrantTransaction
	for _, tx := range txs {
		gt := GrantTransaction{
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
			disclosedPseudonym := explorer.GeneratePseudonym(realAddress)
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
		grantTxs = []GrantTransaction{}
	}

	c.JSON(http.StatusOK, GrantTransactionsResponse{
		Transactions:    grantTxs,
		DisclosureLevel: disclosureLevel,
		AddressLabels:   labels,
		HasMore:         hasMore,
	})
}

// GrantActivityLogsResponse is the response for GET /api/v1/explorer/grant/:grant_id/activity
type GrantActivityLogsResponse struct {
	Logs   []GrantActivityLogEntry `json:"logs"`
	Total  int                     `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

// GrantActivityLogEntry is a stripped-down log entry safe for grant holders.
// SECURITY: Does NOT include request_params, ip_address, correlation_id, or entry_hash.
type GrantActivityLogEntry struct {
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"` // RFC 3339
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
	entries := make([]GrantActivityLogEntry, 0, len(logs))
	for _, log := range logs {
		entries = append(entries, GrantActivityLogEntry{
			Method:     log.Method,
			StatusCode: log.StatusCode,
			Timestamp:  log.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, GrantActivityLogsResponse{
		Logs:   entries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// getViewerIdentity was removed in RD-1028. It read the viewer DID only from
// "subject" and was blind to the impersonation viewer override
// (viewerDIDOverrideContextKey), so under View-as the single-item explorer
// handlers resolved the wrong viewer (the admin / anonymous, not the
// impersonated target) — wrong 404s, and a fail-open risk where the admin's
// broader access could bleed into the impersonated view. All explorer handlers
// now resolve the viewer via getViewerDIDFromRequest, which honours the
// override. The ?wallet= viewer path it carried was also a viewer-impersonation
// oracle and is gone with it.

// resolveViewerDID resolves the viewer's DID from an explicit DID or wallet address.
// Returns empty string if neither is provided or the wallet has no linked DID.
func (s *Server) resolveViewerDID(ctx context.Context, wallet, did string) string {
	if did != "" {
		return did
	}
	if wallet != "" {
		viewerDID, err := s.db.GetDIDByEthAddress(ctx, wallet)
		if err != nil {
			return ""
		}
		return viewerDID
	}
	return ""
}

// calculateAddressVisibility determines the visibility of a target address for a wallet-based viewer.
// Delegates to GetBatchVisibilityDetailed so the visibility decision is made by the same
// code path that the RedactionEngine uses (via GetBatchVisibility).
func (s *Server) calculateAddressVisibility(ctx context.Context, viewerWallet, targetAddress string) AddressVisibility {
	return s.calculateAddressVisibilityWithDID(ctx, viewerWallet, "", targetAddress)
}

// calculateAddressVisibilityWithDID determines the visibility of a single address.
// It delegates to GetBatchVisibilityDetailed (single-element batch) so that the
// visibility level decision matches the RedactionEngine's GetBatchVisibility.

// maskAsPublic returns a visibility response identical to a genuinely public
// (unregistered) address. This eliminates the 1-bit oracle: an attacker cannot
// distinguish "registered but hidden" from "not registered at all."
func maskAsPublic(address string) AddressVisibility {
	return AddressVisibility{
		Address: strings.ToLower(address),
		Visible: true,
		Level:   VisibilityFull,
		Reason:  ReasonPublicAddress,
	}
}

func (s *Server) calculateAddressVisibilityWithDID(ctx context.Context, viewerWallet, did, targetAddress string) AddressVisibility {
	viewerDID := s.resolveViewerDID(ctx, viewerWallet, did)
	results, err := s.db.GetBatchVisibilityDetailed(ctx, viewerDID, []string{targetAddress})
	if err != nil {
		return AddressVisibility{
			Address: strings.ToLower(targetAddress),
			Visible: false,
			Level:   VisibilityHidden,
			Reason:  ReasonNoAccess,
		}
	}
	if vis, ok := results[strings.ToLower(targetAddress)]; ok {
		return vis
	}
	return AddressVisibility{
		Address: strings.ToLower(targetAddress),
		Visible: false,
		Level:   VisibilityHidden,
		Reason:  ReasonNoAccess,
	}
}

// viewerHasFullDisclosureGrant checks if the authenticated viewer has an active
// full-disclosure grant on the target address. This is used by address-specific
// endpoints to allow full disclosure recipients to view address pages.
//
// NOTE: GetBatchVisibility now includes disclosure grants (G17 reverted), so this
// check is a secondary fallback for address-specific endpoints where the target
// address is already known from the URL path.
func (s *Server) viewerHasFullDisclosureGrant(ctx context.Context, viewerDID, targetAddress string) bool {
	if viewerDID == "" || targetAddress == "" {
		return false
	}
	has, err := s.db.ViewerHasFullDisclosureGrant(ctx, viewerDID, targetAddress)
	if err != nil {
		return false
	}
	return has
}

// addressVisibleOrFullGrant returns true if the address is visible via standard
// RBAC/ownership checks OR the viewer has a full disclosure grant on it.
// Used by address-specific endpoints (not transaction lists) to upgrade visibility.
func (s *Server) addressVisibleOrFullGrant(ctx context.Context, viewerDID, address string) bool {
	// RD-1028: no wallet parameter. Viewer identity is the resolved DID from
	// getViewerDIDFromRequest (which honours the impersonation override); the
	// removed ?wallet= path was a viewer-impersonation oracle.
	visibility := s.calculateAddressVisibilityWithDID(ctx, "", viewerDID, address)
	if visibility.Level != VisibilityHidden && visibility.Level != VisibilityRedacted {
		return true
	}
	// Fallback: check disclosure grants for the specific address the viewer
	// navigated to. GetBatchVisibility should already handle this, but this
	// ensures coverage for edge cases.
	return s.viewerHasFullDisclosureGrant(ctx, viewerDID, address)
}

// addDisclosureAddressToFilter returns a copy of the visibility filter with the
// disclosure address added to the visible set. This ensures that transaction
// counts and filtered queries include transactions involving the disclosed address.
//
// L4: pre-fix both the constructor (filter==nil) and copy paths dropped
// VisibleTxHashes — disclosed-address views silently suppressed the
// viewer's visibleTo-shared txs. Now both code paths preserve every
// VisibilityFilter field.
func (s *Server) addDisclosureAddressToFilter(filter *explorer.VisibilityFilter, address string) *explorer.VisibilityFilter {
	if filter == nil {
		return &explorer.VisibilityFilter{
			AllPrivate:       true,
			VisibleAddresses: []string{address},
		}
	}
	// Check if already present
	for _, addr := range filter.VisibleAddresses {
		if addr == address {
			return filter
		}
	}
	// Copy to avoid mutating the original — including VisibleTxHashes.
	newFilter := &explorer.VisibilityFilter{
		AllPrivate:          filter.AllPrivate,
		VisibleAddresses:    make([]string, len(filter.VisibleAddresses)+1),
		VisibleTxHashes:     append([]string(nil), filter.VisibleTxHashes...),
		ParticipantTxHashes: append([]string(nil), filter.ParticipantTxHashes...),
	}
	copy(newFilter.VisibleAddresses, filter.VisibleAddresses)
	newFilter.VisibleAddresses[len(filter.VisibleAddresses)] = address
	return newFilter
}

// redactOptsFromFilter builds RedactOpts from a VisibilityFilter, passing
// the visibleTo tx hashes so RedactTransactions doesn't drop them.
func redactOptsFromFilter(filter *explorer.VisibilityFilter) explorer.RedactOpts {
	if filter == nil || len(filter.VisibleTxHashes) == 0 {
		return explorer.RedactOpts{}
	}
	m := make(map[string]bool, len(filter.VisibleTxHashes))
	for _, h := range filter.VisibleTxHashes {
		m[strings.ToLower(h)] = true
	}
	// RD-1155: carry the label-only participant-union subset through so the
	// redactor can distinguish participation from a visibleTo share.
	var pm map[string]bool
	if len(filter.ParticipantTxHashes) > 0 {
		pm = make(map[string]bool, len(filter.ParticipantTxHashes))
		for _, h := range filter.ParticipantTxHashes {
			pm[strings.ToLower(h)] = true
		}
	}
	return explorer.RedactOpts{VisibleTxHashes: m, ParticipantTxHashes: pm}
}

// buildRedactOptsForViewer builds RedactOpts for single-item endpoints
// (getExplorerTransaction et al). Mirrors the list-path opts derivation
// (buildVisibilityFilter → redactOptsFromFilter) so the cross-redactor
// row-survival invariant from RD-1009 holds on by-hash surfaces too —
// without this, a tx whose tx.from / tx.to are both hidden but whose
// derived token-transfer rows have an admin-visible counterparty would
// 404 at GET /transactions/:hash while still appearing in /transfers and
// in the /transactions list. Closing the gap at this single helper
// applies the fix to every single-item handler that calls it (12 sites
// across explorer_api.go).
//
// Anonymous viewers (viewerDID == "") get the empty-opts early-return so
// we don't pay the buildVisibilityFilter DB work for callers that have
// no possible visibility anyway.
func (s *Server) buildRedactOptsForViewer(ctx context.Context, viewerDID string) explorer.RedactOpts {
	if viewerDID == "" {
		return explorer.RedactOpts{}
	}
	filter := s.buildVisibilityFilter(ctx, viewerDID)
	opts := redactOptsFromFilter(filter)
	opts.ViewerIsAdmin = s.isViewerAdmin(ctx, viewerDID)
	s.applyAdminTxView(&opts)
	return opts
}

// applyAdminTxView wires the deployment-wide ORG_ADMIN_VIEW_USER_TXS policy
// into RedactOpts and ensures a RedactStats is attached whenever any
// audit-relevant code path may fire. Keeping this in one place means every
// opts builder gets identical treatment.
//
// Two reveal classes require auditing:
//   - AdminUserTxsRevealed — only when the elevated org-admin audit view
//     is in effect (admin + ORG_ADMIN_VIEW_USER_TXS).
//   - GrantFullReveals — whenever a Full disclosure grant promotes a
//     counterparty's address above its base (regulatory subpoena reveal).
//     Independent of the admin flag — Full-grant holders are typically
//     auditors / regulators acting under a subpoena, not org admins.
//
// Both counters live on the same RedactStats so callers only thread one
// pointer through opts; auditAdminUserTxView and auditGrantFullReveal
// inspect their respective fields.
func (s *Server) applyAdminTxView(opts *explorer.RedactOpts) {
	opts.OrgAdminViewUserTxs = s.config.OrgAdminViewUserTxs
	if opts.Stats == nil {
		opts.Stats = &explorer.RedactStats{}
	}
}

// auditAdminUserTxView writes one rbac_audit_log entry when an elevated
// org-admin view actually revealed user↔user rows (stats.AdminUserTxsRevealed
// > 0). It is best-effort: a failed audit write is logged loudly but does not
// fail the read, matching the existing CreateAuditLog call sites. The entry
// records WHO (admin DID), WHAT (access), WHERE (endpoint label + target),
// HOW MANY rows, and the client IP — addresses are never logged here because
// the view itself never exposes them.
//
// This call sites also doubles as the audit-log hook for Full-grant
// counterparty reveals (stats.GrantFullReveals > 0). Two reveal classes,
// one Stats pointer threaded through every redactor — emit a separate
// audit entry for each class actually triggered.
func (s *Server) auditAdminUserTxView(c *gin.Context, viewerDID, endpoint, target string, stats *explorer.RedactStats) {
	if stats == nil {
		return
	}
	if stats.AdminUserTxsRevealed > 0 {
		entry := &rbac.AuditLogEntry{
			ActorExternalID: viewerDID,
			Action:          rbac.AuditActionAccess,
			ResourceType:    rbac.ResourceTypeExplorerUserTxs,
			ResourceName:    endpoint,
			NewValue: map[string]any{
				"endpoint":      endpoint,
				"target":        target,
				"rows_revealed": stats.AdminUserTxsRevealed,
				"elevated_by":   "ORG_ADMIN_VIEW_USER_TXS",
			},
			IPAddress: c.ClientIP(),
		}
		if target != "" {
			entry.ResourceID = &target
		}
		if err := s.db.CreateAuditLog(c.Request.Context(), entry); err != nil {
			slog.Error("failed to write admin-user-tx-view audit log",
				"viewer", viewerDID, "endpoint", endpoint, "error", err)
		}
	}
	s.auditGrantFullReveal(c, viewerDID, endpoint, target, stats)
}

// auditGrantFullReveal writes one rbac_audit_log entry per redactor pass
// where a Full disclosure grant promoted at least one counterparty's
// address from a private level (Hidden / Redacted / Pseudonymous) to Full.
// This is a regulatory-subpoena reveal: the viewer holds an approved
// Full-level grant and the redactor has just disclosed an otherwise-
// private counterparty's real address. The compliance trail captures
// WHO (viewer DID — the grant requester), WHERE (endpoint + target), HOW
// MANY counterparties were revealed, and the client IP.
//
// The address material itself is never logged — the audit row is a
// volume / locus signal, not a content record. Investigators chasing a
// specific reveal correlate via (actor, endpoint, target_tx_hash,
// timestamp) against the disclosure_grants table.
//
// Resource type is the disclosure-grant (not explorer_user_txs) so audit
// reviewers can pivot from a grant ID to every reveal it produced.
// ResourceName is the endpoint label; ResourceID is the target tx hash
// or address when single-item, empty for list surfaces.
//
// Best-effort, matching the other audit-log call sites: a write failure
// is logged loudly but does not fail the read.
func (s *Server) auditGrantFullReveal(c *gin.Context, viewerDID, endpoint, target string, stats *explorer.RedactStats) {
	if stats == nil || stats.GrantFullReveals == 0 {
		return
	}
	entry := &rbac.AuditLogEntry{
		ActorExternalID: viewerDID,
		Action:          rbac.AuditActionAccess,
		ResourceType:    rbac.ResourceTypeDisclosureGrant,
		ResourceName:    endpoint,
		NewValue: map[string]any{
			"endpoint":                endpoint,
			"target":                  target,
			"counterparties_revealed": stats.GrantFullReveals,
			"reveal_class":            "disclosure_grant_full_counterparty",
		},
		IPAddress: c.ClientIP(),
	}
	if target != "" {
		entry.ResourceID = &target
	}
	if err := s.db.CreateAuditLog(c.Request.Context(), entry); err != nil {
		slog.Error("failed to write grant-full-reveal audit log",
			"viewer", viewerDID, "endpoint", endpoint, "error", err)
	}
}

// isViewerAdmin checks if the viewer has admin-level access in any org.
// A viewer is considered admin if they have 'admin' in group_access.claims
// (HasAdminClaim) OR are a member of an is_org_admin group (IsOrgAdmin).
func (s *Server) isViewerAdmin(ctx context.Context, viewerDID string) bool {
	if viewerDID == "" {
		return false
	}
	user, err := s.db.GetUserByExternalID(ctx, viewerDID)
	if err != nil || user == nil {
		return false
	}
	isAdmin, err := s.db.HasAdminClaim(ctx, user.ID)
	if err != nil {
		return false
	}
	if isAdmin {
		return true
	}
	isOrgAdmin, _, err := s.db.IsOrgAdmin(ctx, user.ID)
	if err != nil {
		return false
	}
	return isOrgAdmin
}

func (s *Server) getExplorerChainID(c *gin.Context) {
	// Approximation: return 1 or get from proxy if needed
	c.JSON(http.StatusOK, gin.H{"chain_id": 1})
}

func (s *Server) getExplorerStats(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	stats, err := s.explorerStore.GetChainStatsFiltered(c.Request.Context(), filter)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get chain stats",
			"explorer: GetChainStatsFiltered failed",
			"viewer_did", viewerDID, "err", err)
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (s *Server) getExplorerBlocks(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}

	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)

	blocks, err := s.explorerStore.GetBlocksFiltered(c.Request.Context(), limit, beforeBlock, filter)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get blocks",
			"explorer: GetBlocksFiltered failed",
			"viewer_did", viewerDID, "limit", limit, "err", err)
		return
	}
	c.JSON(http.StatusOK, blocks)
}

func (s *Server) getExplorerBlock(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := strconv.ParseUint(c.Param("number"), 10, 64)
	if err != nil {
		respondBadRequest(c, "invalid block number")
		return
	}
	block, err := s.explorerStore.GetBlock(c.Request.Context(), num)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get block",
			"explorer: GetBlock failed",
			"block_number", num, "err", err)
		return
	}
	if block == nil {
		respondNotFound(c, "block not found")
		return
	}
	// Adjust TransactionCount to reflect only visible transactions
	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	if filter != nil {
		filteredCount, err := s.explorerStore.GetBlockTransactionCountFiltered(c.Request.Context(), num, filter)
		if err == nil {
			block.TransactionCount = filteredCount
		}
	}
	c.JSON(http.StatusOK, block)
}

func (s *Server) getExplorerBlockByHash(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	block, err := s.explorerStore.GetBlockByHash(c.Request.Context(), hash)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get block by hash",
			"explorer: GetBlockByHash failed",
			"hash", hash, "err", err)
		return
	}
	if block == nil {
		respondNotFound(c, "block not found")
		return
	}
	// Adjust TransactionCount to reflect only visible transactions
	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	if filter != nil {
		filteredCount, err := s.explorerStore.GetBlockTransactionCountFiltered(c.Request.Context(), block.Number, filter)
		if err == nil {
			block.TransactionCount = filteredCount
		}
	}
	c.JSON(http.StatusOK, block)
}

// getViewerDIDFromRequest extracts the viewer's DID.
// Priority: (1) impersonation override set by the admin/impersonate middleware
// (RD-928), (2) validated JWT claims set by OptionalJWTAuthMiddleware.
//
// The override is *only* writable by impersonationGateMiddleware, which runs
// after the tier-2 admin gate + same-org check + audit log row. By the time
// the override appears in the context, the request has been authorised and
// recorded — downstream handlers may treat it as ground truth.
//
// L3: the ?wallet=<addr> shortcut was a viewer-impersonation oracle —
// any unauthenticated caller who knew a wallet address could probe
// the explorer view of the wallet's owner. The caller never proves
// possession of the wallet. Now ?wallet= is honoured ONLY when the
// caller also has a valid JWT (subject set by OptionalJWTAuthMiddleware),
// in which case the JWT subject itself takes priority anyway. The
// shortcut therefore is effectively dead and the surface is closed.
//
// If a legitimate non-JWT consumer needs viewer-as-wallet resolution,
// they must sign a challenge — that is a future feature, not the
// silent oracle this used to be.
func (s *Server) getViewerDIDFromRequest(c *gin.Context) string {
	// 1. Impersonation override (RD-928). Only writable by the dedicated
	// middleware after tier-2 admin + same-org + audit. See
	// internal/server/impersonation.go.
	if override, exists := c.Get(viewerDIDOverrideContextKey); exists {
		if did, ok := override.(string); ok && did != "" {
			return did
		}
	}
	// 2. JWT claims (set by OptionalJWTAuthMiddleware)
	if subject, exists := c.Get("subject"); exists {
		if did, ok := subject.(string); ok && did != "" {
			return did
		}
	}
	// 3. Wallet lookup is intentionally removed — the previous
	// implementation allowed any caller to impersonate any wallet's
	// view without proof of possession.
	return ""
}

// buildVisibilityFilter resolves which addresses should be excluded from
// transaction queries at the SQL level. Only org-registered addresses and
// user EOAs can be hidden — unregistered addresses default to VisibilityFull (public).
func (s *Server) buildVisibilityFilter(ctx context.Context, viewerDID string) *explorer.VisibilityFilter {
	// All contracts are private by default — use allowlist mode.
	// Only addresses the viewer has VisibilityFull on are shown.

	// 1. Get all registered org contracts
	orgAddrs, err := s.db.GetAllRegisteredAddresses(ctx)
	if err != nil {
		orgAddrs = []string{}
	}

	// 2. Get all linked user EOAs
	userAddrs, err := s.db.GetAllLinkedEOAAddresses(ctx)
	if err != nil {
		userAddrs = []string{}
	}

	// Combine to get all known addresses
	allAddrs := append(orgAddrs, userAddrs...)

	// Even with no known addresses, we still need AllPrivate=true to hide
	// everything by default. With an empty visible list, no txs are shown.
	filter := &explorer.VisibilityFilter{
		AllPrivate: true,
	}

	if len(allAddrs) == 0 {
		return filter
	}

	visMap, err := s.db.GetBatchVisibility(ctx, viewerDID, allAddrs)
	if err != nil {
		return filter
	}

	// SQL-allowlist membership covers two row-survival paths:
	//   1. VisibilityFull addresses — the viewer can see the real address,
	//      so rows mentioning them MUST survive the allowlist.
	//   2. Disclosure-grant addresses at non-Full levels (Pseudonymous /
	//      Redacted) — the matrix in /docs/security/privacy-requirements
	//      §"Disclosure Levels" requires rows mentioning the granted party
	//      to surface in /transactions and /transfers (under the grant's
	//      lens). Field-level rendering still hides the actual addresses
	//      via applyRedaction; the SQL-level inclusion only affects which
	//      rows reach the redactor. Without this, a row whose tx.from is
	//      Bob@Pseudonymous and tx.to is a private contract would be
	//      pre-dropped by the allowlist before the redactor's grant lens
	//      could run — breaking the by-hash/list coherence invariant for
	//      grant-only viewers.
	//
	// The detailed lookup is required because we only want to include
	// grant-driven non-Full addresses, not RBAC-resolved ones (which can
	// never be Pseudonymous / Redacted in current resolution but we keep
	// the guard tight for future-proofing). visibilityRank order means
	// Full grants already register as VisibilityFull above and would
	// take this path too — the explicit grant lookup catches the
	// non-Full grant cells.
	visMapDetailed, _ := s.db.GetBatchVisibilityDetailed(ctx, viewerDID, allAddrs)

	visibleSet := make(map[string]bool, len(visMap))
	// fullVisible holds ONLY the addresses the viewer sees at Full. It drives
	// the transfer-participant union below (RD-1079); the pseudonymous/redacted
	// grant addresses are added to visibleSet for SQL address-survival but must
	// not drive a full-reveal union.
	fullVisible := make([]string, 0, len(visMap))
	for addr, level := range visMap {
		if level == explorer.VisibilityFull {
			visibleSet[addr] = true
			fullVisible = append(fullVisible, addr)
		}
	}
	for addr, meta := range visMapDetailed {
		if meta.Reason == explorer.ReasonDisclosureGrant &&
			(meta.Level == explorer.VisibilityPseudonymous ||
				meta.Level == explorer.VisibilityRedacted) {
			visibleSet[addr] = true
		}
	}
	visible := make([]string, 0, len(visibleSet))
	for addr := range visibleSet {
		visible = append(visible, addr)
	}
	filter.VisibleAddresses = visible

	// Add visibleTo tx hashes: txs shared with the viewer via the visibleTo param
	// should appear in regular explorer views.
	if viewerDID != "" {
		visibleTxHashes, err := s.db.GetVisibleTxHashesForDID(ctx, viewerDID)
		if err == nil && len(visibleTxHashes) > 0 {
			filter.VisibleTxHashes = visibleTxHashes
		}
	}

	// RD-1009: union in tx hashes whose token-transfer participants the viewer
	// can see. Without this the SQL filter drops a tx whose tx.from / tx.to are
	// both hidden (typically an EOA wallet + a private token contract) even
	// when one of its derived token-transfer rows has a visible counterparty —
	// so /transfers surfaces the transfer (and its parent tx_hash via
	// TokenTransfer.TxHash) but /transactions is missing the row. Unioning the
	// hash into VisibleTxHashes closes the asymmetry at the SQL filter and (via
	// redactOptsFromFilter) keeps the redactor's bothHidden branch from dropping
	// the row across the list / by-hash / internal / logs surfaces.
	//
	// RD-1079: drive the union ONLY with addresses the viewer sees at FULL
	// (`fullVisible`), NOT the pseudonymous/redacted disclosure-grant addresses
	// that were also added to `visible` for SQL address-survival. VisibleTxHashes
	// is a full-identity-reveal override in the redactor (it promotes both tx
	// addresses to Full), so driving it from a *pseudonymous* grant subject would
	// reveal that subject's counterparty's real address on every tx where the
	// subject is a transfer participant — defeating the "graph without identity"
	// guarantee of a pseudonymous disclosure. A Full-level viewer (admin, or a
	// full disclosure grant) IS entitled to see counterparties, so the RD-1009
	// coherence fix still applies to them. The cost for a pseudonymous/redacted-
	// grant viewer: the subject's transfer still shows in /transfers
	// (pseudonymised by the redactor's counterparty lens), but the parent tx
	// does not surface in /transactions — a row-coherence gap that is strictly
	// more private than the leak it replaces.
	//
	// Bounded scan: capped at transferParticipantUnionLimit to keep the join
	// O(window) rather than O(full table).
	if len(fullVisible) > 0 {
		transferTxs, err := s.explorerStore.FindTransferParticipantTxs(
			ctx, fullVisible, nil /* beforeBlock */, transferParticipantUnionLimit)
		if err == nil && len(transferTxs) > 0 {
			// Dedup against any hashes the visibleTo lookup already added.
			existing := make(map[string]bool, len(filter.VisibleTxHashes))
			for _, h := range filter.VisibleTxHashes {
				existing[strings.ToLower(h)] = true
			}
			for h := range transferTxs {
				if !existing[h] {
					filter.VisibleTxHashes = append(filter.VisibleTxHashes, h)
					// RD-1155: track the participant-union hashes separately so
					// the redactor labels these reveals "Counterparty" rather than
					// "Shared". Label-only — VisibleTxHashes still drives survival
					// and SQL filtering exactly as before.
					filter.ParticipantTxHashes = append(filter.ParticipantTxHashes, h)
					existing[h] = true
				}
			}
		}
	}

	return filter
}

func (s *Server) getExplorerTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}
	withCategories := c.Query("with_categories") == "true"
	viewerDID := s.getViewerDIDFromRequest(c)

	// Build SQL-level visibility filter to exclude transactions where both
	// participants (or the deployer for contract creations) are hidden.
	// This replaces the previous fetch-redact loop with a single query.
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)

	var txs []explorer.Transaction
	var err error
	if withCategories {
		txs, err = s.explorerStore.GetTransactionsWithCategoriesFiltered(c.Request.Context(), limit, beforeBlock, filter)
	} else {
		txs, err = s.explorerStore.GetTransactionsFiltered(c.Request.Context(), limit, beforeBlock, filter)
	}
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transactions",
			"explorer: GetTransactions(WithCategories)Filtered failed",
			"viewer_did", viewerDID, "limit", limit, "with_categories", withCategories, "err", err)
		return
	}

	// Field-level redaction still needed (replacing addresses with [PRIVATE],
	// stripping values, etc.) — the SQL filter only drops entire rows.
	opts := redactOptsFromFilter(filter)
	opts.ViewerIsAdmin = s.isViewerAdmin(c.Request.Context(), viewerDID)
	s.applyAdminTxView(&opts)
	redacted, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "transactions", "", opts.Stats)

	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransaction(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	withCategories := c.Query("with_categories") == "true"
	var tx *explorer.Transaction
	var err error
	if withCategories {
		tx, err = s.explorerStore.GetTransactionWithCategories(c.Request.Context(), hash)
	} else {
		tx, err = s.explorerStore.GetTransaction(c.Request.Context(), hash)
	}
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transaction",
			"explorer: GetTransaction(WithCategories) failed",
			"hash", hash, "with_categories", withCategories, "err", err)
		return
	}
	if tx == nil {
		respondNotFound(c, "transaction not found")
		return
	}

	viewerDID := s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redactedTxs, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), []explorer.Transaction{*tx}, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "transaction", hash, opts.Stats)
	if len(redactedTxs) == 0 {
		// Transaction was completely hidden
		respondNotFound(c, "transaction not found")
		return
	}

	c.JSON(http.StatusOK, redactedTxs[0])
}

// countAcrossPages pages through an item feed and sums a per-page count over
// the DISTINCT items, bounded by maxScan. It exists because privacy/gRPC mode
// clamps each indexer fetch to a small max page size (~100), so a single fetch
// cannot count an active address's transactions.
//
// fetch(before) returns the page older than the given block cursor (nil = newest
// first); cursorOf extracts an item's block; keyOf returns a stable per-item
// identity; perPageCount counts the countable items in a page (e.g. redaction
// survivors). Dedup by identity keeps the count correct even when the backend
// ignores `before` and re-serves or reorders rows (the gRPC indexer maps
// `before` to an inclusive block-range bound and does not guarantee order):
// already-seen rows are dropped, and the cursor advances by the page minimum, so
// a non-paginating backend under-reports rather than double-counts. It stops at
// an empty page, when a page yields no new items, at genesis, or at maxScan.
func countAcrossPages[T any](
	fetch func(before *uint64) ([]T, error),
	cursorOf func(T) uint64,
	keyOf func(T) string,
	perPageCount func([]T) (int, error),
	maxScan int,
) (int, error) {
	count, scanned := 0, 0
	seen := make(map[string]struct{})
	var before *uint64
	for scanned < maxScan {
		page, err := fetch(before)
		if err != nil {
			return 0, err
		}
		if len(page) == 0 {
			break
		}
		fresh := make([]T, 0, len(page))
		var minCursor uint64
		for i, item := range page {
			if c := cursorOf(item); i == 0 || c < minCursor {
				minCursor = c
			}
			if _, dup := seen[keyOf(item)]; dup {
				continue
			}
			seen[keyOf(item)] = struct{}{}
			fresh = append(fresh, item)
		}
		if len(fresh) == 0 {
			break
		}
		scanned += len(fresh)
		n, err := perPageCount(fresh)
		if err != nil {
			return 0, err
		}
		count += n
		if minCursor == 0 {
			break
		}
		bb := minCursor
		before = &bb
	}
	return count, nil
}

// countVisibleAddressTxs returns a stable, visibility-aware, post-redaction
// transaction count for an address. It pages through the address's txs and sums
// redaction survivors, so it is NOT capped at a single indexer page (privacy/
// gRPC mode clamps page size to ~100). Bounded by maxScan to keep the cost
// finite for very active addresses; opts is reused across pages so opts.Stats
// accumulates the full-view redaction stats for the audit log.
func (s *Server) countVisibleAddressTxs(ctx context.Context, address, viewerDID string, opts explorer.RedactOpts) (int, error) {
	const (
		perPage = 1000  // SQL honors this fully; the gRPC backend clamps to the indexer max (~100)
		maxScan = 10000 // safety bound (matches the prior single-fetch cap)
	)
	return countAcrossPages(
		func(before *uint64) ([]explorer.Transaction, error) {
			return s.explorerStore.GetTransactionsByAddress(ctx, address, perPage, before)
		},
		func(t explorer.Transaction) uint64 { return t.BlockNumber },
		func(t explorer.Transaction) string { return t.Hash },
		func(page []explorer.Transaction) (int, error) {
			redacted, err := s.explorerRedactor.RedactTransactions(ctx, page, viewerDID, opts)
			if err != nil {
				return 0, err
			}
			return len(redacted), nil
		},
		maxScan,
	)
}

// countAcrossOffsetPages sums redaction survivors across an offset-paginated
// dataset — for stores that expose (limit, offset) rather than the cursor
// model countAcrossPages handles. Bounded by maxScan so the cost stays finite
// for very active addresses/tokens; beyond maxScan the count under-reports,
// which is safe (it never over-reports rows the viewer cannot see).
//
// keyOf returns a stable per-row identity for the re-serve guard: if a page's
// head row repeats, the backend ignored `offset` and re-served an earlier page
// (the gRPC GetTransfersByToken / GetInternalTransactionsByAddress feeds do
// exactly this — they send only PageSize). We stop before counting the repeat,
// so a non-paginating backend under-reports rather than over-reports — the same
// guarantee countAcrossPages enforces with its cursor check.
func countAcrossOffsetPages[T any](
	fetch func(offset int) ([]T, error),
	perPageCount func([]T) (int, error),
	keyOf func(T) string,
	pageSize int,
	maxScan int,
) (int, error) {
	count, offset := 0, 0
	var prevHead string
	haveHead := false
	for offset < maxScan {
		page, err := fetch(offset)
		if err != nil {
			return 0, err
		}
		if len(page) == 0 {
			break
		}
		// Re-serve guard: an unchanged head row means the backend ignored offset
		// and re-served a counted page — stop before double-counting.
		head := keyOf(page[0])
		if haveHead && head == prevHead {
			break
		}
		prevHead, haveHead = head, true
		n, err := perPageCount(page)
		if err != nil {
			return 0, err
		}
		count += n
		if len(page) < pageSize {
			break // last page
		}
		offset += len(page)
	}
	return count, nil
}

// countVisibleAddressTransfers returns the visibility-aware, post-redaction
// token-transfer count for an address (RD-1154), mirroring
// countVisibleAddressTxs over the token_transfers feed (cursor-paginated).
func (s *Server) countVisibleAddressTransfers(ctx context.Context, address, viewerDID string, opts explorer.RedactOpts) (int, error) {
	const (
		perPage = 1000
		maxScan = 10000
	)
	return countAcrossPages(
		func(before *uint64) ([]explorer.TokenTransfer, error) {
			return s.explorerStore.GetTransfersByAddress(ctx, address, perPage, before)
		},
		func(t explorer.TokenTransfer) uint64 { return t.BlockNumber },
		func(t explorer.TokenTransfer) string { return t.TxHash + ":" + strconv.Itoa(t.LogIndex) },
		func(page []explorer.TokenTransfer) (int, error) {
			redacted, err := s.explorerRedactor.RedactTransfers(ctx, page, viewerDID, opts)
			if err != nil {
				return 0, err
			}
			return len(redacted), nil
		},
		maxScan,
	)
}

// countVisibleAddressInternalTxs returns the visibility-aware, post-redaction
// internal-tx count for an address (RD-1154). GetInternalTransactionsByAddress
// is offset-paginated, so it uses countAcrossOffsetPages.
func (s *Server) countVisibleAddressInternalTxs(ctx context.Context, address, viewerDID string, opts explorer.RedactOpts) (int, error) {
	const (
		perPage = 1000
		maxScan = 10000
	)
	return countAcrossOffsetPages(
		func(offset int) ([]explorer.InternalTransaction, error) {
			itxs, _, err := s.explorerStore.GetInternalTransactionsByAddress(ctx, address, perPage, offset)
			return itxs, err
		},
		func(page []explorer.InternalTransaction) (int, error) {
			redacted, err := s.explorerRedactor.RedactInternalTransactions(ctx, page, viewerDID, opts)
			if err != nil {
				return 0, err
			}
			return len(redacted), nil
		},
		func(t explorer.InternalTransaction) string { return strconv.FormatInt(t.ID, 10) },
		perPage,
		maxScan,
	)
}

// countVisibleTokenTransfers returns the visibility-aware, post-redaction
// transfer count for a token contract (RD-1154) — the token page's "Transfers"
// badge. GetTransfersByToken is offset-paginated.
func (s *Server) countVisibleTokenTransfers(ctx context.Context, tokenAddress, viewerDID string, opts explorer.RedactOpts) (int, error) {
	const (
		perPage = 1000
		maxScan = 10000
	)
	return countAcrossOffsetPages(
		func(offset int) ([]explorer.TokenTransfer, error) {
			transfers, _, err := s.explorerStore.GetTransfersByToken(ctx, tokenAddress, perPage, offset)
			return transfers, err
		},
		func(page []explorer.TokenTransfer) (int, error) {
			redacted, err := s.explorerRedactor.RedactTransfers(ctx, page, viewerDID, opts)
			if err != nil {
				return 0, err
			}
			return len(redacted), nil
		},
		func(t explorer.TokenTransfer) string { return strconv.FormatInt(t.ID, 10) },
		perPage,
		maxScan,
	)
}

// countVisibleTokenHolders returns the visibility-aware, post-redaction holder
// count for a token contract (RD-1154) — the token page's "Holders" badge.
// RedactTokenHolders drops holders whose address is Hidden to the viewer.
func (s *Server) countVisibleTokenHolders(ctx context.Context, tokenAddress, viewerDID string) (int, error) {
	const (
		perPage = 1000
		maxScan = 10000
	)
	return countAcrossOffsetPages(
		func(offset int) ([]explorer.TokenHolder, error) {
			holders, _, err := s.explorerStore.GetTokenHolders(ctx, tokenAddress, perPage, offset)
			return holders, err
		},
		func(page []explorer.TokenHolder) (int, error) {
			redacted, err := s.explorerRedactor.RedactTokenHolders(ctx, page, viewerDID)
			if err != nil {
				return 0, err
			}
			return len(redacted), nil
		},
		func(h explorer.TokenHolder) string { return h.Address },
		perPage,
		maxScan,
	)
}

// visibleCountOrZero returns a per-viewer, visibility-aware count, failing SAFE:
// on error it logs loudly and returns 0 — never the raw pre-computed aggregate.
// RD-758/RD-1154: a count-computation error must not fall through to the
// unfiltered total, which would leak how many rows the viewer cannot see. 0 is
// the safe floor — it can never over-report hidden rows — and keeps the stats
// page functional if a derived-table query fails transiently.
func visibleCountOrZero(count int, err error, surface, address string) int {
	if err != nil {
		slog.Error("explorer: visibility-aware count failed; badge falls back to 0 (never the raw aggregate)",
			"surface", surface, "address", address, "err", err)
		return 0
	}
	return count
}

func (s *Server) getExplorerAddressStats(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := c.Param("address")

	// Pre-authorization check: Can they see this address via RBAC or full disclosure grant?
	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found") // Masking forbidden as not found to avoid info leaks
		return
	}

	stats, err := s.explorerStore.GetAddressStats(c.Request.Context(), address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get address stats",
			"explorer: GetAddressStats failed",
			"address", address, "err", err)
		return
	}

	// RD-1154 / G22: the pre-computed address_stats aggregate counts (TxCount,
	// TokenTransferCount, InternalTxCount) are RAW — they ignore the viewer's
	// visibility, so a restricted viewer would see totals larger than the rows
	// they can actually load, leaking how many rows are hidden from them
	// (count-disclosure — RD-758). Recompute all three live by paging the
	// underlying rows through the SAME redactor + opts the list endpoints use
	// and summing survivors, so every badge matches the visible rows. Paging —
	// rather than one fetch — is required because in privacy/gRPC mode the
	// indexer clamps page size to ~100. A shared opts accumulates full-view
	// stats across the three passes for one audit entry. visibleCountOrZero
	// fails SAFE: a counting error yields 0, never the raw aggregate.
	resolvedDID := viewerDID
	opts := s.buildRedactOptsForViewer(c.Request.Context(), resolvedDID)

	txCount, txErr := s.countVisibleAddressTxs(c.Request.Context(), address, resolvedDID, opts)
	stats.TxCount = visibleCountOrZero(txCount, txErr, "transactions", address)

	transferCount, trErr := s.countVisibleAddressTransfers(c.Request.Context(), address, resolvedDID, opts)
	stats.TokenTransferCount = visibleCountOrZero(transferCount, trErr, "token_transfers", address)

	internalCount, inErr := s.countVisibleAddressInternalTxs(c.Request.Context(), address, resolvedDID, opts)
	stats.InternalTxCount = visibleCountOrZero(internalCount, inErr, "internal_transactions", address)

	s.auditAdminUserTxView(c, resolvedDID, "address_stats", address, opts.Stats)

	c.JSON(http.StatusOK, stats)
}

func (s *Server) getExplorerAddressTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := c.Param("address")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}

	// Pre-authorization check: Can they see this address via RBAC or full disclosure grant?
	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found") // Masking forbidden as not found
		return
	}

	txs, err := s.explorerStore.GetTransactionsByAddress(c.Request.Context(), address, limit, beforeBlock)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transactions by address",
			"explorer: GetTransactionsByAddress failed",
			"address", address, "limit", limit, "err", err)
		return
	}

	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redactedTxs, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "address_transactions", address, opts.Stats)

	c.JSON(http.StatusOK, redactedTxs)
}

func (s *Server) getExplorerSyncStatus(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	status, err := s.explorerStore.GetSyncStatus(c.Request.Context())
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get sync status",
			"explorer: GetSyncStatus failed",
			"err", err)
		return
	}
	c.JSON(http.StatusOK, status)
}

func (s *Server) indexExplorerBlock(c *gin.Context) {
	// Proxy to indexer or return not implemented for now
	respondInternalError(c, "manual indexing through proxy not yet implemented")
}

// --- Block sub-endpoints ---

func (s *Server) getExplorerBlockTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := strconv.ParseUint(c.Param("number"), 10, 64)
	if err != nil {
		respondBadRequest(c, "invalid block number")
		return
	}
	txs, err := s.explorerStore.GetTransactionsByBlock(c.Request.Context(), num)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get block transactions",
			"explorer: GetTransactionsByBlock failed",
			"block_number", num, "err", err)
		return
	}
	if txs == nil {
		txs = []explorer.Transaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "block_transactions", c.Param("number"), opts.Stats)
	if redacted == nil {
		redacted = []explorer.Transaction{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerBlockInternalTxs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := strconv.ParseUint(c.Param("number"), 10, 64)
	if err != nil {
		respondBadRequest(c, "invalid block number")
		return
	}
	itxs, err := s.explorerStore.GetInternalTransactionsByBlock(c.Request.Context(), num)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get block internal transactions",
			"explorer: GetInternalTransactionsByBlock failed",
			"block_number", num, "err", err)
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "block_internal_txs", c.Param("number"), opts.Stats)
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerLatestBlockNumber(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := s.explorerStore.GetLatestBlockNumber(c.Request.Context())
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get latest block number",
			"explorer: GetLatestBlockNumber failed",
			"err", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"number": num})
}

// --- Transaction sub-endpoints ---

func (s *Server) getExplorerTransactionsPaginated(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	page := 1
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 25
	if ps := c.Query("pageSize"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	withCategories := c.Query("with_categories") == "true"
	viewerDID := s.getViewerDIDFromRequest(c)

	// Build SQL-level visibility filter
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)

	var txs []explorer.Transaction
	var total int64
	var err error
	if withCategories {
		txs, total, err = s.explorerStore.GetTransactionsPaginatedWithCategoriesFiltered(c.Request.Context(), page, pageSize, filter)
	} else {
		txs, total, err = s.explorerStore.GetTransactionsPaginatedFiltered(c.Request.Context(), page, pageSize, filter)
	}
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transactions",
			"explorer: GetTransactionsPaginated(WithCategories)Filtered failed",
			"viewer_did", viewerDID, "page", page, "page_size", pageSize, "with_categories", withCategories, "err", err)
		return
	}
	if txs == nil {
		txs = []explorer.Transaction{}
	}

	// Field-level redaction still needed for address masking and value stripping.
	pOpts := redactOptsFromFilter(filter)
	pOpts.ViewerIsAdmin = s.isViewerAdmin(c.Request.Context(), viewerDID)
	s.applyAdminTxView(&pOpts)
	redacted, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID, pOpts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "transactions_paginated", "", pOpts.Stats)
	if redacted == nil {
		redacted = []explorer.Transaction{}
	}

	// NOTE: total comes from SQL count which doesn't account for G10 post-query
	// drops. This is a known pagination limitation — the total may slightly
	// overcount. Fixing this requires loading all pages which is too expensive.
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

func (s *Server) getExplorerTransactionInternal(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	itxs, err := s.explorerStore.GetInternalTransactionsByTx(c.Request.Context(), hash)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get internal transactions",
			"explorer: GetInternalTransactionsByTx failed",
			"hash", hash, "err", err)
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)

	// RD-1122: thread the parent tx's from/to so the viewer's direct
	// counterparty (already shown at the tx/Overview level) isn't over-redacted
	// in nested trace frames. Mirrors getExplorerTransactionLogs' participant
	// override. The redaction engine reveals these addresses per-side and only
	// to a viewer who is themselves a parent participant, so deeper foreign-org
	// frames stay redacted.
	if parentTx, perr := s.explorerStore.GetTransaction(c.Request.Context(), hash); perr == nil && parentTx != nil {
		opts.ParentParticipants = append(opts.ParentParticipants, parentTx.From)
		if parentTx.To != nil {
			opts.ParentParticipants = append(opts.ParentParticipants, *parentTx.To)
		}
	}

	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "transaction_internal", hash, opts.Stats)
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransactionTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	transfers, err := s.explorerStore.GetTransfersByTransaction(c.Request.Context(), hash)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transfers",
			"explorer: GetTransfersByTransaction failed",
			"hash", hash, "err", err)
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "transaction_transfers", hash, opts.Stats)
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransactionLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	logs, err := s.explorerStore.GetLogsByTransaction(c.Request.Context(), hash)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transaction logs",
			"explorer: GetLogsByTransaction failed",
			"hash", hash, "err", err)
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)

	// Fetch parent tx to get from/to for participant override.
	// If the viewer is the sender/receiver, they should see the logs.
	var participantAddrs []string
	if parentTx, err := s.explorerStore.GetTransaction(c.Request.Context(), hash); err == nil && parentTx != nil {
		participantAddrs = append(participantAddrs, parentTx.From)
		if parentTx.To != nil {
			participantAddrs = append(participantAddrs, *parentTx.To)
		}
	}

	logOpts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactLogsWithOpts(c.Request.Context(), logs, viewerDID, &logOpts, participantAddrs...)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransactionOPDeposit(c *gin.Context) {
	// This is not an OP Stack chain — always return 404
	respondNotFound(c, "OP deposit not found (not an OP Stack chain)")
}

// --- Address sub-endpoints ---

func (s *Server) getExplorerAddressBalance(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	// Forward eth_getBalance to the node via JSON-RPC
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getBalance",
		Params:  []interface{}{address, "latest"},
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)
	respBody, _, err := s.proxy.Forward(reqBody)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get balance",
			"explorer: eth_getBalance forward failed",
			"address", address, "err", err)
		return
	}

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		respondInternalError(c, "failed to parse balance response")
		return
	}

	c.JSON(http.StatusOK, rpcResp.Result)
}

func (s *Server) getExplorerAddressCode(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getCode",
		Params:  []interface{}{address, "latest"},
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)
	respBody, _, err := s.proxy.Forward(reqBody)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get code",
			"explorer: eth_getCode forward failed",
			"address", address, "err", err)
		return
	}

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		respondInternalError(c, "failed to parse code response")
		return
	}

	// Return as raw bytes (hex-encoded string)
	codeBytes := []byte(rpcResp.Result)
	c.JSON(http.StatusOK, codeBytes)
}

func (s *Server) getExplorerAddressTokenBalances(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	balances, err := s.explorerStore.GetTokenBalances(c.Request.Context(), address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get token balances",
			"explorer: GetTokenBalances failed",
			"address", address, "err", err)
		return
	}
	if balances == nil {
		balances = []explorer.Balance{}
	}

	// Filter out balances whose token contract is restricted for this viewer.
	// A private org token contract must not appear in balance lists for non-members.
	if len(balances) > 0 {
		viewerDID := s.getViewerDIDFromRequest(c)
		tokenAddrs := make([]string, len(balances))
		for i, b := range balances {
			tokenAddrs[i] = strings.ToLower(b.TokenAddress)
		}
		visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, tokenAddrs)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to filter token balances",
				"explorer: GetBatchVisibility (token balances) failed",
				"address", address, "viewer_did", viewerDID, "err", err)
			return
		}
		filtered := balances[:0]
		for _, b := range balances {
			level := visMap[strings.ToLower(b.TokenAddress)]
			switch level {
			case explorer.VisibilityFull:
				filtered = append(filtered, b)
			case explorer.VisibilityPseudonymous:
				b.TokenAddress = explorer.GeneratePseudonym(b.TokenAddress)
				filtered = append(filtered, b)
				// VisibilityHidden, VisibilityRedacted: drop this balance entry
			}
		}
		balances = filtered
	}

	c.JSON(http.StatusOK, balances)
}

func (s *Server) getExplorerAddressTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}

	transfers, err := s.explorerStore.GetTransfersByAddress(c.Request.Context(), address, limit, beforeBlock)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get address transfers",
			"explorer: GetTransfersByAddress failed",
			"address", address, "limit", limit, "err", err)
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID = s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "address_transfers", address, opts.Stats)
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerAddressInternal(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	itxs, _, err := s.explorerStore.GetInternalTransactionsByAddress(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get internal transactions",
			"explorer: GetInternalTransactionsByAddress failed",
			"address", address, "limit", limit, "offset", offset, "err", err)
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID = s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "address_internal", address, opts.Stats)
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

func (s *Server) getExplorerAddressLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	logs, _, err := s.explorerStore.GetLogsByAddress(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get address logs",
			"explorer: GetLogsByAddress failed",
			"address", address, "limit", limit, "offset", offset, "err", err)
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID = s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

func (s *Server) getExplorerAddressContract(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	contract, err := s.explorerStore.GetContract(c.Request.Context(), address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get contract",
			"explorer: GetContract failed",
			"address", address, "err", err)
		return
	}
	if contract == nil {
		respondNotFound(c, "contract not found")
		return
	}
	// Redact the creator address - it may belong to a private user
	if contract.Creator != "" {
		viewerDID := s.getViewerDIDFromRequest(c)
		redactedCreator, err := s.explorerRedactor.RedactAddress(c.Request.Context(), contract.Creator, viewerDID)
		if err == nil {
			contract.Creator = redactedCreator
		}
	}
	c.JSON(http.StatusOK, contract)
}

func (s *Server) getExplorerAddressIsContract(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	isContract, err := s.explorerStore.IsContract(c.Request.Context(), address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to check is_contract",
			"explorer: IsContract failed",
			"address", address, "err", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_contract": isContract})
}

func (s *Server) updateExplorerAddressABI(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Require full visibility: only org members (or public contracts) may update ABI.
	// This prevents unauthorized writes to private org contracts.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), "", viewerDID, address)
	if visibility.Level != VisibilityFull {
		respondNotFound(c, "address not found")
		return
	}

	var body json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"explorer: updateExplorerAddressABI invalid body",
			"address", address, "err", err)
		return
	}

	if err := s.explorerStore.SetContractABI(c.Request.Context(), address, body); err != nil {
		respondInternalErrorAndLog(c, "failed to set contract ABI",
			"explorer: SetContractABI failed",
			"address", address, "err", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "address": address})
}

// --- Logs ---

func (s *Server) getExplorerLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	var address, topic0 *string
	var fromBlock, toBlock *uint64

	if a := c.Query("address"); a != "" {
		lower := strings.ToLower(a)
		address = &lower
	}
	if t := c.Query("topic0"); t != "" {
		topic0 = &t
	}
	if fb := c.Query("from"); fb != "" {
		if v, err := strconv.ParseUint(fb, 10, 64); err == nil {
			fromBlock = &v
		}
	}
	if tb := c.Query("to"); tb != "" {
		if v, err := strconv.ParseUint(tb, 10, 64); err == nil {
			toBlock = &v
		}
	}

	limit := 100
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	logs, err := s.explorerStore.GetLogs(c.Request.Context(), address, topic0, fromBlock, toBlock, limit)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get logs",
			"explorer: GetLogs failed",
			"address", address, "topic0", topic0, "from_block", fromBlock, "to_block", toBlock, "limit", limit, "err", err)
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	c.JSON(http.StatusOK, redacted)
}

// --- Tokens ---

func (s *Server) getExplorerTokens(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	tokenType := c.Query("type")

	tokens, _, err := s.explorerStore.GetTokens(c.Request.Context(), limit, offset, tokenType)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get tokens",
			"explorer: GetTokens failed",
			"limit", limit, "offset", offset, "token_type", tokenType, "err", err)
		return
	}
	if tokens == nil {
		tokens = []explorer.Token{}
	}

	// Apply visibility filtering: collect token addresses, check visibility,
	// then drop Hidden tokens and redact Redacted/Pseudonymous tokens.
	if len(tokens) > 0 {
		viewerDID := s.getViewerDIDFromRequest(c)
		tokenAddrs := make([]string, len(tokens))
		for i, t := range tokens {
			tokenAddrs[i] = strings.ToLower(t.Address)
		}
		visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, tokenAddrs)
		if err != nil {
			respondInternalErrorAndLog(c, "visibility check failed",
				"explorer: GetBatchVisibility (token list) failed",
				"viewer_did", viewerDID, "err", err)
			return
		}

		var filtered []explorer.Token
		for _, t := range tokens {
			level := visMap[strings.ToLower(t.Address)]
			switch level {
			case explorer.VisibilityHidden:
				// Drop entirely — token must not appear in the list.
				continue
			case explorer.VisibilityRedacted:
				t.Address = "[PRIVATE]"
				t.Name = nil
				t.Symbol = ""
				t.TotalSupply = nil
				t.HolderCount = 0
				t.TransferCount = 0
				t.CreationTx = nil
				t.L1Address = nil
				t.USDPrice = nil
				t.IconURL = nil
			case explorer.VisibilityPseudonymous:
				pseudonym := explorer.GeneratePseudonym(t.Address)
				t.Address = pseudonym
				t.Name = nil
				t.Symbol = ""
				t.TotalSupply = nil
				t.HolderCount = 0
				t.TransferCount = 0
				t.CreationTx = nil
				t.L1Address = nil
				t.USDPrice = nil
				t.IconURL = nil
				// VisibilityFull or unrecognized: return as-is
			}
			filtered = append(filtered, t)
		}
		if filtered == nil {
			filtered = []explorer.Token{}
		}
		// Never expose raw DB total — return filtered count only.
		c.JSON(http.StatusOK, gin.H{"data": filtered, "total": len(filtered)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": tokens, "total": len(tokens)})
}

func (s *Server) getExplorerToken(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check: if the token address is Hidden OR Redacted,
	// pretend it doesn't exist.
	//
	// M12: pre-fix, Hidden → 404 and Redacted → 200-with-masked-fields.
	// The 200-vs-404 split was an enumeration oracle: it told an
	// attacker whether an arbitrary address was registered to *some*
	// org. Same class as the G16 fix for /check-address/. Now both
	// non-Full visibilities return the same 404.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), "", viewerDID, address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "token not found")
		return
	}

	token, err := s.explorerStore.GetToken(c.Request.Context(), address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get token",
			"explorer: GetToken failed",
			"address", address, "err", err)
		return
	}
	if token == nil {
		respondNotFound(c, "token not found")
		return
	}

	// Redact sensitive fields for non-full visibility.
	if visibility.Level == VisibilityPseudonymous {
		pseudonym := explorer.GeneratePseudonym(token.Address)
		token.Address = pseudonym
		token.Name = nil
		token.Symbol = ""
		token.TotalSupply = nil
		token.HolderCount = 0
		token.TransferCount = 0
		token.CreationTx = nil
		token.L1Address = nil
		token.USDPrice = nil
		token.IconURL = nil
	} else {
		// RD-1154: GetToken's TransferCount/HolderCount are RAW aggregates that
		// ignore the viewer's visibility — a viewer who can see the token but
		// only a subset of its transfers/holders would otherwise learn how many
		// are hidden (count-disclosure — RD-758). Recompute both as filtered
		// survivor counts so the badges match the rows the viewer can load.
		// visibleCountOrZero fails SAFE: a counting error yields 0, never raw.
		ctx := c.Request.Context()
		opts := s.buildRedactOptsForViewer(ctx, viewerDID)
		tc, tcErr := s.countVisibleTokenTransfers(ctx, address, viewerDID, opts)
		token.TransferCount = visibleCountOrZero(tc, tcErr, "token_transfers", address)
		hc, hcErr := s.countVisibleTokenHolders(ctx, address, viewerDID)
		token.HolderCount = visibleCountOrZero(hc, hcErr, "token_holders", address)
	}

	c.JSON(http.StatusOK, token)
}

func (s *Server) getExplorerTokenHolders(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check on the token address itself.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), "", viewerDID, address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "token not found")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	holders, _, err := s.explorerStore.GetTokenHolders(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get token holders",
			"explorer: GetTokenHolders failed",
			"address", address, "limit", limit, "offset", offset, "err", err)
		return
	}
	if holders == nil {
		holders = []explorer.TokenHolder{}
	}
	resolvedDID := viewerDID
	redacted, err := s.explorerRedactor.RedactTokenHolders(c.Request.Context(), holders, resolvedDID)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenHolder{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

func (s *Server) getExplorerTokenTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check on the token address itself.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), "", viewerDID, address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "token not found")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	transfers, _, err := s.explorerStore.GetTransfersByToken(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get token transfers",
			"explorer: GetTransfersByToken failed",
			"address", address, "limit", limit, "offset", offset, "err", err)
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	resolvedDID := viewerDID
	opts := s.buildRedactOptsForViewer(c.Request.Context(), resolvedDID)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, resolvedDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, resolvedDID, "token_transfers", address, opts.Stats)
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

// --- Transfers ---

func (s *Server) getExplorerAllTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	transfers, _, err := s.explorerStore.GetAllTransfers(c.Request.Context(), limit, offset)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transfers",
			"explorer: GetAllTransfers failed",
			"limit", limit, "offset", offset, "err", err)
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	opts := s.buildRedactOptsForViewer(c.Request.Context(), viewerDID)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID, opts)
	if err != nil {
		respondInternalErrorAndLog(c, "redaction failed",
			"explorer: redaction failed",
			"err", err)
		return
	}
	s.auditAdminUserTxView(c, viewerDID, "all_transfers", "", opts.Stats)
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

// --- Accounts ---

func (s *Server) getExplorerAccounts(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	page := 1
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 25
	if ps := c.Query("pageSize"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	accounts, _, err := s.explorerStore.GetAccountsPaginated(c.Request.Context(), page, pageSize)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get accounts",
			"explorer: GetAccountsPaginated failed",
			"page", page, "page_size", pageSize, "err", err)
		return
	}
	if accounts == nil {
		accounts = []explorer.AddressStats{}
	}

	// Filter/mask accounts based on visibility so private org addresses don't leak.
	if len(accounts) > 0 {
		viewerDID := s.getViewerDIDFromRequest(c)
		addrs := make([]string, len(accounts))
		for i, a := range accounts {
			addrs[i] = strings.ToLower(a.Address)
		}
		visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, addrs)
		if err != nil {
			respondInternalErrorAndLog(c, "visibility check failed",
				"explorer: GetBatchVisibility (accounts) failed",
				"viewer_did", viewerDID, "err", err)
			return
		}
		filtered := accounts[:0]
		for _, a := range accounts {
			level := visMap[strings.ToLower(a.Address)]
			switch level {
			case explorer.VisibilityFull:
				filtered = append(filtered, a)
			case explorer.VisibilityPseudonymous:
				a.Address = explorer.GeneratePseudonym(a.Address)
				filtered = append(filtered, a)
				// VisibilityHidden, VisibilityRedacted: drop this account
			}
		}
		accounts = filtered
	}

	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": accounts, "total": len(accounts)})
}

// --- Search ---

func (s *Server) getExplorerSearchSuggestions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusOK, []explorer.SearchSuggestion{})
		return
	}

	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 50 {
			limit = v
		}
	}

	suggestions, err := s.explorerStore.SearchSuggestions(c.Request.Context(), q, limit)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to search",
			"explorer: SearchSuggestions failed",
			"q_len", len(q), "limit", limit, "err", err)
		return
	}
	if suggestions == nil {
		suggestions = []explorer.SearchSuggestion{}
	}

	// Filter address-type suggestions based on visibility so private org contracts
	// cannot be discovered via search autocomplete.
	if len(suggestions) > 0 {
		var addrValues []string
		for _, sug := range suggestions {
			v := strings.ToLower(sug.Value)
			if len(v) == 42 && strings.HasPrefix(v, "0x") {
				addrValues = append(addrValues, v)
			}
		}
		if len(addrValues) > 0 {
			viewerDID := s.getViewerDIDFromRequest(c)
			visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, addrValues)
			if err != nil {
				respondInternalErrorAndLog(c, "visibility check failed",
					"explorer: GetBatchVisibility (search suggestions) failed",
					"viewer_did", viewerDID, "err", err)
				return
			}
			filtered := suggestions[:0]
			for _, sug := range suggestions {
				v := strings.ToLower(sug.Value)
				if len(v) == 42 && strings.HasPrefix(v, "0x") {
					level := visMap[v]
					if level == explorer.VisibilityHidden || level == explorer.VisibilityRedacted {
						continue // drop hidden/restricted address suggestions
					}
					if level == explorer.VisibilityPseudonymous {
						pseudo := explorer.GeneratePseudonym(sug.Value)
						sug.Value = pseudo
						sug.Label = pseudo
					}
				}
				filtered = append(filtered, sug)
			}
			suggestions = filtered
		}
	}

	c.JSON(http.StatusOK, suggestions)
}

// --- Stats ---

func (s *Server) getExplorerTransactionHistory(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	interval := 60
	if i := c.Query("interval"); i != "" {
		if v, err := strconv.Atoi(i); err == nil && v > 0 {
			interval = v
		}
	}
	limit := 30
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	history, err := s.explorerStore.GetTransactionHistoryFiltered(c.Request.Context(), interval, limit, filter)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get transaction history",
			"explorer: GetTransactionHistoryFiltered failed",
			"viewer_did", viewerDID, "interval", interval, "limit", limit, "err", err)
		return
	}
	if history == nil {
		history = []explorer.TxHistoryPoint{}
	}
	c.JSON(http.StatusOK, history)
}

// --- Sync sub-endpoints ---

func (s *Server) getExplorerIndexerProgress(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	progress, err := s.explorerStore.GetIndexerProgress(c.Request.Context())
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get indexer progress",
			"explorer: GetIndexerProgress failed",
			"err", err)
		return
	}
	if progress == nil {
		// Return zero-value progress
		c.JSON(http.StatusOK, explorer.IndexerProgress{})
		return
	}
	c.JSON(http.StatusOK, progress)
}

func (s *Server) getExplorerCatchupProgress(c *gin.Context) {
	// The proxy has no indexer of its own — return static "not running" response
	c.JSON(http.StatusOK, gin.H{
		"processed":       0,
		"total":           0,
		"percentComplete": 0,
		"isRunning":       false,
	})
}
