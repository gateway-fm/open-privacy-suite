package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
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
	// NextCursor is the opaque continuation to pass back as ?cursor= (RD-1149).
	// Its presence is the sole "more pages" signal: a client keeps paging while
	// next_cursor is present and stops when it is omitted (feed exhausted). It is
	// deliberately the only pagination field — there is no has_more, which would
	// only ever be `next_cursor != ""` and could drift from it.
	NextCursor string `json:"next_cursor,omitempty"`
}

// AddressTransactionsResponse wraps a page of an address's transactions with the
// opaque pagination cursor (RD-1149). NextCursor follows the same token-only
// contract as GrantTransactionsResponse: present ⇒ more pages, omitted ⇒ done.
type AddressTransactionsResponse struct {
	Transactions []explorer.Transaction `json:"transactions"`
	NextCursor   string                 `json:"next_cursor,omitempty"`
}

// AddressTransfersResponse wraps a page of an address's token transfers with the
// opaque pagination cursor (RD-1149). Same token-only contract as above.
type AddressTransfersResponse struct {
	Transfers  []explorer.TokenTransfer `json:"transfers"`
	NextCursor string                   `json:"next_cursor,omitempty"`
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
	explorer.Use(middleware.BodyLimit(MaxRequestBodySize))
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

// getViewerIdentity was removed in RD-1028. It read the viewer DID only from
// "subject" and was blind to the impersonation viewer override
// (viewerDIDOverrideContextKey), so under View-as the single-item explorer
// handlers resolved the wrong viewer (the admin / anonymous, not the
// impersonated target) — wrong 404s, and a fail-open risk where the admin's
// broader access could bleed into the impersonated view. All explorer handlers
// now resolve the viewer via getViewerDIDFromRequest, which honours the
// override. The ?wallet= viewer path it carried was also a viewer-impersonation
// oracle and is gone with it.

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

// calculateAddressVisibilityWithDID determines the visibility of a single address
// for the given viewer DID. It delegates to GetBatchVisibilityDetailed (single-
// element batch) so the level matches the RedactionEngine's GetBatchVisibility.
// Viewer identity is always a DID resolved from the JWT / impersonation override
// (RD-1164 #7: the wallet-based resolveViewerDID path was removed — an
// unauthenticated ?wallet= lookup was a deanonymization oracle).
func (s *Server) calculateAddressVisibilityWithDID(ctx context.Context, viewerDID, targetAddress string) AddressVisibility {
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
	visibility := s.calculateAddressVisibilityWithDID(ctx, viewerDID, address)
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

// getExplorerChainID returns the chain ID reported to the explorer backend.
//
// @Summary      Chain ID
// @Description  Returns the chain ID for the explorer backend. Private network only (serves the explorer backend); not reachable through the public ingress.
// @Tags         Explorer
// @Produce      json
// @Success      200 {object} ExplorerChainIDResponse
// @Router       /api/v1/explorer/chain-id [get]
func (s *Server) getExplorerChainID(c *gin.Context) {
	// Approximation: return 1 or get from proxy if needed
	c.JSON(http.StatusOK, gin.H{"chain_id": 1})
}

// getExplorerStats returns chain-wide aggregate statistics.
//
// @Summary      Chain statistics
// @Description  Returns chain-wide aggregate counts (blocks, transactions, addresses, tokens). Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: totals reflect only rows the viewer may see, so a restricted viewer sees smaller counts than the raw chain totals.
// @Tags         Explorer
// @Produce      json
// @Success      200 {object} explorer.ChainStats
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/stats [get]
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

// maxExplorerPageLimit caps the page size of explorer list endpoints (RD-1179).
const maxExplorerPageLimit = 100

// clampExplorerLimit bounds a parsed explorer page limit to [1, maxExplorerPageLimit],
// falling back to def for non-positive values (RD-1179). Explorer handlers parse
// limit with `limit, _ := strconv.Atoi(...)`, which ignores both the parse error
// and the sign — so without this an unbounded ?limit= reaches SQL directly, and a
// negative limit becomes Postgres `LIMIT ALL` (a full-table dump).
func clampExplorerLimit(limit, def int) int {
	if limit <= 0 {
		return def
	}
	if limit > maxExplorerPageLimit {
		return maxExplorerPageLimit
	}
	return limit
}

// clampExplorerOffset floors a parsed explorer offset at 0 (RD-1179). A negative
// OFFSET otherwise reaches SQL, where Postgres rejects it ("OFFSET must not be
// negative") — turning a bad query param into a 500.
func clampExplorerOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

// getExplorerBlocks returns a page of recent blocks, newest first.
//
// @Summary      List recent blocks
// @Description  Returns a page of blocks, newest first. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: each block's transactionCount reflects only transactions the viewer may see.
// @Tags         Explorer
// @Produce      json
// @Param        limit query int false "Max blocks to return" default(25)
// @Param        before query int false "Return blocks strictly older than this block number (pagination cursor)"
// @Success      200 {array} explorer.Block
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/blocks [get]
func (s *Server) getExplorerBlocks(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	limit = clampExplorerLimit(limit, 25)
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

// getExplorerBlock returns a single block by its number.
//
// @Summary      Get block by number
// @Description  Returns a single block by number. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: the block's transactionCount reflects only transactions the viewer may see.
// @Tags         Explorer
// @Produce      json
// @Param        number path int true "Block number"
// @Success      200 {object} explorer.Block
// @Failure      400 {object} APIError "invalid block number"
// @Failure      404 {object} APIError "block not found"
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/blocks/{number} [get]
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
		if err != nil {
			// RD-1176: fail-safe to 0, don't fall back to the raw chain-wide count.
			filteredCount = 0
		}
		block.TransactionCount = filteredCount
	}
	c.JSON(http.StatusOK, block)
}

// getExplorerBlockByHash returns a single block by its hash.
//
// @Summary      Get block by hash
// @Description  Returns a single block by its hash. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: the block's transactionCount reflects only transactions the viewer may see.
// @Tags         Explorer
// @Produce      json
// @Param        hash path string true "Block hash (0x-prefixed)"
// @Success      200 {object} explorer.Block
// @Failure      404 {object} APIError "block not found"
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/blocks/hash/{hash} [get]
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
		if err != nil {
			// RD-1176: fail-safe to 0, don't fall back to the raw chain-wide count.
			filteredCount = 0
		}
		block.TransactionCount = filteredCount
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

// getExplorerTransactions returns a page of recent transactions, newest first.
//
// @Summary      List recent transactions
// @Description  Returns a page of transactions, newest first. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: transactions where every participant is hidden are dropped, and surviving rows have addresses and values redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        before query int false "Return rows strictly older than this block number (pagination cursor)"
// @Param        with_categories query bool false "Include transaction category tags" default(false)
// @Success      200 {array} explorer.Transaction
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transactions [get]
func (s *Server) getExplorerTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	limit = clampExplorerLimit(limit, 25)
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

// getExplorerTransaction returns a single transaction by hash.
//
// @Summary      Get transaction by hash
// @Description  Returns a single transaction by hash. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: addresses and values are redacted per the viewer's visibility. Fail-closed: a transaction the viewer cannot see at all returns 404 (indistinguishable from a truly missing hash).
// @Tags         Explorer
// @Produce      json
// @Param        hash path string true "Transaction hash (0x-prefixed)"
// @Param        with_categories query bool false "Include transaction category tags" default(false)
// @Success      200 {object} explorer.Transaction
// @Failure      404 {object} APIError "transaction not found (also returned when the transaction is fully hidden from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transactions/{hash} [get]
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

// isBadCursorErr reports whether err is a malformed pagination cursor from
// either backend: the SQL store's explorer.ErrBadCursor, or the gRPC
// indexer's InvalidArgument ("cursor malformed"). Handlers map it to an
// opaque 400 — a bad cursor fails the request, never restarts the feed.
func isBadCursorErr(err error) bool {
	if errors.Is(err, explorer.ErrBadCursor) {
		return true
	}
	if st, ok := grpcstatus.FromError(err); ok && st.Code() == grpccodes.InvalidArgument {
		return true
	}
	return false
}

// countAcrossPages pages through an item feed and sums a per-page count over
// the DISTINCT items, bounded by maxScan rows fetched. It exists because privacy/gRPC mode
// clamps each indexer fetch to a small max page size (~100), so a single fetch
// cannot count an active address's transactions.
//
// RD-1149: the walk advances on the backend's opaque continuation cursor
// (fetch("") = newest first; next == "" = feed exhausted), which resumes on
// the exact (block, idx) keyset position — the previous bare-block advance
// skipped a boundary block's remaining rows, so the survivor walk undercounted.
// keyOf dedupe is kept as defense in depth against a re-serving backend
// (under-count, never double-count), and a non-advancing cursor terminates
// the walk. perPageCount counts the countable items in a page (e.g. redaction
// survivors).
func countAcrossPages[T any](
	fetch func(cursor string) ([]T, string, error),
	keyOf func(T) string,
	perPageCount func([]T) (int, error),
	maxScan int,
) (int, error) {
	count, scanned := 0, 0
	seen := make(map[string]struct{})
	var cursor string
	for scanned < maxScan {
		page, next, err := fetch(cursor)
		if err != nil {
			return 0, err
		}
		if len(page) == 0 {
			break
		}
		fresh := make([]T, 0, len(page))
		for _, item := range page {
			k := keyOf(item)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			fresh = append(fresh, item)
		}
		// Bound by rows FETCHED, not distinct rows kept: a backend that heavily
		// re-serves or overlaps pages must not be able to drive far more than
		// maxScan/pageSize fetches (mirrors countAcrossOffsetPages' offset
		// bound). count still sums perPageCount over the distinct items only.
		scanned += len(page)
		if len(fresh) > 0 {
			n, err := perPageCount(fresh)
			if err != nil {
				return 0, err
			}
			count += n
		}
		if next == "" || next == cursor {
			break
		}
		cursor = next
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
		func(cursor string) ([]explorer.Transaction, string, error) {
			return s.explorerStore.GetTransactionsByAddress(ctx, address, perPage, explorer.AddressPage{Cursor: cursor})
		},
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
		func(cursor string) ([]explorer.TokenTransfer, string, error) {
			return s.explorerStore.GetTransfersByAddress(ctx, address, perPage, explorer.AddressPage{Cursor: cursor})
		},
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

// getExplorerAddressStats returns per-address aggregate statistics.
//
// @Summary      Address statistics
// @Description  Returns per-address aggregate counts (transactions, internal transactions, token transfers) plus first/last-seen. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404), and each count is recomputed as the number of rows the viewer can actually see (never the raw total). Fail-closed: a counting error yields 0 for that badge, never the raw aggregate.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Success      200 {object} explorer.AddressStats
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/stats [get]
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

// getExplorerAddressTransactions returns a page of an address's transactions.
//
// @Summary      Transactions for an address
// @Description  Returns a page of transactions involving an address, newest first. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404), and surviving rows are redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Param        limit query int false "Max rows to return" default(25)
// @Param        cursor query string false "Opaque continuation cursor from the previous response's next_cursor (RD-1149); takes precedence over before"
// @Param        before query int false "Legacy: return rows strictly older than this block number (may skip rows of the boundary block — prefer cursor)"
// @Success      200 {object} AddressTransactionsResponse
// @Failure      400 {object} APIError "malformed pagination cursor"
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/transactions [get]
func (s *Server) getExplorerAddressTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := c.Param("address")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	limit = clampExplorerLimit(limit, 25)
	page := explorer.AddressPage{Cursor: c.Query("cursor")}
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			page.BeforeBlock = &val
		}
	}

	// Pre-authorization check: Can they see this address via RBAC or full disclosure grant?
	viewerDID := s.getViewerDIDFromRequest(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerDID, address) {
		respondNotFound(c, "address not found") // Masking forbidden as not found
		return
	}

	txs, nextCursor, err := s.explorerStore.GetTransactionsByAddress(c.Request.Context(), address, limit, page)
	if err != nil {
		if isBadCursorErr(err) {
			respondBadRequest(c, "invalid pagination cursor")
			return
		}
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

	if redactedTxs == nil {
		redactedTxs = []explorer.Transaction{}
	}
	// RD-1149: the opaque continuation is returned in the response body
	// (next_cursor), omitted when the feed is exhausted. Its presence is the
	// only "more pages" signal — no X-Next-Cursor header, no has_more.
	c.JSON(http.StatusOK, AddressTransactionsResponse{
		Transactions: redactedTxs,
		NextCursor:   nextCursor,
	})
}

// getExplorerSyncStatus returns the indexer sync status.
//
// @Summary      Sync status
// @Description  Returns the last indexed block and whether indexing is in progress. Private network only (serves the explorer backend); not reachable through the public ingress.
// @Tags         Explorer
// @Produce      json
// @Success      200 {object} explorer.SyncStatus
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/sync/status [get]
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

// indexExplorerBlock is a placeholder for manual block indexing.
//
// @Summary      Trigger indexing of a block (not implemented)
// @Description  Placeholder for manual block indexing. Private network only (serves the explorer backend); not reachable through the public ingress. The proxy has no indexer of its own, so this always responds 500 (not implemented).
// @Tags         Explorer
// @Produce      json
// @Param        number path int true "Block number"
// @Failure      500 {object} APIError "manual indexing through proxy not yet implemented"
// @Router       /api/v1/explorer/index/block/{number} [post]
func (s *Server) indexExplorerBlock(c *gin.Context) {
	// Proxy to indexer or return not implemented for now
	respondInternalError(c, "manual indexing through proxy not yet implemented")
}

// --- Block sub-endpoints ---

// getExplorerBlockTransactions returns the transactions in a block.
//
// @Summary      Transactions in a block
// @Description  Returns the transactions contained in a block. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: transactions fully hidden from the viewer are dropped and surviving rows are redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        number path int true "Block number"
// @Success      200 {array} explorer.Transaction
// @Failure      400 {object} APIError "invalid block number"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/blocks/{number}/transactions [get]
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

// getExplorerBlockInternalTxs returns the internal transactions in a block.
//
// @Summary      Internal transactions in a block
// @Description  Returns the internal (trace) transactions contained in a block. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: frames fully hidden from the viewer are dropped and surviving rows are redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        number path int true "Block number"
// @Success      200 {array} explorer.InternalTransaction
// @Failure      400 {object} APIError "invalid block number"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/blocks/{number}/internal [get]
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

// getExplorerLatestBlockNumber returns the highest indexed block number.
//
// @Summary      Latest block number
// @Description  Returns the highest indexed block number. Private network only (serves the explorer backend); not reachable through the public ingress.
// @Tags         Explorer
// @Produce      json
// @Success      200 {object} ExplorerBlockNumberResponse
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/blocks/latest/number [get]
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

// getExplorerTransactionsPaginated returns a page of transactions with a total.
//
// @Summary      List transactions (page/pageSize)
// @Description  Returns a page of transactions plus a total count, using page/pageSize pagination. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: rows fully hidden from the viewer are dropped and surviving rows are redacted. Note the total is a SQL-level count that may slightly overcount relative to the redacted rows in data.
// @Tags         Explorer
// @Produce      json
// @Param        page query int false "1-based page number" default(1)
// @Param        pageSize query int false "Rows per page (1-100)" default(25)
// @Param        with_categories query bool false "Include transaction category tags" default(false)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.Transaction}
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transactions/paginated [get]
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

// getExplorerTransactionInternal returns the internal transactions of a tx.
//
// @Summary      Internal transactions for a transaction
// @Description  Returns the internal (trace) frames of a transaction. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: frames are redacted per the viewer's visibility, with the parent transaction's own counterparties revealed only to a viewer who is themselves a parent participant.
// @Tags         Explorer
// @Produce      json
// @Param        hash path string true "Transaction hash (0x-prefixed)"
// @Success      200 {array} explorer.InternalTransaction
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transactions/{hash}/internal [get]
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

// getExplorerTransactionTransfers returns the token transfers of a tx.
//
// @Summary      Token transfers for a transaction
// @Description  Returns the token transfers emitted by a transaction. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: transfers are redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        hash path string true "Transaction hash (0x-prefixed)"
// @Success      200 {array} explorer.TokenTransfer
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transactions/{hash}/transfers [get]
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

// getExplorerTransactionLogs returns the event logs of a tx.
//
// @Summary      Event logs for a transaction
// @Description  Returns the event logs emitted by a transaction. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: logs are redacted per the viewer's visibility, with logs of the parent transaction revealed to a viewer who is the transaction's sender or recipient.
// @Tags         Explorer
// @Produce      json
// @Param        hash path string true "Transaction hash (0x-prefixed)"
// @Success      200 {array} explorer.Log
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transactions/{hash}/logs [get]
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

// getExplorerTransactionOPDeposit reports OP Stack deposit metadata for a tx.
//
// @Summary      OP Stack deposit for a transaction (not applicable)
// @Description  Returns OP Stack L1 deposit metadata for a transaction. Private network only (serves the explorer backend); not reachable through the public ingress. This deployment is not an OP Stack chain, so this always responds 404.
// @Tags         Explorer
// @Produce      json
// @Param        hash path string true "Transaction hash (0x-prefixed)"
// @Failure      404 {object} APIError "OP deposit not found (not an OP Stack chain)"
// @Router       /api/v1/explorer/transactions/{hash}/op-deposit [get]
func (s *Server) getExplorerTransactionOPDeposit(c *gin.Context) {
	// This is not an OP Stack chain — always return 404
	respondNotFound(c, "OP deposit not found (not an OP Stack chain)")
}

// --- Address sub-endpoints ---

// getExplorerAddressBalance returns the native balance of an address.
//
// @Summary      Native balance of an address
// @Description  Returns the current native-token balance of an address as a hex-quantity string (forwarded from eth_getBalance). Private network only (serves the explorer backend); not reachable through the public ingress. Access is privacy-filtered: it requires visibility of the address (else 404), so a viewer cannot probe balances of addresses hidden from them.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Success      200 {string} string "hex-quantity balance in wei" example(0x0)
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "upstream RPC or parse failure"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/balance [get]
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

// getExplorerAddressCode returns the deployed bytecode at an address.
//
// @Summary      Deployed bytecode at an address
// @Description  Returns the contract bytecode at an address (forwarded from eth_getCode). Private network only (serves the explorer backend); not reachable through the public ingress. Access is privacy-filtered: it requires visibility of the address (else 404). The body is a base64-encoded JSON string wrapping the node's hex code result.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Success      200 {string} string "base64-encoded JSON string of the hex bytecode"
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "upstream RPC or parse failure"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/code [get]
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

// getExplorerAddressTokenBalances returns the token balances of an address.
//
// @Summary      Token balances of an address
// @Description  Returns the token balances held by an address. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404), and balances of token contracts hidden from the viewer are dropped (pseudonymous token contracts have their address masked).
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Success      200 {array} explorer.Balance
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup or visibility check failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/balances [get]
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
				b.TokenAddress = s.pseudonym(b.TokenAddress)
				filtered = append(filtered, b)
				// VisibilityHidden, VisibilityRedacted: drop this balance entry
			}
		}
		balances = filtered
	}

	c.JSON(http.StatusOK, balances)
}

// getExplorerAddressTransfers returns a page of an address's token transfers.
//
// @Summary      Token transfers for an address
// @Description  Returns a page of token transfers involving an address, newest first. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404), and surviving rows are redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Param        limit query int false "Max rows to return" default(25)
// @Param        cursor query string false "Opaque continuation cursor from the previous response's next_cursor (RD-1149); takes precedence over before"
// @Param        before query int false "Legacy: return rows strictly older than this block number (may skip rows of the boundary block — prefer cursor)"
// @Success      200 {object} AddressTransfersResponse
// @Failure      400 {object} APIError "malformed pagination cursor"
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/transfers [get]
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
	limit = clampExplorerLimit(limit, 25)
	page := explorer.AddressPage{Cursor: c.Query("cursor")}
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			page.BeforeBlock = &val
		}
	}

	transfers, nextCursor, err := s.explorerStore.GetTransfersByAddress(c.Request.Context(), address, limit, page)
	if err != nil {
		if isBadCursorErr(err) {
			respondBadRequest(c, "invalid pagination cursor")
			return
		}
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
	// RD-1149: continuation returned in the body (next_cursor), omitted when the
	// feed is exhausted. Its presence is the only "more pages" signal — no
	// X-Next-Cursor header, no has_more.
	c.JSON(http.StatusOK, AddressTransfersResponse{
		Transfers:  redacted,
		NextCursor: nextCursor,
	})
}

// getExplorerAddressInternal returns a page of an address's internal txs.
//
// @Summary      Internal transactions for an address
// @Description  Returns a page of internal (trace) transactions involving an address plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404); rows are redacted per the viewer's visibility and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Param        limit query int false "Max rows to return" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.InternalTransaction}
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/internal [get]
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
	limit = clampExplorerLimit(limit, 25)
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	offset = clampExplorerOffset(offset)

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

// getExplorerAddressLogs returns a page of an address's event logs.
//
// @Summary      Event logs for an address
// @Description  Returns a page of event logs emitted by an address plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404); logs are redacted per the viewer's visibility and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Param        limit query int false "Max rows to return" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.Log}
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/logs [get]
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
	limit = clampExplorerLimit(limit, 25)
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	offset = clampExplorerOffset(offset)

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

// getExplorerAddressContract returns contract metadata for an address.
//
// @Summary      Contract metadata for an address
// @Description  Returns deployed-contract metadata (bytecode, verification, ABI, source) for an address. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: access requires visibility of the address (else 404), and the creator address is redacted per the viewer's visibility so a private deployer is not revealed.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} explorer.Contract
// @Failure      404 {object} APIError "address or contract not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/contract [get]
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
		if err != nil {
			// RD-1176: fail closed — never keep the raw deployer EOA on a
			// redaction error (it may be a private foreign user).
			redactedCreator = "[REDACTED]"
		}
		contract.Creator = redactedCreator
	}
	c.JSON(http.StatusOK, contract)
}

// getExplorerAddressIsContract reports whether an address is a contract.
//
// @Summary      Whether an address is a contract
// @Description  Reports whether an address has deployed code (is a contract). Private network only (serves the explorer backend); not reachable through the public ingress. Access is privacy-filtered: it requires visibility of the address (else 404), so a viewer cannot probe hidden addresses.
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Account address (0x-prefixed hex)"
// @Success      200 {object} ExplorerIsContractResponse
// @Failure      404 {object} APIError "address not found (also returned when the address is hidden from the viewer)"
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/is-contract [get]
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

// updateExplorerAddressABI stores a contract ABI for an address.
//
// @Summary      Set the ABI for a contract
// @Description  Stores the ABI JSON for a contract address. Private network only (serves the explorer backend); not reachable through the public ingress. This is privacy-gated: the write requires FULL visibility of the address for the resolved viewer, so only members of the owning org (or a public contract) may update the ABI; other viewers get 404 (indistinguishable from a missing address). The request body is the raw ABI JSON.
// @Tags         Explorer
// @Accept       json
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body object true "Raw contract ABI JSON (array of ABI entries)"
// @Success      200 {object} ExplorerABIUpdateResponse
// @Failure      400 {object} APIError "invalid request body"
// @Failure      404 {object} APIError "address not found (also returned when the viewer lacks full visibility)"
// @Failure      500 {object} APIError "failed to set contract ABI"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/addresses/{address}/abi [post]
func (s *Server) updateExplorerAddressABI(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Require full visibility: only org members (or public contracts) may update ABI.
	// This prevents unauthorized writes to private org contracts.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerDID, address)
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

// getExplorerLogs returns event logs matching optional filters.
//
// @Summary      Query event logs
// @Description  Returns event logs matching the given address / topic / block-range filters. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: logs are redacted per the viewer's visibility.
// @Tags         Explorer
// @Produce      json
// @Param        address query string false "Filter by emitting contract address (0x-prefixed hex)" example(0x0000000000000000000000000000000000000001)
// @Param        topic0 query string false "Filter by first log topic (event signature hash)"
// @Param        from query int false "Start block (inclusive)"
// @Param        to query int false "End block (inclusive)"
// @Param        limit query int false "Max rows to return (1-1000)" default(100)
// @Success      200 {array} explorer.Log
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/logs [get]
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

// getExplorerTokens returns a page of tokens with a filtered total.
//
// @Summary      List tokens
// @Description  Returns a page of tokens plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: token contracts hidden from the viewer are dropped, redacted/pseudonymous ones have their identifying fields masked, and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Param        type query string false "Filter by token type (e.g. ERC20, ERC721)"
// @Success      200 {object} ExplorerListResponse{data=[]explorer.Token}
// @Failure      500 {object} APIError "lookup or visibility check failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/tokens [get]
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
	offset = clampExplorerOffset(offset)
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

		// RD-1177 F3: for Full tokens the list previously returned GetTokens'
		// RAW HolderCount/TransferCount aggregates, while the single-token
		// endpoint (getExplorerToken) recomputes them as visible-survivor counts
		// (RD-1154). §3.9 blesses grant/Full holders *seeing* these counts, not
		// seeing RAW over-reporting counts that reveal how many holders/transfers
		// are hidden. Recompute here so the list agrees with its single-item
		// sibling. Fail-safe to 0 on error via visibleCountOrZero.
		ctx := c.Request.Context()
		opts := s.buildRedactOptsForViewer(ctx, viewerDID)
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
				pseudonym := s.pseudonym(t.Address)
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
			default:
				// VisibilityFull (or unrecognized — recomputing is fail-safe):
				// replace raw counts with visibility-aware survivor counts.
				tc, tcErr := s.countVisibleTokenTransfers(ctx, t.Address, viewerDID, opts)
				t.TransferCount = visibleCountOrZero(tc, tcErr, "token_transfers", t.Address)
				hc, hcErr := s.countVisibleTokenHolders(ctx, t.Address, viewerDID)
				t.HolderCount = visibleCountOrZero(hc, hcErr, "token_holders", t.Address)
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

// getExplorerToken returns metadata for a single token contract.
//
// @Summary      Get token by address
// @Description  Returns metadata for a single token contract. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: a token hidden or redacted from the viewer returns 404 (same response for both, to avoid an existence oracle); a pseudonymous token has its identifying fields masked; for a fully visible token, holder and transfer counts are recomputed as the number of rows the viewer can see (fail-safe to 0 on error, never the raw aggregate).
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Token contract address (0x-prefixed hex)"
// @Success      200 {object} explorer.Token
// @Failure      404 {object} APIError "token not found (also returned when the token is hidden or redacted from the viewer)"
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/tokens/{address} [get]
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
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerDID, address)
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
		pseudonym := s.pseudonym(token.Address)
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

// getExplorerTokenHolders returns a page of a token's holders.
//
// @Summary      Token holders
// @Description  Returns a page of holders of a token contract plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: a token hidden or redacted from the viewer returns 404; holders whose address is hidden from the viewer are dropped and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Token contract address (0x-prefixed hex)"
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.TokenHolder}
// @Failure      404 {object} APIError "token not found (also returned when the token is hidden or redacted from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/tokens/{address}/holders [get]
func (s *Server) getExplorerTokenHolders(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check on the token address itself.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerDID, address)
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
	offset = clampExplorerOffset(offset)

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

// getExplorerTokenTransfers returns a page of a token's transfers.
//
// @Summary      Token transfers
// @Description  Returns a page of transfers of a token contract plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: a token hidden or redacted from the viewer returns 404; surviving transfers are redacted per the viewer's visibility and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        address path string true "Token contract address (0x-prefixed hex)"
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.TokenTransfer}
// @Failure      404 {object} APIError "token not found (also returned when the token is hidden or redacted from the viewer)"
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/tokens/{address}/transfers [get]
func (s *Server) getExplorerTokenTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check on the token address itself.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerDID, address)
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
	offset = clampExplorerOffset(offset)

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

// getExplorerAllTransfers returns a page of all token transfers.
//
// @Summary      List all token transfers
// @Description  Returns a page of token transfers across all tokens plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: transfers are redacted per the viewer's visibility and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        limit query int false "Max rows to return (1-100)" default(25)
// @Param        offset query int false "Rows to skip (pagination)" default(0)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.TokenTransfer}
// @Failure      500 {object} APIError "lookup or redaction failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/transfers [get]
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
	offset = clampExplorerOffset(offset)

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

// getExplorerAccounts returns a page of accounts with a filtered total.
//
// @Summary      List accounts
// @Description  Returns a page of accounts (address statistics) plus the count of returned rows. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: accounts hidden from the viewer are dropped, pseudonymous ones have their address masked, and total is the count of returned rows (never the raw DB total).
// @Tags         Explorer
// @Produce      json
// @Param        page query int false "1-based page number" default(1)
// @Param        pageSize query int false "Rows per page (1-100)" default(25)
// @Success      200 {object} ExplorerListResponse{data=[]explorer.AddressStats}
// @Failure      500 {object} APIError "lookup or visibility check failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/accounts [get]
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
		// RD-1177 F1: the per-address activity counts on explorer.AddressStats
		// (TxCount / TokenTransferCount / InternalTxCount) are RAW aggregates
		// that ignore the viewer's visibility — identical count-disclosure to
		// RD-1154/G22, which was fixed for the single-address /addresses/:address/stats
		// endpoint (getExplorerAddressStats) but missed here. Worse, this list is
		// ordered by raw tx_count DESC, so even the ranking leaks. Recompute all
		// three counts for Full rows via the SAME helpers + shared opts the
		// single-address endpoint uses (fail-safe to 0 on error via
		// visibleCountOrZero), and zero them for pseudonymous rows — a
		// pseudonymised party's activity volume is not the viewer's to see, and
		// the single-address endpoint never serves pseudonymous (it 404s).
		//
		// Cost note: this recomputes up to pageSize (≤100) × 3 visibility-aware
		// counts, each bounded by its helper's maxScan. Matches the accepted cost
		// of getExplorerAddressStats, multiplied by the page size.
		ctx := c.Request.Context()
		opts := s.buildRedactOptsForViewer(ctx, viewerDID)
		filtered := accounts[:0]
		for _, a := range accounts {
			level := visMap[strings.ToLower(a.Address)]
			switch level {
			case explorer.VisibilityFull:
				txCount, txErr := s.countVisibleAddressTxs(ctx, a.Address, viewerDID, opts)
				a.TxCount = visibleCountOrZero(txCount, txErr, "transactions", a.Address)
				trCount, trErr := s.countVisibleAddressTransfers(ctx, a.Address, viewerDID, opts)
				a.TokenTransferCount = visibleCountOrZero(trCount, trErr, "token_transfers", a.Address)
				inCount, inErr := s.countVisibleAddressInternalTxs(ctx, a.Address, viewerDID, opts)
				a.InternalTxCount = visibleCountOrZero(inCount, inErr, "internal_transactions", a.Address)
				filtered = append(filtered, a)
			case explorer.VisibilityPseudonymous:
				a.Address = s.pseudonym(a.Address)
				// Do not leak a pseudonymised party's raw activity volume.
				a.TxCount = 0
				a.TokenTransferCount = 0
				a.InternalTxCount = 0
				filtered = append(filtered, a)
				// VisibilityHidden, VisibilityRedacted: drop this account
			}
		}
		accounts = filtered
		// One audit entry for any rows revealed under ORG_ADMIN_VIEW_USER_TXS
		// across the recompute passes (no-op under the default posture).
		s.auditAdminUserTxView(c, viewerDID, "accounts", "", opts.Stats)
	}

	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": accounts, "total": len(accounts)})
}

// --- Search ---

// getExplorerSearchSuggestions returns autocomplete suggestions for a query.
//
// @Summary      Search autocomplete suggestions
// @Description  Returns autocomplete suggestions (blocks, transactions, addresses, tokens) for a query string. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: address/contract suggestions hidden or redacted from the viewer are dropped and pseudonymous ones are masked, so private contracts cannot be discovered via autocomplete. An empty query returns an empty list.
// @Tags         Explorer
// @Produce      json
// @Param        q query string false "Search query (empty returns no suggestions)"
// @Param        limit query int false "Max suggestions to return (1-50)" default(10)
// @Success      200 {array} explorer.SearchSuggestion
// @Failure      500 {object} APIError "search or visibility check failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/search/suggestions [get]
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
						pseudo := s.pseudonym(sug.Value)
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

// getExplorerTransactionHistory returns a time series of transaction counts.
//
// @Summary      Transaction-count history
// @Description  Returns a time series of transaction counts bucketed by interval. Private network only (serves the explorer backend); not reachable through the public ingress. The response is privacy-filtered for the resolved viewer: counts reflect only transactions the viewer may see.
// @Tags         Explorer
// @Produce      json
// @Param        interval query int false "Bucket size in minutes" default(60)
// @Param        limit query int false "Max buckets to return (1-100)" default(30)
// @Success      200 {array} explorer.TxHistoryPoint
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/stats/tx-history [get]
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

// getExplorerIndexerProgress returns the indexer backfill progress.
//
// @Summary      Indexer progress
// @Description  Returns indexer backfill progress (min/max fetched block, backfill-complete flag). Private network only (serves the explorer backend); not reachable through the public ingress.
// @Tags         Explorer
// @Produce      json
// @Success      200 {object} explorer.IndexerProgress
// @Failure      500 {object} APIError "lookup failed"
// @Failure      503 {object} APIError "explorer store not configured"
// @Router       /api/v1/explorer/sync/indexer-progress [get]
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

// getExplorerCatchupProgress returns indexer catch-up progress.
//
// @Summary      Catch-up progress
// @Description  Returns indexer catch-up progress. Private network only (serves the explorer backend); not reachable through the public ingress. The proxy has no indexer of its own, so this always reports a static "not running" state.
// @Tags         Explorer
// @Produce      json
// @Success      200 {object} ExplorerCatchupProgressResponse
// @Router       /api/v1/explorer/sync/catchup [get]
func (s *Server) getExplorerCatchupProgress(c *gin.Context) {
	// The proxy has no indexer of its own — return static "not running" response
	c.JSON(http.StatusOK, gin.H{
		"processed":       0,
		"total":           0,
		"percentComplete": 0,
		"isRunning":       false,
	})
}
