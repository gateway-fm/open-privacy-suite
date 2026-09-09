package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestImpersonation_DisclosureCounterparty_NoAdminBleed_RD1079 is the end-to-end
// proof that View-as (RD-1028) does NOT mix the signed-in admin's visibility
// with the impersonated user's, for the disclosed-account counterparty case
// (RD-1079).
//
// Fixture: Charlie (private EOA) sends a token transfer to Eve (private EOA).
//   - Dave holds a *pseudonymous* disclosure grant on Eve.
//   - The signed-in Admin holds a *full* disclosure grant on Eve — i.e. broader
//     visibility: as Admin, Eve drives the row-survival union and the redactor
//     reveals Eve's counterparty (Charlie) in full hex.
//   - Both Dave and Admin are in a group with a token contract grant (event
//     access) so the transfer survives RedactTransfers' event-access strip.
//
// Assertions:
//   - Admin viewing DIRECTLY → Charlie is revealed in full hex (broad view).
//   - Admin viewing-as Dave (subject=admin, override=Dave) → Charlie is
//     rendered as a PSEUDONYM, never the real hex, and is NOT labeled
//     `visible_to_grant`/"Shared". The admin's full-grant visibility does not
//     bleed into the impersonated session — the impersonated viewer governs.
//
// This is the RD-1079 leak under impersonation; it composes the RD-1028
// viewer-resolution (override governs) with the RD-1079 Full-only union.
func TestImpersonation_DisclosureCounterparty_NoAdminBleed_RD1079(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, extendedExplorerSchemaRD1009)
	require.NoError(t, err, "create token_transfers table")
	t.Cleanup(func() { _, _ = conn.ExecContext(ctx, "DROP TABLE IF EXISTS token_transfers") })

	// Router mirroring impersonationGateMiddleware + adminAuth: header-driven
	// subject (authenticated admin) and override (impersonated target).
	gin.SetMode(gin.TestMode)
	router := gin.New()
	grp := router.Group("/api/v1/explorer")
	grp.Use(func(c *gin.Context) {
		if sub := c.GetHeader("X-Test-Subject"); sub != "" {
			c.Set("subject", sub)
		}
		if ov := c.GetHeader("X-Test-Override"); ov != "" {
			c.Set(viewerDIDOverrideContextKey, ov)
		}
		c.Next()
	})
	grp.GET("/addresses/:address/transfers", srv.getExplorerAddressTransfers)

	// --- Org + token contract + a group with event access on the token.
	orgID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "rd1079-imp", "RD-1079 Impersonation Org")
	require.NoError(t, err)

	groupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'members', 'Members', 0, 'members')",
		groupID, orgID)
	require.NoError(t, err)

	const token = "0xdaadd00000000000000000000000000000000001"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		contractID, orgID, token, "Stablecoin Token")
	require.NoError(t, err)
	// Non-empty event_rules → group members get token event access, so the
	// transfer survives RedactTransfers' per-contract event-access strip.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO contract_grants (id, contract_id, group_id, event_rules) VALUES ($1, $2, $3, '["*"]'::jsonb)`,
		uuid.New().String(), contractID, groupID)
	require.NoError(t, err)

	// --- Viewers: Dave (pseudonymous grant) + Admin (full grant), both members.
	daveDID := "did:test:rd1079_imp_dave"
	daveUID := createTestUserForExplorer(t, database, daveDID)
	addUserToGroup(t, database, daveUID, groupID)

	adminDID := "did:test:rd1079_imp_admin"
	adminUID := createTestUserForExplorer(t, database, adminDID)
	addUserToGroup(t, database, adminUID, groupID)

	// --- Eve (disclosed subject) + Charlie (her counterparty), both private EOAs.
	const eveEOA = "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc"
	eveUID := createTestUserForExplorer(t, database, "did:test:rd1079_imp_eve")
	require.NoError(t, database.SystemLinkEthAddress(ctx, "did:test:rd1079_imp_eve", eveEOA))

	const charlieEOA = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
	_ = createTestUserForExplorer(t, database, "did:test:rd1079_imp_charlie")
	require.NoError(t, database.SystemLinkEthAddress(ctx, "did:test:rd1079_imp_charlie", charlieEOA))

	// --- Disclosure grants on Eve: Dave=pseudonymous, Admin=full.
	grantOnEve := func(requesterDID, level string) {
		reqID := uuid.New().String()
		scope := `{"disclosure_level":"` + level + `"}`
		_, err := conn.ExecContext(ctx, `
			INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
			VALUES ($1, $2, $3, $4, $5::jsonb, 'rd1079 imp', 'approved', NOW())`,
			reqID, requesterDID, eveUID, orgID, scope)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `
			INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
			VALUES ($1, $2, $3, $4::jsonb, NOW(), $5)`,
			uuid.New().String(), reqID, "imphash_"+level, scope, time.Now().Add(24*time.Hour))
		require.NoError(t, err)
	}
	grantOnEve(daveDID, "pseudonymous")
	grantOnEve(adminDID, "full")

	// --- Chain: tx Charlie -> token, ERC-20 transfer Charlie -> Eve.
	blockNum := seedExplorerBlock(t, conn)
	const txHash = "0xrd1079_imp_repro"
	seedExplorerTransaction(t, conn, blockNum, txHash, charlieEOA, token)
	_, err = conn.ExecContext(ctx, `
		INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ($1, 0, $2, $3, $4, 100, $5)`,
		txHash, token, charlieEOA, eveEOA, blockNum)
	require.NoError(t, err)

	getTransfers := func(subject, override string) []explorer.TokenTransfer {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/addresses/"+eveEOA+"/transfers", nil)
		if subject != "" {
			req.Header.Set("X-Test-Subject", subject)
		}
		if override != "" {
			req.Header.Set("X-Test-Override", override)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "transfers endpoint should return 200")
		var resp apimodels.AddressTransfersResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp.Transfers
	}

	// Control — Admin views DIRECTLY (subject=admin, no override). The admin's
	// FULL grant on Eve drives the union and reveals the counterparty in full
	// hex. This proves the admin genuinely has broader visibility, so the
	// View-as result below cannot be a false negative.
	adminView := getTransfers(adminDID, "")
	require.Len(t, adminView, 1, "admin should see Eve's transfer")
	require.Equalf(t, charlieEOA, adminView[0].From,
		"control: admin's full grant must reveal the counterparty in full hex (got %q)", adminView[0].From)

	// The actual test — Admin views-AS Dave (subject=admin, override=Dave).
	// Dave's PSEUDONYMOUS grant must govern: counterparty pseudonymised, never
	// the real hex, never the "Shared" (visible_to_grant) label. The admin's
	// full-grant visibility must NOT bleed in.
	asDave := getTransfers(adminDID, daveDID)
	require.Len(t, asDave, 1, "View-as Dave should still surface Eve's transfer (Eve is in VisibleAddresses)")

	gotFrom := asDave[0].From
	require.NotEqualf(t, charlieEOA, gotFrom,
		"RD-1079 / View-as bleed: counterparty leaked in full hex under impersonation (got %q)", gotFrom)
	require.Equalf(t, explorer.GeneratePseudonym(charlieEOA, nil), gotFrom,
		"counterparty must render as Dave's pseudonymous lens, got %q", gotFrom)
	require.Equalf(t, explorer.GeneratePseudonym(eveEOA, nil), asDave[0].To,
		"disclosed subject must render at her pseudonym, got %q", asDave[0].To)

	// Label check (the frontend-visible symptom): the counterparty must NOT be
	// tagged visible_to_grant/"Shared" — Dave holds no per-tx visibleTo share.
	require.NotEqualf(t, explorer.ReasonVisibleToGrant, asDave[0].AddressMetadata[charlieEOA],
		"counterparty must not carry the visible_to_grant/\"Shared\" label under a pseudonymous grant")
	// The disclosed subject herself is correctly tagged disclosure_grant.
	require.Equal(t, explorer.ReasonDisclosureGrant, asDave[0].AddressMetadata[eveEOA],
		"disclosed subject should be tagged disclosure_grant")
}
