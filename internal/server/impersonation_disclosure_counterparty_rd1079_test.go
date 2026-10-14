package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestImpersonation_DisclosureCounterparty_NoAdminBleed_RD1079 verifies
// the disclosure rendering policy for direct and impersonated viewers.
// Disclosure grants apply only to their grantee's direct session.
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
			// Same context the impersonation gate installs (RD-1318: it
			// also marks the target's disclosure grants as unavailable).
			setImpersonationContext(c, ov, c.GetHeader("X-Test-Subject"), "rd1079-imp-org")
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

	fetch := func(subject, override string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/addresses/"+eveEOA+"/transfers", nil)
		if subject != "" {
			req.Header.Set("X-Test-Subject", subject)
		}
		if override != "" {
			req.Header.Set("X-Test-Override", override)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	getTransfers := func(subject, override string) []explorer.TokenTransfer {
		w := fetch(subject, override)
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

	// Control — Dave views DIRECTLY: his PSEUDONYMOUS grant governs, the
	// counterparty is pseudonymised, never the real hex, never "Shared".
	asDaveHimself := getTransfers(daveDID, "")
	require.Len(t, asDaveHimself, 1, "Dave sees Eve's transfer through his own grant")
	require.Equalf(t, explorer.GeneratePseudonym(charlieEOA, nil), asDaveHimself[0].From,
		"counterparty must render as Dave's pseudonymous lens, got %q", asDaveHimself[0].From)
	require.Equalf(t, explorer.GeneratePseudonym(eveEOA, nil), asDaveHimself[0].To,
		"disclosed subject must render at her pseudonym, got %q", asDaveHimself[0].To)
	require.NotEqualf(t, explorer.ReasonVisibleToGrant, asDaveHimself[0].AddressMetadata[charlieEOA],
		"counterparty must not carry the visible_to_grant/\"Shared\" label under a pseudonymous grant")
	require.Equal(t, explorer.ReasonDisclosureGrant, asDaveHimself[0].AddressMetadata[eveEOA],
		"disclosed subject should be tagged disclosure_grant")

	// The actual test — Admin views-AS Dave (subject=admin, override=Dave).
	// Neither the admin's own FULL grant nor Dave's grant applies: grants
	// belong to their grantee, never to an admin viewing as them (RD-1318).
	// Without a grant Eve is hidden from Dave's view, so her address page is
	// not found — and no form of Charlie or Eve (hex, pseudonym, grant label)
	// reaches the admin.
	w := fetch(adminDID, daveDID)
	require.Equal(t, http.StatusNotFound, w.Code, "View-as Dave without his grant: %s", w.Body.String())
	body := strings.ToLower(w.Body.String())
	for _, hiddenValue := range []string{
		strings.TrimPrefix(charlieEOA, "0x"), strings.TrimPrefix(eveEOA, "0x"),
		strings.ToLower(explorer.GeneratePseudonym(charlieEOA, nil)), strings.ToLower(explorer.GeneratePseudonym(eveEOA, nil)),
		string(explorer.ReasonDisclosureGrant),
	} {
		require.NotContainsf(t, body, hiddenValue, "View-as returned %q: %s", hiddenValue, w.Body.String())
	}
}
