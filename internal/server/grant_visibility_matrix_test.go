package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGrantVisibilityMatrixRouter creates a gin router with all grant-related endpoints
// needed for the G01-G21 visibility matrix tests.
func setupGrantVisibilityMatrixRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/grant/:grant_id/resolve/:address_id", srv.resolveAddressID)
	explorerGroup.GET("/grant/:grant_id/:address_id/transactions", srv.getGrantTransactions)
	explorerGroup.GET("/grant/:grant_id/activity", srv.getGrantActivityLogs)
	return router
}

// grantSetup holds all the IDs and tokens needed to exercise a single disclosure grant.
type grantSetup struct {
	GrantID      string
	AddressID    string // HMAC(targetAddr, grantID)
	RequesterDID string
	TargetDID    string
	TargetAddr   string
}

// createFullDisclosureGrant creates a disclosure grant with both scope methods and disclosure level.
// This is the test helper needed for G01-G05 which require specifying both fields.
func createFullDisclosureGrant(
	t *testing.T,
	srv *Server,
	methods []string,
	level disclosure.DisclosureLevel,
	expiresAt time.Time,
) grantSetup {
	t.Helper()
	database := srv.db
	ctx := context.Background()

	// Use unique DIDs per grant to avoid cross-test contamination.
	suffix := uuid.New().String()[:8]
	requesterDID := fmt.Sprintf("did:test:requester_%s", suffix)
	targetDID := fmt.Sprintf("did:test:target_%s", suffix)
	targetAddr := fmt.Sprintf("0x%040s", strings.ReplaceAll(suffix, "-", "")+"aabb00112233445566778899001122334455")[:42]

	// Create users
	createTestUserForExplorer(t, database, requesterDID)
	targetUserID := createTestUserForExplorer(t, database, targetDID)
	linkEthAddressToUser(t, database, targetDID, targetAddr)

	// Ensure default org exists
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// Build scope JSON with both methods and disclosure_level
	methodsJSON := "[]"
	if len(methods) > 0 {
		parts := make([]string, len(methods))
		for i, m := range methods {
			parts[i] = fmt.Sprintf(`"%s"`, m)
		}
		methodsJSON = "[" + strings.Join(parts, ",") + "]"
	}
	scope := fmt.Sprintf(`{"methods":%s,"disclosure_level":"%s"}`, methodsJSON, level)

	// Create disclosure request
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5, 'Test grant for visibility matrix', 'approved', NOW())`,
		requestID, requesterDID, targetUserID, defaultOrgID, scope)
	require.NoError(t, err)

	// Create grant — granted_at 1 hour in the past so seeded logs fall within bounds
	grantID := uuid.New().String()
	grantStart := time.Now().Add(-1 * time.Hour)
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		grantID, requestID, "test-hash-"+grantID, scope, grantStart, expiresAt)
	require.NoError(t, err)

	addressID := explorer.GenerateAddressID(targetAddr, grantID)

	return grantSetup{
		GrantID:      grantID,
		AddressID:    addressID,
		RequesterDID: requesterDID,
		TargetDID:    targetDID,
		TargetAddr:   targetAddr,
	}
}

// ============================================================================
// G01-G05: Grant Page Tab Behavior (resolve + transactions + activity)
// ============================================================================

func TestGrantVisibilityMatrix(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupGrantVisibilityMatrixRouter(srv)

	// ----------------------------------------------------------------
	// G01: activity_logs scope, full level
	// ----------------------------------------------------------------
	t.Run("G01_ActivityLogs_Full", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"activity_logs"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		// Seed activity logs for the target
		seedAccessLogs(t, database, gs.TargetDID, 3)

		// Seed transactions for the target address
		externalAddr := "0xeeee000000000000000000000000000000000101"
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, "0xtx_g01_"+gs.GrantID[:8], gs.TargetAddr, externalAddr)

		// --- Resolve ---
		t.Run("Resolve", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.ResolveAddressResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "full", resp.DisclosureLevel)
			assert.Contains(t, resp.ScopeMethods, "activity_logs")
			require.NotNil(t, resp.RealAddress, "full level should expose real address")
			assert.Equal(t, gs.TargetAddr, *resp.RealAddress)
		})

		// --- Transactions ---
		// The grant transactions endpoint does NOT check scope methods; it only uses disclosure_level.
		// With full level and activity_logs scope, the transactions endpoint still returns data.
		// The UI is responsible for hiding/showing the tab based on scope_methods from resolve.
		t.Run("Transactions_200_FullLevel", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "full", resp.DisclosureLevel)
			// Full level shows real addresses
			for _, tx := range resp.Transactions {
				assert.NotNil(t, tx.TxHash, "full level should include tx hash")
			}
		})

		// --- Activity Logs ---
		t.Run("Activity_200", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantActivityLogsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.GreaterOrEqual(t, resp.Total, 3,
				"activity_logs scope should allow fetching logs")
		})
	})

	// ----------------------------------------------------------------
	// G02: full_disclosure scope, redacted level
	// ----------------------------------------------------------------
	t.Run("G02_FullDisclosure_Redacted", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"full_disclosure"}, disclosure.DisclosureRedacted,
			time.Now().Add(24*time.Hour))

		seedAccessLogs(t, database, gs.TargetDID, 2)

		// --- Resolve ---
		t.Run("Resolve", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.ResolveAddressResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "redacted", resp.DisclosureLevel)
			assert.Contains(t, resp.ScopeMethods, "full_disclosure")
			assert.Nil(t, resp.RealAddress, "redacted level must NOT expose real address")
			// Raw body must not contain the real address
			assert.NotContains(t, w.Body.String(), gs.TargetAddr,
				"SECURITY: real address must not appear in redacted resolve response")
		})

		// --- Transactions (redacted = txs visible, all addresses [PRIVATE]) ---
		t.Run("Transactions_200_PrivatePlaceholders", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "redacted", resp.DisclosureLevel)
			// No tx seeding here — body is empty by chance, not by short-circuit.
			// The level-correctness assertions live in the dedicated redacted tests
			// (TestGrantTransactions_RedactedDisclosure, RedactedGrant_*).
			assert.NotContains(t, w.Body.String(), gs.TargetAddr,
				"real address must not appear in redacted response")
		})

		// --- Activity Logs (full_disclosure scope includes activity) ---
		t.Run("Activity_200", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantActivityLogsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.GreaterOrEqual(t, resp.Total, 2,
				"full_disclosure scope should allow fetching activity logs")
		})
	})

	// ----------------------------------------------------------------
	// G03: full_disclosure scope, full level
	// ----------------------------------------------------------------
	t.Run("G03_FullDisclosure_Full", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"full_disclosure"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		seedAccessLogs(t, database, gs.TargetDID, 2)

		externalAddr := "0xeeee000000000000000000000000000000000301"
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, "0xtx_g03_"+gs.GrantID[:8], gs.TargetAddr, externalAddr)

		// --- Resolve ---
		t.Run("Resolve", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.ResolveAddressResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "full", resp.DisclosureLevel)
			assert.Contains(t, resp.ScopeMethods, "full_disclosure")
			require.NotNil(t, resp.RealAddress)
			assert.Equal(t, gs.TargetAddr, *resp.RealAddress)
		})

		// --- Transactions (full = real addresses) ---
		t.Run("Transactions_200_RealAddresses", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "full", resp.DisclosureLevel)
			require.NotEmpty(t, resp.Transactions)
			for _, tx := range resp.Transactions {
				assert.NotNil(t, tx.TxHash, "full disclosure should include tx hash")
				assert.NotEqual(t, "hidden", tx.Value, "full disclosure should show real values")
				assert.False(t, strings.HasPrefix(tx.From, "Address-"),
					"full disclosure should use real addresses, got %s", tx.From)
				assert.False(t, strings.HasPrefix(tx.From, "External-"),
					"full disclosure should use real addresses, got %s", tx.From)
			}
		})

		// --- Activity Logs ---
		t.Run("Activity_200", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantActivityLogsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.GreaterOrEqual(t, resp.Total, 2)
		})
	})

	// ----------------------------------------------------------------
	// G04: transaction_history scope, full level
	// ----------------------------------------------------------------
	t.Run("G04_TransactionHistory_Full", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"transaction_history"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		seedAccessLogs(t, database, gs.TargetDID, 2)

		externalAddr := "0xeeee000000000000000000000000000000000401"
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, "0xtx_g04_"+gs.GrantID[:8], gs.TargetAddr, externalAddr)

		// --- Resolve ---
		t.Run("Resolve", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.ResolveAddressResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "full", resp.DisclosureLevel)
			assert.Contains(t, resp.ScopeMethods, "transaction_history")
		})

		// --- Transactions (full level = real data) ---
		t.Run("Transactions_200", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "full", resp.DisclosureLevel)
			assert.NotEmpty(t, resp.Transactions)
		})

		// --- Activity Logs (403 — wrong scope) ---
		t.Run("Activity_403_WrongScope", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code,
				"transaction_history scope must NOT allow activity log access")
		})
	})

	// ----------------------------------------------------------------
	// G05: transaction_history scope, pseudonymous level
	// ----------------------------------------------------------------
	t.Run("G05_TransactionHistory_Pseudonymous", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"transaction_history"}, disclosure.DisclosurePseudonymous,
			time.Now().Add(24*time.Hour))

		externalAddr := "0xeeee000000000000000000000000000000000501"
		block := seedExplorerBlock(t, conn)
		seedExplorerTransaction(t, conn, block, "0xtx_g05_"+gs.GrantID[:8], gs.TargetAddr, externalAddr)

		// --- Resolve ---
		t.Run("Resolve", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.ResolveAddressResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "pseudonymous", resp.DisclosureLevel)
			assert.Contains(t, resp.ScopeMethods, "transaction_history")
			assert.Nil(t, resp.RealAddress,
				"SECURITY: pseudonymous must NOT expose real address in resolve")
			assert.NotEmpty(t, resp.Pseudonym)
			assert.NotContains(t, w.Body.String(), gs.TargetAddr,
				"SECURITY: real address must not appear in pseudonymous response body")
		})

		// --- Transactions (pseudonymous = pseudonymized addresses) ---
		t.Run("Transactions_200_Pseudonymized", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			var resp apimodels.GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			assert.Equal(t, "pseudonymous", resp.DisclosureLevel)
			require.NotEmpty(t, resp.Transactions)

			// Values should be hidden, tx hashes absent
			for _, tx := range resp.Transactions {
				assert.Nil(t, tx.TxHash,
					"pseudonymous should NOT include tx hash")
				assert.Equal(t, "hidden", tx.Value,
					"pseudonymous should hide value")
			}

			// SECURITY: Real addresses must not appear in the response body
			body := w.Body.String()
			assert.NotContains(t, body, gs.TargetAddr,
				"SECURITY: real target address must not leak in pseudonymous mode")
			assert.NotContains(t, body, externalAddr,
				"SECURITY: real external address must not leak in pseudonymous mode")

			// Check pseudonym labels
			disclosedPseudonym := explorer.GeneratePseudonym(gs.TargetAddr, nil)
			assert.Equal(t, "disclosed", resp.AddressLabels[disclosedPseudonym])
		})

		// --- Activity Logs (403 — wrong scope) ---
		t.Run("Activity_403_WrongScope", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code,
				"transaction_history scope must NOT allow activity log access")
		})
	})

	// ----------------------------------------------------------------
	// G14: Missing address stats (EOA with no explorer data)
	// ----------------------------------------------------------------
	t.Run("G14_MissingAddressStats_NoError", func(t *testing.T) {
		// Create a grant for an EOA that has NO transactions or stats in the explorer DB.
		gs := createFullDisclosureGrant(t, srv,
			[]string{"full_disclosure"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		// Do NOT seed any transactions for gs.TargetAddr.

		// Resolve should still succeed (it only looks up the address in the Open Privacy Suite DB).
		t.Run("Resolve_200", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code,
				"resolve must succeed even if address has no explorer stats")
			var resp apimodels.ResolveAddressResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "full", resp.DisclosureLevel)
			require.NotNil(t, resp.RealAddress)
		})

		// Transactions should return 200 with empty list (not 500).
		t.Run("Transactions_200_Empty", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code,
				"grant transactions for EOA with no history must return 200, not 500")
			var resp apimodels.GrantTransactionsResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Empty(t, resp.Transactions)
			assert.Empty(t, resp.NextCursor, "exhausted feed omits next_cursor (RD-1149, token-only)")
		})
	})

	// ----------------------------------------------------------------
	// G15: Expired grant
	// ----------------------------------------------------------------
	t.Run("G15_ExpiredGrant", func(t *testing.T) {
		// Create a grant that has already expired.
		gs := createFullDisclosureGrant(t, srv,
			[]string{"full_disclosure"}, disclosure.DisclosureFull,
			time.Now().Add(-1*time.Hour)) // expired 1 hour ago

		// Resolve should fail
		t.Run("Resolve_Forbidden", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// resolveAddressID returns 403 for expired grants
			assert.Equal(t, http.StatusForbidden, w.Code,
				"expired grant should be rejected by resolve")
			assert.Contains(t, w.Body.String(), "expired")
		})

		// Activity logs should fail
		t.Run("Activity_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code,
				"expired grant should return 404 for activity logs")
		})

		// Transactions should fail
		t.Run("Transactions_Forbidden", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code,
				"expired grant should be rejected by transactions endpoint")
			assert.Contains(t, w.Body.String(), "expired")
		})
	})

	// ----------------------------------------------------------------
	// Additional edge cases derived from the matrix
	// ----------------------------------------------------------------

	// Verify that scope_methods is correctly serialized in resolve responses
	// when multiple methods are present.
	t.Run("Resolve_MultipleScopes", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"transaction_history", "activity_logs"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		req := httptest.NewRequest("GET",
			"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
		addBearerToken(t, req, srv, gs.RequesterDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		var resp apimodels.ResolveAddressResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		assert.Equal(t, "full", resp.DisclosureLevel)
		assert.Contains(t, resp.ScopeMethods, "transaction_history")
		assert.Contains(t, resp.ScopeMethods, "activity_logs")
		assert.Len(t, resp.ScopeMethods, 2)
	})

	// Verify that a non-holder viewer gets uniform 404 (not 403) for activity logs
	// to prevent grant enumeration (G08).
	t.Run("G08_NonHolder_Activity_404", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"activity_logs"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		// Create a different user who is NOT the grant holder
		strangerDID := "did:test:stranger_" + uuid.New().String()[:8]
		createTestUserForExplorer(t, database, strangerDID)

		req := httptest.NewRequest("GET",
			"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
		addBearerToken(t, req, srv, strangerDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"non-holder must get 404, not 403, to prevent enumeration")
	})

	// Verify that anonymous (no JWT) gets 401 for activity logs.
	t.Run("Activity_NoJWT_401", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"activity_logs"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		req := httptest.NewRequest("GET",
			"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
		// No bearer token
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// Verify revoked grant is rejected across all endpoints.
	t.Run("RevokedGrant_AllEndpoints", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"full_disclosure"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		// Revoke the grant
		ctx := context.Background()
		_, err := database.Conn().ExecContext(ctx,
			"UPDATE disclosure_grants SET revoked_at = NOW(), revoked_reason = 'test revocation' WHERE id = $1",
			gs.GrantID)
		require.NoError(t, err)

		t.Run("Resolve_Forbidden", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+gs.AddressID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.Contains(t, w.Body.String(), "revoked")
		})

		t.Run("Transactions_Forbidden", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+gs.AddressID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.Contains(t, w.Body.String(), "revoked")
		})

		t.Run("Activity_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/activity", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Activity endpoint returns 404 for expired/revoked (anti-enumeration)
			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	})

	// Verify nonexistent grant returns 404 for all endpoints.
	t.Run("NonexistentGrant_AllEndpoints", func(t *testing.T) {
		fakeGrant := uuid.New().String()
		fakeAddr := "deadbeef12345678"

		viewerDID := "did:test:nonexist_viewer_" + uuid.New().String()[:8]
		createTestUserForExplorer(t, database, viewerDID)

		t.Run("Resolve_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+fakeGrant+"/resolve/"+fakeAddr, nil)
			addBearerToken(t, req, srv, viewerDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)
		})

		t.Run("Transactions_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+fakeGrant+"/"+fakeAddr+"/transactions", nil)
			addBearerToken(t, req, srv, viewerDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)
		})

		t.Run("Activity_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+fakeGrant+"/activity", nil)
			addBearerToken(t, req, srv, viewerDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	})

	// Verify that wrong address_id for a valid grant returns 404 (not 500).
	t.Run("WrongAddressID_404", func(t *testing.T) {
		gs := createFullDisclosureGrant(t, srv,
			[]string{"full_disclosure"}, disclosure.DisclosureFull,
			time.Now().Add(24*time.Hour))

		wrongAddrID := "abcdef0123456789"

		t.Run("Resolve_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/resolve/"+wrongAddrID, nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Contains(t, w.Body.String(), "address not found")
		})

		t.Run("Transactions_404", func(t *testing.T) {
			req := httptest.NewRequest("GET",
				"/api/v1/explorer/grant/"+gs.GrantID+"/"+wrongAddrID+"/transactions", nil)
			addBearerToken(t, req, srv, gs.RequesterDID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Contains(t, w.Body.String(), "address not found")
		})
	})
}
