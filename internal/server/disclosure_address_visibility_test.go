package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupDisclosureVisibilityRouter creates a gin router with address endpoints
// needed for disclosure visibility tests.
func setupDisclosureVisibilityRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/addresses/:address/stats", srv.getExplorerAddressStats)
	explorerGroup.GET("/addresses/:address/transactions", srv.getExplorerAddressTransactions)
	explorerGroup.GET("/addresses/:address/is-contract", srv.getExplorerAddressIsContract)
	explorerGroup.GET("/transactions", srv.getExplorerTransactions)
	return router
}

func TestAddressStats_FullDisclosureGrantVisibility(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	// Create the address_stats table
	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	router := setupDisclosureVisibilityRouter(srv)

	// --- Actors ---
	const (
		aliceDID = "did:test:alice_disclosure_stats"
		bobDID   = "did:test:bob_disclosure_stats"

		aliceAddr = "0xaaaa000000000000000000000000000000008001"
	)

	// Alice: address owner
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	linkEthAddressToUser(t, database, aliceDID, aliceAddr)

	// Bob: disclosure grant recipient
	createTestUserForExplorer(t, database, bobDID)

	// Seed explorer data for Alice's address
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_disclosure_stats_1", aliceAddr, "0x0000000000000000000000000000000000000001")
	block2 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block2, "0xtx_disclosure_stats_2", "0x0000000000000000000000000000000000000001", aliceAddr)

	_, err = conn.ExecContext(ctx,
		`INSERT INTO address_stats (address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract)
		 VALUES ($1, 2, 0, 0, 1000, 2000, false)`, aliceAddr)
	require.NoError(t, err)

	t.Run("anonymous viewer gets 404 for hidden address", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/stats", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("bob without grant gets 404 for hidden address", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/stats", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("bob with pseudonymous grant cannot access address stats", func(t *testing.T) {
		createDisclosureGrantWithLevel(t, database, bobDID, aliceUserID,
			disclosure.DisclosurePseudonymous, time.Now().Add(24*time.Hour))

		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/stats", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code, "a disclosure grant cannot upgrade ordinary address access")
	})

	t.Run("bob with full grant cannot access address stats", func(t *testing.T) {
		createDisclosureGrantWithLevel(t, database, bobDID, aliceUserID,
			disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/stats", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code, "a disclosure grant cannot upgrade ordinary address access")

	})

	t.Run("alice can access her own address stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/stats", nil)
		addBearerToken(t, req, srv, aliceDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestAddressTransactions_FullDisclosureGrantVisibility verifies that the
// address transactions endpoint respects full disclosure grants.
func TestAddressTransactions_FullDisclosureGrantVisibility(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)

	router := setupDisclosureVisibilityRouter(srv)

	const (
		aliceDID = "did:test:alice_disclosure_txs"
		bobDID   = "did:test:bob_disclosure_txs"

		aliceAddr = "0xaaaa000000000000000000000000000000008101"
	)

	// Alice: address owner
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	linkEthAddressToUser(t, database, aliceDID, aliceAddr)

	// Bob: will get disclosure grant
	createTestUserForExplorer(t, database, bobDID)

	// Seed a transaction for Alice's address
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_disclosure_txs_1", aliceAddr, "0x0000000000000000000000000000000000000001")

	t.Run("bob without grant gets 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/transactions", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("bob with full grant cannot access address transactions", func(t *testing.T) {
		createDisclosureGrantWithLevel(t, database, bobDID, aliceUserID,
			disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/transactions", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code, "a disclosure grant cannot upgrade ordinary address access")

	})
}

// TestAddressIsContract_FullDisclosureGrantVisibility verifies the is-contract
// endpoint also respects full disclosure grants.
func TestAddressIsContract_FullDisclosureGrantVisibility(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	// The is-contract endpoint queries address_stats as a fallback, so we
	// need the table to exist.
	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	router := setupDisclosureVisibilityRouter(srv)

	const (
		aliceDID = "did:test:alice_disclosure_iscontract"
		bobDID   = "did:test:bob_disclosure_iscontract"

		aliceAddr = "0xaaaa000000000000000000000000000000008201"
	)

	// Alice: address owner
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	linkEthAddressToUser(t, database, aliceDID, aliceAddr)

	// Bob: will get disclosure grant
	createTestUserForExplorer(t, database, bobDID)

	t.Run("bob without grant gets 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/is-contract", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("bob with full grant cannot check is-contract", func(t *testing.T) {
		createDisclosureGrantWithLevel(t, database, bobDID, aliceUserID,
			disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+aliceAddr+"/is-contract", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code, "a disclosure grant cannot upgrade ordinary address access")
	})
}

// Disclosure grants do not upgrade the general transaction list.
func TestDisclosureGrantsInvisibleInTransactionLists(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)

	router := setupDisclosureVisibilityRouter(srv)

	const (
		aliceDID = "did:test:alice_g17"
		bobDID   = "did:test:bob_g17"

		aliceAddr = "0xaaaa000000000000000000000000000000008301"
	)

	// Alice: address owner with linked address
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	linkEthAddressToUser(t, database, aliceDID, aliceAddr)

	// Bob: disclosure grant recipient
	createTestUserForExplorer(t, database, bobDID)

	// Create full disclosure grant from Bob on Alice
	createDisclosureGrantWithLevel(t, database, bobDID, aliceUserID,
		disclosure.DisclosureFull, time.Now().Add(24*time.Hour))

	// Seed a transaction involving Alice's address
	block1 := seedExplorerBlock(t, conn)
	seedExplorerTransaction(t, conn, block1, "0xtx_g17_test", aliceAddr, "0x0000000000000000000000000000000000000001")

	t.Run("transaction list shows disclosed address txs with grant", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions?limit=100", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var txs []explorer.Transaction
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &txs))

		// Bob must not see Alice's transaction through the regular API.
		found := false
		for _, tx := range txs {
			if tx.Hash == "0xtx_g17_test" {
				found = true
				break
			}
		}
		assert.False(t, found, "disclosed transactions must stay outside the regular transaction list")
	})

	t.Run("viewer without grant does not see hidden address txs", func(t *testing.T) {
		const daveDID = "did:test:dave_no_grant"
		createTestUserForExplorer(t, database, daveDID)

		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions?limit=100", nil)
		addBearerToken(t, req, srv, daveDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var txs []explorer.Transaction
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &txs))

		for _, tx := range txs {
			assert.NotEqual(t, "0xtx_g17_test", tx.Hash,
				"viewer without grant should NOT see hidden address txs")
		}
	})
}
