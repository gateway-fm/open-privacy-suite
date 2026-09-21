package server

// Tests that exercise the nil explorerStore early-return path in all explorer
// handlers.  When explorerStore is nil the server returns 503 before touching
// the DB, so no database setup is needed.
//
// These tests ensure:
//   1. Every store-backed handler is covered (nil-check path).
//   2. getExplorerChainID (no nil-check) is fully covered.
//   3. getViewerDIDFromRequest helper is covered.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// buildNilStoreRouter creates a gin router wired to a zero-value Server
// (explorerStore is nil). Middleware is intentionally skipped.
func buildNilStoreRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	srv := &Server{} // explorerStore is nil

	r := gin.New()
	g := r.Group("/api/v1/explorer")

	// Always-available (no nil store check)
	g.GET("/chain-id", srv.getExplorerChainID)

	// Store-backed — all return 503 when store is nil
	g.GET("/stats", srv.getExplorerStats)
	g.GET("/stats/tx-history", srv.getExplorerTransactionHistory)

	g.GET("/blocks", srv.getExplorerBlocks)
	g.GET("/blocks/latest/number", srv.getExplorerLatestBlockNumber)
	g.GET("/blocks/hash/:hash", srv.getExplorerBlockByHash)
	g.GET("/blocks/:number", srv.getExplorerBlock)
	g.GET("/blocks/:number/transactions", srv.getExplorerBlockTransactions)
	g.GET("/blocks/:number/internal", srv.getExplorerBlockInternalTxs)

	g.GET("/transactions", srv.getExplorerTransactions)
	g.GET("/transactions/paginated", srv.getExplorerTransactionsPaginated)
	g.GET("/transactions/:hash", srv.getExplorerTransaction)
	g.GET("/transactions/:hash/internal", srv.getExplorerTransactionInternal)
	g.GET("/transactions/:hash/transfers", srv.getExplorerTransactionTransfers)
	g.GET("/transactions/:hash/logs", srv.getExplorerTransactionLogs)
	g.GET("/transactions/:hash/op-deposit", srv.getExplorerTransactionOPDeposit)

	g.GET("/addresses/:address/stats", srv.getExplorerAddressStats)
	g.GET("/addresses/:address/transactions", srv.getExplorerAddressTransactions)
	g.GET("/addresses/:address/balance", srv.getExplorerAddressBalance)
	g.GET("/addresses/:address/code", srv.getExplorerAddressCode)
	g.GET("/addresses/:address/balances", srv.getExplorerAddressTokenBalances)
	g.GET("/addresses/:address/transfers", srv.getExplorerAddressTransfers)
	g.GET("/addresses/:address/internal", srv.getExplorerAddressInternal)
	g.GET("/addresses/:address/logs", srv.getExplorerAddressLogs)
	g.GET("/addresses/:address/contract", srv.getExplorerAddressContract)
	g.GET("/addresses/:address/is-contract", srv.getExplorerAddressIsContract)

	g.GET("/logs", srv.getExplorerLogs)

	g.GET("/tokens", srv.getExplorerTokens)
	g.GET("/tokens/:address", srv.getExplorerToken)
	g.GET("/tokens/:address/holders", srv.getExplorerTokenHolders)
	g.GET("/tokens/:address/transfers", srv.getExplorerTokenTransfers)

	g.GET("/transfers", srv.getExplorerAllTransfers)
	g.GET("/accounts", srv.getExplorerAccounts)
	g.GET("/search/suggestions", srv.getExplorerSearchSuggestions)

	g.GET("/sync/status", srv.getExplorerSyncStatus)
	g.GET("/sync/indexer-progress", srv.getExplorerIndexerProgress)
	g.GET("/sync/catchup", srv.getExplorerCatchupProgress)

	g.POST("/index/block/:number", srv.indexExplorerBlock)

	return r
}

func doRequest(t *testing.T, router *gin.Engine, method, path string, expectedStatus int) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != expectedStatus {
		t.Errorf("%s %s: expected status %d, got %d (body: %s)",
			method, path, expectedStatus, w.Code, w.Body.String())
	}
}

func TestExplorerHandlers_AlwaysAvailable(t *testing.T) {
	r := buildNilStoreRouter()
	// These handlers have no explorerStore nil-check — they always respond.
	doRequest(t, r, http.MethodGet, "/api/v1/explorer/chain-id", http.StatusOK)
	doRequest(t, r, http.MethodGet, "/api/v1/explorer/sync/catchup", http.StatusOK)
	doRequest(t, r, http.MethodGet, "/api/v1/explorer/transactions/0xabc/op-deposit", http.StatusNotFound)
	doRequest(t, r, http.MethodPost, "/api/v1/explorer/index/block/1", http.StatusInternalServerError)
}

func TestExplorerHandlers_NilStore_Returns503(t *testing.T) {
	r := buildNilStoreRouter()

	addr := "0x1234567890123456789012345678901234567890"
	hash := "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
	num := "42"

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/explorer/stats"},
		{http.MethodGet, "/api/v1/explorer/stats/tx-history"},
		{http.MethodGet, "/api/v1/explorer/blocks"},
		{http.MethodGet, "/api/v1/explorer/blocks/latest/number"},
		{http.MethodGet, "/api/v1/explorer/blocks/hash/" + hash},
		{http.MethodGet, "/api/v1/explorer/blocks/" + num},
		{http.MethodGet, "/api/v1/explorer/blocks/" + num + "/transactions"},
		{http.MethodGet, "/api/v1/explorer/blocks/" + num + "/internal"},
		{http.MethodGet, "/api/v1/explorer/transactions"},
		{http.MethodGet, "/api/v1/explorer/transactions/paginated"},
		{http.MethodGet, "/api/v1/explorer/transactions/" + hash},
		{http.MethodGet, "/api/v1/explorer/transactions/" + hash + "/internal"},
		{http.MethodGet, "/api/v1/explorer/transactions/" + hash + "/transfers"},
		{http.MethodGet, "/api/v1/explorer/transactions/" + hash + "/logs"},
		// op-deposit is always 404 (no nil check) — tested separately above
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/stats"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/transactions"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/balance"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/code"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/balances"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/transfers"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/internal"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/logs"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/contract"},
		{http.MethodGet, "/api/v1/explorer/addresses/" + addr + "/is-contract"},
		{http.MethodGet, "/api/v1/explorer/logs"},
		{http.MethodGet, "/api/v1/explorer/tokens"},
		{http.MethodGet, "/api/v1/explorer/tokens/" + addr},
		{http.MethodGet, "/api/v1/explorer/tokens/" + addr + "/holders"},
		{http.MethodGet, "/api/v1/explorer/tokens/" + addr + "/transfers"},
		{http.MethodGet, "/api/v1/explorer/transfers"},
		{http.MethodGet, "/api/v1/explorer/accounts"},
		{http.MethodGet, "/api/v1/explorer/search/suggestions"},
		{http.MethodGet, "/api/v1/explorer/sync/status"},
		{http.MethodGet, "/api/v1/explorer/sync/indexer-progress"},
		// sync/catchup and index/block are always available — tested separately above
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			doRequest(t, r, ep.method, ep.path, http.StatusServiceUnavailable)
		})
	}
}

// TestExplorerHandlers_GetViewerDID_NoAuth verifies the DID helper returns
// empty string when no JWT context is present.
func TestExplorerHandlers_GetViewerDID_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &Server{}
	r := gin.New()
	r.GET("/probe", func(c *gin.Context) {
		did := srv.getViewerDIDFromRequest(c)
		c.JSON(http.StatusOK, gin.H{"did": did})
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"did":""`) {
		t.Errorf("expected empty DID, got %s", w.Body.String())
	}
}
