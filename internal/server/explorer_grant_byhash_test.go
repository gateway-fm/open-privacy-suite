package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// setupByHashGrantRouter wires the surfaces exercised in this file:
//   - /transactions/:hash (by-hash, the CTO-reported reproducer)
//   - /transactions       (list — confirms row-survival agrees with by-hash)
//   - /transactions/:hash/transfers / /internal (cross-redactor invariant)
func setupByHashGrantRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/transactions", srv.getExplorerTransactions)
	explorerGroup.GET("/transactions/:hash", srv.getExplorerTransaction)
	explorerGroup.GET("/transactions/:hash/transfers", srv.getExplorerTransactionTransfers)
	explorerGroup.GET("/transactions/:hash/internal", srv.getExplorerTransactionInternal)
	return router
}

// Every disclosure level leaves ordinary by-hash and list reads hidden;
// ordinary reads also do not emit disclosure reveal audit entries.
func TestExplorerByHash_DisclosureGrant_AllLevelsReturn404(t *testing.T) {
	for _, level := range []disclosure.DisclosureLevel{disclosure.DisclosureFull, disclosure.DisclosurePseudonymous, disclosure.DisclosureRedacted} {
		t.Run(string(level), func(t *testing.T) {
			srv, database, conn := setupTestServerForExplorerTransactions(t)
			router := setupByHashGrantRouter(srv)
			const viewer = "did:rd1353:auditor"
			const target = "did:rd1353:target"
			const address = "0xbbbb000000000000000000000000000000000099"
			createTestUserForExplorer(t, database, viewer)
			uid := createTestUserForExplorer(t, database, target)
			linkEthAddressToUser(t, database, target, address)
			createDisclosureGrantWithLevel(t, database, viewer, uid, level, time.Now().Add(time.Hour))
			hash := "0xbyhash_" + string(level)
			seedExplorerTransaction(t, conn, seedExplorerBlock(t, conn), hash, address, "0xcccc000000000000000000000000000000000099")
			before := countDisclosureGrantAuditEntries(t, database, viewer)
			for _, path := range []string{"/transactions/" + hash, "/transactions"} {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer"+path, nil)
				addBearerToken(t, req, srv, viewer)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if path == "/transactions" {
					require.Equal(t, http.StatusOK, w.Code)
					require.Empty(t, parseTransactionsResponse(t, w.Body.Bytes()))
				} else {
					require.Equal(t, http.StatusNotFound, w.Code)
				}
			}
			require.Equal(t, before, countDisclosureGrantAuditEntries(t, database, viewer))
		})
	}
}

// countDisclosureGrantAuditEntries returns the number of rbac_audit_log
// rows with resource_type=disclosure_grant and the given actor. Used to
// diff audit emission across by-hash assertions.
func countDisclosureGrantAuditEntries(t *testing.T, database *db.DB, actorDID string) int {
	t.Helper()
	row := database.Conn().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM rbac_audit_log WHERE resource_type = $1 AND actor_external_id = $2`,
		rbac.ResourceTypeDisclosureGrant, actorDID)
	var n int
	require.NoError(t, row.Scan(&n))
	return n
}
