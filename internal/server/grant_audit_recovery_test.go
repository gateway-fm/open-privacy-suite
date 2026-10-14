package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Reproduce a supported admin user deletion between disclosure enumeration
// and access-event persistence, without nondeterministic goroutine timing.
func TestGrantAuditBatch_DeletedSubjectDoesNotLoseOtherAudits(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	createTestUserForExplorer(t, database, testViewerDID)
	deletedUser := createTestUserForExplorer(t, database, "did:review:deleted")
	liveUser := createTestUserForExplorer(t, database, "did:review:live")
	linkEthAddressToUser(t, database, "did:review:deleted", "0x1111111111111111111111111111111111111000")
	linkEthAddressToUser(t, database, "did:review:live", "0x2222222222222222222222222222222222222000")
	deletedGrant := createDisclosureGrantWithLevel(t, database, testViewerDID, deletedUser, disclosure.DisclosureFull, time.Now().Add(time.Hour))
	liveGrant := createDisclosureGrantWithLevel(t, database, testViewerDID, liveUser, disclosure.DisclosureFull, time.Now().Add(time.Hour))
	router := gin.New()
	router.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	router.GET("/review", func(c *gin.Context) {
		addresses, err := srv.getDisclosedAddressesForViewer(c.Request.Context(), testViewerDID)
		require.NoError(t, err)
		require.Len(t, addresses, 2)
		counts := map[string]int{}
		for _, a := range addresses {
			counts[a.GrantID]++
		}
		// This is the same storage operation used by the admin delete-user route.
		require.NoError(t, database.DeleteUser(c.Request.Context(), deletedUser))
		var remaining int
		require.NoError(t, conn.QueryRowContext(c.Request.Context(), "SELECT count(*) FROM disclosure_grants WHERE id=$1", deletedGrant).Scan(&remaining))
		require.Zero(t, remaining, "subject deletion cascades to its grant")
		srv.recordGrantListRead(c, counts)
		c.JSON(http.StatusOK, gin.H{"returned_grants": len(counts)})
	})
	req := httptest.NewRequest(http.MethodGet, "/review", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var saved int
	require.NoError(t, conn.QueryRowContext(context.Background(), "SELECT count(*) FROM disclosure_events WHERE grant_id=$1", liveGrant).Scan(&saved))
	require.Equal(t, 1, saved, "unaffected grant must retain its audit receipt")
}

func TestGrantAuditBatch_RequestCancellationKeepsAuditAttempt(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	createTestUserForExplorer(t, database, testViewerDID)
	target := createTestUserForExplorer(t, database, "did:review:cancellation")
	grant := createDisclosureGrantWithLevel(t, database, testViewerDID, target, disclosure.DisclosureFull, time.Now().Add(time.Hour))
	router := gin.New()
	router.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	router.GET("/review", func(c *gin.Context) {
		counts := map[string]int{grant: 3}
		ctx, cancel := context.WithCancel(c.Request.Context())
		cancel()
		c.Request = c.Request.WithContext(ctx)
		srv.recordGrantListRead(c, counts)
		c.JSON(http.StatusOK, gin.H{})
	})
	req := httptest.NewRequest(http.MethodGet, "/review", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var saved int
	require.NoError(t, conn.QueryRowContext(context.Background(), "SELECT count(*) FROM disclosure_events WHERE grant_id=$1", grant).Scan(&saved))
	require.Equal(t, 1, saved)
}
