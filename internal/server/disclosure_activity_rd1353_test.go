package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/disclosure"
)

func TestDisclosureApprovalMalformedBodyRD1353(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	srv := &Server{}
	router.POST("/approve/:request_id", func(c *gin.Context) { c.Set("user_id", "owner"); srv.approveDisclosureRequest(c) })
	for _, body := range []string{`{"scope":`, `{"scope":{"date_range":{"start":"bad"}}}`, `{"scope":{"methods":42}}`, `{} {}`, `{} trailing`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/approve/r", bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		require.NotPanics(t, func() { router.ServeHTTP(w, r) })
		assert.Equal(t, http.StatusBadRequest, w.Code, body)
	}
}

func TestDisclosureInvalidCreateScopeRD1353(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := newMockDisclosureStore()
	srv := &Server{disclosureService: disclosure.NewService(store)}
	router.POST("/requests", srv.createDisclosureRequest)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/requests", bytes.NewBufferString(`{"target_user_id":"target","reason":"audit","scope":{"methods":["eth_call"]}}`))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, store.requests)
}

func TestDisclosureLegacyReadEligibilityRD1353(t *testing.T) {
	srv, jwtService, database := setupTestServerForDisclosure(t)
	defer database.Close()
	ctx := context.Background()
	viewerID, _ := createTestUser(t, database, jwtService, "did:test:legacy-viewer")
	targetID, _ := createTestUser(t, database, jwtService, "did:test:legacy-target")
	orgID, _ := ensureDefaultOrgMembership(t, database, "did:test:legacy-viewer")
	router := gin.New()
	router.Use(func(c *gin.Context) {
		if c.GetHeader("X-Test-Org") != "" {
			c.Request = c.Request.WithContext(withViewerOrgScope(c.Request.Context(), c.GetHeader("X-Test-Org")))
		}
	})
	router.GET("/grants/:grant_id/logs", srv.getDisclosureLogs)
	router.GET("/grants/:grant_id/summary", srv.getDisclosureSummary)
	router.GET("/grants/:grant_id/report/:report_type", srv.getDisclosureReport)
	router.GET("/grants/:grant_id/events", srv.getDisclosureEvents)
	grantID := createDisclosureGrantWithScopeJSON(t, database, "did:test:legacy-viewer", targetID, `{"methods":["activity_logs"],"disclosure_level":"pseudonymous"}`, time.Now().Add(time.Hour))
	rawToken, hash := testTokenHash()
	_, err := database.Conn().ExecContext(ctx, `UPDATE disclosure_grants SET grant_token_hash = $1 WHERE id = $2`, hash, grantID)
	require.NoError(t, err)
	require.NoError(t, database.LogAccess(ctx, "did:test:legacy-target", "eth_call", 200, "127.0.0.1"))
	get := func(path, org string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/grants/"+grantID+path, nil)
		r.Header.Set("X-Disclosure-Token", rawToken)
		r.Header.Set("X-Test-Org", org)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/logs", "/summary", "/report/activity_summary", "/events"} {
		w := get(path, orgID)
		assert.Equal(t, http.StatusOK, w.Code, "%s: %s", path, w.Body.String())
		assert.NotContains(t, w.Body.String(), "127.0.0.1", "non-full response strips IP")
		assert.Equal(t, http.StatusNotFound, get(path, uuid.NewString()).Code, "foreign org")
	}
	var recordedViewer string
	err = database.Conn().QueryRowContext(ctx, `SELECT viewer_user_id::text FROM disclosure_events WHERE grant_id=$1 AND action='view_logs' ORDER BY accessed_at DESC LIMIT 1`, grantID).Scan(&recordedViewer)
	require.NoError(t, err)
	assert.Equal(t, viewerID, recordedViewer)

	for _, scope := range []string{`{"methods":["transaction_history"]}`, `{"methods":["activity_logs"],"addresses":["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}`} {
		_, err = database.Conn().ExecContext(ctx, `UPDATE disclosure_grants SET scope=$1 WHERE id=$2`, scope, grantID)
		require.NoError(t, err)
		for _, path := range []string{"/logs", "/summary", "/report/activity_summary"} {
			assert.Equal(t, http.StatusForbidden, get(path, orgID).Code, scope)
		}
	}
	_, err = database.Conn().ExecContext(ctx, `UPDATE disclosure_grants SET scope='{"methods":["activity_logs"]}' WHERE id=$1`, grantID)
	require.NoError(t, err)
	_, err = database.Conn().ExecContext(ctx, `UPDATE user_memberships SET expires_at=NOW()-INTERVAL '1 minute' WHERE user_id=$1`, viewerID)
	require.NoError(t, err)
	for _, path := range []string{"/logs", "/summary", "/report/activity_summary", "/events"} {
		assert.Equal(t, http.StatusNotFound, get(path, orgID).Code, "expired membership")
	}
}
