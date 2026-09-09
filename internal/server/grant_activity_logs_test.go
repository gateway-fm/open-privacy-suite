package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGrantActivityRouter creates a gin router with the grant activity logs endpoint.
func setupGrantActivityRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/grant/:grant_id/activity", srv.getGrantActivityLogs)
	return router
}

// createGrantWithScope creates a disclosure grant with specific scope methods.
// The grant's granted_at is set to 1 hour in the past so that recently-seeded
// access logs (which use NOW() or NOW() - small offset) fall within the grant window.
func createGrantWithScope(t *testing.T, database *db.DB, requesterDID, targetUserID string, methods []string, expiresAt time.Time) string {
	t.Helper()
	ctx := context.Background()

	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	requestID := uuid.New().String()
	scope := `{"methods":[]}`
	if len(methods) > 0 {
		methodsJSON := "["
		for i, m := range methods {
			if i > 0 {
				methodsJSON += ","
			}
			methodsJSON += fmt.Sprintf(`"%s"`, m)
		}
		methodsJSON += "]"
		scope = fmt.Sprintf(`{"methods":%s}`, methodsJSON)
	}

	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5, 'Test grant', 'approved', NOW())`,
		requestID, requesterDID, targetUserID, defaultOrgID, scope)
	require.NoError(t, err)

	grantID := uuid.New().String()
	grantStart := time.Now().Add(-1 * time.Hour)
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		grantID, requestID, "test-hash-"+grantID, scope, grantStart, expiresAt)
	require.NoError(t, err)

	return grantID
}

// seedAccessLogs inserts access log entries for a user.
func seedAccessLogs(t *testing.T, database *db.DB, externalID string, count int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < count; i++ {
		method := "eth_call"
		if i%3 == 0 {
			method = "eth_sendTransaction"
		}
		query := fmt.Sprintf(
			`INSERT INTO access_logs (external_id, method, status_code, ip_address, created_at)
			VALUES ($1, $2, 200, '10.0.0.1', NOW() - interval '%d minutes')`, i)
		_, err := database.Conn().ExecContext(ctx, query, externalID, method)
		require.NoError(t, err)
	}
}

func TestGrantActivityLogs_HolderCanFetch(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	// Create target user with logs
	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	seedAccessLogs(t, database, testTargetDID, 5)

	// Create viewer and grant with activity_logs scope
	createTestUserForExplorer(t, database, testViewerDID)
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"activity_logs"}, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apimodels.GrantActivityLogsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 5, resp.Total)
	assert.Equal(t, 5, len(resp.Logs))
	assert.Equal(t, 25, resp.Limit)
	assert.Equal(t, 0, resp.Offset)

	// Verify all logs have required fields
	for _, log := range resp.Logs {
		assert.NotEmpty(t, log.Method)
		assert.NotZero(t, log.StatusCode)
		assert.NotEmpty(t, log.Timestamp)
	}
}

func TestGrantActivityLogs_FullDisclosureScopeAllowed(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	seedAccessLogs(t, database, testTargetDID, 3)

	createTestUserForExplorer(t, database, testViewerDID)
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"full_disclosure"}, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apimodels.GrantActivityLogsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 3, resp.Total)
}

func TestGrantActivityLogs_NonHolderGets404(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	createTestUserForExplorer(t, database, testViewerDID)
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"activity_logs"}, time.Now().Add(24*time.Hour))

	// Different DID trying to access
	otherDID := "did:privado:other_user"
	createTestUserForExplorer(t, database, otherDID)

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, otherDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Must be 404, not 403 -- prevents enumeration
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGrantActivityLogs_ExpiredGrantReturns404(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	createTestUserForExplorer(t, database, testViewerDID)

	// Grant already expired
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"activity_logs"}, time.Now().Add(-1*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGrantActivityLogs_TransactionHistoryScopeReturns403(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	createTestUserForExplorer(t, database, testViewerDID)

	// Grant with transaction_history only -- no activity_logs
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"transaction_history"}, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGrantActivityLogs_ResponseDoesNotContainSensitiveFields(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	seedAccessLogs(t, database, testTargetDID, 2)

	createTestUserForExplorer(t, database, testViewerDID)
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"activity_logs"}, time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Parse as raw JSON map to check for unexpected fields
	var raw map[string]json.RawMessage
	err := json.Unmarshal(w.Body.Bytes(), &raw)
	require.NoError(t, err)

	var logs []map[string]json.RawMessage
	err = json.Unmarshal(raw["logs"], &logs)
	require.NoError(t, err)
	require.NotEmpty(t, logs)

	for _, log := range logs {
		_, hasIPAddress := log["ip_address"]
		_, hasRequestParams := log["request_params"]
		_, hasCorrelationID := log["correlation_id"]
		_, hasEntryHash := log["entry_hash"]

		assert.False(t, hasIPAddress, "response must NOT contain ip_address")
		assert.False(t, hasRequestParams, "response must NOT contain request_params")
		assert.False(t, hasCorrelationID, "response must NOT contain correlation_id")
		assert.False(t, hasEntryHash, "response must NOT contain entry_hash")

		// Verify expected fields are present
		_, hasMethod := log["method"]
		_, hasStatusCode := log["status_code"]
		_, hasTimestamp := log["timestamp"]
		assert.True(t, hasMethod, "response must contain method")
		assert.True(t, hasStatusCode, "response must contain status_code")
		assert.True(t, hasTimestamp, "response must contain timestamp")
	}
}

func TestGrantActivityLogs_Pagination(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	seedAccessLogs(t, database, testTargetDID, 10)

	createTestUserForExplorer(t, database, testViewerDID)
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"activity_logs"}, time.Now().Add(24*time.Hour))

	// First page
	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity?limit=3&offset=0", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp1 apimodels.GrantActivityLogsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp1)
	require.NoError(t, err)
	assert.Equal(t, 10, resp1.Total)
	assert.Equal(t, 3, len(resp1.Logs))
	assert.Equal(t, 3, resp1.Limit)
	assert.Equal(t, 0, resp1.Offset)

	// Second page
	req2 := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity?limit=3&offset=3", nil)
	addBearerToken(t, req2, srv, testViewerDID)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var resp2 apimodels.GrantActivityLogsResponse
	err = json.Unmarshal(w2.Body.Bytes(), &resp2)
	require.NoError(t, err)
	assert.Equal(t, 10, resp2.Total)
	assert.Equal(t, 3, len(resp2.Logs))
	assert.Equal(t, 3, resp2.Offset)
}

func TestGrantActivityLogs_LogsWithinGrantTimeBoundsOnly(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	ctx := context.Background()

	// Create grant with explicit time bounds: granted_at = 1 hour ago, expires = 1 hour from now
	createTestUserForExplorer(t, database, testViewerDID)
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	scope := `{"methods":["activity_logs"]}`
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5, 'Test', 'approved', NOW())`,
		requestID, testViewerDID, targetUserID, defaultOrgID, scope)
	require.NoError(t, err)

	grantID := uuid.New().String()
	grantStart := time.Now().Add(-1 * time.Hour)
	grantEnd := time.Now().Add(1 * time.Hour)
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		grantID, requestID, "test-hash-"+grantID, scope, grantStart, grantEnd)
	require.NoError(t, err)

	// Old logs (2 hours ago) -- OUTSIDE grant bounds
	for i := 0; i < 3; i++ {
		_, err := database.Conn().ExecContext(ctx,
			`INSERT INTO access_logs (external_id, method, status_code, ip_address, created_at)
			VALUES ($1, 'eth_call', 200, '10.0.0.1', NOW() - interval '2 hours')`,
			testTargetDID)
		require.NoError(t, err)
	}
	// Recent logs (5 minutes ago) -- WITHIN grant bounds
	for i := 0; i < 2; i++ {
		_, err := database.Conn().ExecContext(ctx,
			`INSERT INTO access_logs (external_id, method, status_code, ip_address, created_at)
			VALUES ($1, 'eth_sendTransaction', 200, '10.0.0.1', NOW() - interval '5 minutes')`,
			testTargetDID)
		require.NoError(t, err)
	}

	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apimodels.GrantActivityLogsResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Only the 2 recent logs should be within grant time bounds
	assert.Equal(t, 2, resp.Total)
	for _, log := range resp.Logs {
		assert.Equal(t, "eth_sendTransaction", log.Method)
	}
}

func TestGrantActivityLogs_NoJWTReturns401(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	targetUserID := createTestUserForExplorer(t, database, testTargetDID)
	createTestUserForExplorer(t, database, testViewerDID)
	grantID := createGrantWithScope(t, database, testViewerDID, targetUserID,
		[]string{"activity_logs"}, time.Now().Add(24*time.Hour))

	// No bearer token
	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+grantID+"/activity", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGrantActivityLogs_NonexistentGrantReturns404(t *testing.T) {
	srv, _ := setupTestServerForExplorer(t)
	router := setupGrantActivityRouter(srv)

	fakeGrantID := uuid.New().String()
	req := httptest.NewRequest("GET", "/api/v1/explorer/grant/"+fakeGrantID+"/activity", nil)
	addBearerToken(t, req, srv, testViewerDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
