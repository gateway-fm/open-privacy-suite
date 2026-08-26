package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1242: the wallet and the browser are different HTTP clients. A rejected
// proof used to leave the session pending, so the browser polled for five
// minutes and then claimed a timeout. These tests pin the status endpoint
// reporting the rejection instead.

func statusOf(t *testing.T, srv *Server, sessionID string) (int, SessionStatusResponse) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auth/session/:id/status", srv.handleAuthSessionStatus)

	req := httptest.NewRequest("GET", "/api/v1/auth/session/"+sessionID+"/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var body SessionStatusResponse
	if w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	}
	return w.Code, body
}

func TestHandleAuthSessionStatus_ReportsFailure(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	sessionID := srv.sessionStore.CreateSession(nil)
	require.NotEmpty(t, sessionID)

	// Pending: no failure reported yet.
	code, body := statusOf(t, srv, sessionID)
	require.Equal(t, http.StatusOK, code)
	require.False(t, body.Failed)
	require.False(t, body.Completed)

	require.NoError(t, srv.sessionStore.FailSession(sessionID, AuthFailVerification))

	code, body = statusOf(t, srv, sessionID)
	require.Equal(t, http.StatusOK, code)
	assert.True(t, body.Failed, "a rejected proof must be reported so the browser stops polling")
	assert.False(t, body.Completed)
	assert.Equal(t, AuthFailVerification, body.Reason)
	assert.Nil(t, body.Tokens, "a failed session must never carry tokens")
}

// The wire reason goes through the closed allowlist, so an oracle-sensitive or
// unexpected internal code must not reach the poller.
func TestHandleAuthSessionStatus_CollapsesSensitiveReason(t *testing.T) {
	tests := []struct {
		name   string
		stored string
		want   string
	}{
		{"ban state collapses", AuthFailAccountBanned, AuthFailWireGeneric},
		{"internal error collapses", AuthFailInternalError, AuthFailWireGeneric},
		{"raw error text collapses", "dial tcp 10.0.0.5:8545: connection refused", AuthFailWireGeneric},
		{"humanity passes through", AuthFailHumanityRequired, AuthFailHumanityRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := setupTestServerForAuth(t)
			defer srv.db.Close()

			sessionID := srv.sessionStore.CreateSession(nil)
			require.NotEmpty(t, sessionID)
			require.NoError(t, srv.sessionStore.FailSession(sessionID, tt.stored))

			code, body := statusOf(t, srv, sessionID)
			require.Equal(t, http.StatusOK, code)
			assert.True(t, body.Failed)
			assert.Equal(t, tt.want, body.Reason)
			assert.NotContains(t, body.Reason, "10.0.0.5",
				"internal detail must never reach the poller")
		})
	}
}

// A wallet retry that succeeds must still deliver tokens, even though an
// earlier attempt was recorded as failed.
func TestHandleAuthSessionStatus_SuccessAfterFailureWins(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	sessionID := srv.sessionStore.CreateSession(nil)
	require.NotEmpty(t, sessionID)
	require.NoError(t, srv.sessionStore.FailSession(sessionID, AuthFailInternalError))

	subject := "did:privado:retry-after-transient-failure"
	accessToken, err := jwtService.IssueAccessToken(subject, true)
	require.NoError(t, err)
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)
	require.NoError(t, srv.sessionStore.CompleteSession(sessionID, accessToken, refreshToken))

	code, body := statusOf(t, srv, sessionID)
	require.Equal(t, http.StatusOK, code)
	assert.True(t, body.Completed)
	assert.False(t, body.Failed, "a successful retry must supersede the recorded failure")
	assert.Empty(t, body.Reason)
	require.NotNil(t, body.Tokens)
	assert.Equal(t, accessToken, body.Tokens.AccessToken)
}

// Failure must not become a way to distinguish "exists" from "does not exist":
// an unknown session ID keeps returning 404, as before.
func TestHandleAuthSessionStatus_UnknownSessionStill404(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	code, _ := statusOf(t, srv, "11111111-2222-3333-4444-555555555555")
	assert.Equal(t, http.StatusNotFound, code)
}

// A malformed wallet callback is recorded on the session too — otherwise the
// browser waits out the poll budget for a request that was rejected instantly.
func TestHandleAuthCallback_MalformedBodyFailsSession(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	sessionID := srv.sessionStore.CreateSession(nil)
	require.NotEmpty(t, sessionID)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/auth/callback", srv.handleAuthCallback)

	req := httptest.NewRequest("POST", "/api/v1/auth/callback?session="+sessionID,
		strings.NewReader(`{"not_a_token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)

	code, body := statusOf(t, srv, sessionID)
	require.Equal(t, http.StatusOK, code)
	assert.True(t, body.Failed, "a malformed callback must be visible to the poller")
	assert.Equal(t, AuthFailInvalidRequest, body.Reason)
}
