package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
)

func TestHandleRefreshPreservesVerifiedPrincipalKind(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	t.Cleanup(func() { _ = srv.db.Close() })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)
	for _, kind := range []auth.PrincipalKind{auth.PrincipalHuman, auth.PrincipalService, ""} {
		t.Run(string(kind), func(t *testing.T) {
			subject := "did:test:" + string(kind)
			refresh, err := jwtService.IssueRefreshTokenForPrincipal(subject, kind)
			require.NoError(t, err)
			require.NoError(t, srv.db.SaveRefreshToken(t.Context(), auth.HashToken(refresh), subject, time.Now().Add(time.Hour)))
			body, err := json.Marshal(apimodels.RefreshRequest{RefreshToken: refresh})
			require.NoError(t, err)
			request := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			var tokens apimodels.AuthResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &tokens))
			accessClaims, err := jwtService.ValidateAccessToken(tokens.AccessToken)
			require.NoError(t, err)
			require.Equal(t, kind, accessClaims.PrincipalKind)
			refreshClaims, err := jwtService.ValidateRefreshToken(tokens.RefreshToken)
			require.NoError(t, err)
			require.Equal(t, kind, refreshClaims.PrincipalKind)
		})
	}
}
