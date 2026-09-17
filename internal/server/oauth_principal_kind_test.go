package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
)

func TestOAuthSilentCompletionPreservesServiceAndLegacyKind(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})
	router.POST("/oauth/token", srv.handleOAuthToken)
	hash, err := bcrypt.GenerateFromPassword([]byte("test-client-secret"), bcrypt.MinCost)
	require.NoError(t, err)
	srv.config.OAuthFirstPartyClients["block-explorer"] = string(hash)
	subject := "did:privado:service-shaped-did"
	ensureUser(t, srv, subject)
	for _, kind := range []auth.PrincipalKind{auth.PrincipalService, ""} {
		token, err := srv.jwtService.IssueAccessTokenForPrincipal(subject, true, kind, nil)
		require.NoError(t, err)
		redirect := "http://localhost:3001/api/auth/callback"
		id := srv.oauthSessionStore.CreateSession("block-explorer", redirect, "state", "", subject)
		request := httptest.NewRequest(http.MethodPost, "/oauth/session/"+id+"/silent-complete", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, 200, response.Code, response.Body.String())
		session := srv.oauthSessionStore.GetSession(id)
		require.Equal(t, string(kind), session.PrincipalKind)
		raw, err := json.Marshal(apimodels.OAuthTokenRequest{GrantType: "authorization_code", Code: session.Code, RedirectURI: redirect, ClientID: "block-explorer"})
		require.NoError(t, err)
		request = httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request.SetBasicAuth("block-explorer", "test-client-secret")
		response = httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, 200, response.Code, response.Body.String())
		var tokens apimodels.OAuthTokenResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &tokens))
		claims, err := srv.jwtService.ValidateAccessToken(tokens.AccessToken)
		require.NoError(t, err)
		require.Equal(t, kind, claims.PrincipalKind)
		refresh, err := srv.jwtService.ValidateRefreshToken(tokens.RefreshToken)
		require.NoError(t, err)
		require.Equal(t, kind, refresh.PrincipalKind)
	}
}
