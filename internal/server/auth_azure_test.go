package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/apimodels"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// AzureStateStore unit tests
// ---------------------------------------------------------------------------

func TestAzureStateStore_CreateAndConsume(t *testing.T) {
	store := NewAzureStateStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	state, nonce := store.Create()
	require.NotEmpty(t, state)
	require.NotEmpty(t, nonce)

	// First consume succeeds
	got, ok := store.Consume(state)
	assert.True(t, ok)
	assert.Equal(t, nonce, got)

	// Second consume fails (single-use)
	_, ok = store.Consume(state)
	assert.False(t, ok, "consuming the same state twice should fail")
}

func TestAzureStateStore_ConsumeNonExistent(t *testing.T) {
	store := NewAzureStateStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	_, ok := store.Consume("does-not-exist")
	assert.False(t, ok, "non-existent token should return ok=false")
}

func TestAzureStateStore_ExpiredToken(t *testing.T) {
	store := NewAzureStateStore(1*time.Millisecond, 1*time.Hour)
	defer store.Stop()

	state, _ := store.Create()

	// Wait for the TTL to expire
	time.Sleep(5 * time.Millisecond)

	_, ok := store.Consume(state)
	assert.False(t, ok, "expired token should be rejected")
}

func TestAzureStateStore_MultipleTokens(t *testing.T) {
	store := NewAzureStateStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	state1, nonce1 := store.Create()
	state2, nonce2 := store.Create()

	assert.NotEqual(t, state1, state2)
	assert.NotEqual(t, nonce1, nonce2)

	// Consuming one doesn't affect the other
	got2, ok := store.Consume(state2)
	assert.True(t, ok)
	assert.Equal(t, nonce2, got2)

	got1, ok := store.Consume(state1)
	assert.True(t, ok)
	assert.Equal(t, nonce1, got1)
}

// ---------------------------------------------------------------------------
// Handler-level tests
// ---------------------------------------------------------------------------

// newMockOIDCDiscoveryServer returns an httptest.Server serving a minimal OIDC
// discovery document and empty JWKS, suitable for creating a real
// AzureADAuthenticator via NewAzureADAuthenticatorFromIssuer.
func newMockOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		disc := map[string]interface{}{
			"issuer":                                serverURL,
			"authorization_endpoint":                serverURL + "/authorize",
			"token_endpoint":                        serverURL + "/token",
			"jwks_uri":                              serverURL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(disc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	})

	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	return srv
}

func mustNewTestAzureAuthenticator(t *testing.T, issuerURL string) *auth.AzureADAuthenticator {
	t.Helper()
	authn, err := auth.NewAzureADAuthenticatorFromIssuer("test-client", "test-secret", issuerURL)
	require.NoError(t, err)
	return authn
}

func setupAzureHandlerRouter(s *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auth/providers", s.handleAuthProviders)
	router.GET("/api/v1/auth/azure/url", s.handleAzureAuthURL)
	return router
}

func TestHandleAuthProviders(t *testing.T) {
	mockOIDC := newMockOIDCDiscoveryServer(t)
	defer mockOIDC.Close()

	tests := []struct {
		name              string
		azureConfigured   bool
		expectedProviders []string
	}{
		{
			name:              "azure not configured returns only privado",
			azureConfigured:   false,
			expectedProviders: []string{"privado"},
		},
		{
			name:              "azure configured returns both providers",
			azureConfigured:   true,
			expectedProviders: []string{"privado", "azuread"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &config.Config{Environment: "development"}}
			if tc.azureConfigured {
				s.azureAuthenticator = mustNewTestAzureAuthenticator(t, mockOIDC.URL)
				s.azureStateStore = NewAzureStateStore(10*time.Minute, 1*time.Minute)
				defer s.azureStateStore.Stop()
			}

			router := setupAzureHandlerRouter(s)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp apimodels.ProvidersResponse
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedProviders, resp.Providers)
		})
	}
}

func TestHandleAzureAuthURL(t *testing.T) {
	mockOIDC := newMockOIDCDiscoveryServer(t)
	defer mockOIDC.Close()

	tests := []struct {
		name            string
		azureConfigured bool
		redirectURI     string
		expectedStatus  int
	}{
		{
			name:            "not configured returns 404",
			azureConfigured: false,
			redirectURI:     "http://localhost/callback",
			expectedStatus:  http.StatusNotFound,
		},
		{
			name:            "configured returns 200 with URL",
			azureConfigured: true,
			redirectURI:     "http://localhost/callback",
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "missing redirect_uri returns 400",
			azureConfigured: true,
			redirectURI:     "",
			expectedStatus:  http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &config.Config{Environment: "development"}}
			if tc.azureConfigured {
				s.azureAuthenticator = mustNewTestAzureAuthenticator(t, mockOIDC.URL)
				s.azureStateStore = NewAzureStateStore(10*time.Minute, 1*time.Minute)
				defer s.azureStateStore.Stop()
			}

			router := setupAzureHandlerRouter(s)

			path := "/api/v1/auth/azure/url"
			if tc.redirectURI != "" {
				path += "?redirect_uri=" + tc.redirectURI
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)

			if tc.expectedStatus == http.StatusOK {
				var resp apimodels.AzureURLResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.URL, "URL should not be empty")
				assert.NotEmpty(t, resp.State, "State should not be empty")
				assert.Contains(t, resp.URL, "redirect_uri=")
			}
		})
	}
}
