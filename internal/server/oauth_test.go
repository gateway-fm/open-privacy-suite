package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// setupTestServerForOAuth creates a test server with OAuth support
func setupTestServerForOAuth(t *testing.T) *Server {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development (no external PostgreSQL needed)
		dbURL = sharedTestDBURL(t)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Reset database (drops all tables and runs migrations)
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	// Create JWT service
	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	// Create mock Privado verifier
	mockVerifier := &mockPrivadoVerifier{
		verifyFunc: func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
			// Mock: accept any JWZ token and return a test DID
			if jwzToken == "" {
				return "", fmt.Errorf("empty JWZ token")
			}
			return "did:privado:test123", nil
		},
	}

	// Create test config
	cfg := &config.Config{
		VerifierID:         "did:privado:verifier:test",
		BaseURL:            "http://localhost:8080",
		Environment:        "development",
		CORSAllowedOrigins: "",
	}

	srv := &Server{
		db:                database,
		privadoVerifier:   mockVerifier,
		jwtService:        jwtService,
		rbacAccessCtrl:    rbac.NewAccessController(database, 5*time.Minute),
		proxy:             nil, // Not needed for OAuth tests
		sessionStore:      auth.NewSessionStore(10*time.Minute, 1*time.Minute),
		oauthSessionStore: NewOAuthSessionStore(OAuthSessionTTL, OAuthCleanupInterval, DefaultMaxOAuthSessions),
		config:            cfg,
	}
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	return srv
}

// TestOAuth_AuthorizeEndpoint tests the OAuth authorize endpoint
func TestOAuth_AuthorizeEndpoint(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		queryParams    map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name: "valid request with all required parameters",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing client_id",
			queryParams: map[string]string{
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "missing redirect_uri",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"response_type": "code",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "missing response_type",
			queryParams: map[string]string{
				"client_id":    "explorer-app",
				"redirect_uri": "http://localhost:3000/callback",
				"state":        "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "missing state",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_request",
		},
		{
			name: "invalid response_type - token not supported",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "token", // Should be "code" for authorization code flow
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "unsupported_response_type",
		},
		{
			name: "invalid response_type - implicit flow not supported",
			queryParams: map[string]string{
				"client_id":     "explorer-app",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "id_token",
				"state":         "random-state-value",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "unsupported_response_type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

			// Build query string
			q := url.Values{}
			for k, v := range tt.queryParams {
				q.Set(k, v)
			}

			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errResp apimodels.OAuthErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedError, errResp.Error)
			}

			if tt.expectedStatus == http.StatusOK {
				var resp map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.NotEmpty(t, resp["oauth_session_id"])
				assert.NotEmpty(t, resp["auth_session_id"])
				assert.NotNil(t, resp["auth_request"])
			}
		})
	}
}

// TestOAuth_TokenEndpoint tests the OAuth token exchange endpoint
func TestOAuth_TokenEndpoint(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupSession   func() string // returns the authorization code
		requestBody    func(code string) apimodels.OAuthTokenRequest
		expectedStatus int
		expectedError  string
		checkResponse  func(t *testing.T, resp apimodels.OAuthTokenResponse)
	}{
		{
			name: "valid code exchange returns JWT",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-1", "")
				require.NotEmpty(t, oauthSessionID)
				code := generateSecureCode()
				err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				require.NoError(t, err)
				return code
			},
			requestBody: func(code string) apimodels.OAuthTokenRequest {
				return apimodels.OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp apimodels.OAuthTokenResponse) {
				assert.NotEmpty(t, resp.AccessToken)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.Greater(t, resp.ExpiresIn, 0)

				// Validate the access token
				claims, err := srv.jwtService.ValidateAccessToken(resp.AccessToken)
				require.NoError(t, err)
				assert.Equal(t, "did:privado:test123", claims.Subject)
				assert.True(t, claims.KYC)
			},
		},
		{
			name: "invalid code returns error",
			setupSession: func() string {
				return "invalid-code"
			},
			requestBody: func(code string) apimodels.OAuthTokenRequest {
				return apimodels.OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_grant",
		},
		{
			name: "invalid grant_type returns error",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-2", "")
				code := generateSecureCode()
				srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				return code
			},
			requestBody: func(code string) apimodels.OAuthTokenRequest {
				return apimodels.OAuthTokenRequest{
					GrantType:   "password",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "unsupported_grant_type",
		},
		{
			name: "mismatched redirect_uri returns error",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-3", "")
				code := generateSecureCode()
				srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				return code
			},
			requestBody: func(code string) apimodels.OAuthTokenRequest {
				return apimodels.OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://malicious-site.com/callback",
					ClientID:    "explorer-app",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_grant",
		},
		{
			name: "mismatched client_id returns error",
			setupSession: func() string {
				oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-4", "")
				code := generateSecureCode()
				srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
				return code
			},
			requestBody: func(code string) apimodels.OAuthTokenRequest {
				return apimodels.OAuthTokenRequest{
					GrantType:   "authorization_code",
					Code:        code,
					RedirectURI: "http://localhost:3000/callback",
					ClientID:    "wrong-client",
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.POST("/oauth/token", srv.handleOAuthToken)

			code := tt.setupSession()
			tokenReq := tt.requestBody(code)
			reqBody, _ := json.Marshal(tokenReq)

			req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errResp apimodels.OAuthErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedError, errResp.Error)
			}

			if tt.checkResponse != nil && tt.expectedStatus == http.StatusOK {
				var resp apimodels.OAuthTokenResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				tt.checkResponse(t, resp)
			}
		})
	}
}

// TestOAuth_TokenEndpoint_FormEncoded tests the token endpoint with form-encoded requests
func TestOAuth_TokenEndpoint_FormEncoded(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a valid session
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-form", "")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	// Build form-encoded body
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("redirect_uri", "http://localhost:3000/callback")
	formData.Set("client_id", "explorer-app")

	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apimodels.OAuthTokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

// TestOAuth_CodeReplayProtection tests that authorization codes can only be used once
func TestOAuth_CodeReplayProtection(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a valid session with a code
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-replay", "")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := apimodels.OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	// First use should succeed
	req1 := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	var resp apimodels.OAuthTokenResponse
	err = json.Unmarshal(w1.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	// Second use should fail (replay protection)
	req2 := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusBadRequest, w2.Code)

	var errResp apimodels.OAuthErrorResponse
	err = json.Unmarshal(w2.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "already been used")
}

// TestOAuth_RedirectURIValidation tests redirect URI validation rules
func TestOAuth_RedirectURIValidation(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Update config with allowed redirect URIs
	srv.config.BaseURL = "https://explorer.example.com"

	tests := []struct {
		name           string
		redirectURI    string
		expectedStatus int
		description    string
	}{
		{
			name:           "localhost http allowed",
			redirectURI:    "http://localhost:3000/callback",
			expectedStatus: http.StatusOK,
			description:    "localhost URLs should be allowed for development",
		},
		{
			name:           "localhost https allowed",
			redirectURI:    "https://localhost:3000/callback",
			expectedStatus: http.StatusOK,
			description:    "localhost with HTTPS should be allowed",
		},
		{
			name:           "localhost with different port allowed",
			redirectURI:    "http://localhost:8080/oauth/callback",
			expectedStatus: http.StatusOK,
			description:    "localhost with any port should be allowed",
		},
		{
			name:           "127.0.0.1 allowed",
			redirectURI:    "http://127.0.0.1:3000/callback",
			expectedStatus: http.StatusOK,
			description:    "127.0.0.1 should be allowed for development",
		},
		{
			name:           "configured base URL allowed",
			redirectURI:    "https://explorer.example.com/callback",
			expectedStatus: http.StatusOK,
			description:    "configured BASE_URL should be allowed",
		},
		{
			name:           "arbitrary external URL rejected",
			redirectURI:    "https://evil.com/steal-token",
			expectedStatus: http.StatusBadRequest,
			description:    "arbitrary external URLs should be rejected",
		},
		{
			name:           "external URL with similar domain rejected",
			redirectURI:    "https://explorer.example.com.evil.com/callback",
			expectedStatus: http.StatusBadRequest,
			description:    "domains that look similar but aren't should be rejected",
		},
		{
			name:           "http external URL rejected",
			redirectURI:    "http://external-site.com/callback",
			expectedStatus: http.StatusBadRequest,
			description:    "non-localhost HTTP URLs should be rejected",
		},
		{
			name:           "javascript URL rejected",
			redirectURI:    "javascript:alert('xss')",
			expectedStatus: http.StatusBadRequest,
			description:    "javascript: URLs should be rejected",
		},
		{
			name:           "data URL rejected",
			redirectURI:    "data:text/html,<script>alert('xss')</script>",
			expectedStatus: http.StatusBadRequest,
			description:    "data: URLs should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

			q := url.Values{}
			q.Set("client_id", "explorer-app")
			q.Set("redirect_uri", tt.redirectURI)
			q.Set("response_type", "code")
			q.Set("state", "test-state")

			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

// TestOAuth_RedirectURIValidation_CORSOrigins tests that CORS allowed origins work as redirect URIs
func TestOAuth_RedirectURIValidation_CORSOrigins(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Set up CORS allowed origins
	srv.config.CORSAllowedOrigins = "https://app1.example.com,https://app2.example.com"
	srv.config.BaseURL = "https://privacy-proxy.example.com"

	tests := []struct {
		name           string
		redirectURI    string
		expectedStatus int
	}{
		{
			name:           "CORS origin app1 allowed",
			redirectURI:    "https://app1.example.com/callback",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "CORS origin app2 allowed",
			redirectURI:    "https://app2.example.com/oauth/callback",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "non-CORS origin rejected",
			redirectURI:    "https://app3.example.com/callback",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

			q := url.Values{}
			q.Set("client_id", "explorer-app")
			q.Set("redirect_uri", tt.redirectURI)
			q.Set("response_type", "code")
			q.Set("state", "test-state")

			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// TestOAuth_RedirectURIValidation_WildcardCORS tests that wildcard CORS does NOT allow arbitrary redirect URIs
func TestOAuth_RedirectURIValidation_WildcardCORS(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Set up wildcard CORS — should NOT grant redirect URI access to arbitrary domains
	srv.config.CORSAllowedOrigins = "*"

	router := gin.New()
	router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

	// Wildcard CORS should NOT allow arbitrary external redirect URIs
	q := url.Values{}
	q.Set("client_id", "explorer-app")
	q.Set("redirect_uri", "https://any-site.com/callback")
	q.Set("response_type", "code")
	q.Set("state", "test-state")

	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "wildcard CORS must not allow arbitrary redirect URIs")
}

// TestOAuth_SessionStatus tests the session status polling endpoint
func TestOAuth_SessionStatus(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/session/:id/status", srv.handleOAuthSessionStatus)

	t.Run("incomplete session", func(t *testing.T) {
		// Create a session without a code
		oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-incomplete", "")
		require.NotEmpty(t, oauthSessionID)

		req := httptest.NewRequest("GET", "/oauth/session/"+oauthSessionID+"/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp apimodels.OAuthSessionStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Completed)
		assert.Empty(t, resp.RedirectURL)
	})

	t.Run("completed session", func(t *testing.T) {
		// Create a session with a code
		oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-complete", "")
		require.NotEmpty(t, oauthSessionID)
		code := generateSecureCode()
		err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/oauth/session/"+oauthSessionID+"/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp apimodels.OAuthSessionStatusResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Completed)
		assert.Contains(t, resp.RedirectURL, code)
		assert.Contains(t, resp.RedirectURL, "state=test-state")
	})

	t.Run("non-existent session", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/oauth/session/non-existent-id/status", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestOAuth_SessionExpiry tests that OAuth sessions/codes expire properly
func TestOAuth_SessionExpiry(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a session store with very short TTL
	shortTTLStore := NewOAuthSessionStore(50*time.Millisecond, 1*time.Hour, 100)
	defer shortTTLStore.Stop()
	srv.oauthSessionStore = shortTTLStore

	// Create a session
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-expiry", "")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(100 * time.Millisecond)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := apimodels.OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp apimodels.OAuthErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)
}

// TestOAuth_CodeExpiry tests that authorization codes expire after OAuthCodeTTL
func TestOAuth_CodeExpiry(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a session with a code
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-code-expiry", "")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	// Manually expire the code by modifying the session
	session := srv.oauthSessionStore.GetSession(oauthSessionID)
	require.NotNil(t, session)
	session.CodeExpires = time.Now().Add(-1 * time.Second) // Set to past

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := apimodels.OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp apimodels.OAuthErrorResponse
	err = json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "expired")
}

// TestOAuth_StateParameterPreserved tests that the state parameter is preserved through the flow
func TestOAuth_StateParameterPreserved(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/session/:id/status", srv.handleOAuthSessionStatus)

	// Test various state values
	states := []string{
		"simple-state",
		"state-with-special-chars-!@#$%",
		"base64encodedstate==",
		"very-long-state-value-" + strings.Repeat("x", 100),
	}

	for _, state := range states {
		t.Run("state="+state[:minInt(20, len(state))], func(t *testing.T) {
			// Create a session with the state
			oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", state, "auth-session-state-"+state[:minInt(10, len(state))], "")
			require.NotEmpty(t, oauthSessionID)

			// Add a code to mark as complete
			code := generateSecureCode()
			err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
			require.NoError(t, err)

			// Check status to get redirect URL
			req := httptest.NewRequest("GET", "/oauth/session/"+oauthSessionID+"/status", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp apimodels.OAuthSessionStatusResponse
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)

			// Parse the redirect URL and verify state
			redirectURL, err := url.Parse(resp.RedirectURL)
			require.NoError(t, err)
			assert.Equal(t, state, redirectURL.Query().Get("state"), "state should be preserved exactly")
		})
	}
}

// TestOAuth_ConcurrentCodeExchange tests that concurrent code exchanges are handled correctly
func TestOAuth_ConcurrentCodeExchange(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	// Create a session with a code
	oauthSessionID := srv.oauthSessionStore.CreateSession("explorer-app", "http://localhost:3000/callback", "test-state", "auth-session-concurrent", "")
	require.NotEmpty(t, oauthSessionID)
	code := generateSecureCode()
	err := srv.oauthSessionStore.SetCode(oauthSessionID, code, "did:privado:test123", true)
	require.NoError(t, err)

	router := gin.New()
	router.POST("/oauth/token", srv.handleOAuthToken)

	tokenRequest := apimodels.OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "http://localhost:3000/callback",
		ClientID:    "explorer-app",
	}
	reqBody, _ := json.Marshal(tokenRequest)

	// Launch multiple concurrent requests
	const numRequests = 10
	var wg sync.WaitGroup
	results := make(chan int, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	wg.Wait()
	close(results)

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for statusCode := range results {
		if statusCode == http.StatusOK {
			successCount++
		} else {
			failureCount++
		}
	}

	// Only one request should succeed (first one to claim the code)
	assert.Equal(t, 1, successCount, "only one concurrent request should succeed")
	assert.Equal(t, numRequests-1, failureCount, "all other requests should fail")
}

// TestOAuth_FullFlow tests the complete OAuth authorization flow
func TestOAuth_FullFlow(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/authorize", srv.handleOAuthAuthorize)
	router.POST("/oauth/callback", srv.handleOAuthCallback)
	router.POST("/oauth/token", srv.handleOAuthToken)
	router.GET("/oauth/session/:id/status", srv.handleOAuthSessionStatus)

	// Enable mock login for testing
	srv.config.AllowMockLogin = true

	// Step 1: Start OAuth flow with authorize request
	state := "unique-state-value-12345"
	redirectURI := "http://localhost:3000/callback"

	q := url.Values{}
	q.Set("client_id", "explorer-app")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)

	req1 := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	// Parse the response
	var authorizeResp map[string]interface{}
	err := json.Unmarshal(w1.Body.Bytes(), &authorizeResp)
	require.NoError(t, err)

	oauthSessionID := authorizeResp["oauth_session_id"].(string)
	authSessionID := authorizeResp["auth_session_id"].(string)
	require.NotEmpty(t, oauthSessionID)
	require.NotEmpty(t, authSessionID)

	// Step 2: Simulate Privado authentication callback with mock token
	callbackBody := map[string]interface{}{
		"token": "mock.token.did:privado:test_user_123",
	}
	callbackBodyBytes, _ := json.Marshal(callbackBody)

	req2 := httptest.NewRequest("POST", "/oauth/callback?session="+authSessionID+"&oauth_session="+oauthSessionID, bytes.NewReader(callbackBodyBytes))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var callbackResp map[string]interface{}
	err = json.Unmarshal(w2.Body.Bytes(), &callbackResp)
	require.NoError(t, err)
	assert.Equal(t, "success", callbackResp["status"])

	// Extract code from redirect URL
	callbackRedirectURL, err := url.Parse(callbackResp["redirect_url"].(string))
	require.NoError(t, err)
	authCode := callbackRedirectURL.Query().Get("code")
	require.NotEmpty(t, authCode)
	assert.Equal(t, state, callbackRedirectURL.Query().Get("state"))

	// Step 3: Exchange authorization code for tokens
	tokenRequest := apimodels.OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        authCode,
		RedirectURI: redirectURI,
		ClientID:    "explorer-app",
	}
	tokenReqBody, _ := json.Marshal(tokenRequest)

	req3 := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(tokenReqBody))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	assert.Equal(t, http.StatusOK, w3.Code)

	var tokenResp apimodels.OAuthTokenResponse
	err = json.Unmarshal(w3.Body.Bytes(), &tokenResp)
	require.NoError(t, err)

	// Verify token response
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
	assert.Greater(t, tokenResp.ExpiresIn, 0)

	// Validate the JWT
	claims, err := srv.jwtService.ValidateAccessToken(tokenResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "did:privado:test_user_123", claims.Subject)
}

// TestOAuth_SessionStoreCapacity tests the session store capacity limits
func TestOAuth_SessionStoreCapacity(t *testing.T) {
	// Create a store with very low capacity
	store := NewOAuthSessionStore(10*time.Minute, 1*time.Hour, 3)
	defer store.Stop()

	// Create sessions up to capacity
	for i := 0; i < 3; i++ {
		sessionID := store.CreateSession("client", "http://localhost/callback", fmt.Sprintf("state-%d", i), fmt.Sprintf("auth-%d", i), "")
		assert.NotEmpty(t, sessionID, "should create session %d", i)
	}

	// Try to create one more - should fail
	sessionID := store.CreateSession("client", "http://localhost/callback", "state-overflow", "auth-overflow", "")
	assert.Empty(t, sessionID, "should not create session beyond capacity")
}

// TestOAuthSessionStore_Cleanup tests that expired sessions are cleaned up
func TestOAuthSessionStore_Cleanup(t *testing.T) {
	// Create a store with very short TTL and cleanup interval
	store := NewOAuthSessionStore(50*time.Millisecond, 100*time.Millisecond, 100)
	defer store.Stop()

	// Create a session
	sessionID := store.CreateSession("client", "http://localhost/callback", "state", "auth", "")
	require.NotEmpty(t, sessionID)

	// Verify session exists
	session := store.GetSession(sessionID)
	require.NotNil(t, session)

	// Wait for expiration and cleanup
	time.Sleep(200 * time.Millisecond)

	// Verify session is gone
	session = store.GetSession(sessionID)
	assert.Nil(t, session, "expired session should be cleaned up")
}

// TestOAuthSessionStore_CodeIndex tests that code index is properly maintained
func TestOAuthSessionStore_CodeIndex(t *testing.T) {
	store := NewOAuthSessionStore(10*time.Minute, 1*time.Hour, 100)
	defer store.Stop()

	// Create session and set code
	sessionID := store.CreateSession("client", "http://localhost/callback", "state", "auth", "")
	require.NotEmpty(t, sessionID)

	code := "test-code-12345"
	err := store.SetCode(sessionID, code, "did:user:123", true)
	require.NoError(t, err)

	// Should be able to retrieve by code
	session := store.GetSessionByCode(code)
	require.NotNil(t, session)
	assert.Equal(t, "did:user:123", session.UserDID)

	// Delete session and verify code index is cleaned up
	store.DeleteSession(sessionID)

	session = store.GetSessionByCode(code)
	assert.Nil(t, session, "code index should be cleaned up after session deletion")
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestOAuth_SessionInfo tests GET /oauth/session/:id/info
func TestOAuth_SessionInfo(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/oauth/session/:id/info", srv.handleOAuthSessionInfo)

	// Helper: create a pending OAuth session with a real auth request stored in the auth session
	createSessionWithAuthReq := func(t *testing.T) string {
		t.Helper()
		authReq, err := srv.privadoVerifier.CreateAuthorizationRequest("did:privado:verifier:test", "http://localhost/cb", "test")
		require.NoError(t, err)
		authSessionID := srv.sessionStore.CreateSession(authReq)
		require.NotEmpty(t, authSessionID)
		oauthSessionID := srv.oauthSessionStore.CreateSession("client", "http://localhost/cb", "state", authSessionID, "")
		require.NotEmpty(t, oauthSessionID)
		return oauthSessionID
	}

	t.Run("returns auth request for valid session", func(t *testing.T) {
		oauthSessionID := createSessionWithAuthReq(t)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/session/"+oauthSessionID+"/info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "auth_request")
		assert.Contains(t, resp, "allow_mock")
		// In default test config AllowMockLogin=false, so allow_mock should be false
		assert.Equal(t, false, resp["allow_mock"])
	})

	t.Run("returns allow_mock true when enabled in dev", func(t *testing.T) {
		srv.config.AllowMockLogin = true
		defer func() { srv.config.AllowMockLogin = false }()

		oauthSessionID := createSessionWithAuthReq(t)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/session/"+oauthSessionID+"/info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["allow_mock"])
	})

	t.Run("returns 404 for nonexistent session", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/session/nonexistent-id/info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("allow_mock is false in production even if AllowMockLogin is true", func(t *testing.T) {
		srv.config.AllowMockLogin = true
		srv.config.Environment = "production"
		defer func() {
			srv.config.AllowMockLogin = false
			srv.config.Environment = "development"
		}()

		oauthSessionID := createSessionWithAuthReq(t)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/session/"+oauthSessionID+"/info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, false, resp["allow_mock"])
	})

	t.Run("returns 404 when auth session is missing", func(t *testing.T) {
		// Create an OAuth session pointing to a non-existent auth session ID
		oauthSessionID := srv.oauthSessionStore.CreateSession("client", "http://localhost/cb", "state", "nonexistent-auth-session", "")
		require.NotEmpty(t, oauthSessionID)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/session/"+oauthSessionID+"/info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestOAuth_MockComplete tests POST /oauth/session/:id/mock-complete
func TestOAuth_MockComplete(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/oauth/session/:id/mock-complete", srv.handleOAuthMockComplete)

	// Helper to create a pending OAuth session
	createPendingSession := func(t *testing.T) string {
		t.Helper()
		authReq, err := srv.privadoVerifier.CreateAuthorizationRequest("did:privado:verifier:test", "http://localhost/cb", "test")
		require.NoError(t, err)
		authSessionID := srv.sessionStore.CreateSession(authReq)
		require.NotEmpty(t, authSessionID)
		oauthSessionID := srv.oauthSessionStore.CreateSession("client", "http://localhost/callback", "state", authSessionID, "")
		require.NotEmpty(t, oauthSessionID)
		return oauthSessionID
	}

	t.Run("forbidden when AllowMockLogin is false", func(t *testing.T) {
		srv.config.AllowMockLogin = false
		oauthSessionID := createPendingSession(t)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("forbidden in production even if AllowMockLogin is true", func(t *testing.T) {
		srv.config.AllowMockLogin = true
		srv.config.Environment = "production"
		defer func() {
			srv.config.AllowMockLogin = false
			srv.config.Environment = "development"
		}()
		oauthSessionID := createPendingSession(t)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("completes session successfully in dev mode", func(t *testing.T) {
		srv.config.AllowMockLogin = true
		defer func() { srv.config.AllowMockLogin = false }()
		oauthSessionID := createPendingSession(t)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["ok"])
		assert.Contains(t, resp["did"].(string), "did:privado:mock_")

		// Session should now have a code set
		session := srv.oauthSessionStore.GetSession(oauthSessionID)
		require.NotNil(t, session)
		assert.NotEmpty(t, session.Code)
	})

	t.Run("returns 409 when session already completed", func(t *testing.T) {
		srv.config.AllowMockLogin = true
		defer func() { srv.config.AllowMockLogin = false }()
		oauthSessionID := createPendingSession(t)

		// Complete first time
		w1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete", nil)
		router.ServeHTTP(w1, req1)
		require.Equal(t, http.StatusOK, w1.Code)

		// Try to complete again
		w2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete", nil)
		router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusConflict, w2.Code)
	})

	t.Run("returns 404 for nonexistent session", func(t *testing.T) {
		srv.config.AllowMockLogin = true
		defer func() { srv.config.AllowMockLogin = false }()

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/session/nonexistent/mock-complete", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestOAuth_BrowserRedirect tests the browser-vs-JSON behavior of handleOAuthAuthorize
func TestOAuth_BrowserRedirect(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	makeAuthorizeReq := func(accept, frontendURL string) *httptest.ResponseRecorder {
		srv.config.FrontendURL = frontendURL
		router := gin.New()
		router.GET("/oauth/authorize", srv.handleOAuthAuthorize)

		w := httptest.NewRecorder()
		q := url.Values{}
		q.Set("client_id", "explorer")
		q.Set("redirect_uri", "http://localhost:3000/callback")
		q.Set("response_type", "code")
		q.Set("state", "test-state")
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("non-browser request returns JSON", func(t *testing.T) {
		w := makeAuthorizeReq("application/json", "")

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp, "oauth_session_id")
		assert.Contains(t, resp, "auth_request")
	})

	t.Run("browser request without FrontendURL returns 500", func(t *testing.T) {
		// The inline-HTML fallback was removed — a single audited login UI
		// (the React page at FRONTEND_URL) is the only browser flow. With
		// FrontendURL unset, the endpoint refuses the browser request so
		// the misconfiguration is visible instead of silently serving a
		// second-class page.
		w := makeAuthorizeReq("text/html,application/xhtml+xml", "")

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "server_error", resp["error"])
	})

	t.Run("browser request with FrontendURL redirects to login page", func(t *testing.T) {
		w := makeAuthorizeReq("text/html,application/xhtml+xml", "http://localhost:5173")

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "http://localhost:5173/login?oauth_session=")
	})

	t.Run("FrontendURL redirect includes correct oauth_session param", func(t *testing.T) {
		w := makeAuthorizeReq("text/html", "http://localhost:5173")

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		parsed, err := url.Parse(location)
		require.NoError(t, err)
		assert.Equal(t, "http://localhost:5173", parsed.Scheme+"://"+parsed.Host)
		assert.Equal(t, "/login", parsed.Path)
		oauthSession := parsed.Query().Get("oauth_session")
		assert.NotEmpty(t, oauthSession)

		// Verify the oauth session actually exists
		session := srv.oauthSessionStore.GetSession(oauthSession)
		assert.NotNil(t, session)
		assert.Equal(t, "explorer", session.ClientID)
	})

	t.Run("trailing slash in FrontendURL is stripped", func(t *testing.T) {
		w := makeAuthorizeReq("text/html", "http://localhost:5173/")

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		// Should not have double slash
		assert.NotContains(t, location, "//login")
		assert.Contains(t, location, "/login?oauth_session=")
	})
}

// TestOAuth_TokenExchange_ReturnsRefreshToken tests the full OAuth flow returns a refresh token
// and that the refresh token can be used to obtain new tokens, with old tokens being revoked.
func TestOAuth_TokenExchange_ReturnsRefreshToken(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/oauth/authorize", srv.handleOAuthAuthorize)
	router.POST("/oauth/session/:id/mock-complete", srv.handleOAuthMockComplete)
	router.POST("/oauth/token", srv.handleOAuthToken)
	router.POST("/api/v1/refresh", srv.handleRefresh)

	// Enable mock login for testing
	srv.config.AllowMockLogin = true

	// Step 1: Start OAuth flow with authorize request
	state := "refresh-test-state"
	redirectURI := "http://localhost:3000/callback"

	q := url.Values{}
	q.Set("client_id", "explorer-app")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)

	authorizeReq := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	authorizeW := httptest.NewRecorder()
	router.ServeHTTP(authorizeW, authorizeReq)

	require.Equal(t, http.StatusOK, authorizeW.Code)

	var authorizeResp map[string]interface{}
	err := json.Unmarshal(authorizeW.Body.Bytes(), &authorizeResp)
	require.NoError(t, err)

	oauthSessionID := authorizeResp["oauth_session_id"].(string)
	require.NotEmpty(t, oauthSessionID)

	// Step 2: Complete the session via mock-complete
	mockCompleteReq := httptest.NewRequest("POST", "/oauth/session/"+oauthSessionID+"/mock-complete", nil)
	mockCompleteW := httptest.NewRecorder()
	router.ServeHTTP(mockCompleteW, mockCompleteReq)

	require.Equal(t, http.StatusOK, mockCompleteW.Code)

	// Step 3: Get the authorization code from the session status
	session := srv.oauthSessionStore.GetSession(oauthSessionID)
	require.NotNil(t, session)
	require.NotEmpty(t, session.Code)

	// Step 4: Exchange the code for tokens via POST /oauth/token
	tokenRequest := apimodels.OAuthTokenRequest{
		GrantType:   "authorization_code",
		Code:        session.Code,
		RedirectURI: redirectURI,
		ClientID:    "explorer-app",
	}
	tokenReqBody, _ := json.Marshal(tokenRequest)

	tokenReq := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(tokenReqBody))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenW := httptest.NewRecorder()
	router.ServeHTTP(tokenW, tokenReq)

	require.Equal(t, http.StatusOK, tokenW.Code)

	var tokenResp apimodels.OAuthTokenResponse
	err = json.Unmarshal(tokenW.Body.Bytes(), &tokenResp)
	require.NoError(t, err)

	// Step 5: Assert the response includes all expected fields
	assert.NotEmpty(t, tokenResp.AccessToken, "access_token must be present")
	assert.NotEmpty(t, tokenResp.RefreshToken, "refresh_token must be present")
	assert.Equal(t, "Bearer", tokenResp.TokenType, "token_type must be Bearer")
	assert.Greater(t, tokenResp.ExpiresIn, 0, "expires_in must be positive")

	// Validate the access token is a valid JWT
	claims, err := srv.jwtService.ValidateAccessToken(tokenResp.AccessToken)
	require.NoError(t, err)
	assert.Contains(t, claims.Subject, "did:privado:mock_")

	// Step 6: Use the refresh token to get new tokens via POST /api/v1/refresh
	refreshReqBody, _ := json.Marshal(apimodels.RefreshRequest{
		RefreshToken: tokenResp.RefreshToken,
	})

	refreshReq := httptest.NewRequest("POST", "/api/v1/refresh", bytes.NewReader(refreshReqBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshW := httptest.NewRecorder()
	router.ServeHTTP(refreshW, refreshReq)

	require.Equal(t, http.StatusOK, refreshW.Code)

	var refreshResp apimodels.AuthResponse
	err = json.Unmarshal(refreshW.Body.Bytes(), &refreshResp)
	require.NoError(t, err)

	// Step 7: Assert the refresh response includes new tokens
	assert.NotEmpty(t, refreshResp.AccessToken, "refreshed access_token must be present")
	assert.NotEmpty(t, refreshResp.RefreshToken, "refreshed refresh_token must be present")
	assert.Equal(t, "Bearer", refreshResp.TokenType, "refreshed token_type must be Bearer")
	assert.Greater(t, refreshResp.ExpiresIn, 0, "refreshed expires_in must be positive")

	// The new tokens should be different from the original ones (rotation)
	assert.NotEqual(t, tokenResp.AccessToken, refreshResp.AccessToken, "new access token should differ from old")
	assert.NotEqual(t, tokenResp.RefreshToken, refreshResp.RefreshToken, "new refresh token should differ from old")

	// Validate the new access token
	newClaims, err := srv.jwtService.ValidateAccessToken(refreshResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claims.Subject, newClaims.Subject, "subject should be preserved across refresh")

	// Step 8: Verify the old refresh token no longer works (it was revoked during rotation)
	oldRefreshReqBody, _ := json.Marshal(apimodels.RefreshRequest{
		RefreshToken: tokenResp.RefreshToken,
	})

	oldRefreshReq := httptest.NewRequest("POST", "/api/v1/refresh", bytes.NewReader(oldRefreshReqBody))
	oldRefreshReq.Header.Set("Content-Type", "application/json")
	oldRefreshW := httptest.NewRecorder()
	router.ServeHTTP(oldRefreshW, oldRefreshReq)

	assert.Equal(t, http.StatusUnauthorized, oldRefreshW.Code, "old refresh token should be rejected after rotation")
}

// TestOAuth_TokenEndpoint_FirstPartyClientAuth — RD-1006: clients on the
// first-party allowlist must authenticate at /oauth/token with the bcrypt-
// hashed client_secret registered for their client_id. Verifies both
// transport options (HTTP Basic and body parameter) and the bypass path for
// non-first-party callers (preserves the pre-RD-1006 behaviour for any flow
// that hasn't opted in).
func TestOAuth_TokenEndpoint_FirstPartyClientAuth(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	const (
		clientID     = "explorer-test"
		clientSecret = "correct-horse-battery-staple"
		redirectURI  = "http://localhost:3000/callback"
		userDID      = "did:privado:fpc-test"
	)

	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	require.NoError(t, err)
	srv.config.OAuthFirstPartyClients = map[string]string{clientID: string(hash)}

	// seedCode creates a fresh OAuth session bound to clientID + redirectURI
	// and returns its single-use authorization code.
	seedCode := func(authSessionID string) string {
		sid := srv.oauthSessionStore.CreateSession(clientID, redirectURI, "state-x", authSessionID, "")
		require.NotEmpty(t, sid)
		code := generateSecureCode()
		require.NoError(t, srv.oauthSessionStore.SetCode(sid, code, userDID, true))
		return code
	}

	gin.SetMode(gin.TestMode)

	type tweakReq func(req *http.Request, body *apimodels.OAuthTokenRequest)

	tests := []struct {
		name           string
		clientIDUsed   string // override for the request body's client_id (defaults to clientID)
		allowlist      map[string]string
		tweak          tweakReq
		expectedStatus int
		expectedError  string
	}{
		{
			name: "first-party + correct HTTP Basic → 200",
			tweak: func(req *http.Request, _ *apimodels.OAuthTokenRequest) {
				req.SetBasicAuth(clientID, clientSecret)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "first-party + wrong HTTP Basic → 401 invalid_client",
			tweak: func(req *http.Request, _ *apimodels.OAuthTokenRequest) {
				req.SetBasicAuth(clientID, "wrong-secret")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_client",
		},
		{
			name: "first-party + correct client_secret_post → 200",
			tweak: func(_ *http.Request, body *apimodels.OAuthTokenRequest) {
				body.ClientSecret = clientSecret
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "first-party + wrong client_secret_post → 401 invalid_client",
			tweak: func(_ *http.Request, body *apimodels.OAuthTokenRequest) {
				body.ClientSecret = "wrong-secret"
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_client",
		},
		{
			name:           "first-party + no secret at all → 401 invalid_client",
			tweak:          func(_ *http.Request, _ *apimodels.OAuthTokenRequest) {}, // omit secret
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_client",
		},
		{
			name:      "non-first-party client bypasses RD-1006 (empty allowlist)",
			allowlist: map[string]string{}, // override: allowlist empty for this case
			tweak:     func(_ *http.Request, _ *apimodels.OAuthTokenRequest) {},
			// pre-RD-1006 behaviour: token endpoint accepts the code without
			// client authentication when the client is not on the allowlist.
			expectedStatus: http.StatusOK,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Per-test allowlist (defaults to the bcrypt-hashed first-party config)
			if tt.allowlist != nil {
				srv.config.OAuthFirstPartyClients = tt.allowlist
			} else {
				srv.config.OAuthFirstPartyClients = map[string]string{clientID: string(hash)}
			}

			code := seedCode(fmt.Sprintf("auth-sess-fpc-%d", i))
			body := apimodels.OAuthTokenRequest{
				GrantType:   "authorization_code",
				Code:        code,
				RedirectURI: redirectURI,
				ClientID:    clientID,
			}
			raw, _ := json.Marshal(body)
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")

			// Apply tweak — may set Basic auth, mutate body.ClientSecret, etc.
			// Re-marshal afterwards if the body changed.
			if tt.tweak != nil {
				prev := body
				tt.tweak(req, &body)
				if body != prev {
					raw, _ = json.Marshal(body)
					req.Body = http.NoBody
					req = httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(raw))
					req.Header.Set("Content-Type", "application/json")
					// Re-apply tweak so Basic auth header survives the rebuild.
					tt.tweak(req, &body)
				}
			}

			router := gin.New()
			router.POST("/oauth/token", srv.handleOAuthToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, tt.expectedStatus, w.Code, "body=%s", w.Body.String())
			if tt.expectedError != "" {
				var errResp apimodels.OAuthErrorResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
				assert.Equal(t, tt.expectedError, errResp.Error)
			} else if tt.expectedStatus == http.StatusOK {
				var ok apimodels.OAuthTokenResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ok))
				assert.NotEmpty(t, ok.AccessToken)
			}
		})
	}
}
