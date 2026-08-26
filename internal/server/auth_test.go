package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPrivadoVerifier is a mock for testing (implements PrivadoVerifier interface)
type mockPrivadoVerifier struct {
	createRequestFunc         func(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error)
	createHumanityRequestFunc func(verifierID, callbackURL, reason, issuerDID string, hc auth.HumanityRequestConfig) (*protocol.AuthorizationRequestMessage, error)
	verifyFunc                func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error)
	verifyWithProofDataFunc   func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error)
	registeredNetworksFunc    func() []string
}

// RegisteredNetworks defaults to the pair a stock deployment wires when Billions
// is configured, so tests that do not care about network advertisement behave
// as before (RD-1241).
func (m *mockPrivadoVerifier) RegisteredNetworks() []string {
	if m.registeredNetworksFunc != nil {
		return m.registeredNetworksFunc()
	}
	return []string{"billions:main", "privado:main"}
}

func (m *mockPrivadoVerifier) CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error) {
	if m.createRequestFunc != nil {
		return m.createRequestFunc(verifierID, callbackURL, reason)
	}
	// Mock a realistic iden3comm authorization request. The Typ /
	// ThreadID / From fields are required by the protocol and parsed
	// by mobile wallets; tests that pin the wire contract need them
	// populated (see TestHandleAuthRequest_IdenComContract).
	return &protocol.AuthorizationRequestMessage{
		ID:       "mock-request-id",
		ThreadID: "mock-thread-id",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/request",
		From:     verifierID,
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
		},
	}, nil
}

func (m *mockPrivadoVerifier) CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string, hc auth.HumanityRequestConfig) (*protocol.AuthorizationRequestMessage, error) {
	if m.createHumanityRequestFunc != nil {
		return m.createHumanityRequestFunc(verifierID, callbackURL, reason, issuerDID, hc)
	}
	circuitID := hc.CircuitID
	if circuitID == "" {
		circuitID = "credentialAtomicQueryMTPV2"
	}
	credentialSubject, _ := hc.Query["credentialSubject"]
	if credentialSubject == nil {
		credentialSubject = map[string]any{"isHuman": map[string]any{"$eq": 1}}
	}
	credType := hc.CredentialType
	if credType == "" {
		credType = "ProofOfHumanity"
	}
	return &protocol.AuthorizationRequestMessage{
		ID:       "mock-request-id",
		ThreadID: "mock-thread-id",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/request",
		From:     verifierID,
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
			Scope: []protocol.ZeroKnowledgeProofRequest{
				{
					ID:        1,
					CircuitID: circuitID,
					Query: map[string]any{
						"allowedIssuers":    []string{issuerDID},
						"credentialSubject": credentialSubject,
						"context":           hc.SchemaURL,
						"type":              credType,
					},
				},
			},
		},
	}, nil
}

func (m *mockPrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, jwzToken, authRequest, verifierID)
	}
	return "did:privado:test123", nil
}

func (m *mockPrivadoVerifier) VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error) {
	if m.verifyWithProofDataFunc != nil {
		return m.verifyWithProofDataFunc(ctx, jwzToken, authRequest, verifierID)
	}
	// Default: call the basic verifyFunc and wrap result
	if m.verifyFunc != nil {
		did, err := m.verifyFunc(ctx, jwzToken, authRequest, verifierID)
		if err != nil {
			return nil, err
		}
		return &auth.VerificationResult{UserDID: did}, nil
	}
	return &auth.VerificationResult{UserDID: "did:privado:test123"}, nil
}

func setupTestServerForAuth(t *testing.T) (*Server, *auth.JWTService) {
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
		VerifierID:  "did:privado:verifier:test",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	srv := &Server{
		db:              database,
		privadoVerifier: mockVerifier,
		jwtService:      jwtService,
		rbacAccessCtrl:  rbac.NewAccessController(database, 5*time.Minute),
		proxy:           nil, // Not needed for auth tests
		sessionStore:    auth.NewSessionStore(10*time.Minute, 1*time.Minute),
		config:          cfg,
	}
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	return srv, jwtService
}

func TestHandleAuthRequest_Success(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)

	req := httptest.NewRequest("POST", "/auth/request", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AuthRequestResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.SessionID)
	assert.NotNil(t, response.AuthRequest)
	assert.NotEmpty(t, response.AuthRequest.Body.CallbackURL)
}

// TestHandleAuthRequest_IdenComContract pins the iden3comm-protocol
// fields that mobile wallets parse from the QR / deeplink. Ports the
// non-trivial assertions from auth-formats.spec.ts (the trivial
// "endpoint returns 200 + session_id" case is already covered by
// TestHandleAuthRequest_Success).
//
// Two invariants matter to wallet integrations:
//
//  1. Required iden3comm fields are populated (id, thid, typ, type,
//     from, body.callbackUrl, body.reason). A wallet failing to parse
//     any of these silently aborts the auth flow.
//  2. The marshalled auth_request stays small enough to QR-encode at
//     a scanning-reliable density. ~2000 bytes is the practical cap
//     with error correction.
func TestHandleAuthRequest_IdenComContract(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)

	req := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var response AuthRequestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.NotNil(t, response.AuthRequest)

	ar := response.AuthRequest
	assert.NotEmpty(t, ar.ID, "iden3comm: id is required")
	assert.NotEmpty(t, ar.ThreadID, "iden3comm: thid is required")
	assert.Equal(t, "application/iden3comm-plain-json", string(ar.Typ), "iden3comm: typ must be plain-json")
	assert.Equal(t, "https://iden3-communication.io/authorization/1.0/request", string(ar.Type), "iden3comm: type must be authorization/1.0/request")
	assert.NotEmpty(t, ar.From, "iden3comm: from (issuer DID) is required")
	assert.NotEmpty(t, ar.Body.CallbackURL, "iden3comm: body.callbackUrl is required")
	assert.Contains(t, ar.Body.CallbackURL, "/auth/callback?session=", "callback URL must carry the session ID")
	assert.NotEmpty(t, ar.Body.Reason, "iden3comm: body.reason is required for wallet display")

	authReqJSON, err := json.Marshal(ar)
	require.NoError(t, err)
	assert.Less(t, len(authReqJSON), 2000,
		"auth_request must stay under ~2000 bytes for reliable QR scanning; got %d", len(authReqJSON))
}

func TestHandleAuthCallback_Success(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)
	router.POST("/auth/callback", srv.handleAuthCallback)

	// Step 1: Create auth request
	req1 := httptest.NewRequest("POST", "/auth/request", nil)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	var authReqResp AuthRequestResponse
	json.Unmarshal(w1.Body.Bytes(), &authReqResp)
	sessionID := authReqResp.SessionID

	// Step 2: Callback with proof
	reqBody := map[string]interface{}{
		"token": "mock.jwz.token",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req2 := httptest.NewRequest("POST", "/auth/callback?session="+sessionID, bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var response AuthResponse
	err := json.Unmarshal(w2.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int(AccessTokenTTL.Seconds()), response.ExpiresIn)
}

func TestHandleAuthCallback_VerificationFailure(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)
	router.POST("/auth/callback", srv.handleAuthCallback)

	// Step 1: Create auth request
	req1 := httptest.NewRequest("POST", "/auth/request", nil)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	var authReqResp AuthRequestResponse
	json.Unmarshal(w1.Body.Bytes(), &authReqResp)
	sessionID := authReqResp.SessionID

	// Update mock to return error
	mockVerifier := srv.privadoVerifier.(*mockPrivadoVerifier)
	mockVerifier.verifyFunc = func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
		return "", fmt.Errorf("verification failed")
	}

	// Step 2: Callback with invalid proof
	reqBody := map[string]interface{}{
		"token": "invalid.token",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req2 := httptest.NewRequest("POST", "/auth/callback?session="+sessionID, bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestHandleAuthVerify_DevelopmentOnly(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// In development mode, /auth/verify should be available
	if !srv.config.IsProduction() {
		router.POST("/auth/request", srv.handleAuthRequest)
		router.POST("/auth/verify", srv.handleAuthVerify)

		// Step 1: Create auth request
		req1 := httptest.NewRequest("POST", "/auth/request", nil)
		req1.Header.Set("Content-Type", "application/json")
		w1 := httptest.NewRecorder()
		router.ServeHTTP(w1, req1)

		var authReqResp AuthRequestResponse
		json.Unmarshal(w1.Body.Bytes(), &authReqResp)
		sessionID := authReqResp.SessionID

		// Step 2: Verify with proof
		verifyReq := AuthVerifyRequest{
			SessionID: sessionID,
			JWZToken:  "mock.jwz.token",
		}
		verifyBody, _ := json.Marshal(verifyReq)

		req2 := httptest.NewRequest("POST", "/auth/verify", bytes.NewReader(verifyBody))
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)

		var response AuthResponse
		err := json.Unmarshal(w2.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)

		// RD-1008: /auth/verify is the mock-login path — must also set the
		// pp_access cookie so the browser carries it on cross-subdomain
		// navigation to /oauth/authorize.
		ck := findCookie(t, w2, auth.AccessCookieName)
		require.NotNil(t, ck, "/auth/verify must set the pp_access cookie")
		assert.Equal(t, response.AccessToken, ck.Value)
		assert.True(t, ck.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
	}
}

func TestHandleAuthCallback_VerifierIDMismatch(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)
	router.POST("/auth/callback", srv.handleAuthCallback)

	// Step 1: Create auth request
	req1 := httptest.NewRequest("POST", "/auth/request", nil)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	var authReqResp AuthRequestResponse
	json.Unmarshal(w1.Body.Bytes(), &authReqResp)
	sessionID := authReqResp.SessionID

	// Update mock to simulate verifier ID mismatch
	// In the real implementation, this would happen when authResponse.To != verifierID
	// The proof was generated for a different verifier
	mockVerifier := srv.privadoVerifier.(*mockPrivadoVerifier)
	mockVerifier.verifyFunc = func(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
		// Simulate verifier ID mismatch: the proof claims to be for a different verifier
		// This mimics what happens in the real code when authResponse.To != verifierID
		return "", fmt.Errorf("verifier ID mismatch: proof intended for did:privado:other_verifier, but expected %s", verifierID)
	}

	// Step 2: Callback with proof that has wrong verifier ID
	reqBody := map[string]interface{}{
		"token": "proof.for.different.verifier",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req2 := httptest.NewRequest("POST", "/auth/callback?session="+sessionID, bytes.NewReader(jsonBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	// Should fail with unauthorized due to verifier ID mismatch.
	assert.Equal(t, http.StatusUnauthorized, w2.Code)

	// RD-1178: the body must be OPAQUE to this unauthenticated caller — it
	// must not echo the raw verifier error, which carries the server's
	// verifier DID and iden3 internals (proof-forgery / config-enumeration
	// aid). The detail goes to slog only.
	var errorResp map[string]interface{}
	err := json.Unmarshal(w2.Body.Bytes(), &errorResp)
	require.NoError(t, err)
	assert.Equal(t, "verification failed", errorResp["error"].(string))
	body := w2.Body.String()
	assert.NotContains(t, body, "verifier ID mismatch")
	assert.NotContains(t, body, "did:privado:other_verifier")
}

func TestHandleRefresh_Success(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue a refresh token
	subject := "did:privado:test123"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	// Save refresh token to DB
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(context.Background(), tokenHash, subject, expiresAt)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AuthResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	// Should be a new refresh token (rotated)
	assert.NotEqual(t, refreshToken, response.RefreshToken)
}

func TestHandleRefresh_InvalidToken(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody := map[string]interface{}{
		"refresh_token": "invalid.token",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRefresh_RevokedToken(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue and save refresh token
	subject := "did:privado:test123"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(context.Background(), tokenHash, subject, expiresAt)
	require.NoError(t, err)

	// Revoke the token
	err = srv.db.RevokeRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleRefresh_BannedUser(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Create a user and issue a refresh token
	subject := "did:privado:banned-user"
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: subject,
		Metadata:   map[string]any{},
	}
	err := srv.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(context.Background(), tokenHash, subject, expiresAt)
	require.NoError(t, err)

	// Ban the user
	user.Banned = true
	err = srv.db.UpdateUser(context.Background(), user)
	require.NoError(t, err)

	// Attempt to refresh — should be rejected
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	reqBody, _ := json.Marshal(map[string]any{"refresh_token": refreshToken})
	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "account is banned", response["error"])

	// Verify the refresh token was also revoked in DB
	stored, err := srv.db.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	assert.True(t, stored.Revoked, "refresh token should be revoked for banned user")
}

func TestHandleRevoke_Success(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue and save refresh token
	subject := "did:privado:test123"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(context.Background(), tokenHash, subject, expiresAt)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/revoke", srv.handleRevoke)

	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify token is revoked
	token, err := srv.db.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.True(t, token.Revoked)
}

func TestHandleRevoke_WithAccessToken(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Issue access and refresh tokens
	subject := "did:privado:test123"
	accessToken, err := jwtService.IssueAccessToken(subject, true)
	require.NoError(t, err)
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)

	// Save refresh token
	refreshHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = srv.db.SaveRefreshToken(context.Background(), refreshHash, subject, expiresAt)
	require.NoError(t, err)

	// Verify access token is NOT revoked initially
	accessTokenID := auth.HashToken(accessToken)
	revoked, err := srv.db.IsAccessTokenRevoked(context.Background(), accessTokenID)
	require.NoError(t, err)
	assert.False(t, revoked, "access token should not be revoked initially")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/revoke", srv.handleRevoke)

	// Revoke both tokens
	reqBody := map[string]interface{}{
		"refresh_token": refreshToken,
		"access_token":  accessToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify refresh token is revoked
	token, err := srv.db.GetRefreshToken(context.Background(), refreshHash)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.True(t, token.Revoked, "refresh token should be revoked")

	// Verify access token is now revoked
	revoked, err = srv.db.IsAccessTokenRevoked(context.Background(), accessTokenID)
	require.NoError(t, err)
	assert.True(t, revoked, "access token should be revoked after /revoke call")
}

// RD-1008: handler-level coverage proving the pp_access cookie actually
// ships on the three real production code paths (session-status poll on
// login completion, refresh rotation, revoke/logout). Catches a future
// regression that removes the SetAccessCookie / ClearAccessCookie call.

// findCookie returns the cookie with the given name from a recorded response,
// or nil if absent.
func findCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHandleAuthSessionStatus_SetsAccessCookie(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Seed a completed session — what the auth callback would produce.
	sessionID := srv.sessionStore.CreateSession(nil)
	require.NotEmpty(t, sessionID)
	subject := "did:privado:cookie-issue-1"
	accessToken, err := jwtService.IssueAccessToken(subject, true)
	require.NoError(t, err)
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)
	require.NoError(t, srv.sessionStore.CompleteSession(sessionID, accessToken, refreshToken))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auth/session/:id/status", srv.handleAuthSessionStatus)

	req := httptest.NewRequest("GET", "/api/v1/auth/session/"+sessionID+"/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	ck := findCookie(t, w, auth.AccessCookieName)
	require.NotNil(t, ck, "session-status must set the pp_access cookie when returning a completed session — the cross-subdomain navigation to /oauth/authorize relies on it")
	assert.Equal(t, accessToken, ck.Value)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
	assert.Equal(t, "/", ck.Path)
	assert.Equal(t, int(AccessTokenTTL.Seconds()), ck.MaxAge)
}

func TestHandleRefresh_SetsAccessCookie(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	subject := "did:privado:cookie-issue-2"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)
	tokenHash := auth.HashToken(refreshToken)
	require.NoError(t, srv.db.SaveRefreshToken(context.Background(), tokenHash, subject, time.Now().Add(7*24*time.Hour)))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/refresh", srv.handleRefresh)

	jsonBody, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	req := httptest.NewRequest("POST", "/refresh", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	ck := findCookie(t, w, auth.AccessCookieName)
	require.NotNil(t, ck, "refresh must re-issue the pp_access cookie so the browser stays in sync after rotation")
	// Cookie value should match the new access token in the JSON body.
	var resp AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, resp.AccessToken, ck.Value)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
	assert.Equal(t, int(AccessTokenTTL.Seconds()), ck.MaxAge)
}

func TestHandleRevoke_ClearsAccessCookie(t *testing.T) {
	srv, jwtService := setupTestServerForAuth(t)
	defer srv.db.Close()

	subject := "did:privado:cookie-issue-3"
	refreshToken, err := jwtService.IssueRefreshToken(subject)
	require.NoError(t, err)
	require.NoError(t, srv.db.SaveRefreshToken(context.Background(), auth.HashToken(refreshToken), subject, time.Now().Add(7*24*time.Hour)))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/revoke", srv.handleRevoke)

	jsonBody, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	ck := findCookie(t, w, auth.AccessCookieName)
	require.NotNil(t, ck, "revoke/logout must clear the pp_access cookie")
	assert.Empty(t, ck.Value)
	assert.Less(t, ck.MaxAge, 0, "MaxAge<0 deletes the cookie on the client")
}
