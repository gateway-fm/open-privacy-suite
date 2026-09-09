package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestServerForEthLink creates a test server configured for ETH link tests
func setupTestServerForEthLink(t *testing.T) *Server {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development
		dbURL = sharedTestDBURL(t)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		VerifierID:     "did:privado:verifier:test",
		BaseURL:        "http://localhost:8080",
		Environment:    "development",
		MockSignatures: true, // Enable mock mode for tests
	}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		challengeStore: NewChallengeStore(5*time.Minute, 1*time.Minute),
		config:         cfg,
	}

	t.Cleanup(func() {
		srv.rbacAccessCtrl.Stop()
		srv.challengeStore.Stop()
		srv.db.Close()
	})

	return srv
}

// createTestJWT creates a valid JWT for testing
func createTestJWT(t *testing.T, srv *Server, subject string) string {
	token, err := srv.jwtService.IssueAccessToken(subject, true)
	require.NoError(t, err)
	return token
}

// TestChallengeStore tests the challenge store functionality
func TestChallengeStore_CreateAndGet(t *testing.T) {
	cs := NewChallengeStore(5*time.Minute, 1*time.Minute)
	defer cs.Stop()

	did := "did:privado:test123"

	// Create challenge
	challenge, err := cs.CreateChallenge(did)
	require.NoError(t, err)
	assert.NotEmpty(t, challenge.Nonce)
	assert.NotEmpty(t, challenge.Message)
	assert.Equal(t, did, challenge.DID)

	// Get challenge (should succeed and consume it)
	retrieved := cs.GetChallenge(challenge.Nonce)
	require.NotNil(t, retrieved)
	assert.Equal(t, challenge.Nonce, retrieved.Nonce)
	assert.Equal(t, challenge.DID, retrieved.DID)

	// Try to get again (should fail - one-time use)
	retrieved2 := cs.GetChallenge(challenge.Nonce)
	assert.Nil(t, retrieved2)
}

func TestChallengeStore_NonExistentNonce(t *testing.T) {
	cs := NewChallengeStore(5*time.Minute, 1*time.Minute)
	defer cs.Stop()

	retrieved := cs.GetChallenge("non-existent-nonce")
	assert.Nil(t, retrieved)
}

func TestChallengeStore_ExpiredChallenge(t *testing.T) {
	// Create store with very short TTL
	cs := NewChallengeStore(1*time.Millisecond, 1*time.Second)
	defer cs.Stop()

	challenge, err := cs.CreateChallenge("did:privado:test123")
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Should return nil (expired)
	retrieved := cs.GetChallenge(challenge.Nonce)
	assert.Nil(t, retrieved)
}

// TestHandleEthLinkChallenge tests the challenge creation endpoint
func TestHandleEthLinkChallenge_Success(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)

	req := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response apimodels.ChallengeResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.Nonce)
	assert.NotEmpty(t, response.Message)
	assert.Contains(t, response.Message, subject)
}

func TestHandleEthLinkChallenge_Unauthorized(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)

	req := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	// No Authorization header
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestHandleEthLinkVerify tests the verification and linking endpoint
func TestHandleEthLinkVerify_Success(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)

	// Step 1: Create challenge
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	var challengeResp apimodels.ChallengeResponse
	err := json.Unmarshal(w1.Body.Bytes(), &challengeResp)
	require.NoError(t, err)

	// Step 2: Verify with mock signature (MockSignatures=true)
	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     challengeResp.Nonce,
		Address:   "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F",
		Signature: "0x" + strings.Repeat("a", 130), // Mock signature
	}
	body, _ := json.Marshal(verifyReq)

	req2 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)

	var verifyResp map[string]any
	err = json.Unmarshal(w2.Body.Bytes(), &verifyResp)
	require.NoError(t, err)
	assert.Equal(t, "address linked successfully", verifyResp["message"])
}

func TestHandleEthLinkVerify_InvalidNonce(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)

	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     "invalid-nonce",
		Address:   "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F",
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired nonce")
}

func TestHandleEthLinkVerify_InvalidAddress(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)

	// Create challenge
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	var challengeResp apimodels.ChallengeResponse
	json.Unmarshal(w1.Body.Bytes(), &challengeResp)

	// Verify with invalid address
	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     challengeResp.Nonce,
		Address:   "invalid-address",
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid ethereum address format")
}

// TestHandleGetEthAddresses tests the address listing endpoint
func TestHandleGetEthAddresses_Empty(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/eth/addresses", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleGetEthAddresses)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)

	req := httptest.NewRequest("GET", "/eth/addresses", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]any
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Empty(t, response["addresses"])
}

func TestHandleGetEthAddresses_WithLinkedAddress(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)
	router.GET("/eth/addresses", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleGetEthAddresses)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)
	testAddress := "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F"

	// Link an address first
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	var challengeResp apimodels.ChallengeResponse
	json.Unmarshal(w1.Body.Bytes(), &challengeResp)

	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     challengeResp.Nonce,
		Address:   testAddress,
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body, _ := json.Marshal(verifyReq)
	req2 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	// Now get addresses
	req := httptest.NewRequest("GET", "/eth/addresses", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]apimodels.EthAddressResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	require.Len(t, response["addresses"], 1)
	assert.Equal(t, "0x742d35cc6634c0532925a3b844bc9e7595f5be5f", response["addresses"][0].Address) // lowercased
}

// TestHandleDeleteEthAddress tests the address unlinking endpoint
func TestHandleDeleteEthAddress_Success(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)
	router.DELETE("/eth/addresses/:address", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleDeleteEthAddress)
	router.GET("/eth/addresses", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleGetEthAddresses)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)
	testAddress := "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F"

	// Link an address first
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	var challengeResp apimodels.ChallengeResponse
	json.Unmarshal(w1.Body.Bytes(), &challengeResp)

	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     challengeResp.Nonce,
		Address:   testAddress,
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body, _ := json.Marshal(verifyReq)
	req2 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	// Delete the address
	req := httptest.NewRequest("DELETE", "/eth/addresses/"+testAddress, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "address unlinked successfully")

	// Verify it's gone
	req3 := httptest.NewRequest("GET", "/eth/addresses", nil)
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	var response map[string][]any
	json.Unmarshal(w3.Body.Bytes(), &response)
	assert.Empty(t, response["addresses"])
}

func TestHandleDeleteEthAddress_NotFound(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.DELETE("/eth/addresses/:address", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleDeleteEthAddress)

	subject := "did:privado:test123"
	token := createTestJWT(t, srv, subject)

	req := httptest.NewRequest("DELETE", "/eth/addresses/0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "address not found")
}

// TestHandleEthLinkVerify_WrongUser tests that a user can't use another user's challenge
func TestHandleEthLinkVerify_WrongUser(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)

	user1 := "did:privado:user1"
	user2 := "did:privado:user2"
	token1 := createTestJWT(t, srv, user1)
	token2 := createTestJWT(t, srv, user2)

	// User 1 creates a challenge
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token1)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	var challengeResp apimodels.ChallengeResponse
	json.Unmarshal(w1.Body.Bytes(), &challengeResp)

	// User 2 tries to use User 1's challenge
	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     challengeResp.Nonce,
		Address:   "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F",
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body, _ := json.Marshal(verifyReq)

	req := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token2)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "challenge does not belong to this user")
}

// TestHandleDeleteEthAddress_OtherUsersAddress tests isolation between users
func TestHandleDeleteEthAddress_OtherUsersAddress(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)
	router.DELETE("/eth/addresses/:address", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleDeleteEthAddress)

	user1 := "did:privado:user1"
	user2 := "did:privado:user2"
	token1 := createTestJWT(t, srv, user1)
	token2 := createTestJWT(t, srv, user2)
	testAddress := "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F"

	// User 1 links an address
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token1)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	var challengeResp apimodels.ChallengeResponse
	json.Unmarshal(w1.Body.Bytes(), &challengeResp)

	verifyReq := apimodels.VerifyLinkRequest{
		Nonce:     challengeResp.Nonce,
		Address:   testAddress,
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body, _ := json.Marshal(verifyReq)
	req2 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token1)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	// User 2 tries to delete User 1's address
	req := httptest.NewRequest("DELETE", "/eth/addresses/"+testAddress, nil)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "address not found")
}

// Test helper to verify addresses are properly stored
func TestLinkAddress_DatabaseStorage(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	subject := "did:privado:test123"
	address := "0x742d35cc6634c0532925a3b844bc9e7595f5be5f"

	// Link directly via database (bypass HTTP)
	err := srv.db.LinkEthAddress(context.Background(), subject, address, "mock-signature", "mock-hash")
	require.NoError(t, err)

	// Verify via database
	links, err := srv.db.GetEthAddressesByDID(context.Background(), subject)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, address, links[0].EthAddress)
	assert.Equal(t, subject, links[0].DID)
}

// TestLinkAddress_MultipleDIDs verifies that multiple DIDs can link the same address
// (e.g. shared deployer key used by two users). The unique constraint is on (did, eth_address).
func TestLinkAddress_MultipleDIDs(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	user1 := "did:privado:user1"
	user2 := "did:privado:user2"
	address := "0x742d35cc6634c0532925a3b844bc9e7595f5be5f"

	// User 1 links the address
	err := srv.db.LinkEthAddress(context.Background(), user1, address, "sig1", "hash1")
	require.NoError(t, err)

	// User 2 also links the same address — must succeed
	err = srv.db.LinkEthAddress(context.Background(), user2, address, "sig2", "hash2")
	require.NoError(t, err)

	// Both users should see the address in their linked list
	links1, err := srv.db.GetEthAddressesByDID(context.Background(), user1)
	require.NoError(t, err)
	require.Len(t, links1, 1)
	assert.Equal(t, address, links1[0].EthAddress)

	links2, err := srv.db.GetEthAddressesByDID(context.Background(), user2)
	require.NoError(t, err)
	require.Len(t, links2, 1)
	assert.Equal(t, address, links2[0].EthAddress)
}

// TestLinkAddress_SameDIDRefresh verifies that the same DID can refresh its own link.
func TestLinkAddress_SameDIDRefresh(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	subject := "did:privado:test123"
	address := "0x742d35cc6634c0532925a3b844bc9e7595f5be5f"

	// Initial link
	err := srv.db.LinkEthAddress(context.Background(), subject, address, "sig1", "hash1")
	require.NoError(t, err)

	// Same DID re-links with a new signature — must succeed
	err = srv.db.LinkEthAddress(context.Background(), subject, address, "sig2", "hash2")
	require.NoError(t, err)

	// Address still belongs to the same DID
	links, err := srv.db.GetEthAddressesByDID(context.Background(), subject)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, address, links[0].EthAddress)
}

// TestLinkAddress_RevokedCannotRelink verifies that a revoked address link cannot be
// re-established by the same user. Requires explicit admin action to un-revoke.
func TestLinkAddress_RevokedCannotRelink(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	subject := "did:privado:test123"
	address := "0x742d35cc6634c0532925a3b844bc9e7595f5be5f"

	// Initial link
	err := srv.db.LinkEthAddress(context.Background(), subject, address, "sig1", "hash1")
	require.NoError(t, err)

	// Admin revokes the link
	err = srv.db.RevokeEthAddressLink(context.Background(), subject, address)
	require.NoError(t, err)

	// Same DID tries to re-link — must fail with revocation error
	err = srv.db.LinkEthAddress(context.Background(), subject, address, "sig2", "hash2")
	require.ErrorIs(t, err, db.ErrAddressLinkRevoked)

	// Address must still be revoked (not visible in active links)
	links, err := srv.db.GetEthAddressesByDID(context.Background(), subject)
	require.NoError(t, err)
	assert.Empty(t, links, "revoked address should not appear in active links")
}

// TestHandleEthLinkVerify_MultipleDIDs_HTTP tests that multiple users can link the
// same address via the HTTP endpoint (e.g. shared deployer key).
func TestHandleEthLinkVerify_MultipleDIDs_HTTP(t *testing.T) {
	srv := setupTestServerForEthLink(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)

	user1 := "did:privado:user1"
	user2 := "did:privado:user2"
	token1 := createTestJWT(t, srv, user1)
	token2 := createTestJWT(t, srv, user2)
	testAddress := "0x742d35Cc6634C0532925a3b844Bc9e7595f5bE5F"

	// User 1 links the address
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token1)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	var challenge1 apimodels.ChallengeResponse
	err := json.Unmarshal(w1.Body.Bytes(), &challenge1)
	require.NoError(t, err)

	verifyReq1 := apimodels.VerifyLinkRequest{
		Nonce:     challenge1.Nonce,
		Address:   testAddress,
		Signature: "0x" + strings.Repeat("a", 130),
	}
	body1, _ := json.Marshal(verifyReq1)
	req2 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body1))
	req2.Header.Set("Authorization", "Bearer "+token1)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	// User 2 links the same address — should succeed (shared key scenario)
	req3 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req3.Header.Set("Authorization", "Bearer "+token2)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	require.Equal(t, http.StatusOK, w3.Code)

	var challenge2 apimodels.ChallengeResponse
	err = json.Unmarshal(w3.Body.Bytes(), &challenge2)
	require.NoError(t, err)

	verifyReq2 := apimodels.VerifyLinkRequest{
		Nonce:     challenge2.Nonce,
		Address:   testAddress,
		Signature: "0x" + strings.Repeat("b", 130),
	}
	body2, _ := json.Marshal(verifyReq2)
	req4 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body2))
	req4.Header.Set("Authorization", "Bearer "+token2)
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	router.ServeHTTP(w4, req4)

	assert.Equal(t, http.StatusOK, w4.Code)
	assert.Contains(t, w4.Body.String(), "address linked successfully")
}
