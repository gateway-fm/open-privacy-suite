package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// linkAddressViaHTTP performs the challenge/verify flow and returns the recorder
// for the verify step. The caller can check w.Code to verify success.
func linkAddressViaHTTP(t *testing.T, router *gin.Engine, token, address string) *httptest.ResponseRecorder {
	t.Helper()

	// Step 1: challenge
	req1 := httptest.NewRequest("POST", "/eth/link/challenge", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	var cr apimodels.ChallengeResponse
	require.NoError(t, json.Unmarshal(w1.Body.Bytes(), &cr))

	// Step 2: verify with mock signature
	body, _ := json.Marshal(apimodels.VerifyLinkRequest{
		Nonce:     cr.Nonce,
		Address:   address,
		Signature: "0x" + strings.Repeat("a", 130),
	})
	req2 := httptest.NewRequest("POST", "/eth/link/verify", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	return w2
}

// setupSecurityTestServer builds a server with JWT auth routes for eth-link
// plus the admin collisions endpoint behind X-Admin-Token auth.
func setupSecurityTestServer(t *testing.T) (*Server, *gin.Engine) {
	t.Helper()

	srv := setupTestServerForEthLink(t)

	// Override config to include an admin API token.
	srv.config.AdminAPIToken = "test-admin-token"

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// User-facing ETH link routes (JWT auth).
	router.POST("/eth/link/challenge", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkChallenge)
	router.POST("/eth/link/verify", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleEthLinkVerify)
	router.GET("/eth/addresses", auth.JWTAuthMiddleware(srv.jwtService, srv.db), srv.handleGetEthAddresses)

	// Admin collision endpoint (admin token auth).
	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	admin.GET("/eth-addresses/collisions", srv.getEthAddressCollisions)

	return srv, router
}

// ---------------------------------------------------------------------------
// SIEM / linking behaviour (observable via HTTP + DB state)
// ---------------------------------------------------------------------------

func TestHandleEthLinkVerify_SIEMOnNormalLink(t *testing.T) {
	srv, router := setupSecurityTestServer(t)

	did := "did:privado:siem_normal"
	token := createTestJWT(t, srv, did)
	addr := "0x1111111111111111111111111111111111111111"

	w := linkAddressViaHTTP(t, router, token, addr)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify DB state.
	links, err := srv.db.GetEthAddressesByDID(context.Background(), did)
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, strings.ToLower(addr), links[0].EthAddress)
}

func TestHandleEthLinkVerify_SIEMOnCollision(t *testing.T) {
	srv, router := setupSecurityTestServer(t)

	didA := "did:privado:siem_coll_a"
	didB := "did:privado:siem_coll_b"
	addr := "0x2222222222222222222222222222222222222222"

	// DID_A system-links the address directly in the DB.
	require.NoError(t, srv.db.SystemLinkEthAddress(context.Background(), didA, addr))

	// DID_B user-links via HTTP — collision path.
	tokenB := createTestJWT(t, srv, didB)
	w := linkAddressViaHTTP(t, router, tokenB, addr)
	assert.Equal(t, http.StatusOK, w.Code, "collision should still succeed")

	// Both DIDs should be linked.
	dids, err := srv.db.GetDIDsByEthAddress(context.Background(), strings.ToLower(addr))
	require.NoError(t, err)
	assert.Len(t, dids, 2)
	assert.Contains(t, dids, didA)
	assert.Contains(t, dids, didB)
}

func TestHandleEthLinkVerify_CollisionDoesNotLeak(t *testing.T) {
	srv, router := setupSecurityTestServer(t)

	didA := "did:privado:leak_a"
	didB := "did:privado:leak_b"
	addr := "0x3333333333333333333333333333333333333333"

	tokenA := createTestJWT(t, srv, didA)
	tokenB := createTestJWT(t, srv, didB)

	// DID_A links the address.
	wA := linkAddressViaHTTP(t, router, tokenA, addr)
	require.Equal(t, http.StatusOK, wA.Code)

	// DID_B links the same address.
	wB := linkAddressViaHTTP(t, router, tokenB, addr)
	assert.Equal(t, http.StatusOK, wB.Code)

	// Both DIDs must still have their links.
	addrsA, err := srv.db.GetLinkedEthAddresses(context.Background(), didA)
	require.NoError(t, err)
	assert.Len(t, addrsA, 1, "DID_A should still have the address")

	addrsB, err := srv.db.GetLinkedEthAddresses(context.Background(), didB)
	require.NoError(t, err)
	assert.Len(t, addrsB, 1, "DID_B should also have the address")
}

// ---------------------------------------------------------------------------
// Admin collision endpoint
// ---------------------------------------------------------------------------

func TestGetEthAddressCollisions_NoCollisions(t *testing.T) {
	_, router := setupSecurityTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/admin/eth-addresses/collisions", nil)
	req.Header.Set("X-Admin-Token", "test-admin-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, float64(0), body["count"])

	collisions, ok := body["collisions"].([]any)
	require.True(t, ok)
	assert.Empty(t, collisions)
}

func TestGetEthAddressCollisions_WithCollision(t *testing.T) {
	srv, router := setupSecurityTestServer(t)
	ctx := context.Background()

	didA := "did:privado:admin_coll_a"
	didB := "did:privado:admin_coll_b"
	addr := "0x4444444444444444444444444444444444444444"

	// Create a collision: two DIDs, same address.
	require.NoError(t, srv.db.LinkEthAddress(ctx, didA, addr, "sigA", "hashA"))
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, didB, addr))

	req := httptest.NewRequest("GET", "/api/v1/admin/eth-addresses/collisions", nil)
	req.Header.Set("X-Admin-Token", "test-admin-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Collisions []struct {
			EthAddress string   `json:"eth_address"`
			DIDs       []string `json:"dids"`
			LinkTypes  []string `json:"link_types"`
		} `json:"collisions"`
		Count int `json:"count"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, 1, body.Count)
	require.Len(t, body.Collisions, 1)
	assert.Equal(t, addr, body.Collisions[0].EthAddress)
	assert.Len(t, body.Collisions[0].DIDs, 2)
	assert.Contains(t, body.Collisions[0].DIDs, didA)
	assert.Contains(t, body.Collisions[0].DIDs, didB)
}

func TestGetEthAddressCollisions_RequiresAuth(t *testing.T) {
	_, router := setupSecurityTestServer(t)

	// No auth header at all.
	req := httptest.NewRequest("GET", "/api/v1/admin/eth-addresses/collisions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden,
		"expected 401 or 403, got %d", w.Code)

	// Wrong token.
	req2 := httptest.NewRequest("GET", "/api/v1/admin/eth-addresses/collisions", nil)
	req2.Header.Set("X-Admin-Token", "wrong-token")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.True(t, w2.Code == http.StatusUnauthorized || w2.Code == http.StatusForbidden,
		"expected 401 or 403, got %d", w2.Code)
}
