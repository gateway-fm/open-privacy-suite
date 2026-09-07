//go:build mockauth

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"privacy-proxy/internal/apimodels"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleAuthVerify_BillionsBootstrap_MockBypass exercises the §3.1
// invariant from the manual test plan: with REQUIRE_PROOF_OF_HUMANITY=true
// AND a valid (parsed) BillionsCredentialQuery loaded, the server still
// accepts mock-login tokens in dev builds. The opt-in PoH gate must apply
// to the JWZ-verification path only, not short-circuit the dev mock flow.
//
// The refuse-to-boot half (missing/malformed query file → panic on
// config.Load) is already covered by TestLoad_BillionsCredentialQueryFile
// in internal/config. This test pins the success half.
func TestHandleAuthVerify_BillionsBootstrap_MockBypass(t *testing.T) {
	srv, _ := setupTestServerForAuth(t)
	defer srv.db.Close()

	// Simulate a fully-configured Path B environment without breaking the
	// existing mock-verifier setup. A real Billions credential check would
	// run inside privadoVerifier.VerifyJWZWithProofData; we never get there
	// for mock tokens.
	srv.config.AllowMockLogin = true
	srv.config.RequireProofOfHumanity = true
	srv.config.BillionsIssuerDID = "did:test:billions"
	srv.config.BillionsCredentialQueryFile = "/dev/null/skip"
	srv.config.BillionsCredentialQuery = map[string]any{
		"credentialSubject": map[string]any{
			"isHuman": map[string]any{"$eq": 1},
		},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/request", srv.handleAuthRequest)
	router.POST("/auth/verify", srv.handleAuthVerify)

	// Step 1 — open a session.
	openReq := httptest.NewRequest(http.MethodPost, "/auth/request", nil)
	openReq.Header.Set("Content-Type", "application/json")
	openW := httptest.NewRecorder()
	router.ServeHTTP(openW, openReq)
	require.Equal(t, http.StatusOK, openW.Code, "auth/request should succeed even with PoH on")

	var open apimodels.AuthRequestResponse
	require.NoError(t, json.Unmarshal(openW.Body.Bytes(), &open))
	require.NotEmpty(t, open.SessionID)

	// Step 2 — verify with a mock JWZ token. tryMockLogin (mockauth build
	// tag) sees the "mock." prefix and short-circuits to a synthetic DID
	// without ever calling privadoVerifier — so the PoH gate at line ~489
	// of auth.go cannot fire.
	verifyBody := apimodels.AuthVerifyRequest{
		SessionID: open.SessionID,
		JWZToken:  "mock.did:privado:billions_bypass_test",
	}
	body, err := json.Marshal(verifyBody)
	require.NoError(t, err)

	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(body))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyW := httptest.NewRecorder()
	router.ServeHTTP(verifyW, verifyReq)

	require.Equal(t, http.StatusOK, verifyW.Code,
		"mock-login must bypass PoH; got status %d body %s", verifyW.Code, verifyW.Body.String())

	var resp apimodels.AuthResponse
	require.NoError(t, json.Unmarshal(verifyW.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.AccessToken, "mock-login must mint an access token")
	assert.NotEmpty(t, resp.RefreshToken, "mock-login must mint a refresh token")
}
