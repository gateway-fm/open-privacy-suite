package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spMockOIDC is a minimal OIDC server that publishes a real JWKS and signs
// tokens with a test RSA key — enough for VerifyAccessToken to validate a
// service-principal access token end-to-end. (The auth package has an
// equivalent unexported helper; this is the server-package twin.)
type spMockOIDC struct {
	*httptest.Server
	key    *rsa.PrivateKey
	keyID  string
	issuer string
}

func newSPMockOIDC(t *testing.T) *spMockOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	m := &spMockOIDC{key: key, keyID: "sp-test-key"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                m.issuer,
			"authorization_endpoint":                m.issuer + "/authorize",
			"token_endpoint":                        m.issuer + "/token",
			"jwks_uri":                              m.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: m.keyID, Algorithm: string(jose.RS256), Use: "sig"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	srv := httptest.NewServer(mux)
	m.Server = srv
	m.issuer = srv.URL
	return m
}

func (m *spMockOIDC) signToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// TestHandleAzureServicePrincipal exercises the RD-1120 endpoint end-to-end
// against a real DB: a service-principal access token is verified, the tenant
// allowlist is enforced, the SP is auto-provisioned as azuread:<oid>, and our
// local tokens are issued.
func TestHandleAzureServicePrincipal(t *testing.T) {
	ts := setupTestServerForAzureTenants(t)

	mockOIDC := newSPMockOIDC(t)
	defer mockOIDC.Close()

	// Authenticator validates against the mock JWKS; SP audience defaults to the
	// client ID ("test-client") since we don't set a custom one.
	authn, err := auth.NewAzureADAuthenticatorFromIssuer("test-client", "test-secret", mockOIDC.issuer)
	require.NoError(t, err)
	ts.azureAuthenticator = authn

	ts.router.POST("/api/v1/auth/azure/service-principal", ts.handleAzureServicePrincipal)

	const allowedTID = "aaaabbbb-cccc-dddd-eeee-ffffffffffff"
	_, err = ts.db.CreateAllowedAzureTenant(context.Background(), &db.AllowedAzureTenant{
		ID:            uuid.New().String(),
		TenantID:      allowedTID,
		Label:         "SP Test Tenant",
		AutoProvision: true,
	})
	require.NoError(t, err)

	post := func(body interface{}) *httptest.ResponseRecorder {
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/azure/service-principal", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)
		return w
	}
	// mintToken signs a valid SP access token for the given tenant (oid derived
	// from tid so each tenant maps to a distinct service principal).
	mintToken := func(oid, tid string) string {
		now := time.Now()
		return mockOIDC.signToken(t, map[string]interface{}{
			"iss": mockOIDC.issuer,
			"aud": "test-client",
			"exp": jwt.NewNumericDate(now.Add(time.Hour)),
			"iat": jwt.NewNumericDate(now),
			"oid": oid,
			"tid": tid,
		})
	}

	t.Run("allowed tenant provisions SP and issues tokens", func(t *testing.T) {
		w := post(map[string]interface{}{"access_token": mintToken("sp-allowed-oid", allowedTID)})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp apimodels.AuthResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, "Bearer", resp.TokenType)

		// The SP is provisioned as azuread:<oid> with its tenant pinned.
		user, err := ts.db.GetUserByExternalID(context.Background(), auth.AzureSubject("sp-allowed-oid"))
		require.NoError(t, err)
		require.NotNil(t, user, "service principal should be auto-provisioned")
		require.NotNil(t, user.AuthTenantID)
		assert.Equal(t, allowedTID, *user.AuthTenantID)
		// RD-1131: SPs are NOT auto-KYC'd by default.
		assert.False(t, user.KYC, "service principal must not be KYC-verified by default")
	})

	t.Run("tenant not in allowlist is rejected", func(t *testing.T) {
		w := post(map[string]interface{}{"access_token": mintToken("sp-other-oid", "99999999-8888-7777-6666-555555555555")})
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("malformed token is rejected", func(t *testing.T) {
		w := post(map[string]interface{}{"access_token": "not-a-jwt"})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("missing access_token is a bad request", func(t *testing.T) {
		w := post(map[string]interface{}{})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("auto-KYC provisions SP as KYC-verified when enabled (RD-1131)", func(t *testing.T) {
		ts.config.AutoKYCAzureServicePrincipal = true
		defer func() { ts.config.AutoKYCAzureServicePrincipal = false }()

		// Fresh allowed tenant + distinct oid so this is a brand-new provision.
		const autoKYCTID = "11112222-3333-4444-5555-666677778888"
		_, err := ts.db.CreateAllowedAzureTenant(context.Background(), &db.AllowedAzureTenant{
			ID:            uuid.New().String(),
			TenantID:      autoKYCTID,
			Label:         "Auto-KYC SP Tenant",
			AutoProvision: true,
		})
		require.NoError(t, err)

		w := post(map[string]interface{}{"access_token": mintToken("sp-autokyc-oid", autoKYCTID)})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		user, err := ts.db.GetUserByExternalID(context.Background(), auth.AzureSubject("sp-autokyc-oid"))
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.True(t, user.KYC, "SP should be auto-KYC'd when AUTO_KYC_AZURE_SERVICE_PRINCIPAL is enabled")
	})

	t.Run("not configured returns 404", func(t *testing.T) {
		ts.azureAuthenticator = nil // last subtest — mutating shared state is fine here
		w := post(map[string]interface{}{"access_token": "anything"})
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
