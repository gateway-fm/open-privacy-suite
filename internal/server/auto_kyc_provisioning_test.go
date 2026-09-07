package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1131 auto-KYC end-to-end coverage for the two identity classes that the
// service-principal test (auth_azure_service_principal_test.go) does not cover:
// the interactive Azure-user class and the Privado class. Each class is driven
// by its own config flag (AUTO_KYC_AZURE_USER / AUTO_KYC_PRIVADO, default
// false). The flag becomes the `kyc` value passed to rbac.EnsureUserExists at
// provisioning time, which applies it ONLY to newly-created rows; every call
// site then re-reads user.KYC, so an existing (admin-managed) user's KYC is
// never changed by a login. These tests assert that invariant against a real
// provisioned `users` row (kyc=false default, kyc=true when the flag is on,
// existing-user KYC preserved regardless of the flag).

// TestAutoKYCAzureUserProvisioning exercises the interactive Azure-user
// provisioning path (RD-1131). It is tested at the completeAzureLogin level —
// the shared post-identity helper that handleAzureCallback invokes immediately
// after exchanging the authorization code. handleAzureCallback calls
//
//	s.completeAzureLogin(c, identity, "azure_ad", s.config.AutoKYCAzureUser)
//
// so driving completeAzureLogin with the same autoKYCNewUser argument exercises
// the exact tenant-allowlist + EnsureUserExists provisioning + KYC re-read flow
// the real handler runs. Only the Azure code-exchange (which requires Microsoft)
// is bypassed; the provisioning and KYC decision under test are unchanged.
func TestAutoKYCAzureUserProvisioning(t *testing.T) {
	ts := setupTestServerForAzureTenants(t)

	// Test-only route that reproduces handleAzureCallback's post-exchange call:
	// it synthesizes the verified identity from query params and forwards the
	// per-class flag exactly as the real handler does.
	ts.router.POST("/test/azure/complete", func(c *gin.Context) {
		identity := &auth.AzureIdentity{
			OID:      c.Query("oid"),
			TenantID: c.Query("tid"),
		}
		ts.completeAzureLogin(c, identity, "azure_ad", ts.config.AutoKYCAzureUser)
	})

	const allowedTID = "aaaabbbb-cccc-dddd-eeee-ffffffffffff"
	_, err := ts.db.CreateAllowedAzureTenant(context.Background(), &db.AllowedAzureTenant{
		ID:            uuid.New().String(),
		TenantID:      allowedTID,
		Label:         "Azure User Test Tenant",
		AutoProvision: true,
	})
	require.NoError(t, err)

	login := func(oid string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/test/azure/complete?oid="+oid+"&tid="+allowedTID, nil)
		w := httptest.NewRecorder()
		ts.router.ServeHTTP(w, req)
		return w
	}

	t.Run("new user provisions kyc=false when AUTO_KYC_AZURE_USER is off", func(t *testing.T) {
		require.False(t, ts.config.AutoKYCAzureUser, "default must be off")

		oid := "azuser-default-" + uuid.NewString()
		w := login(oid)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp apimodels.AuthResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.AccessToken)

		user, err := ts.db.GetUserByExternalID(context.Background(), auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, user, "interactive azure user should be auto-provisioned")
		assert.False(t, user.KYC, "azure user must not be KYC-verified when AUTO_KYC_AZURE_USER is off")
	})

	t.Run("new user provisions kyc=true when AUTO_KYC_AZURE_USER is on", func(t *testing.T) {
		ts.config.AutoKYCAzureUser = true
		defer func() { ts.config.AutoKYCAzureUser = false }()

		oid := "azuser-autokyc-" + uuid.NewString()
		w := login(oid)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		user, err := ts.db.GetUserByExternalID(context.Background(), auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.True(t, user.KYC, "azure user should be auto-KYC'd when AUTO_KYC_AZURE_USER is on")
	})

	t.Run("existing user keeps admin-set KYC regardless of the flag", func(t *testing.T) {
		// First login provisions the user with the flag OFF -> kyc=false.
		require.False(t, ts.config.AutoKYCAzureUser)
		oid := "azuser-existing-" + uuid.NewString()
		subject := auth.AzureSubject(oid)

		w := login(oid)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		user, err := ts.db.GetUserByExternalID(context.Background(), subject)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.False(t, user.KYC)

		// An admin marks the existing user as KYC-verified out of band.
		user.KYC = true
		require.NoError(t, ts.db.UpdateUser(context.Background(), user))

		// Re-login with the auto-KYC flag ON. Because EnsureUserExists only
		// applies kyc to NEW rows and the handler re-reads user.KYC, the
		// admin-managed value must be preserved (not overwritten, and not
		// flipped back to false by a different flag setting).
		ts.config.AutoKYCAzureUser = true
		defer func() { ts.config.AutoKYCAzureUser = false }()

		w = login(oid)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		reread, err := ts.db.GetUserByExternalID(context.Background(), subject)
		require.NoError(t, err)
		require.NotNil(t, reread)
		assert.True(t, reread.KYC, "existing user's admin-set KYC must be preserved across re-login")

		// And the inverse direction: an admin-cleared user must NOT be re-KYC'd
		// by a subsequent login even with the flag still ON.
		reread.KYC = false
		require.NoError(t, ts.db.UpdateUser(context.Background(), reread))

		w = login(oid)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		final, err := ts.db.GetUserByExternalID(context.Background(), subject)
		require.NoError(t, err)
		require.NotNil(t, final)
		assert.False(t, final.KYC, "existing user's admin-cleared KYC must NOT be re-set by login when the flag is on")
	})
}

// TestAutoKYCPrivadoProvisioning exercises the Privado provisioning path
// (RD-1131, AUTO_KYC_PRIVADO). The full HTTP login (verifyAndIssueTokens)
// requires a verified ZK JWZ proof from a real Privado verifier, which is not
// feasible to mint in a unit/integration test. We therefore test at the
// lowest provisioning boundary: the exact rbac.EnsureUserExists + KYC re-read
// sequence that verifyAndIssueTokens runs, with the kyc argument sourced from
// s.config.AutoKYCPrivado just as the real code does:
//
//	kyc := s.config.AutoKYCPrivado
//	user, _ := s.rbacAccessCtrl.EnsureUserExists(ctx, userDID, kyc, false)
//	if user != nil { kyc = user.KYC }
//
// This asserts the new-user-reflects-flag and existing-user-preserved
// invariants against the real provisioned `users` row. The boundary not
// covered here (the ZK verification preceding this block) is independent of the
// KYC decision.
func TestAutoKYCPrivadoProvisioning(t *testing.T) {
	ts := setupTestServerForAzureTenants(t)

	// provision mirrors the verifyAndIssueTokens KYC block verbatim, sourcing
	// the kyc seed from AUTO_KYC_PRIVADO. Returns the KYC value the login would
	// have stamped into the issued token.
	provision := func(did string) bool {
		kyc := ts.config.AutoKYCPrivado
		user, err := ts.rbacAccessCtrl.EnsureUserExists(context.Background(), did, kyc, false)
		require.NoError(t, err)
		require.NotNil(t, user)
		if user != nil {
			kyc = user.KYC
		}
		return kyc
	}

	t.Run("new user provisions kyc=false when AUTO_KYC_PRIVADO is off", func(t *testing.T) {
		require.False(t, ts.config.AutoKYCPrivado, "default must be off")

		did := "did:privado:default:" + uuid.NewString()
		tokenKYC := provision(did)
		assert.False(t, tokenKYC, "issued token must carry kyc=false")

		user, err := ts.db.GetUserByExternalID(context.Background(), did)
		require.NoError(t, err)
		require.NotNil(t, user, "privado user should be auto-provisioned")
		assert.False(t, user.KYC, "privado user must not be KYC-verified when AUTO_KYC_PRIVADO is off")
	})

	t.Run("new user provisions kyc=true when AUTO_KYC_PRIVADO is on", func(t *testing.T) {
		ts.config.AutoKYCPrivado = true
		defer func() { ts.config.AutoKYCPrivado = false }()

		did := "did:privado:autokyc:" + uuid.NewString()
		tokenKYC := provision(did)
		assert.True(t, tokenKYC, "issued token must carry kyc=true")

		user, err := ts.db.GetUserByExternalID(context.Background(), did)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.True(t, user.KYC, "privado user should be auto-KYC'd when AUTO_KYC_PRIVADO is on")
	})

	t.Run("existing user keeps admin-set KYC regardless of the flag", func(t *testing.T) {
		require.False(t, ts.config.AutoKYCPrivado)
		did := "did:privado:existing:" + uuid.NewString()

		// First login provisions with the flag OFF -> kyc=false.
		require.False(t, provision(did))
		user, err := ts.db.GetUserByExternalID(context.Background(), did)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.False(t, user.KYC)

		// Admin marks the existing user KYC-verified out of band.
		user.KYC = true
		require.NoError(t, ts.db.UpdateUser(context.Background(), user))

		// Re-login with AUTO_KYC_PRIVADO ON: existing user's KYC is preserved.
		ts.config.AutoKYCPrivado = true
		defer func() { ts.config.AutoKYCPrivado = false }()

		assert.True(t, provision(did), "re-login must surface the preserved KYC=true")
		reread, err := ts.db.GetUserByExternalID(context.Background(), did)
		require.NoError(t, err)
		require.NotNil(t, reread)
		assert.True(t, reread.KYC, "existing privado user's admin-set KYC must be preserved")

		// Inverse: admin-cleared user is not re-KYC'd by login even with flag ON.
		reread.KYC = false
		require.NoError(t, ts.db.UpdateUser(context.Background(), reread))

		assert.False(t, provision(did), "re-login must not re-KYC an admin-cleared user")
		final, err := ts.db.GetUserByExternalID(context.Background(), did)
		require.NoError(t, err)
		require.NotNil(t, final)
		assert.False(t, final.KYC, "existing privado user's admin-cleared KYC must NOT be re-set by login")
	})
}
