package server

import (
	"net/http"
	"testing"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1299: the deployment-wide read profile and the effective value of
// ORG_ADMIN_VIEW_USER_TXS (which strict switches off) are reported read-only on
// GET /api/v1/admin/system/read-profile so an operator can prove which policy
// a running deployment enforces.
func TestAdminSystem_ReadProfile_ReportsEffectivePolicy(t *testing.T) {
	cases := []struct {
		name           string
		profile        rbac.ReadProfile
		flag           bool
		wantProfile    string
		wantFlagEff    bool
		wantFlagConfig bool
	}{
		{"standard, flag off", rbac.ReadProfileStandard, false, "standard", false, false},
		{"standard, flag on", rbac.ReadProfileStandard, true, "standard", true, true},
		{"strict, flag off", rbac.ReadProfileStrict, false, "strict", false, false},
		// Strict wins: the flag stays configured but has no effect.
		{"strict, flag on", rbac.ReadProfileStrict, true, "strict", false, true},
		// A never-wired profile is enforced as strict and reported as such.
		{"unset", rbac.ReadProfileUnset, true, "strict", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := setupSystemAdminTestServer(t)
			ts.Server.config = &config.Config{ReadProfile: tc.profile, OrgAdminViewUserTxs: tc.flag}
			ts.router.GET("/api/v1/admin/system/read-profile", ts.Server.handleGetReadProfile)

			w, resp := doSystemRequest(t, ts, http.MethodGet, "/api/v1/admin/system/read-profile", "jwt_admin", nil)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, tc.wantProfile, resp["profile"])
			assert.Equal(t, tc.wantFlagEff, resp["org_admin_view_user_txs"])
			assert.Equal(t, tc.wantFlagConfig, resp["org_admin_view_user_txs_configured"])
		})
	}
}

// The explorer's elevated admin audit view must never apply under strict,
// whatever the flag says (strict wins; the flag cannot bypass it).
func TestOrgAdminViewUserTxsEffective_StrictWins(t *testing.T) {
	cases := []struct {
		profile rbac.ReadProfile
		flag    bool
		want    bool
	}{
		{rbac.ReadProfileStandard, true, true},
		{rbac.ReadProfileStandard, false, false},
		{rbac.ReadProfileStrict, true, false},
		{rbac.ReadProfileUnset, true, false},
	}
	for _, tc := range cases {
		s := &Server{config: &config.Config{ReadProfile: tc.profile, OrgAdminViewUserTxs: tc.flag}}
		assert.Equalf(t, tc.want, s.orgAdminViewUserTxsEffective(), "profile=%v flag=%v", tc.profile, tc.flag)
	}
	assert.False(t, (&Server{}).orgAdminViewUserTxsEffective(), "nil config must not enable the audit view")
	assert.True(t, (&Server{}).readProfile().Strict(), "nil config must enforce strict")
}
