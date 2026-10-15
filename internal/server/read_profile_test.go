package server

import (
	"bytes"
	"context"
	"net/http"
	"strings"
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
// regardless of the configured flag (strict takes precedence).
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

// Both explorer construction paths (startup and the reconnect loop) go through
// newExplorerRedactor, which installs the server's read profile; an engine
// built without a config enforces strict.
func TestNewExplorerRedactor_UsesServerReadProfile(t *testing.T) {
	for _, p := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		s := &Server{config: &config.Config{ReadProfile: p}}
		assert.Equal(t, p, s.newExplorerRedactor(nil, nil).ReadProfile())
	}
	assert.True(t, (&Server{}).newExplorerRedactor(nil, nil).ReadProfile().Strict())
}

// readProfileGovernsResponse names exactly the methods whose /rpc response the
// read profile governs: every catalog method the response filter rewrites, and
// no other. A method added to applyResponseFilter without being added to the
// test-request refusal (or the reverse) fails here. The probe is an upstream
// answer of an unexpected shape, which every governed filter withholds (fail
// closed) and every ungoverned method passes through unchanged.
func TestReadProfileGovernsResponse_MatchesResponseFilter(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		ReadProfile:    rbac.ReadProfileStandard,
		RBACAccessCtrl: ts.rbacAccessCtrl,
		RateLimiter:    &noopRateLimiter{},
	})
	probe := []byte(`{"jsonrpc":"2.0","id":1,"result":"0xparity"}`)
	methods := rbac.SupportedMethods()
	require.NotEmpty(t, methods)
	governed := 0
	for _, m := range methods {
		got := p.applyResponseFilter(context.Background(), &ProcessRequest{Method: m, UserID: "did:test:parity"}, &rbac.AccessCheckResult{Allowed: true}, probe)
		filtered := !bytes.Equal(got, probe)
		assert.Equal(t, filtered, readProfileGovernsResponse(m), "%s: response filtered=%v", m, filtered)
		if readProfileGovernsResponse(m) {
			governed++
		}
		// Case variants resolve the same way.
		assert.Equal(t, readProfileGovernsResponse(m), readProfileGovernsResponse(strings.ToUpper(m)), "%s upper-case", m)
	}
	assert.Equal(t, 10, governed, "the governed set covers the ten filtered methods")
}
