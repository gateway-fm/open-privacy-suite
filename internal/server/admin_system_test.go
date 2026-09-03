package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the super-admin in-memory toggle for the eth_call cross-org
// tracing knob (RD-915 follow-up).
//
// The endpoint sits at /api/v1/admin/system/eth-call-tracing and is the
// emergency rollback lever — it must be:
//   - super-admin only on POST (auth_method == "admin_token"),
//   - audit-logged with reason on every toggle,
//   - in-memory only (a restart re-arms the env default),
//   - readable by any admin so dashboards can prove the state.

// setupSystemAdminTestServer wires just enough of Server to exercise the
// admin_system handlers. Avoids the full admin-middleware chain so the
// test can dial up an explicit auth_method via a tiny shim middleware
// keyed on a header. Mirrors the seam the real middleware sets at
// server.go where adminAuthMiddleware writes auth_method into the
// gin.Context.
func setupSystemAdminTestServer(t *testing.T) *testServerRBAC {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	// Build a minimal processor — we only need ethCallTracing state
	// management, not the trace path itself.
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              &proxy.Proxy{},
		AccessLogger:       ts.db,
		CircuitBreaker:     NewCircuitBreaker(),
		ConcurrencyLimiter: NewConcurrencyLimiter(50, 0),
		EthCallTracing:     &EthCallTracingConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	ts.Server.jsonrpcProcessor = proc

	// Test middleware: take auth_method from a header so tests can
	// flip between admin_token and jwt_admin trivially.
	router := ts.router
	system := router.Group("/api/v1/admin/system")
	system.Use(func(c *gin.Context) {
		if am := c.GetHeader("X-Test-Auth-Method"); am != "" {
			c.Set("auth_method", am)
		}
		c.Next()
	})
	system.GET("/eth-call-tracing", ts.Server.handleGetEthCallTracing)
	system.POST("/eth-call-tracing", ts.Server.handlePostEthCallTracing)
	system.GET("/intra-org-grant-tracing", ts.Server.handleGetIntraOrgGrantTracing)
	system.POST("/intra-org-grant-tracing", ts.Server.handlePostIntraOrgGrantTracing)

	return ts
}

func doSystemRequest(t *testing.T, ts *testServerRBAC, method, path, authMethod string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(reqBody))
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	var resp map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
	}
	return w, resp
}

func TestAdminSystem_EthCallTracing_GetInitialIsEnvOn(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	w, resp := doSystemRequest(t, ts, http.MethodGet, "/api/v1/admin/system/eth-call-tracing", "admin_token", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, true, resp["enabled"])
	assert.Equal(t, true, resp["env_default"])
	assert.Equal(t, "env", resp["source"])
	assert.Empty(t, resp["changed_at"])
	assert.Empty(t, resp["changed_by"])
}

func TestAdminSystem_EthCallTracing_PostRequiresSuperAdmin(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	// jwt_admin (tier-2 org admin) must NOT be able to toggle a
	// fleet-wide setting.
	w, resp := doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/eth-call-tracing", "jwt_admin", map[string]any{
		"enabled": false,
		"reason":  "test",
	})
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, resp["error"], "super-admin")
}

func TestAdminSystem_EthCallTracing_PostRequiresReason(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	w, _ := doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/eth-call-tracing", "admin_token", map[string]any{
		"enabled": false,
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminSystem_EthCallTracing_ToggleFlipsState(t *testing.T) {
	ts := setupSystemAdminTestServer(t)

	// Verify starting state.
	require.True(t, ts.Server.jsonrpcProcessor.EthCallTracingSnapshot().Enabled)

	// Disable.
	w, resp := doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/eth-call-tracing", "admin_token", map[string]any{
		"enabled": false,
		"reason":  "sev-1 rollback drill",
	})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, false, resp["enabled"])
	assert.Equal(t, true, resp["env_default"], "env default must be preserved across runtime overrides")
	assert.Equal(t, "runtime_override", resp["source"])
	assert.Equal(t, "sev-1 rollback drill", resp["reason"])
	assert.NotEmpty(t, resp["changed_at"])

	// State actually flipped.
	snap := ts.Server.jsonrpcProcessor.EthCallTracingSnapshot()
	assert.False(t, snap.Enabled)
	assert.Equal(t, "runtime_override", snap.Source)

	// Re-enable.
	w, resp = doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/eth-call-tracing", "admin_token", map[string]any{
		"enabled": true,
		"reason":  "drill complete, re-arm",
	})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, true, resp["enabled"])
	assert.Equal(t, "runtime_override", resp["source"], "even when value matches env default, source records the explicit toggle")
}

func TestAdminSystem_EthCallTracing_RestartReArmsEnvDefault(t *testing.T) {
	// Simulates: env=true → operator toggles off → process restart
	// re-installs env value. SetEthCallTracing is the restart-time
	// init call and must wipe runtime overrides.
	ts := setupSystemAdminTestServer(t)
	_, _ = doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/eth-call-tracing", "admin_token", map[string]any{
		"enabled": false,
		"reason":  "test",
	})
	require.False(t, ts.Server.jsonrpcProcessor.EthCallTracingSnapshot().Enabled)

	// Boot-time install (what server.go does):
	ts.Server.jsonrpcProcessor.SetEthCallTracing(true, 5*time.Second)
	snap := ts.Server.jsonrpcProcessor.EthCallTracingSnapshot()
	assert.True(t, snap.Enabled, "restart must re-arm env default")
	assert.Equal(t, "env", snap.Source)
	assert.Zero(t, snap.ChangedAt, "metadata is wiped on env re-install")
}

func TestAdminSystem_EthCallTracing_AuditLogWritten(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	ctx := context.Background()

	// Baseline: count audit rows before.
	pre, err := ts.db.ListAuditLogs(ctx, "system_setting", nil, 100, 0)
	require.NoError(t, err)
	preCount := len(pre)

	_, _ = doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/eth-call-tracing", "admin_token", map[string]any{
		"enabled": false,
		"reason":  "audit trail check",
	})

	post, err := ts.db.ListAuditLogs(ctx, "system_setting", nil, 100, 0)
	require.NoError(t, err)
	require.Equal(t, preCount+1, len(post), "every toggle must write exactly one audit row")
	entry := post[0]
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "system_setting", entry.ResourceType)
	assert.Equal(t, "eth_call_tracing", entry.ResourceName)
	assert.Equal(t, "system:admin_token", entry.ActorExternalID)
	// Reason must be in new_value so auditors can review the justification.
	newVal := entry.NewValue
	require.NotNil(t, newVal)
	if reasonField, ok := newVal["reason"]; ok {
		assert.Equal(t, "audit trail check", reasonField)
	} else {
		t.Errorf("audit row's new_value must include the operator-provided reason; got %v", newVal)
	}
}

// RD-1053: intra-org grant scoping toggle. Same endpoint shape and
// super-admin/audit posture as eth_call tracing, but defaults OFF — org
// ownership is the structural isolation boundary and operators opt in.

func TestAdminSystem_IntraOrgGrantTracing_GetInitialIsEnvOff(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	// The processor seeds OFF; setup never calls SetIntraOrgGrantTracing, so
	// the GET must report the default-off state (mirrors the real boot before
	// server.go installs the env value).
	w, resp := doSystemRequest(t, ts, http.MethodGet, "/api/v1/admin/system/intra-org-grant-tracing", "admin_token", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, false, resp["enabled"])
	assert.Equal(t, false, resp["env_default"])
	assert.Equal(t, "env", resp["source"])
}

func TestAdminSystem_IntraOrgGrantTracing_PostRequiresSuperAdmin(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	w, resp := doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/intra-org-grant-tracing", "jwt_admin", map[string]any{
		"enabled": true,
		"reason":  "test",
	})
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, resp["error"], "super-admin")
}

func TestAdminSystem_IntraOrgGrantTracing_PostRequiresReason(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	w, _ := doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/intra-org-grant-tracing", "admin_token", map[string]any{
		"enabled": true,
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminSystem_IntraOrgGrantTracing_ToggleFlipsState(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	require.False(t, ts.Server.jsonrpcProcessor.IntraOrgGrantTracingSnapshot().Enabled)

	// Enable (the meaningful direction for this knob — it tightens access).
	w, resp := doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/intra-org-grant-tracing", "admin_token", map[string]any{
		"enabled": true,
		"reason":  "enable strict intra-org scoping",
	})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, true, resp["enabled"])
	assert.Equal(t, false, resp["env_default"], "env default must be preserved across runtime overrides")
	assert.Equal(t, "runtime_override", resp["source"])

	snap := ts.Server.jsonrpcProcessor.IntraOrgGrantTracingSnapshot()
	assert.True(t, snap.Enabled)
	assert.Equal(t, "runtime_override", snap.Source)

	// Restart re-arms the env default (OFF).
	ts.Server.jsonrpcProcessor.SetIntraOrgGrantTracing(false)
	snap = ts.Server.jsonrpcProcessor.IntraOrgGrantTracingSnapshot()
	assert.False(t, snap.Enabled, "restart must re-arm env default")
	assert.Equal(t, "env", snap.Source)
	assert.Zero(t, snap.ChangedAt)
}

func TestAdminSystem_IntraOrgGrantTracing_AuditLogWritten(t *testing.T) {
	ts := setupSystemAdminTestServer(t)
	ctx := context.Background()

	pre, err := ts.db.ListAuditLogs(ctx, "system_setting", nil, 100, 0)
	require.NoError(t, err)
	preCount := len(pre)

	_, _ = doSystemRequest(t, ts, http.MethodPost, "/api/v1/admin/system/intra-org-grant-tracing", "admin_token", map[string]any{
		"enabled": true,
		"reason":  "audit trail check",
	})

	post, err := ts.db.ListAuditLogs(ctx, "system_setting", nil, 100, 0)
	require.NoError(t, err)
	require.Equal(t, preCount+1, len(post), "every toggle must write exactly one audit row")
	entry := post[0]
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "system_setting", entry.ResourceType)
	assert.Equal(t, "intra_org_grant_tracing", entry.ResourceName)
	assert.Equal(t, "system:admin_token", entry.ActorExternalID)
	if reasonField, ok := entry.NewValue["reason"]; ok {
		assert.Equal(t, "audit trail check", reasonField)
	} else {
		t.Errorf("audit row's new_value must include the operator-provided reason; got %v", entry.NewValue)
	}
}

// Avoid unused-package lint when the file is the only consumer of rbac
// here. Keeps the file self-contained against future refactors.
var _ rbac.AuditLogEntry
