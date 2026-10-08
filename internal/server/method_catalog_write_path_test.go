package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Write-path regression tests for the RPC method catalog (RD-1311): every
// path that stores a group's allowed_methods stores only methods the proxy
// forwards, and never a literal "*".

func putGroupAccess(t *testing.T, router http.Handler, orgID, groupID string, methods []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"allowed_methods": methods, "claims": []string{}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", orgID, groupID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// rbacRouterAs mounts the RBAC routes behind a fixed auth_method, for the
// gates that depend on the caller tier (the anonymous system group is
// super-admin only).
func rbacRouterAs(ts *testServerRBAC, authMethod string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth_method", authMethod)
		c.Next()
	})
	ts.registerRBACRoutes(r.Group("/api"))
	return r
}

func TestSetGroupAccess_RejectsUnsupportedMethods(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	org := createTestOrganization(t, ts, "catalog-write-org")
	group := createTestGroup(t, ts, org.ID, "catalog-write-group")

	w := putGroupAccess(t, ts.router, org.ID, group.ID, []string{"eth_call"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	for _, methods := range [][]string{
		{"eth_getRawTransactionByHash"},
		{"eth_call", "eth_sendRawTransactionSync"},
		{"trace_block"}, // not configured as passthrough
		{"linea_*"},
		{"eth_*"},
		{"eth_get*"},
		{"ETH_CALL"},      // non-canonical spelling would be a dead entry
		{"eth_newFilter"}, // globally blocked
		{""},
	} {
		t.Run(fmt.Sprint(methods), func(t *testing.T) {
			w := putGroupAccess(t, ts.router, org.ID, group.ID, methods)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			var resp map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, errUnsupportedAllowedMethod, resp["error"], "opaque, fixed message")
			for _, m := range methods {
				if m != "" {
					assert.NotContains(t, w.Body.String(), m, "the rejected name is not echoed")
				}
			}
			stored, err := ts.db.GetGroupAccess(ctx, group.ID)
			require.NoError(t, err)
			assert.Equal(t, []string{"eth_call"}, stored.AllowedMethods, "a rejected write must not change the row")
		})
	}
}

func TestSetGroupAccess_AcceptsForwardableMethods(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	registerTestNamespaces(t, map[string][]string{"Linea": {"linea_estimateGas"}, "Tracing": {"trace_block"}},
		map[string]string{"linea_estimateGas": "eth_estimateGas"})
	rbac.PassthroughMethods["trace_block"] = true

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	org := createTestOrganization(t, ts, "catalog-accept-org")
	group := createTestGroup(t, ts, org.ID, "catalog-accept-group")

	methods := []string{"eth_call", "eth_getProof", "eth_getBlockReceipts", "linea_estimateGas", "trace_block"}
	w := putGroupAccess(t, ts.router, org.ID, group.ID, methods)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	stored, err := ts.db.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, methods, stored.AllowedMethods)

	// "*" is still accepted from API clients and stored as its explicit
	// expansion: built-in methods and catalog aliases, never passthrough.
	w = putGroupAccess(t, ts.router, org.ID, group.ID, []string{"*"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	stored, err = ts.db.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	assert.Equal(t, rbac.AllAllowedMethods(), stored.AllowedMethods)
	assert.NotContains(t, stored.AllowedMethods, "*")
	assert.Contains(t, stored.AllowedMethods, "linea_estimateGas")
	assert.NotContains(t, stored.AllowedMethods, "trace_block")

	// Entries listed next to "*" are kept (union), so an exact-name-only or
	// passthrough method is not silently dropped.
	w = putGroupAccess(t, ts.router, org.ID, group.ID, []string{"*", "eth_getProof", "trace_block"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	stored, err = ts.db.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	assert.Contains(t, stored.AllowedMethods, "eth_getProof")
	assert.Contains(t, stored.AllowedMethods, "trace_block")
	assert.NotContains(t, stored.AllowedMethods, "*")
}

// The anonymous group is reachable without any credential, so it may hold
// catalog methods only — not operator aliases, not passthrough methods.
func TestSetGroupAccess_AnonymousGroupAcceptsCatalogMethodsOnly(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	registerTestNamespaces(t, map[string][]string{"Linea": {"linea_estimateGas"}, "Tracing": {"trace_block"}},
		map[string]string{"linea_estimateGas": "eth_estimateGas"})
	rbac.PassthroughMethods["trace_block"] = true

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	seedAnonymousGroupAccess(t, ctx, ts, []string{"eth_chainId"})
	router := rbacRouterAs(ts, "admin_token")

	for _, methods := range [][]string{{"trace_block"}, {"linea_estimateGas"}, {"eth_chainId", "eth_getRawTransactionByHash"}, {"*"}, {"eth_chainId", "*"}} {
		w := putGroupAccess(t, router, rbac.AnonymousOrgID, rbac.AnonymousGroupID, methods)
		assert.Equalf(t, http.StatusBadRequest, w.Code, "%v: %s", methods, w.Body.String())
	}
	stored, err := ts.db.GetGroupAccess(ctx, rbac.AnonymousGroupID)
	require.NoError(t, err)
	assert.Equal(t, []string{"eth_chainId"}, stored.AllowedMethods)

	w := putGroupAccess(t, router, rbac.AnonymousOrgID, rbac.AnonymousGroupID, []string{"eth_chainId", "eth_blockNumber"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// Batch-move initializes a new group with an explicit method list.
func TestBatchMoveNewGroup_StoresExplicitMethodList(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	org := createTestOrganization(t, ts, "catalog-batch-org")
	contractID := createTestContract(t, ts, org.ID, "0x1311000000000000000000000000000000000003", "Catalog C")

	body, err := json.Marshal(map[string]any{
		"contract_ids": []string{contractID},
		"new_group":    map[string]any{"slug": "catalog-deployers-" + uuid.New().String()[:8], "name": "Deployers"},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var result struct {
		TargetGroupID string `json:"target_group_id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	access, err := ts.db.GetGroupAccess(ctx, result.TargetGroupID)
	require.NoError(t, err)
	require.NotNil(t, access)
	assert.NotContains(t, access.AllowedMethods, "*")
	assert.Equal(t, rbac.AllAllowedMethods(), access.AllowedMethods)
	assert.Contains(t, access.Claims, rbac.ClaimDeploy)
}

// A passthrough method returns unfiltered data from every tenant, so granting
// one is a platform decision: a tier-2 org-admin JWT cannot add it to a group
// (it may keep or drop one an admin-tier token already granted).
func TestSetGroupAccess_PassthroughGrantRequiresAdminTier(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	registerTestNamespaces(t, map[string][]string{"zkEVM": {"zkevm_batchNumber"}}, nil)
	rbac.PassthroughMethods["zkevm_batchNumber"] = true

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	org := createTestOrganization(t, ts, "catalog-tier-org")
	group := createTestGroup(t, ts, org.ID, "catalog-tier-group")
	tier2 := rbacRouterAs(ts, "jwt_admin")
	superAdmin := rbacRouterAs(ts, "admin_token")

	w := putGroupAccess(t, tier2, org.ID, group.ID, []string{"eth_call", "zkevm_batchNumber"})
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, errPassthroughAdminTierOnly, resp["error"])
	stored, err := ts.db.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	assert.Nil(t, stored, "a refused write must not create the row")

	w = putGroupAccess(t, superAdmin, org.ID, group.ID, []string{"eth_call", "zkevm_batchNumber"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The org admin can still edit the group around an already-granted
	// passthrough method, and can remove it.
	w = putGroupAccess(t, tier2, org.ID, group.ID, []string{"eth_call", "eth_getLogs", "zkevm_batchNumber"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = putGroupAccess(t, tier2, org.ID, group.ID, []string{"eth_call"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = putGroupAccess(t, tier2, org.ID, group.ID, []string{"eth_call", "zkevm_batchNumber"})
	require.Equal(t, http.StatusForbidden, w.Code, "re-adding after removal is a new grant")
}
