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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServerRBAC wraps Server with a router for testing
type testServerRBAC struct {
	*Server
	router *gin.Engine
}

func setupTestServerForRBAC(t *testing.T) *testServerRBAC {
	// Check if TEST_DATABASE_URL is set
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
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

	// Run migrations
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Clean up RBAC tables (new schema)
	ctx := context.Background()
	conn := database.Conn()
	conn.ExecContext(ctx, "DELETE FROM rbac_audit_log")
	conn.ExecContext(ctx, "DELETE FROM effective_permissions_cache")
	conn.ExecContext(ctx, "DELETE FROM contract_grants")
	conn.ExecContext(ctx, "DELETE FROM contracts")
	conn.ExecContext(ctx, "DELETE FROM preregistered_addresses")
	conn.ExecContext(ctx, "DELETE FROM user_memberships")
	conn.ExecContext(ctx, "DELETE FROM group_access")
	conn.ExecContext(ctx, "DELETE FROM allowed_azure_tenants")
	conn.ExecContext(ctx, "DELETE FROM groups")
	conn.ExecContext(ctx, "DELETE FROM users")
	conn.ExecContext(ctx, "DELETE FROM organizations")
	// Hot-path visibility tables — tx_visible_to has UNIQUE(tx_hash) and
	// SaveTxVisibility ON CONFLICT DO NOTHING (M7), so a row left over from a
	// previous test silently absorbs subsequent SaveTxVisibility calls with
	// the same tx_hash and the new viewer DIDs never land. Same hazard for
	// pending_tx_visibility (M7 outbox). Must wipe per-test.
	conn.ExecContext(ctx, "DELETE FROM tx_visible_to")
	conn.ExecContext(ctx, "DELETE FROM pending_tx_visibility")
	// eth_address_links: keyed by the DID string, not by a FK to users.id
	// (deliberate — DIDs outlive the local user row). DELETE FROM users
	// above does NOT cascade here. In CI's shared Postgres, an earlier
	// test that links e.g. 0xbbbb... to did:imp:admin leaves the row in
	// place; a later test that re-uses the same DID sees the stale link
	// and the parity assertions fail. Per-test reset closes the leak.
	conn.ExecContext(ctx, "DELETE FROM eth_address_links")
	// Same hazard as eth_address_links above: policy_check_log is keyed by
	// subject_did/subject_address, not a FK, so tests reusing a literal DID
	// accumulate rows across the package and break row-count assertions.
	conn.ExecContext(ctx, "DELETE FROM policy_check_log")

	t.Cleanup(func() {
		database.Close()
	})

	cfg := &config.Config{
		NodeURL:     "http://localhost:8545",
		JWTSecret:   "test-secret-key-for-jwt-signing-123",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	// Create RBAC access controller. Stop() tears down the cleanup
	// goroutine spawned by NewCache; without this every test leaks one
	// goroutine that holds memory + a select-loop until process exit.
	// Across ~500 tests in this package the leak compounds enough to push
	// the suite past its 20m timeout (RD-917 follow-up).
	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)
	t.Cleanup(rbacAccessCtrl.Stop)

	// Create server with minimal setup
	gin.SetMode(gin.TestMode)
	router := gin.New()

	server := &Server{
		db:             database,
		config:         cfg,
		jwtService:     jwtService,
		rbacAccessCtrl: rbacAccessCtrl,
	}

	// Register only RBAC routes
	api := router.Group("/api")
	server.registerRBACRoutes(api)

	return &testServerRBAC{
		Server: server,
		router: router,
	}
}

func TestOrganizationAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	var createdOrgID string

	t.Run("CreateOrganization", func(t *testing.T) {
		body := map[string]any{
			"slug":     "test-org",
			"name":     "Test Organization",
			"settings": map[string]any{"feature": true},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "test-org", response["slug"])
		createdOrgID = response["id"].(string)
	})

	t.Run("ListOrganizations", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/orgs", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data := response["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
		assert.NotNil(t, response["total"])
		assert.NotNil(t, response["limit"])
		assert.NotNil(t, response["offset"])
	})

	t.Run("GetOrganization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/orgs/"+createdOrgID, nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, createdOrgID, response["id"])
	})

	t.Run("GetOrganizationNotFound", func(t *testing.T) {
		// Use a valid UUID format that doesn't exist
		req := httptest.NewRequest(http.MethodGet, "/api/orgs/"+uuid.New().String(), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("UpdateOrganization", func(t *testing.T) {
		body := map[string]any{
			"name": "Updated Organization",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/orgs/"+createdOrgID, bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Updated Organization", response["name"])
	})

	t.Run("CreateOrganizationMissingFields", func(t *testing.T) {
		body := map[string]any{
			"slug": "incomplete",
			// Missing "name"
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ListOrganizationsPaginated", func(t *testing.T) {
		// Create a second org for pagination testing
		body := map[string]any{
			"slug":     "test-org-2",
			"name":     "Test Organization 2",
			"settings": map[string]any{},
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		// Test with limit=1
		req = httptest.NewRequest(http.MethodGet, "/api/orgs?limit=1&offset=0", nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data := response["data"].([]any)
		assert.Equal(t, 1, len(data))
		assert.GreaterOrEqual(t, int(response["total"].(float64)), 2)
		assert.Equal(t, float64(1), response["limit"])
		assert.Equal(t, float64(0), response["offset"])

		// Test with offset=1
		req = httptest.NewRequest(http.MethodGet, "/api/orgs?limit=1&offset=1", nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data = response["data"].([]any)
		assert.Equal(t, 1, len(data))
		assert.Equal(t, float64(1), response["offset"])
	})
}

func TestGroupAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Create organization first
	org := createTestOrganization(t, server, "group-test-org")
	var createdGroupID string

	t.Run("CreateGroup", func(t *testing.T) {
		body := map[string]any{
			"slug":        "root",
			"name":        "Root Group",
			"description": "The root group",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		createdGroupID = response["id"].(string)
		assert.Equal(t, "root", response["slug"])
	})

	t.Run("CreateChildGroup_ParentIDIgnored", func(t *testing.T) {
		body := map[string]any{
			"slug":      "child",
			"name":      "Child Group",
			"parent_id": createdGroupID, // should be silently ignored
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// parent_id is ignored — group is flat, depth 0, path is just the slug
		assert.Equal(t, "child", response["path"])
		assert.Equal(t, float64(0), response["depth"])
		assert.Nil(t, response["parent_id"], "parent_id should be nil (ignored)")
	})

	t.Run("ListGroups", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data := response["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 2)
		assert.NotNil(t, response["total"])
		assert.NotNil(t, response["limit"])
		assert.NotNil(t, response["offset"])
	})

	t.Run("GetGroup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s", org.ID, createdGroupID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UpdateGroup", func(t *testing.T) {
		body := map[string]any{
			"name": "Updated Root Group",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s", org.ID, createdGroupID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("SetGroupAccess", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":          []string{"read"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, createdGroupID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GetGroupAccess", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, createdGroupID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		methods := response["allowed_methods"].([]any)
		assert.Len(t, methods, 2)
	})

	t.Run("DeleteGroup", func(t *testing.T) {
		// Create a group to delete
		body := map[string]any{
			"slug": "delete-me",
			"name": "Delete Me",
		}
		jsonBody, _ := json.Marshal(body)

		createReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", org.ID), bytes.NewReader(jsonBody))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		server.router.ServeHTTP(createW, createReq)

		var createResp map[string]any
		json.Unmarshal(createW.Body.Bytes(), &createResp)
		deleteGroupID := createResp["id"].(string)

		// Delete it
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/orgs/%s/groups/%s", org.ID, deleteGroupID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestGroupAccessAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "group-access-test-org")
	group := createTestGroup(t, server, org.ID, "test-group")

	t.Run("SetGroupAccess", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":          []string{"read"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GetGroupAccess", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		methods := response["allowed_methods"].([]any)
		assert.Equal(t, 2, len(methods))
	})
}

func TestGroupAccessValidation(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "access-validation-org")
	group := createTestGroup(t, server, org.ID, "validation-group")

	t.Run("AcceptsWriteMethodsWithoutWriteClaim", func(t *testing.T) {
		// Write methods no longer require a "write" claim — method allowlist is the gate
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_sendTransaction"},
			"claims":          []string{},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsReadMethodsWithoutReadClaim", func(t *testing.T) {
		// Read methods no longer require a "read" claim — method allowlist is the gate
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":          []string{},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsTraceMethodWithoutDeployClaim", func(t *testing.T) {
		// RD-1121: debug_trace* is gated by the method allowlist, not a claim.
		// A group may list debug_traceTransaction with no claims — config-time
		// validation no longer forces the deploy claim (runtime allowlist gate +
		// ValidateTrace enforce access).
		body := map[string]any{
			"allowed_methods": []string{"debug_traceTransaction"},
			"claims":          []string{},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsMethodsWithNoClaims", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_sendTransaction"},
			"claims":          []string{},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsEmptyMethodsList", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{},
			"claims":          []string{},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsUnknownMethodsWithoutClaims", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"some_unknown_method", "another_custom_method"},
			"claims":          []string{}, // No claims needed for unknown methods
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsAllClaimsWithAnyMethods", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{
				"eth_call", "eth_getBalance", "eth_chainId",
				"eth_sendTransaction", "eth_sendRawTransaction",
			},
			"claims": []string{"read", "write", "admin", "upgrade", "deploy"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	// The RPC API key header sub-tests were removed: rpc_api_key_header is no
	// longer a per-group field. The header name is operator-wide via the
	// RPC_API_KEY_HEADER env var. See TestResolveAPIKeyHeader and
	// TestRPCAPIKeyHeaderConfig in jsonrpc_processor_test.go for the
	// 2-branch resolution that replaced the per-group validation path.
}

func TestWildcardMethodExpansion(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "wildcard-test-org")
	group := createTestGroup(t, server, org.ID, "wildcard-group")

	t.Run("WildcardExpandedToExplicitMethods", func(t *testing.T) {
		// Send wildcard with admin claim (which implies read, write, deploy, upgrade)
		body := map[string]any{
			"allowed_methods": []string{"*"},
			"claims":          []string{"admin"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Now GET the access and verify wildcard was expanded
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), nil)
		w = httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		methods := response["allowed_methods"].([]any)

		// Should have been expanded: no "*" in the stored list
		for _, m := range methods {
			assert.NotEqual(t, "*", m.(string), "wildcard should have been expanded")
		}

		// Should contain the expected explicit methods
		allAllowed := rbac.AllAllowedMethods()
		assert.Equal(t, len(allAllowed), len(methods),
			"expanded wildcard should match AllAllowedMethods() count")

		// Verify a few specific methods are present
		methodSet := make(map[string]bool, len(methods))
		for _, m := range methods {
			methodSet[m.(string)] = true
		}
		assert.True(t, methodSet["eth_call"], "should contain eth_call")
		assert.True(t, methodSet["eth_blockNumber"], "should contain eth_blockNumber")
		assert.True(t, methodSet["eth_sendRawTransaction"], "should contain eth_sendRawTransaction")

		// Verify no globally blocked methods
		for _, m := range methods {
			assert.False(t, rbac.IsMethodBlocked(m.(string)),
				"expanded method %s should not be globally blocked", m.(string))
		}
	})

	t.Run("NoWildcardPassesThrough", func(t *testing.T) {
		// Explicit methods should be stored as-is
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":          []string{"read"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// GET and verify exactly the 2 methods
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), nil)
		w = httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		methods := response["allowed_methods"].([]any)
		assert.Equal(t, 2, len(methods))
	})
}

func TestUserAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Create a user directly in the database
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:user123",
		KYC:        true,
		Banned:     false,
		Note:       "Test user",
		Metadata:   map[string]any{},
	}
	err := server.Server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	t.Run("ListUsers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GetUser", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/users/"+user.ID, nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, user.ExternalID, response["external_id"])
	})

	t.Run("UpdateUser", func(t *testing.T) {
		body := map[string]any{
			"banned": true,
			"note":   "Banned for testing",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/users/"+user.ID, bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["banned"])
	})
}

func TestBanUserRevokesRefreshTokens(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Create a user with a refresh token
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:ban-revoke",
		Metadata:   map[string]any{},
	}
	err := server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	// Save a refresh token for the user
	tokenHash := auth.HashToken("test-refresh-token")
	err = server.db.SaveRefreshToken(context.Background(), tokenHash, user.ExternalID, time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	// Verify token exists and is not revoked
	stored, err := server.db.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.False(t, stored.Revoked)

	// Ban the user via API
	body, _ := json.Marshal(map[string]any{"banned": true})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+user.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify refresh token was revoked
	stored, err = server.db.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Revoked, "refresh token should be revoked after banning user")
}

func TestDeleteAzureTenantBansUsersAndRevokesTokens(t *testing.T) {
	server := setupTestServerForRBAC(t)

	tenantID := uuid.New().String()

	// Create tenant in allowlist
	body, _ := json.Marshal(map[string]any{
		"tenant_id":      tenantID,
		"label":          "Test Tenant",
		"auto_provision": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/azure-tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var tenantResp db.AllowedAzureTenant
	err := json.Unmarshal(w.Body.Bytes(), &tenantResp)
	require.NoError(t, err)

	// Create a user belonging to this tenant
	user := &rbac.User{
		ID:           uuid.New().String(),
		ExternalID:   "azuread:" + uuid.New().String(),
		AuthTenantID: &tenantID,
		Metadata:     map[string]any{},
	}
	err = server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	// Save a refresh token for the user
	tokenHash := auth.HashToken("tenant-user-token")
	err = server.db.SaveRefreshToken(context.Background(), tokenHash, user.ExternalID, time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	// Delete the tenant
	req = httptest.NewRequest(http.MethodDelete, "/api/azure-tenants/"+tenantResp.ID, nil)
	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify user was banned
	updatedUser, err := server.db.GetUser(context.Background(), user.ID)
	require.NoError(t, err)
	assert.True(t, updatedUser.Banned, "user should be banned after tenant deletion")
	assert.Equal(t, "Azure AD tenant removed", updatedUser.Note)

	// Verify refresh token was revoked
	stored, err := server.db.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Revoked, "refresh token should be revoked after tenant deletion")
}

func TestMembershipAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Setup: org, group, user
	org := createTestOrganization(t, server, "membership-test-org")
	group := createTestGroup(t, server, org.ID, "membership-group")

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:member",
		KYC:        true,
		Metadata:   map[string]any{},
	}
	err := server.Server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	var createdMembershipID string

	t.Run("CreateMembership", func(t *testing.T) {
		body := map[string]any{
			"group_id": group.ID,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/memberships", user.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		createdMembershipID = response["id"].(string)
	})

	t.Run("ListUserMemberships", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/users/%s/memberships", user.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, len(response), 1)
	})

	t.Run("GetEffectivePermissions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/users/%s/effective-permissions?org=%s", user.ID, org.Slug), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DeleteMembership", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/users/%s/memberships/%s", user.ID, createdMembershipID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestContractAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "contract-test-org")
	_ = createTestGroup(t, server, org.ID, "contract-group")

	testAddress := "0x1234567890123456789012345678901234567890"

	t.Run("CreateContract", func(t *testing.T) {
		body := map[string]any{
			"address": testAddress,
			"name":    "Test Contract",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("ListContracts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UpdateContract", func(t *testing.T) {
		body := map[string]any{
			"name":     "Updated Contract",
			"metadata": map[string]any{"updated": true},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DeleteContract", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/orgs/%s/contracts/%s", org.ID, testAddress), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAccessCheckAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Setup: org, group, user with membership
	org := createTestOrganization(t, server, "access-test-org")
	// Create group
	group := createTestGroup(t, server, org.ID, "access-group")

	// Set group access with allowed methods
	accessBody := map[string]any{
		"allowed_methods": []string{"eth_call", "eth_getBalance"},
		"claims":          []string{"read"},
	}
	accessJson, _ := json.Marshal(accessBody)
	accessReq := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(accessJson))
	accessReq.Header.Set("Content-Type", "application/json")
	accessW := httptest.NewRecorder()
	server.router.ServeHTTP(accessW, accessReq)
	require.Equal(t, http.StatusOK, accessW.Code)

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:access-user",
		KYC:        true,
		Metadata:   map[string]any{},
	}
	err := server.Server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	// Create membership
	memBody := map[string]any{
		"group_id": group.ID,
	}
	memJson, _ := json.Marshal(memBody)
	memReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/memberships", user.ID), bytes.NewReader(memJson))
	memReq.Header.Set("Content-Type", "application/json")
	memW := httptest.NewRecorder()
	server.router.ServeHTTP(memW, memReq)

	t.Run("CheckAccessAllowed", func(t *testing.T) {
		body := map[string]any{
			"user_external_id": user.ExternalID,
			"org_slug":         org.Slug,
			"method":           "eth_call",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/access/check", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["allowed"])
	})

	t.Run("CheckAccessDenied", func(t *testing.T) {
		body := map[string]any{
			"user_external_id": user.ExternalID,
			"org_slug":         org.Slug,
			"method":           "eth_sendTransaction", // Not in allowed methods
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/access/check", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["allowed"])
	})
}

func TestCacheStatsAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	t.Run("GetCacheStats", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/cache/stats", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Contains(t, response, "entries")
		assert.Contains(t, response, "expired_pending")
		assert.Contains(t, response, "max_entries")
	})
}

func TestContractABIUpload(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "abi-test-org")
	testAddress := "0xabcdef1234567890abcdef1234567890abcdef12"

	// Create contract first
	createBody := map[string]any{
		"address": testAddress,
		"name":    "ABI Test Contract",
	}
	createJson, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), bytes.NewReader(createJson))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.router.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	// Valid ERC20-like ABI for testing
	validABI := `[{"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`

	t.Run("UploadValidABI", func(t *testing.T) {
		body := map[string]any{
			"abi": validABI,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Contract should have ABI set
		assert.Equal(t, testAddress, response["address"])
		assert.NotEmpty(t, response["abi"])
	})

	t.Run("VerifyABIInContract", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts/%s", org.ID, testAddress), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Verify ABI is persisted
		assert.NotEmpty(t, response["abi"])
		assert.Contains(t, response["abi"], "balanceOf")
		assert.Contains(t, response["abi"], "transfer")
	})

	t.Run("UploadInvalidJSONABI", func(t *testing.T) {
		body := map[string]any{
			"abi": "not valid json",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("UploadNonArrayABI", func(t *testing.T) {
		body := map[string]any{
			"abi": `{"type": "function"}`, // Object instead of array
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("UploadEmptyABI", func(t *testing.T) {
		body := map[string]any{
			"abi": "[]",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		// Empty array is valid ABI (contract with no public functions)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UploadABIToNonexistentContract", func(t *testing.T) {
		nonexistentAddr := "0x0000000000000000000000000000000000000001"
		body := map[string]any{
			"abi": validABI,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, nonexistentAddr), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Helper functions

func createTestOrganization(t *testing.T, server *testServerRBAC, slug string) *rbac.Organization {
	body := map[string]any{
		"slug":     slug,
		"name":     slug + " Org",
		"settings": map[string]any{},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)

	return &rbac.Organization{
		ID:   response["id"].(string),
		Slug: response["slug"].(string),
		Name: response["name"].(string),
	}
}

func createTestGroup(t *testing.T, server *testServerRBAC, orgID, slug string) *rbac.Group {
	body := map[string]any{
		"slug": slug,
		"name": slug + " Group",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", orgID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)

	return &rbac.Group{
		ID:    response["id"].(string),
		OrgID: orgID,
		Slug:  response["slug"].(string),
		Name:  response["name"].(string),
	}
}

func createTestContract(t *testing.T, server *testServerRBAC, orgID, address, name string) string {
	body := map[string]any{
		"address": address,
		"name":    name,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts", orgID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)
	return response["id"].(string)
}

func createTestContractGrant(t *testing.T, server *testServerRBAC, orgID, address, groupID string) {
	body := map[string]any{
		"group_id": groupID,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/%s/grants", orgID, address), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractGrantSummaryAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "grant-summary-org")
	otherOrg := createTestOrganization(t, server, "other-org-for-isolation")

	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherAddr := "0xcccccccccccccccccccccccccccccccccccccccc"

	contractID1 := createTestContract(t, server, org.ID, addr1, "Contract Alpha")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Contract Beta")
	_ = createTestContract(t, server, otherOrg.ID, otherAddr, "Other Org Contract")

	group1 := createTestGroup(t, server, org.ID, "alpha-group")
	group2 := createTestGroup(t, server, org.ID, "beta-group")

	t.Run("EmptyBeforeGrants", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts/grant-summary", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Empty(t, result, "expected empty map before any grants are created")
	})

	// Grant group1 → contract1, group2 → contract1, group1 → contract2
	createTestContractGrant(t, server, org.ID, addr1, group1.ID)
	createTestContractGrant(t, server, org.ID, addr1, group2.ID)
	createTestContractGrant(t, server, org.ID, addr2, group1.ID)

	t.Run("CorrectCountsAndGroupNames", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts/grant-summary", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))

		// contract1 should have 2 groups
		c1, ok := result[contractID1].(map[string]any)
		require.True(t, ok, "contract1 should appear in summary")
		assert.Equal(t, float64(2), c1["count"])
		groups1 := c1["groups"].([]any)
		assert.Len(t, groups1, 2)

		// contract2 should have 1 group
		c2, ok := result[contractID2].(map[string]any)
		require.True(t, ok, "contract2 should appear in summary")
		assert.Equal(t, float64(1), c2["count"])
		groups2 := c2["groups"].([]any)
		assert.Len(t, groups2, 1)
		g2 := groups2[0].(map[string]any)
		assert.Equal(t, group1.ID, g2["id"])
		assert.Equal(t, group1.Name, g2["name"])
	})

	t.Run("OrgIsolation", func(t *testing.T) {
		// Grant from a group in otherOrg — shouldn't affect org's summary and shouldn't be visible from org's summary
		otherGroup := createTestGroup(t, server, otherOrg.ID, "other-group")
		createTestContractGrant(t, server, otherOrg.ID, otherAddr, otherGroup.ID)

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts/grant-summary", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))

		// otherOrg's contract must not appear
		for contractID := range result {
			assert.NotEqual(t, otherAddr, contractID, "other org contract must not appear in this org's grant summary")
		}
		// org's contracts still correct
		assert.Contains(t, result, contractID1)
		assert.Contains(t, result, contractID2)
		assert.Len(t, result, 2, "only org's 2 contracts should appear")
	})
}
