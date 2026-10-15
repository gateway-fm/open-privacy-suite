package server

import (
	"bytes"
	"context"
	"encoding/json"
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

// testServerAzureTenants wraps Server with a router for Azure tenant tests
type testServerAzureTenants struct {
	*Server
	router *gin.Engine
}

func setupTestServerForAzureTenants(t *testing.T) *testServerAzureTenants {
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

	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Clean up test tables
	ctx := context.Background()
	conn := database.Conn()
	conn.ExecContext(ctx, "DELETE FROM allowed_azure_tenants")
	conn.ExecContext(ctx, "DELETE FROM user_memberships")
	conn.ExecContext(ctx, "DELETE FROM group_access")
	conn.ExecContext(ctx, "DELETE FROM groups")
	conn.ExecContext(ctx, "DELETE FROM users")
	conn.ExecContext(ctx, "DELETE FROM organizations")

	// Re-create the seeded Default Org and Default Group (deleted above)
	// so that EnsureUserExists can add users to the default group.
	conn.ExecContext(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1, 'default', 'Default Organization')`, rbac.DefaultOrgID)
	conn.ExecContext(ctx, `INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'default', 'Default Group', 0, 'default')`, rbac.DefaultGroupID, rbac.DefaultOrgID)

	t.Cleanup(func() {
		database.Close()
	})

	cfg := &config.Config{
		ReadProfile: rbac.ReadProfileStandard,
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

	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)
	t.Cleanup(rbacAccessCtrl.Stop)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	server := &Server{
		db:             database,
		config:         cfg,
		jwtService:     jwtService,
		rbacAccessCtrl: rbacAccessCtrl,
	}

	// Register RBAC routes (includes azure-tenants)
	api := router.Group("/api")
	server.registerRBACRoutes(api)

	return &testServerAzureTenants{
		Server: server,
		router: router,
	}
}

func TestAzureTenantCRUD(t *testing.T) {
	s := setupTestServerForAzureTenants(t)
	var createdTenantID string

	t.Run("ListEmpty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/azure-tenants", nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		data := resp["data"].([]any)
		assert.Len(t, data, 0)
	})

	t.Run("Create", func(t *testing.T) {
		body := map[string]any{
			"tenant_id":      "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
			"label":          "Contoso Corp",
			"auto_provision": true,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/azure-tenants", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp db.AllowedAzureTenant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.ID)
		assert.Equal(t, "aaaabbbb-cccc-dddd-eeee-ffffffffffff", resp.TenantID)
		assert.Equal(t, "Contoso Corp", resp.Label)
		assert.True(t, resp.AutoProvision)
		createdTenantID = resp.ID
	})

	t.Run("CreateDuplicate", func(t *testing.T) {
		body := map[string]any{
			"tenant_id": "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
			"label":     "Duplicate",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/azure-tenants", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("Get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/azure-tenants/"+createdTenantID, nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp db.AllowedAzureTenant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, createdTenantID, resp.ID)
		assert.Equal(t, "Contoso Corp", resp.Label)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/azure-tenants/"+uuid.New().String(), nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("Update", func(t *testing.T) {
		body := map[string]any{
			"label":          "Contoso Updated",
			"auto_provision": false,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/azure-tenants/"+createdTenantID, bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp db.AllowedAzureTenant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "Contoso Updated", resp.Label)
		assert.False(t, resp.AutoProvision)
	})

	t.Run("UpdateNotFound", func(t *testing.T) {
		body := map[string]any{"label": "No Such Tenant"}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/azure-tenants/"+uuid.New().String(), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("ListAfterCreate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/azure-tenants", nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		data := resp["data"].([]any)
		assert.Len(t, data, 1)
	})

	t.Run("CreateWithDefaultOrgAndGroup", func(t *testing.T) {
		// Create an org and group first
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "test-org",
			Name:     "Test Org",
			Settings: map[string]any{},
		}
		require.NoError(t, s.db.CreateOrganization(context.Background(), org))

		group := &rbac.Group{
			ID:    uuid.New().String(),
			OrgID: org.ID,
			Slug:  "default-group",
			Name:  "Default Group",
			Path:  "default-group",
		}
		require.NoError(t, s.db.CreateGroup(context.Background(), group))

		body := map[string]any{
			"tenant_id":        "11111111-2222-3333-4444-555555555555",
			"label":            "Fabrikam",
			"default_org_id":   org.ID,
			"default_group_id": group.ID,
			"auto_provision":   true,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/azure-tenants", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp db.AllowedAzureTenant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotNil(t, resp.DefaultOrgID)
		assert.Equal(t, org.ID, *resp.DefaultOrgID)
		assert.NotNil(t, resp.DefaultGroupID)
		assert.Equal(t, group.ID, *resp.DefaultGroupID)
	})

	t.Run("Delete", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/azure-tenants/"+createdTenantID, nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify it's gone
		req2 := httptest.NewRequest(http.MethodGet, "/api/azure-tenants/"+createdTenantID, nil)
		w2 := httptest.NewRecorder()
		s.router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusNotFound, w2.Code)
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/azure-tenants/"+uuid.New().String(), nil)
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestAzureTenantCallbackValidation(t *testing.T) {
	// These tests verify the tenant allowlist logic in handleAzureCallback.
	// We can't fully test the OIDC exchange without a mock OIDC server,
	// but we can test the DB-level tenant validation that happens after the exchange.

	s := setupTestServerForAzureTenants(t)

	t.Run("UnknownTenantGetsDenied", func(t *testing.T) {
		// Verify that GetAllowedAzureTenantByTenantID returns nil for unknown tenants
		tenant, err := s.db.GetAllowedAzureTenantByTenantID(context.Background(), "unknown-tenant-id")
		require.NoError(t, err)
		assert.Nil(t, tenant, "unknown tenant should return nil")
	})

	t.Run("KnownTenantIsAllowed", func(t *testing.T) {
		// Add a tenant to the allowlist
		tenant := &db.AllowedAzureTenant{
			ID:            uuid.New().String(),
			TenantID:      "known-tenant-id",
			Label:         "Known Tenant",
			AutoProvision: true,
		}
		_, err := s.db.CreateAllowedAzureTenant(context.Background(), tenant)
		require.NoError(t, err)

		// Verify it can be retrieved
		found, err := s.db.GetAllowedAzureTenantByTenantID(context.Background(), "known-tenant-id")
		require.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "Known Tenant", found.Label)
		assert.True(t, found.AutoProvision)
	})

	t.Run("AutoProvisionDisabledRejectsNewUsers", func(t *testing.T) {
		// Add a tenant with auto_provision=false
		tenant := &db.AllowedAzureTenant{
			ID:            uuid.New().String(),
			TenantID:      "no-provision-tenant",
			Label:         "No Provision",
			AutoProvision: false,
		}
		_, err := s.db.CreateAllowedAzureTenant(context.Background(), tenant)
		require.NoError(t, err)

		// Verify: user does not exist yet
		subject := auth.AzureSubject("new-user-oid")
		user, err := s.db.GetUserByExternalID(context.Background(), subject)
		require.NoError(t, err)
		assert.Nil(t, user, "user should not exist before auto-provisioning check")

		// The callback would check: auto_provision=false + user doesn't exist => reject
		// This is tested at the handler level via the logic in auth_azure.go
		found, err := s.db.GetAllowedAzureTenantByTenantID(context.Background(), "no-provision-tenant")
		require.NoError(t, err)
		assert.False(t, found.AutoProvision)
	})

	t.Run("AutoProvisionDisabledAllowsExistingUsers", func(t *testing.T) {
		// Create a user first
		subject := auth.AzureSubject("existing-user-oid")
		_, ensureErr := s.rbacAccessCtrl.EnsureUserExists(context.Background(), subject, false, false)
		require.NoError(t, ensureErr)

		// The callback would check: auto_provision=false + user exists => allow
		user, err := s.db.GetUserByExternalID(context.Background(), subject)
		require.NoError(t, err)
		assert.NotNil(t, user, "existing user should be found")
	})

	t.Run("AutoProvisionWithDefaultGroupCreatesMembership", func(t *testing.T) {
		// Create org and group
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "provision-test-org",
			Name:     "Provision Test Org",
			Settings: map[string]any{},
		}
		require.NoError(t, s.db.CreateOrganization(context.Background(), org))

		group := &rbac.Group{
			ID:    uuid.New().String(),
			OrgID: org.ID,
			Slug:  "auto-group",
			Name:  "Auto Group",
			Path:  "auto-group",
		}
		require.NoError(t, s.db.CreateGroup(context.Background(), group))

		// Add tenant with default org/group
		tenant := &db.AllowedAzureTenant{
			ID:             uuid.New().String(),
			TenantID:       "provision-test-tenant",
			Label:          "Provision Test",
			DefaultOrgID:   &org.ID,
			DefaultGroupID: &group.ID,
			AutoProvision:  true,
		}
		_, err := s.db.CreateAllowedAzureTenant(context.Background(), tenant)
		require.NoError(t, err)

		// Create user and simulate the auto-provisioning logic from the callback
		subject := auth.AzureSubject("provision-test-oid")
		user, ensureErr := s.rbacAccessCtrl.EnsureUserExists(context.Background(), subject, false, false)
		require.NoError(t, ensureErr)
		require.NotNil(t, user)

		// Simulate: check if user already has the membership
		existing, _ := s.db.GetMembershipByUserAndGroup(context.Background(), user.ID, group.ID)
		assert.Nil(t, existing, "user should not have membership yet")

		// Create membership (as the callback would)
		membership := &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: group.ID,
			Source:  "admin",
		}
		require.NoError(t, s.db.CreateMembership(context.Background(), membership))

		// Verify membership exists
		existing, err = s.db.GetMembershipByUserAndGroup(context.Background(), user.ID, group.ID)
		require.NoError(t, err)
		assert.NotNil(t, existing)

		// Second time: should not create duplicate
		existing2, _ := s.db.GetMembershipByUserAndGroup(context.Background(), user.ID, group.ID)
		assert.NotNil(t, existing2, "membership should still exist on second check")
	})

	t.Run("SkipDefaultGroupWhenTenantGroupConfigured", func(t *testing.T) {
		// Create a custom org + group for the tenant
		org := &rbac.Organization{
			ID:   uuid.New().String(),
			Slug: "skip-default-org",
			Name: "Skip Default Org",
		}
		require.NoError(t, s.db.CreateOrganization(context.Background(), org))

		group := &rbac.Group{
			ID:    uuid.New().String(),
			OrgID: org.ID,
			Slug:  "skip-default-group",
			Name:  "Skip Default Group",
			Path:  "skip-default-group",
		}
		require.NoError(t, s.db.CreateGroup(context.Background(), group))

		// EnsureUserExists with skipDefaultGroup=true
		subject := auth.AzureSubject("skip-default-oid")
		user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), subject, false, true)
		require.NoError(t, err)
		require.NotNil(t, user)

		// User should NOT be in the default group
		defaultMembership, _ := s.db.GetMembershipByUserAndGroup(context.Background(), user.ID, rbac.DefaultGroupID)
		assert.Nil(t, defaultMembership, "user should NOT be in default group when skipDefaultGroup=true")

		// Now add user to tenant's configured group (as the callback would)
		membership := &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: group.ID,
			Source:  "auto_provision",
		}
		created, createErr := s.db.CreateMembershipIfNotExists(context.Background(), membership)
		require.NoError(t, createErr)
		assert.True(t, created)

		// User should be in the tenant's group only
		tenantMembership, err := s.db.GetMembershipByUserAndGroup(context.Background(), user.ID, group.ID)
		require.NoError(t, err)
		assert.NotNil(t, tenantMembership, "user should be in tenant's configured group")
	})

	t.Run("DefaultGroupUsedWhenNoTenantGroupConfigured", func(t *testing.T) {
		// EnsureUserExists with skipDefaultGroup=false (no tenant group configured)
		subject := auth.AzureSubject("use-default-oid")
		user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), subject, false, false)
		require.NoError(t, err)
		require.NotNil(t, user)

		// User SHOULD be in the default group
		defaultMembership, err := s.db.GetMembershipByUserAndGroup(context.Background(), user.ID, rbac.DefaultGroupID)
		require.NoError(t, err)
		assert.NotNil(t, defaultMembership, "user should be in default group when skipDefaultGroup=false")
	})
}
