package server

import (
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

// setupAdminAuthTestServer creates a test server with a real database, JWT
// service, and the admin auth middleware wired up.
func setupAdminAuthTestServer(t *testing.T, adminToken string) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = sharedTestDBURL(t)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, db.ResetTestDatabase(database))

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		ReadProfile: rbac.ReadProfileStandard,
		AdminAPIToken: adminToken,
	}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	router := gin.New()

	// Admin routes behind adminAuthMiddleware (matches production setup).
	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	admin.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok":          true,
			"auth_method": c.GetString("auth_method"),
		})
	})

	// /me routes behind JWTAuthMiddleware (matches production setup).
	srv.registerUserProfileRoutes(router)

	t.Cleanup(func() { srv.db.Close() })

	return srv, router
}

// createTestUserWithClaims creates a user, org, group, membership, and group
// access with the given claims.  Returns the user's external ID (DID).
func createTestUserWithClaims(t *testing.T, srv *Server, claims []rbac.Claim) string {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "test-org-" + uuid.New().String()[:8],
		Name: "Test Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "test-group-" + uuid.New().String()[:8],
		Name:  "Test Group",
		Path:  "test-group",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         claims,
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	userDID := "did:test:" + uuid.New().String()[:8]
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	return userDID
}

// createTestOrgAdmin creates a user in an is_org_admin=true group.
// Returns the user's external ID (DID) and the org ID.
func createTestOrgAdmin(t *testing.T, srv *Server) (string, string) {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "admin-org-" + uuid.New().String()[:8],
		Name: "Admin Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "org-admins-" + uuid.New().String()[:8],
		Name:       "Org Admins",
		Path:       "org-admins",
		IsOrgAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	userDID := "did:test:" + uuid.New().String()[:8]
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	return userDID, org.ID
}

// ---------------------------------------------------------------------------
// Tests: adminAuthMiddleware
// ---------------------------------------------------------------------------

func TestAdminAuth_XAdminToken_StillWorks(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("X-Admin-Token", "my-secret-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "admin_token", body["auth_method"])
}

func TestAdminAuth_XAdminToken_WrongValueDenied(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("X-Admin-Token", "wrong-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_JWT_OrgAdminGrantsAccess(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	userDID, _ := createTestOrgAdmin(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "jwt_admin", body["auth_method"])
}

// TestAdminAuth_JWT_BearerSchemeCaseInsensitive pins RD-1217 on the admin
// middleware's Path-2 (JWT Bearer) branch: the auth-scheme is case-insensitive
// (RFC 7235 §2.1), so a lowercase "bearer" with an org-admin JWT must be
// accepted just like "Bearer".
func TestAdminAuth_JWT_BearerSchemeCaseInsensitive(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	userDID, _ := createTestOrgAdmin(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "bearer "+token) // lowercase scheme
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "lowercase bearer scheme must be accepted (RFC 7235 §2.1)")
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "jwt_admin", body["auth_method"])
}

func TestAdminAuth_JWT_ContractAdminGets403(t *testing.T) {
	// Tier 3: admin claim in group_access.claims but NOT is_org_admin.
	// Should be rejected by adminAuthMiddleware — no dashboard access.
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimAdmin})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "org admin or read-only admin required")
}

func TestAdminAuth_JWT_NoAdminClaimGets403(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "org admin or read-only admin required")
}

func TestAdminAuth_NoAuthGets401(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_InvalidJWTGets401(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "my-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_ExpiredJWTGets401(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")

	// Create a JWT service with 0 TTL to produce expired tokens immediately.
	expiredJWT, err := auth.NewJWTService("test-secret", "test-refresh-secret", 0, time.Hour)
	require.NoError(t, err)

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimAdmin})
	token, err := expiredJWT.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// Small sleep to ensure the token is past its expiry.
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminAuth_NoTokenConfigured_AllowsRequest(t *testing.T) {
	// Dev mode: ADMIN_API_TOKEN is empty, no credentials needed.
	_, router := setupAdminAuthTestServer(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: /me/admin-status endpoint
// ---------------------------------------------------------------------------

func TestAdminStatus_OrgAdminUser(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "")

	userDID, orgID := createTestOrgAdmin(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, true, body["is_admin"])

	// Verify admin_org_ids is returned
	adminOrgIDs, ok := body["admin_org_ids"].([]interface{})
	require.True(t, ok, "admin_org_ids should be an array")
	require.Len(t, adminOrgIDs, 1)
	assert.Equal(t, orgID, adminOrgIDs[0].(string))
}

func TestAdminStatus_ContractAdminUser(t *testing.T) {
	// Tier 3: admin claim but NOT is_org_admin. Should NOT be considered admin.
	srv, router := setupAdminAuthTestServer(t, "")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{rbac.ClaimAdmin})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, false, body["is_admin"],
		"contract admin (admin claim only, no is_org_admin) must NOT be admin for dashboard")
}

func TestAdminStatus_NonAdminUser(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "")

	userDID := createTestUserWithClaims(t, srv, []rbac.Claim{})
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, false, body["is_admin"])
}

func TestAdminStatus_UserNotInDB(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "")

	// Create token for a DID that does not exist in the database.
	token, err := srv.jwtService.IssueAccessToken("did:test:nonexistent", true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, false, body["is_admin"])
}

func TestAdminStatus_Unauthenticated(t *testing.T) {
	_, router := setupAdminAuthTestServer(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/admin-status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: expired membership & banned user
// ---------------------------------------------------------------------------

func TestAdminAuth_JWT_ExpiredMembershipDenied(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")
	ctx := t.Context()

	// Create user with is_org_admin group but expired membership.
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "exp-org-" + uuid.New().String()[:8],
		Name: "Expired Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "exp-group-" + uuid.New().String()[:8],
		Name:       "Expired Group",
		Path:       "expired-group",
		IsOrgAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	userDID := "did:test:expired-" + uuid.New().String()[:8]
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	pastTime := time.Now().Add(-24 * time.Hour)
	membership := &rbac.UserMembership{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		GroupID:   group.ID,
		Source:    rbac.MembershipSourceAdmin,
		ExpiresAt: &pastTime,
	}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	// Verify the expired membership is correctly ignored by IsOrgAdmin.
	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, user.ID)
	require.NoError(t, err)
	require.False(t, isOrgAdmin, "IsOrgAdmin should return false for expired membership")
	require.Empty(t, orgIDs)

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "org admin or read-only admin required")
}

func TestAdminAuth_JWT_BannedUserDenied(t *testing.T) {
	srv, router := setupAdminAuthTestServer(t, "my-secret-token")
	ctx := t.Context()

	// Create user with is_org_admin but banned.
	userDID, _ := createTestOrgAdmin(t, srv)

	// Ban the user.
	user, err := srv.db.GetUserByExternalID(ctx, userDID)
	require.NoError(t, err)
	require.NotNil(t, user)
	user.Banned = true
	require.NoError(t, srv.db.UpdateUser(ctx, user))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "banned")
}

