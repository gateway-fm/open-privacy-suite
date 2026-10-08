package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// setupTieredAdminTestServer creates a test server with admin auth, org scoping,
// and RBAC routes wired up for testing the 3-tier admin model.
func setupTieredAdminTestServer(t *testing.T, adminToken string) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dbURL := sharedTestDBURL(t)

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
		ReadProfile:   rbac.ReadProfileStandard,
		AdminAPIToken: adminToken,
		// RD-1132: a fixed restricted operator token so tests can exercise the
		// denyOperator* gates (X-Admin-Token: testOperatorToken → operator_token).
		OperatorAPIToken: testOperatorToken,
	}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}
	// Stop the RBAC cache's cleanup goroutine when the test ends —
	// otherwise every test leaks one and the suite slows to a halt.
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	router := gin.New()

	adminAuth := srv.adminAuthMiddleware()
	orgScope := srv.orgScopingMiddleware()

	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware(), orgScope)
	{
		admin.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true, "auth_method": c.GetString("auth_method")})
		})
		srv.registerRBACRoutes(admin)
	}

	// /me routes
	me := router.Group("/api/v1/me")
	me.Use(auth.JWTAuthMiddleware(srv.jwtService, srv.db))
	{
		me.GET("/admin-status", srv.getMyAdminStatus)
	}

	_ = adminAuth // used in the admin.Use() chain

	t.Cleanup(func() { srv.db.Close() })

	return srv, router
}

// createOrgAndAdminUser creates an org with an org admin user. Returns (userDID, orgID, userID).
func createOrgAndAdminUser(t *testing.T, srv *Server) (string, string, string) {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "org-" + uuid.New().String()[:8],
		Name: "Test Org",
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

	return userDID, org.ID, user.ID
}

// ---------------------------------------------------------------------------
// Tests: IsOrgAdmin DB function
// ---------------------------------------------------------------------------

func TestIsOrgAdmin_TrueForOrgAdminGroup(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()

	_, orgID, userID := createOrgAndAdminUser(t, srv)

	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, userID)
	require.NoError(t, err)
	assert.True(t, isOrgAdmin, "user in is_org_admin group must be detected as org admin")
	assert.Contains(t, orgIDs, orgID)
}

func TestIsOrgAdmin_FalseForAdminClaimOnly(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()

	// Create a user with admin claim but NOT is_org_admin
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "claim-org-" + uuid.New().String()[:8],
		Name: "Claim Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "admin-group-" + uuid.New().String()[:8],
		Name:       "Admin Group",
		Path:       "admin-group",
		IsOrgAdmin: false, // NOT org admin
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin}, // has admin claim
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:" + uuid.New().String()[:8],
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

	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, isOrgAdmin, "user with admin claim but NOT is_org_admin must NOT be detected as org admin")
	assert.Empty(t, orgIDs)
}

func TestIsOrgAdmin_ExpiredMembershipIgnored(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "")
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "exp-org-" + uuid.New().String()[:8],
		Name: "Expired Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:         uuid.New().String(),
		OrgID:      org.ID,
		Slug:       "exp-admins-" + uuid.New().String()[:8],
		Name:       "Expired Admins",
		Path:       "exp-admins",
		IsOrgAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:expired-" + uuid.New().String()[:8],
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

	isOrgAdmin, orgIDs, err := srv.db.IsOrgAdmin(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, isOrgAdmin, "expired membership must not grant org admin")
	assert.Empty(t, orgIDs)
}

// ---------------------------------------------------------------------------
// Tests: Org scoping middleware
// ---------------------------------------------------------------------------

func TestOrgScoping_JWTAdminCanAccessOwnOrg(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+orgID+"/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOrgScoping_JWTAdminCannotAccessOtherOrg(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, _, _ := createOrgAndAdminUser(t, srv)

	// Create a second org that the user does NOT admin
	otherOrg := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "other-org-" + uuid.New().String()[:8],
		Name: "Other Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, otherOrg))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+otherOrg.ID+"/groups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied to this organization")
}

func TestOrgScoping_SuperAdminBypassesOrgScoping(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Create an org
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "super-org-" + uuid.New().String()[:8],
		Name: "Super Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+org.ID+"/groups", nil)
	req.Header.Set("X-Admin-Token", "secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOrgScoping_JWTAdminCanAccessGenericRoutes(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, _, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// Generic routes (no :org_id) are allowed for JWT org admins —
	// they don't expose cross-org data.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: Escalation prevention (is_org_admin flag)
// ---------------------------------------------------------------------------

func TestEscalation_JWTAdminCannotCreateOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":         "new-admin-group",
		"name":         "New Admin Group",
		"is_org_admin": true, // Trying to escalate
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errCreateOrgAdminGroupSuperOnly)
}

func TestEscalation_JWTAdminCanCreateReadonlyAdminGroup(t *testing.T) {
	// RD-866 + RD-917 §2: tier-2 admins can mint is_org_readonly_admin
	// groups within their own org. RO-admin is a strict subset of tier-2,
	// so granting it is delegation (not escalation). Only is_org_admin
	// remains super-admin-only.
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":                  "auditors",
		"name":                  "Auditors",
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestEscalation_JWTAdminCanCreateNonAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":         "normal-group",
		"name":         "Normal Group",
		"is_org_admin": false, // Not escalating
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestEscalation_SuperAdminCanCreateOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "super-create-org-" + uuid.New().String()[:8],
		Name: "Super Create Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	body := map[string]interface{}{
		"slug":         "new-org-admin",
		"name":         "New Org Admin",
		"is_org_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+org.ID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestEscalation_JWTAdminCannotUpdateGroupToOrgAdmin(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	// Create a normal group to try updating
	normalGroup := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgID,
		Slug:  "normal-" + uuid.New().String()[:8],
		Name:  "Normal",
		Path:  "normal",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"is_org_admin": true, // Trying to escalate
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+normalGroup.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errSetOrgAdminStatusSuperOnly)
}

func TestEscalation_JWTAdminCanUpdateGroupToReadonlyAdmin(t *testing.T) {
	// Mirror of TestEscalation_JWTAdminCanCreateReadonlyAdminGroup for the
	// PUT path. RD-866 + RD-917 §2.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	normalGroup := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgID,
		Slug:  "normal-" + uuid.New().String()[:8],
		Name:  "Normal",
		Path:  "normal",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+normalGroup.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEscalation_JWTAdminCanUpdateGroupName(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	// Create a normal group to update
	normalGroup := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgID,
		Slug:  "updatable-" + uuid.New().String()[:8],
		Name:  "Old Name",
		Path:  "updatable",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"name": "New Name",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+normalGroup.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, "New Name", result["name"])
}

func TestEscalation_JWTAdminCanCreateGroupWithAdminClaim(t *testing.T) {
	// Org admins CAN create groups with admin claim (tier 3) — they just
	// cannot set is_org_admin on those groups.
	srv, router := setupTieredAdminTestServer(t, "secret")

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	// First create the group
	groupBody := map[string]interface{}{
		"slug":         "contract-admins",
		"name":         "Contract Admins",
		"is_org_admin": false,
	}
	groupBytes, _ := json.Marshal(groupBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(groupBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var createdGroup map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &createdGroup))
	groupID := createdGroup["id"].(string)

	// Then set access with admin claim
	accessBody := map[string]interface{}{
		"allowed_methods": []string{"eth_call", "eth_sendTransaction"},
		"claims":          []string{"admin"},
	}
	accessBytes, _ := json.Marshal(accessBody)

	req = httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", bytes.NewReader(accessBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"org admin must be able to create groups with admin claim (tier 3 contract admin)")
}

// ---------------------------------------------------------------------------
// Tests: tighter is_org_admin demote / delete gate (RD-917 §2 follow-up)
// ---------------------------------------------------------------------------

func TestEscalation_JWTAdminCannotDemoteOrgAdminGroup(t *testing.T) {
	// A tier-2 admin sending {"is_org_admin": false} on an existing
	// is_org_admin=true group must be rejected with 403. Demoting an admin
	// group strips admin status from every member (potentially including
	// the demoter), causing an org-wide DoS that only super-admin can
	// recover from. Symmetric with the promote-to-true gate.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	// The org-admin group already exists from createOrgAndAdminUser; locate it.
	groups, err := srv.db.ListGroups(ctx, orgID)
	require.NoError(t, err)
	var orgAdminGroupID string
	for _, g := range groups {
		if g.IsOrgAdmin {
			orgAdminGroupID = g.ID
			break
		}
	}
	require.NotEmpty(t, orgAdminGroupID, "test fixture must include an is_org_admin group")

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"is_org_admin": false, // attempting to demote
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGroupID, bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errSetOrgAdminStatusSuperOnly)

	// Verify the flag is still true — gate fired before any DB write.
	g, err := srv.db.GetGroup(ctx, orgAdminGroupID)
	require.NoError(t, err)
	assert.True(t, g.IsOrgAdmin, "demote attempt must not have changed the flag")
}

func TestEscalation_JWTAdminCannotDeleteOrgAdminGroup(t *testing.T) {
	// Deleting an is_org_admin group has the same effect as demoting it —
	// every member loses admin status. Block tier-2; super-admin only.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	userDID, orgID, _ := createOrgAndAdminUser(t, srv)

	groups, err := srv.db.ListGroups(ctx, orgID)
	require.NoError(t, err)
	var orgAdminGroupID string
	for _, g := range groups {
		if g.IsOrgAdmin {
			orgAdminGroupID = g.ID
			break
		}
	}
	require.NotEmpty(t, orgAdminGroupID)

	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGroupID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errDeleteOrgAdminGroupSuperOnly)

	g, err := srv.db.GetGroup(ctx, orgAdminGroupID)
	require.NoError(t, err)
	require.NotNil(t, g, "group must still exist after blocked delete")
}

func TestEscalation_SuperAdminCanDeleteOrgAdminGroup(t *testing.T) {
	// Super-admin (X-Admin-Token) can delete an org-admin group — the gate
	// only fires for jwt_admin. Sanity check.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	_, orgID, _ := createOrgAndAdminUser(t, srv)
	groups, err := srv.db.ListGroups(ctx, orgID)
	require.NoError(t, err)
	var orgAdminGroupID string
	for _, g := range groups {
		if g.IsOrgAdmin {
			orgAdminGroupID = g.ID
			break
		}
	}
	require.NotEmpty(t, orgAdminGroupID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGroupID, nil)
	req.Header.Set("X-Admin-Token", "secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: createUserMembership / deleteUserMembership cross-org scoping (RD-917 §3)
// ---------------------------------------------------------------------------

func TestMembership_JWTAdminCannotAddUserToForeignOrgGroup(t *testing.T) {
	// A tier-2 admin of orgA must not be able to add a user to a group
	// that lives in orgB. The membership route has no :org_id, so the
	// orgScopingMiddleware cannot enforce; the handler must.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Alice: tier-2 admin of orgA.
	aliceDID, _, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	// orgB with its own normal group and a target user.
	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))

	targetUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, targetUser))

	body := map[string]interface{}{"group_id": orgBGroup.ID}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUser.ID+"/memberships", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// RD-942 Finding 1: the user-scope gate added at the top of
	// createUserMembership fires FIRST. Bob has no memberships in alice's
	// scope (no overlap with admin_org_ids), so requireUserInFullAdminScope
	// returns errTargetForeignOrg before the group lookup that would have
	// returned errMembershipForeignOrg. Both protections are in place; the
	// gate ordering is the documented assertion here.
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errTargetForeignOrg)

	// Verify no membership row was inserted.
	memberships, err := srv.db.ListUserMemberships(ctx, targetUser.ID)
	require.NoError(t, err)
	assert.Empty(t, memberships, "blocked add must not have inserted a row")
}

func TestMembership_JWTAdminCannotRemoveForeignOrgMembership(t *testing.T) {
	// Symmetric: tier-2 admin of orgA must not be able to delete a
	// membership row whose group lives in orgB.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, _, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))
	bob := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, bob))
	bobMembership := &rbac.UserMembership{ID: uuid.New().String(), UserID: bob.ID, GroupID: orgBGroup.ID, Source: rbac.MembershipSourceAdmin}
	require.NoError(t, srv.db.CreateMembership(ctx, bobMembership))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+bob.ID+"/memberships/"+bobMembership.ID, nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)

	// Verify membership still exists.
	got, err := srv.db.GetMembership(ctx, bobMembership.ID)
	require.NoError(t, err)
	require.NotNil(t, got, "blocked delete must not have removed the row")
}

func TestMembership_JWTAdminCanAddUserToOwnOrgGroup(t *testing.T) {
	// Positive path: tier-2 admin of orgA can add a user to a normal group
	// in orgA. RD-942 Finding 1 requires the user to already be in alice's
	// full-admin scope before she can manage their memberships — Bob must
	// have at least one membership in orgA already (typically seeded via
	// the by-did onboarding endpoint, but here we set it up directly).
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	// A first group in orgA — Bob's initial membership puts him in alice's
	// scope. Without this the new requireUserInFullAdminScope gate would
	// (correctly) reject the request before the group lookup runs.
	seedGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "seed", Name: "Seed", Path: "seed"}
	require.NoError(t, srv.db.CreateGroup(ctx, seedGroup))

	bob := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, bob))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  bob.ID,
		GroupID: seedGroup.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	// The actual add: a second group in the same org.
	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team", Name: "Team", Path: "team"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	body := map[string]interface{}{"group_id": normalGroup.ID}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+bob.ID+"/memberships", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestMembership_JWTAdminCannotAddUnknownUserUUID is the RD-942 Finding 1
// pinning test: probing with a randomly-generated UUID that has no row in
// `users` must return 403 errTargetForeignOrg, NOT a 500 FK-violation that
// would distinguish "user does not exist" from other error codes. Pre-fix,
// the response-code path was a user-enumeration oracle:
//
//	201 Created                  → user exists, not yet in group
//	409 Conflict                 → user exists and is in group
//	500 Internal Server Error    → user does NOT exist (FK failed)
//
// Post-fix the user-scope gate fires first and returns the same opaque
// errTargetForeignOrg shape regardless of whether the UUID names a real
// user or random garbage.
func TestMembership_JWTAdminCannotAddUnknownUserUUID(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-unknown", Name: "Team", Path: "team-unknown"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	// A UUID that has no row in `users`. Pre-fix this would have surfaced
	// as a 500 FK-fail, leaking the existence boundary.
	unknownUUID := uuid.New().String()

	body := map[string]interface{}{"group_id": normalGroup.ID}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+unknownUUID+"/memberships", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errTargetForeignOrg)
}

// TestMembership_JWTAdminCannotAddCrossOrgUserUUID — the more pointed leak:
// a tier-2 admin of orgA learns (somehow — log, support ticket, screenshot)
// a real user UUID that belongs only to orgB. They must not be able to
// confirm the UUID is real by attempting an add. Same opaque response shape
// as "UUID doesn't exist anywhere".
func TestMembership_JWTAdminCannotAddCrossOrgUserUUID(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-cross", Name: "Team", Path: "team-cross"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	// Bob lives only in orgB — not in alice's scope.
	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))
	bob := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:bob-cross-" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, bob))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  bob.ID,
		GroupID: orgBGroup.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	// Alice tries to add Bob (orgB-only user) to her own org's group. Pre-
	// fix this returned 201 since there was no user-scope check; post-fix
	// the gate rejects with the same opaque shape as an unknown-UUID probe.
	body := map[string]interface{}{"group_id": normalGroup.ID}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+bob.ID+"/memberships", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errTargetForeignOrg)

	// And no membership was inserted in alice's group.
	memberships, err := srv.db.ListUserMemberships(ctx, bob.ID)
	require.NoError(t, err)
	for _, m := range memberships {
		assert.NotEqual(t, normalGroup.ID, m.GroupID, "blocked add must not have inserted a row in alice's group")
	}
}

// ---------------------------------------------------------------------------
// Test: audit log writes (RD-917 §4 — RBAC audit-log evidence completeness)
// ---------------------------------------------------------------------------

func TestAuditLog_GroupCreateRecorded(t *testing.T) {
	// Creating a group via the admin API must produce a row in
	// rbac_audit_log so Vanta / ISO 27001 access-review can trace the
	// change. Pre-fix, the rbac_audit_log table was only written for
	// user creation (internal/rbac/access.go); no group / org / membership
	// mutations were logged.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	body := map[string]interface{}{
		"slug":                  "audited",
		"name":                  "Audited Group",
		"is_org_readonly_admin": true,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	groupID := created["id"].(string)

	entries, err := srv.db.ListAuditLogs(ctx, rbac.ResourceTypeGroup, &groupID, 10, 0)
	require.NoError(t, err)
	require.Len(t, entries, 1, "exactly one audit entry expected for the create")
	entry := entries[0]
	assert.Equal(t, rbac.AuditActionCreate, entry.Action)
	assert.Equal(t, aliceDID, entry.ActorExternalID)
	assert.Equal(t, "Audited Group", entry.ResourceName)
	assert.NotNil(t, entry.NewValue)
	assert.Equal(t, true, entry.NewValue["is_org_readonly_admin"])
}

// ---------------------------------------------------------------------------
// Tests: is_org_admin escalation gate on the membership / batch / set-access
// surfaces (RD-1099). The gate that already blocks tier-2 from minting an
// is_org_admin GROUP must also block them from minting/demoting an org admin
// by adding/removing MEMBERS, deleting the group via batch, or reshaping the
// admin group's access. is_org_readonly_admin stays assignable by tier-2
// (delegation, not escalation) — that is the negative control in each test.
// ---------------------------------------------------------------------------

// setupOrgAdminGateFixture builds an org with a tier-2 admin plus the three
// group shapes the gate distinguishes: full org-admin, read-only-admin, and
// normal. Returns the admin's DID and the org + group IDs.
func setupOrgAdminGateFixture(t *testing.T, srv *Server) (adminDID, orgID, orgAdminGID, roAdminGID, normalGID string) {
	t.Helper()
	ctx := t.Context()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "ogate-" + uuid.New().String()[:8],
		Name: "Org Admin Gate Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))
	orgID = org.ID

	mkGroup := func(slug string, isAdmin, isRO bool) string {
		g := &rbac.Group{
			ID:                 uuid.New().String(),
			OrgID:              orgID,
			Slug:               slug + "-" + uuid.New().String()[:8],
			Name:               slug,
			Path:               slug,
			IsOrgAdmin:         isAdmin,
			IsOrgReadonlyAdmin: isRO,
		}
		require.NoError(t, srv.db.CreateGroup(ctx, g))
		return g.ID
	}
	orgAdminGID = mkGroup("org-admins", true, false)
	roAdminGID = mkGroup("ro-admins", false, true)
	normalGID = mkGroup("members", false, false)

	// Group access on the admin group mirrors createOrgAndAdminUser so the
	// admin-auth middleware resolves the caller as a tier-2 org admin.
	require.NoError(t, srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        orgAdminGID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
	}))

	adminDID = "did:test:" + uuid.New().String()[:8]
	adminUser := &rbac.User{ID: uuid.New().String(), ExternalID: adminDID, KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, adminUser))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  adminUser.ID,
		GroupID: orgAdminGID,
		Source:  rbac.MembershipSourceAdmin,
	}))
	return
}

// createMemberUser creates a user and a membership in groupID, returning both IDs.
func createMemberUser(t *testing.T, srv *Server, groupID string) (userID, membershipID string) {
	t.Helper()
	ctx := t.Context()
	u := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, u))
	m := &rbac.UserMembership{ID: uuid.New().String(), UserID: u.ID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}
	require.NoError(t, srv.db.CreateMembership(ctx, m))
	return u.ID, m.ID
}

// orgAdminGateReq issues an admin-API request. Pass jwt for a tier-2 caller or
// adminTok for super-admin (X-Admin-Token); body may be nil.
func orgAdminGateReq(t *testing.T, router *gin.Engine, method, path, jwt, adminTok string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	if adminTok != "" {
		req.Header.Set("X-Admin-Token", adminTok)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// --- createUserMembership ---------------------------------------------------

func TestEscalation_JWTAdminCannotAddMemberToOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	adminDID, _, orgAdminGID, roAdminGID, normalGID := setupOrgAdminGateFixture(t, srv)
	token, err := srv.jwtService.IssueAccessToken(adminDID, true)
	require.NoError(t, err)

	// Target must be in the caller's full-admin scope (member of the org).
	targetID, _ := createMemberUser(t, srv, normalGID)
	path := "/api/v1/admin/users/" + targetID + "/memberships"

	t.Run("org-admin group is blocked", func(t *testing.T) {
		w := orgAdminGateReq(t, router, http.MethodPost, path, token, "", mustJSON(t, map[string]any{"group_id": orgAdminGID}))
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), errModifyOrgAdminGroupSuperOnly)
	})

	t.Run("readonly-admin group is allowed (delegation)", func(t *testing.T) {
		w := orgAdminGateReq(t, router, http.MethodPost, path, token, "", mustJSON(t, map[string]any{"group_id": roAdminGID}))
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestEscalation_SuperAdminCanAddMemberToOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_, _, orgAdminGID, _, normalGID := setupOrgAdminGateFixture(t, srv)
	targetID, _ := createMemberUser(t, srv, normalGID)

	w := orgAdminGateReq(t, router, http.MethodPost, "/api/v1/admin/users/"+targetID+"/memberships", "", "secret", mustJSON(t, map[string]any{"group_id": orgAdminGID}))
	assert.Equal(t, http.StatusCreated, w.Code)
}

// --- createMembershipByDID --------------------------------------------------

func TestEscalation_JWTAdminCannotOnboardDIDToOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	adminDID, orgID, orgAdminGID, roAdminGID, _ := setupOrgAdminGateFixture(t, srv)
	token, err := srv.jwtService.IssueAccessToken(adminDID, true)
	require.NoError(t, err)
	path := "/api/v1/admin/orgs/" + orgID + "/memberships/by-did"

	t.Run("org-admin group is blocked", func(t *testing.T) {
		body := mustJSON(t, map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": orgAdminGID})
		w := orgAdminGateReq(t, router, http.MethodPost, path, token, "", body)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), errModifyOrgAdminGroupSuperOnly)
	})

	t.Run("readonly-admin group is allowed (delegation)", func(t *testing.T) {
		body := mustJSON(t, map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": roAdminGID})
		w := orgAdminGateReq(t, router, http.MethodPost, path, token, "", body)
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestEscalation_SuperAdminCanOnboardDIDToOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_, orgID, orgAdminGID, _, _ := setupOrgAdminGateFixture(t, srv)

	body := mustJSON(t, map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": orgAdminGID})
	w := orgAdminGateReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did", "", "secret", body)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// --- deleteUserMembership ---------------------------------------------------

func TestEscalation_JWTAdminCannotRemoveMemberFromOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	adminDID, _, orgAdminGID, roAdminGID, _ := setupOrgAdminGateFixture(t, srv)
	token, err := srv.jwtService.IssueAccessToken(adminDID, true)
	require.NoError(t, err)

	t.Run("org-admin group is blocked and not deleted", func(t *testing.T) {
		targetID, mID := createMemberUser(t, srv, orgAdminGID)
		w := orgAdminGateReq(t, router, http.MethodDelete, "/api/v1/admin/users/"+targetID+"/memberships/"+mID, token, "", nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), errModifyOrgAdminGroupSuperOnly)
		m, err := srv.db.GetMembership(t.Context(), mID)
		require.NoError(t, err)
		assert.NotNil(t, m, "membership must survive a denied demotion")
	})

	t.Run("readonly-admin group is allowed (delegation)", func(t *testing.T) {
		targetID, mID := createMemberUser(t, srv, roAdminGID)
		w := orgAdminGateReq(t, router, http.MethodDelete, "/api/v1/admin/users/"+targetID+"/memberships/"+mID, token, "", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestEscalation_SuperAdminCanRemoveMemberFromOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_, _, orgAdminGID, _, _ := setupOrgAdminGateFixture(t, srv)
	targetID, mID := createMemberUser(t, srv, orgAdminGID)

	w := orgAdminGateReq(t, router, http.MethodDelete, "/api/v1/admin/users/"+targetID+"/memberships/"+mID, "", "secret", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- setGroupAccess ---------------------------------------------------------

func TestEscalation_JWTAdminCannotSetAccessOnOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	adminDID, orgID, orgAdminGID, roAdminGID, _ := setupOrgAdminGateFixture(t, srv)
	token, err := srv.jwtService.IssueAccessToken(adminDID, true)
	require.NoError(t, err)

	t.Run("org-admin group is blocked", func(t *testing.T) {
		// Would widen the admin role's methods (e.g. add tracing) — must be denied.
		body := mustJSON(t, map[string]any{"allowed_methods": []string{"eth_call", "debug_traceTransaction"}})
		w := orgAdminGateReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGID+"/access", token, "", body)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), errModifyOrgAdminGroupSuperOnly)
	})

	t.Run("readonly-admin group is allowed", func(t *testing.T) {
		body := mustJSON(t, map[string]any{"allowed_methods": []string{"eth_call"}})
		w := orgAdminGateReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+roAdminGID+"/access", token, "", body)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestEscalation_SuperAdminCanSetAccessOnOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_, orgID, orgAdminGID, _, _ := setupOrgAdminGateFixture(t, srv)

	// claims empty + methods non-empty satisfies the RD-968 org-admin invariants.
	body := mustJSON(t, map[string]any{"allowed_methods": []string{"eth_call"}})
	w := orgAdminGateReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+orgAdminGID+"/access", "", "secret", body)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- batchDeleteGroups ------------------------------------------------------

func TestEscalation_JWTAdminCannotBatchDeleteOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	adminDID, orgID, _, _, normalGID := setupOrgAdminGateFixture(t, srv)
	token, err := srv.jwtService.IssueAccessToken(adminDID, true)
	require.NoError(t, err)
	ctx := t.Context()

	// A second org-admin group (not the caller's own) included in the batch.
	victimAdminGID := uuid.New().String()
	require.NoError(t, srv.db.CreateGroup(ctx, &rbac.Group{
		ID: victimAdminGID, OrgID: orgID, Slug: "victim-" + uuid.New().String()[:8],
		Name: "Victim Admins", Path: "victim", IsOrgAdmin: true,
	}))

	body := mustJSON(t, map[string]any{"group_ids": []string{normalGID, victimAdminGID}})
	w := orgAdminGateReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups/batch-delete", token, "", body)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errDeleteOrgAdminGroupSuperOnly)

	// The whole tx must roll back — the normal group is NOT deleted.
	g, err := srv.db.GetGroup(ctx, normalGID)
	require.NoError(t, err)
	assert.NotNil(t, g, "batch must roll back when it contains an org-admin group")
}

func TestEscalation_JWTAdminCanBatchDeleteNonAdminGroups(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	adminDID, orgID, _, roAdminGID, normalGID := setupOrgAdminGateFixture(t, srv)
	token, err := srv.jwtService.IssueAccessToken(adminDID, true)
	require.NoError(t, err)

	// Normal + read-only-admin groups are both deletable by tier-2.
	body := mustJSON(t, map[string]any{"group_ids": []string{normalGID, roAdminGID}})
	w := orgAdminGateReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups/batch-delete", token, "", body)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEscalation_SuperAdminCanBatchDeleteOrgAdminGroup(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_, orgID, _, _, _ := setupOrgAdminGateFixture(t, srv)
	ctx := t.Context()

	victimAdminGID := uuid.New().String()
	require.NoError(t, srv.db.CreateGroup(ctx, &rbac.Group{
		ID: victimAdminGID, OrgID: orgID, Slug: "victim2-" + uuid.New().String()[:8],
		Name: "Victim Admins 2", Path: "victim2", IsOrgAdmin: true,
	}))

	// Admin-only batch: super-admin manages the admin tier. (RD-1107 blocks a
	// batch that also contains a REGULAR group — covered in the dedicated block
	// test; mixing one in here would now correctly 403.)
	body := mustJSON(t, map[string]any{"group_ids": []string{victimAdminGID}})
	w := orgAdminGateReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups/batch-delete", "", "secret", body)
	assert.Equal(t, http.StatusOK, w.Code)
}
