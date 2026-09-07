package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestServerForUserProfile creates a test server for user profile tests
func setupTestServerForUserProfile(t *testing.T) (*Server, *gin.Engine) {
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

	err = db.ResetTestDatabase(database)
	require.NoError(t, err)

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		VerifierID:     "did:privado:verifier:test",
		BaseURL:        "http://localhost:8080",
		Environment:    "development",
		MockSignatures: true,
	}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}
	t.Cleanup(srv.rbacAccessCtrl.Stop)

	router := gin.New()
	srv.registerUserProfileRoutes(router)

	t.Cleanup(func() {
		srv.db.Close()
	})

	return srv, router
}

func TestGetMyOrganizations_Unauthenticated(t *testing.T) {
	_, router := setupTestServerForUserProfile(t)

	// Request without Authorization header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetMyOrganizations_InvalidToken(t *testing.T) {
	_, router := setupTestServerForUserProfile(t)

	// Request with invalid token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetMyOrganizations_UserNotFound(t *testing.T) {
	srv, router := setupTestServerForUserProfile(t)

	// Create valid token for non-existent user
	token, err := srv.jwtService.IssueAccessToken("did:test:nonexistent", true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

func TestGetMyOrganizations_NoMemberships(t *testing.T) {
	srv, router := setupTestServerForUserProfile(t)
	ctx := t.Context()

	// Create a user with no memberships
	userDID := "did:test:user-no-memberships"
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	err := srv.db.CreateUser(ctx, user)
	require.NoError(t, err)

	// Create valid token
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]apimodels.UserOrgResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Empty(t, response["organizations"])
}

func TestGetMyOrganizations_SingleOrg(t *testing.T) {
	srv, router := setupTestServerForUserProfile(t)
	ctx := t.Context()

	// Create an organization
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "test-org",
		Name: "Test Organization",
	}
	err := srv.db.CreateOrganization(ctx, org)
	require.NoError(t, err)

	// Create a group in the organization
	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "test-group",
		Name:  "Test Group",
		Path:  "test-group",
	}
	err = srv.db.CreateGroup(ctx, group)
	require.NoError(t, err)

	// Create a user
	userDID := "did:test:user-single-org"
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	err = srv.db.CreateUser(ctx, user)
	require.NoError(t, err)

	// Add user to the group
	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	err = srv.db.CreateMembership(ctx, membership)
	require.NoError(t, err)

	// Create valid token
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]apimodels.UserOrgResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	require.Len(t, response["organizations"], 1)
	assert.Equal(t, org.ID, response["organizations"][0].ID)
	assert.Equal(t, org.Slug, response["organizations"][0].Slug)
	assert.Equal(t, org.Name, response["organizations"][0].Name)
}

func TestGetMyOrganizations_MultipleOrgs(t *testing.T) {
	srv, router := setupTestServerForUserProfile(t)
	ctx := t.Context()

	// Create two organizations
	org1 := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "org-one",
		Name: "Organization One",
	}
	org2 := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "org-two",
		Name: "Organization Two",
	}
	err := srv.db.CreateOrganization(ctx, org1)
	require.NoError(t, err)
	err = srv.db.CreateOrganization(ctx, org2)
	require.NoError(t, err)

	// Create groups in each organization
	group1 := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org1.ID,
		Slug:  "group-one",
		Name:  "Group One",
		Path:  "group-one",
	}
	group2 := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org2.ID,
		Slug:  "group-two",
		Name:  "Group Two",
		Path:  "group-two",
	}
	err = srv.db.CreateGroup(ctx, group1)
	require.NoError(t, err)
	err = srv.db.CreateGroup(ctx, group2)
	require.NoError(t, err)

	// Create a user
	userDID := "did:test:user-multi-org"
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	err = srv.db.CreateUser(ctx, user)
	require.NoError(t, err)

	// Add user to both groups
	membership1 := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group1.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	membership2 := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group2.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	err = srv.db.CreateMembership(ctx, membership1)
	require.NoError(t, err)
	err = srv.db.CreateMembership(ctx, membership2)
	require.NoError(t, err)

	// Create valid token
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]apimodels.UserOrgResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Len(t, response["organizations"], 2)

	// Check that both orgs are returned
	orgIDs := make(map[string]bool)
	for _, org := range response["organizations"] {
		orgIDs[org.ID] = true
	}
	assert.True(t, orgIDs[org1.ID], "org1 should be in response")
	assert.True(t, orgIDs[org2.ID], "org2 should be in response")
}

func TestGetMyOrganizations_UserCannotSeeOtherUsersOrgs(t *testing.T) {
	srv, router := setupTestServerForUserProfile(t)
	ctx := t.Context()

	// Create an organization
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "secret-org",
		Name: "Secret Organization",
	}
	err := srv.db.CreateOrganization(ctx, org)
	require.NoError(t, err)

	// Create a group
	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "secret-group",
		Name:  "Secret Group",
		Path:  "secret-group",
	}
	err = srv.db.CreateGroup(ctx, group)
	require.NoError(t, err)

	// Create User A (member of the org)
	userADID := "did:test:user-a"
	userA := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userADID,
		KYC:        true,
	}
	err = srv.db.CreateUser(ctx, userA)
	require.NoError(t, err)

	// Add User A to the group
	membershipA := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userA.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	err = srv.db.CreateMembership(ctx, membershipA)
	require.NoError(t, err)

	// Create User B (NOT a member of the org)
	userBDID := "did:test:user-b"
	userB := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userBDID,
		KYC:        true,
	}
	err = srv.db.CreateUser(ctx, userB)
	require.NoError(t, err)

	// User A should see the org
	tokenA, err := srv.jwtService.IssueAccessToken(userADID, true)
	require.NoError(t, err)

	reqA := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	reqA.Header.Set("Authorization", "Bearer "+tokenA)
	wA := httptest.NewRecorder()
	router.ServeHTTP(wA, reqA)

	assert.Equal(t, http.StatusOK, wA.Code)
	var responseA map[string][]apimodels.UserOrgResponse
	err = json.Unmarshal(wA.Body.Bytes(), &responseA)
	require.NoError(t, err)
	require.Len(t, responseA["organizations"], 1)
	assert.Equal(t, org.ID, responseA["organizations"][0].ID)

	// User B should NOT see the org
	tokenB, err := srv.jwtService.IssueAccessToken(userBDID, true)
	require.NoError(t, err)

	reqB := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	reqB.Header.Set("Authorization", "Bearer "+tokenB)
	wB := httptest.NewRecorder()
	router.ServeHTTP(wB, reqB)

	assert.Equal(t, http.StatusOK, wB.Code)
	var responseB map[string][]apimodels.UserOrgResponse
	err = json.Unmarshal(wB.Body.Bytes(), &responseB)
	require.NoError(t, err)
	assert.Empty(t, responseB["organizations"], "User B should not see any orgs")
}

func TestGetMyOrganizations_DeduplicatesOrgs(t *testing.T) {
	srv, router := setupTestServerForUserProfile(t)
	ctx := t.Context()

	// Create an organization
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "dedup-org",
		Name: "Dedup Organization",
	}
	err := srv.db.CreateOrganization(ctx, org)
	require.NoError(t, err)

	// Create two groups in the SAME organization
	group1 := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "group-a",
		Name:  "Group A",
		Path:  "group-a",
	}
	group2 := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "group-b",
		Name:  "Group B",
		Path:  "group-b",
	}
	err = srv.db.CreateGroup(ctx, group1)
	require.NoError(t, err)
	err = srv.db.CreateGroup(ctx, group2)
	require.NoError(t, err)

	// Create a user
	userDID := "did:test:user-dedup"
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: userDID,
		KYC:        true,
	}
	err = srv.db.CreateUser(ctx, user)
	require.NoError(t, err)

	// Add user to BOTH groups in the same org
	membership1 := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group1.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	membership2 := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group2.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	err = srv.db.CreateMembership(ctx, membership1)
	require.NoError(t, err)
	err = srv.db.CreateMembership(ctx, membership2)
	require.NoError(t, err)

	// Create valid token
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]apimodels.UserOrgResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should only return the org ONCE, not twice
	assert.Len(t, response["organizations"], 1, "org should be deduplicated")
	assert.Equal(t, org.ID, response["organizations"][0].ID)
}
