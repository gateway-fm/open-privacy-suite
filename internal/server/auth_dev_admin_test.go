//go:build mockauth

package server

import (
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestServerForDevAdmin creates a minimal Server with AllowMockLogin enabled
// and a real database for testing ensureMockUserIsAdmin.
func setupTestServerForDevAdmin(t *testing.T) *Server {
	t.Helper()

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

	t.Cleanup(func() { database.Close() })

	cfg := &config.Config{
		ReadProfile:    rbac.ReadProfileStandard,
		AllowMockLogin: true,
	}

	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)
	t.Cleanup(rbacAccessCtrl.Stop)

	// Reset the package-level devAdmin state so tests are independent.
	devAdmin = devAdminProvisioner{}

	return &Server{
		db:             database,
		rbacAccessCtrl: rbacAccessCtrl,
		config:         cfg,
	}
}

func TestEnsureMockUserIsAdmin_SkipsScriptUsers(t *testing.T) {
	srv := setupTestServerForDevAdmin(t)
	ctx := t.Context()
	store := srv.rbacAccessCtrl.Store()

	// Create a script-provisioned user (did:test:*)
	scriptUser, err := srv.rbacAccessCtrl.EnsureUserExists(ctx, "did:test:alice", false, true)
	require.NoError(t, err)

	// Call ensureMockUserIsAdmin for the script user
	srv.ensureMockUserIsAdmin(ctx, scriptUser.ID, "did:test:alice")

	// The dev-admin org/group should not even have been created for this user,
	// but even if it was (from a prior call), the user must not be a member.
	org, err := store.GetOrganizationBySlug(ctx, "dev-admin-org")
	require.NoError(t, err)
	if org != nil {
		group, err := store.GetGroupBySlug(ctx, org.ID, "dev-admin-group")
		require.NoError(t, err)
		if group != nil {
			membership, err := store.GetMembershipByUserAndGroup(ctx, scriptUser.ID, group.ID)
			require.NoError(t, err)
			assert.Nil(t, membership, "did:test:* user should NOT be added to dev-admin group")
		}
	}
}

func TestEnsureMockUserIsAdmin_ProvisionsMockUsers(t *testing.T) {
	srv := setupTestServerForDevAdmin(t)
	ctx := t.Context()
	store := srv.rbacAccessCtrl.Store()

	// Create an ad-hoc mock user (did:privado:mock_*)
	mockUser, err := srv.rbacAccessCtrl.EnsureUserExists(ctx, "did:privado:mock_123456", false, true)
	require.NoError(t, err)

	// Call ensureMockUserIsAdmin for the mock user
	srv.ensureMockUserIsAdmin(ctx, mockUser.ID, "did:privado:mock_123456")

	// The dev-admin org and group should now exist
	org, err := store.GetOrganizationBySlug(ctx, "dev-admin-org")
	require.NoError(t, err)
	require.NotNil(t, org, "dev-admin-org should have been created")

	group, err := store.GetGroupBySlug(ctx, org.ID, "dev-admin-group")
	require.NoError(t, err)
	require.NotNil(t, group, "dev-admin-group should have been created")

	// The mock user should be a member of the dev-admin group
	membership, err := store.GetMembershipByUserAndGroup(ctx, mockUser.ID, group.ID)
	require.NoError(t, err)
	require.NotNil(t, membership, "mock user should be added to dev-admin group")
	assert.Equal(t, mockUser.ID, membership.UserID)
	assert.Equal(t, group.ID, membership.GroupID)

	// The group should have the admin claim
	access, err := store.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	require.NotNil(t, access, "dev-admin group should have access configured")
	assert.Contains(t, access.Claims, rbac.ClaimAdmin)
}

func TestEnsureMockUserIsAdmin_Idempotent(t *testing.T) {
	srv := setupTestServerForDevAdmin(t)
	ctx := t.Context()
	store := srv.rbacAccessCtrl.Store()

	// Create an ad-hoc mock user
	mockUser, err := srv.rbacAccessCtrl.EnsureUserExists(ctx, "did:privado:mock_idempotent", false, true)
	require.NoError(t, err)

	// Call ensureMockUserIsAdmin twice
	srv.ensureMockUserIsAdmin(ctx, mockUser.ID, "did:privado:mock_idempotent")
	srv.ensureMockUserIsAdmin(ctx, mockUser.ID, "did:privado:mock_idempotent")

	// Verify only one membership exists by looking it up (if there were duplicates,
	// the DB unique constraint would have caused an error, but let's verify the
	// function returns cleanly and the membership is still valid).
	org, err := store.GetOrganizationBySlug(ctx, "dev-admin-org")
	require.NoError(t, err)
	require.NotNil(t, org)

	group, err := store.GetGroupBySlug(ctx, org.ID, "dev-admin-group")
	require.NoError(t, err)
	require.NotNil(t, group)

	membership, err := store.GetMembershipByUserAndGroup(ctx, mockUser.ID, group.ID)
	require.NoError(t, err)
	require.NotNil(t, membership, "membership should still exist after second call")

	// List all memberships for this user in this group to confirm no duplicates.
	// GetMembershipByUserAndGroup returns at most one row, so we verify via a
	// broader query: list all memberships for the user.
	memberships, err := store.ListUserMemberships(ctx, mockUser.ID)
	require.NoError(t, err)

	devAdminCount := 0
	for _, m := range memberships {
		if m.GroupID == group.ID {
			devAdminCount++
		}
	}
	assert.Equal(t, 1, devAdminCount, "should have exactly one dev-admin membership, not duplicates")
}

func TestEnsureMockUserIsAdmin_DisabledWhenMockLoginOff(t *testing.T) {
	srv := setupTestServerForDevAdmin(t)
	ctx := t.Context()
	store := srv.rbacAccessCtrl.Store()

	// Disable mock login
	srv.config.AllowMockLogin = false

	mockUser, err := srv.rbacAccessCtrl.EnsureUserExists(ctx, "did:privado:mock_disabled", false, true)
	require.NoError(t, err)

	srv.ensureMockUserIsAdmin(ctx, mockUser.ID, "did:privado:mock_disabled")

	// Nothing should have been created
	org, err := store.GetOrganizationBySlug(ctx, "dev-admin-org")
	require.NoError(t, err)
	assert.Nil(t, org, "dev-admin-org should not be created when AllowMockLogin is false")
}
