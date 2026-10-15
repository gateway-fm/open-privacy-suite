//go:build mockauth

package server

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// devAdminProvisioner lazily creates a "dev-admin" org+group with the admin
// claim and adds mock-login users to it. This gives mock users immediate admin
// dashboard access without manual RBAC setup.
//
// Safety: the entire file is gated behind the "mockauth" build tag, which is
// excluded from production Docker builds. Additionally, the provisioning is
// guarded by AllowMockLogin at runtime.
type devAdminProvisioner struct {
	mu      sync.Mutex
	groupID string // cached after first successful setup
}

var devAdmin devAdminProvisioner

// ensureMockUserIsAdmin grants the admin claim to a mock-login user.
// It lazily creates the dev-admin org+group on first call, then adds the user
// as a member (idempotent — skips if already a member).
func (s *Server) ensureMockUserIsAdmin(ctx context.Context, userID, userDID string) {
	if !s.config.AllowMockLogin || s.rbacAccessCtrl == nil {
		return
	}

	// Skip script-provisioned users (did:test:*) — they have intentional
	// group setups from setup-test-accounts.sh and should not be auto-added
	// to the dev-admin group on every login.
	if strings.HasPrefix(userDID, "did:test:") {
		return
	}

	store := s.rbacAccessCtrl.Store()

	devAdmin.mu.Lock()
	defer devAdmin.mu.Unlock()

	// Lazy-init: create org + group + access if not yet done
	if devAdmin.groupID == "" {
		groupID, err := bootstrapDevAdminGroup(ctx, store)
		if err != nil {
			slog.Warn("failed to bootstrap dev-admin group", "error", err)
			return
		}
		devAdmin.groupID = groupID
	}

	// Check if user already has membership
	existing, _ := store.GetMembershipByUserAndGroup(ctx, userID, devAdmin.groupID)
	if existing != nil {
		return
	}

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: devAdmin.groupID,
		Source:  rbac.MembershipSourceAdmin,
	}
	if err := store.CreateMembership(ctx, membership); err != nil {
		slog.Warn("failed to add mock user to dev-admin group", "user_id", userID, "error", err)
	}
}

func bootstrapDevAdminGroup(ctx context.Context, store rbac.Store) (string, error) {
	const orgSlug = "dev-admin-org"
	const groupSlug = "dev-admin-group"

	// Find or create org
	org, err := store.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return "", err
	}
	if org == nil {
		org = &rbac.Organization{
			ID:   uuid.New().String(),
			Slug: orgSlug,
			Name: "Dev Admin Org (auto-created)",
		}
		if err := store.CreateOrganization(ctx, org); err != nil {
			return "", err
		}
	}

	// Find or create group
	group, err := store.GetGroupBySlug(ctx, org.ID, groupSlug)
	if err != nil {
		return "", err
	}
	if group == nil {
		group = &rbac.Group{
			ID:         uuid.New().String(),
			OrgID:      org.ID,
			Slug:       groupSlug,
			Name:       "Dev Admin Group (auto-created)",
			Depth:      0,
			Path:       groupSlug,
			IsOrgAdmin: true, // Dev mode: full org admin for dashboard access
		}
		if err := store.CreateGroup(ctx, group); err != nil {
			return "", err
		}
	}

	// Ensure group is org admin (may have been created before 3-tier model)
	if !group.IsOrgAdmin {
		group.IsOrgAdmin = true
		_ = store.UpdateGroup(ctx, group)
	}

	// Ensure admin claim on the group
	access, _ := store.GetGroupAccess(ctx, group.ID)
	if access == nil {
		access = &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        group.ID,
			AllowedMethods: rbac.AllAllowedMethods(), // explicit "*" expansion, never a literal "*"
			Claims:         []rbac.Claim{rbac.ClaimAdmin},
		}
		if err := store.CreateGroupAccess(ctx, access); err != nil {
			return "", err
		}
	}

	return group.ID, nil
}
