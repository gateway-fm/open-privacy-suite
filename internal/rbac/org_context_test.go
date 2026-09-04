package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// MockOrgContextStore implements Store interface for OrgContext tests
type MockOrgContextStore struct {
	memberships           []*MembershipWithDetails
	organizations         map[string]*Organization
	contractOwners        map[string]string // address -> orgID
	addressOwnedByOrg     map[string]map[string]bool // address -> orgID -> bool
	registeredToAnyOrg    map[string]bool // address -> bool
	membershipsErr        error
	orgErr                error
	contractOwnerErr      error
	addressOwnedErr       error
	registeredToAnyOrgErr error
}

func (m *MockOrgContextStore) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	if m.membershipsErr != nil {
		return nil, m.membershipsErr
	}
	return m.memberships, nil
}

func (m *MockOrgContextStore) ListActiveUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	if m.membershipsErr != nil {
		return nil, m.membershipsErr
	}
	return m.memberships, nil
}

func (m *MockOrgContextStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	if m.orgErr != nil {
		return nil, m.orgErr
	}
	return m.organizations[id], nil
}

func (m *MockOrgContextStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	if m.contractOwnerErr != nil {
		return "", m.contractOwnerErr
	}
	return m.contractOwners[address], nil
}

func (m *MockOrgContextStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	if m.addressOwnedErr != nil {
		return false, m.addressOwnedErr
	}
	if m.addressOwnedByOrg == nil {
		return false, nil
	}
	if orgMap, ok := m.addressOwnedByOrg[address]; ok {
		return orgMap[orgID], nil
	}
	return false, nil
}

func (m *MockOrgContextStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	if m.registeredToAnyOrgErr != nil {
		return false, m.registeredToAnyOrgErr
	}
	return m.registeredToAnyOrg[address], nil
}

// Implement remaining Store interface methods as no-ops for tests
func (m *MockOrgContextStore) CreateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockOrgContextStore) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) { return nil, nil }
func (m *MockOrgContextStore) UpdateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockOrgContextStore) ListOrganizations(ctx context.Context) ([]*Organization, error) { return nil, nil }
func (m *MockOrgContextStore) ListOrganizationsPaginated(ctx context.Context, limit, offset int) ([]*Organization, int, error) { return nil, 0, nil }
func (m *MockOrgContextStore) DeleteOrganization(ctx context.Context, id string) error { return nil }
func (m *MockOrgContextStore) CreateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockOrgContextStore) GetGroup(ctx context.Context, id string) (*Group, error) { return nil, nil }
func (m *MockOrgContextStore) GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error) { return nil, nil }
func (m *MockOrgContextStore) UpdateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockOrgContextStore) ListGroups(ctx context.Context, orgID string) ([]*Group, error) { return nil, nil }
func (m *MockOrgContextStore) ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error) { return nil, nil }
func (m *MockOrgContextStore) DeleteGroup(ctx context.Context, id string) error { return nil }
func (m *MockOrgContextStore) GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) { return nil, nil }
func (m *MockOrgContextStore) CreateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockOrgContextStore) GetContract(ctx context.Context, id string) (*Contract, error) { return nil, nil }
func (m *MockOrgContextStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) { return nil, nil }
func (m *MockOrgContextStore) GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error) { return nil, nil }
func (m *MockOrgContextStore) GetContractByAddressGlobal(ctx context.Context, address string) (*Contract, error) { return nil, nil }
func (m *MockOrgContextStore) UpdateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockOrgContextStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) { return nil, nil }
func (m *MockOrgContextStore) ListContractsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Contract, int, error) { return nil, 0, nil }
func (m *MockOrgContextStore) DeleteContract(ctx context.Context, id string) error { return nil }
func (m *MockOrgContextStore) GetContractDeployerByAddress(ctx context.Context, address string) (*string, error) { return nil, nil }
func (m *MockOrgContextStore) CreateContractGrant(ctx context.Context, grant *ContractGrant) error { return nil }
func (m *MockOrgContextStore) GetContractGrant(ctx context.Context, id string) (*ContractGrant, error) { return nil, nil }
func (m *MockOrgContextStore) UpdateContractGrant(ctx context.Context, grant *ContractGrant) error { return nil }
func (m *MockOrgContextStore) ListContractGrants(ctx context.Context, contractID string) ([]*ContractGrant, error) { return nil, nil }
func (m *MockOrgContextStore) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error) { return nil, nil }
func (m *MockOrgContextStore) ListContractGrantsBatch(ctx context.Context, groupIDs []string) (map[string][]*ContractGrant, error) { return make(map[string][]*ContractGrant), nil }
func (m *MockOrgContextStore) DeleteContractGrant(ctx context.Context, id string) error { return nil }
func (m *MockOrgContextStore) GetContractGrantSummary(ctx context.Context, orgID string) (map[string]*ContractGrantSummary, error) { return nil, nil }
func (m *MockOrgContextStore) CreateUser(ctx context.Context, user *User) error { return nil }
func (m *MockOrgContextStore) GetUser(ctx context.Context, id string) (*User, error) { return nil, nil }
func (m *MockOrgContextStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) { return nil, nil }
func (m *MockOrgContextStore) UpdateUser(ctx context.Context, user *User) error { return nil }
func (m *MockOrgContextStore) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) { return nil, nil }
func (m *MockOrgContextStore) ListUsersPaginated(ctx context.Context, limit, offset int) ([]*User, int, error) { return nil, 0, nil }
func (m *MockOrgContextStore) DeleteUser(ctx context.Context, id string) error { return nil }
func (m *MockOrgContextStore) CreateMembership(ctx context.Context, m2 *UserMembership) error { return nil }
func (m *MockOrgContextStore) GetMembership(ctx context.Context, id string) (*UserMembership, error) { return nil, nil }
func (m *MockOrgContextStore) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error) { return nil, nil }
func (m *MockOrgContextStore) ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error) { return nil, nil }
func (m *MockOrgContextStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) { return nil, nil }
func (m *MockOrgContextStore) ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error) { return nil, nil }
func (m *MockOrgContextStore) DeleteMembership(ctx context.Context, id string) error { return nil }
func (m *MockOrgContextStore) DeleteExpiredMemberships(ctx context.Context) (int64, error) { return 0, nil }
func (m *MockOrgContextStore) CreateGroupAccess(ctx context.Context, access *GroupAccess) error { return nil }
func (m *MockOrgContextStore) GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error) { return nil, nil }
func (m *MockOrgContextStore) GetGroupAccessBatch(ctx context.Context, groupIDs []string) (map[string]*GroupAccess, error) { return make(map[string]*GroupAccess), nil }
func (m *MockOrgContextStore) UpdateGroupAccess(ctx context.Context, access *GroupAccess) error { return nil }
func (m *MockOrgContextStore) DeleteGroupAccess(ctx context.Context, groupID string) error { return nil }
func (m *MockOrgContextStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) { return nil, nil }
func (m *MockOrgContextStore) CreatePreregisteredAddress(ctx context.Context, addr *PreregisteredAddress) error { return nil }
func (m *MockOrgContextStore) GetPreregisteredAddress(ctx context.Context, id string) (*PreregisteredAddress, error) { return nil, nil }
func (m *MockOrgContextStore) PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error { return nil }
func (m *MockOrgContextStore) DeletePreregisteredAddressByAddress(ctx context.Context, address string) error { return nil }
func (m *MockOrgContextStore) ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Group, int, error) { return nil, 0, nil }
func (m *MockOrgContextStore) ListGroupsWithAccessPaginated(ctx context.Context, orgID string, limit, offset int) ([]*GroupWithAccess, int, error) { return nil, 0, nil }
func (m *MockOrgContextStore) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*ContractGrant, error) { return nil, nil }
func (m *MockOrgContextStore) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*ContractGrant, error) { return nil, nil }
func (m *MockOrgContextStore) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error) { return nil, nil }
func (m *MockOrgContextStore) UpdateMembership(ctx context.Context, membership *UserMembership) error { return nil }
func (m *MockOrgContextStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error { return nil }
func (m *MockOrgContextStore) InvalidateCacheForUser(ctx context.Context, userID string) error { return nil }
func (m *MockOrgContextStore) InvalidateCacheForOrg(ctx context.Context, orgID string) error { return nil }
func (m *MockOrgContextStore) InvalidateCacheForGroup(ctx context.Context, groupID string) error { return nil }
func (m *MockOrgContextStore) CleanupExpiredCache(ctx context.Context) (int64, error) { return 0, nil }
func (m *MockOrgContextStore) CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error { return nil }
func (m *MockOrgContextStore) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error) { return nil, nil }
func (m *MockOrgContextStore) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error) { return nil, nil }
func (m *MockOrgContextStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) { return false, nil }
func (m *MockOrgContextStore) MarkAddressUsed(ctx context.Context, address string) error { return nil }
func (m *MockOrgContextStore) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) { return nil, nil }
func (m *MockOrgContextStore) SystemLinkEthAddress(_ context.Context, _, _ string) error { return nil }
func (m *MockOrgContextStore) GetOrgIDsForEthAddress(ctx context.Context, address string) ([]string, error) {
	return nil, nil
}
func (m *MockOrgContextStore) GrantContractToDeployerGroup(ctx context.Context, orgID, contractID, deployerUserID string) error { return nil }

// Shared infrastructure stubs
func (m *MockOrgContextStore) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) { return false, nil }
func (m *MockOrgContextStore) CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error { return nil }
func (m *MockOrgContextStore) ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error) { return nil, nil }
func (m *MockOrgContextStore) DeleteSharedInfrastructure(ctx context.Context, address string) error { return nil }

func TestNewOrgContext(t *testing.T) {
	ctx := context.Background()

	t.Run("creates context for contract in user's org", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, err := NewOrgContext(ctx, store, user, "0xContract1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if orgCtx.OrgID() != "org-a" {
			t.Errorf("expected org-a, got %s", orgCtx.OrgID())
		}
		if !orgCtx.UserBelongsToOrg() {
			t.Error("expected user to belong to org")
		}
	})

	t.Run("error for contract in different org", func(t *testing.T) {
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-b", // Different org!
			},
		}
		user := &User{ID: "user-1"}

		_, err := NewOrgContext(ctx, store, user, "0xContract1")
		if err == nil {
			t.Fatal("expected error for cross-org access")
		}
		if !strings.Contains(err.Error(), ErrContractAccessDenied) {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("creates context for public contract", func(t *testing.T) {
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			contractOwners: map[string]string{}, // Contract not owned by any org
		}
		user := &User{ID: "user-1"}

		orgCtx, err := NewOrgContext(ctx, store, user, "0xPublicContract")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !orgCtx.IsPublicContext() {
			t.Error("expected public context")
		}
	})

	t.Run("creates context with empty target address", func(t *testing.T) {
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, err := NewOrgContext(ctx, store, user, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !orgCtx.IsPublicContext() {
			t.Error("expected public context for empty target")
		}
	})

	t.Run("multi-org user can access contract from any org", func(t *testing.T) {
		orgB := &Organization{ID: "org-b", Slug: "org-b"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
				{Group: &Group{OrgID: "org-b"}},
			},
			organizations: map[string]*Organization{
				"org-b": orgB,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-b", // Owned by org-b
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, err := NewOrgContext(ctx, store, user, "0xContract1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if orgCtx.OrgID() != "org-b" {
			t.Errorf("expected org-b, got %s", orgCtx.OrgID())
		}
	})

	t.Run("error when memberships lookup fails", func(t *testing.T) {
		store := &MockOrgContextStore{
			membershipsErr: errors.New("db error"),
		}
		user := &User{ID: "user-1"}

		_, err := NewOrgContext(ctx, store, user, "0xContract1")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestNewOrgContextForOrg(t *testing.T) {
	ctx := context.Background()

	t.Run("creates context for explicit org user belongs to", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, err := NewOrgContextForOrg(ctx, store, user, "org-a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if orgCtx.OrgID() != "org-a" {
			t.Errorf("expected org-a, got %s", orgCtx.OrgID())
		}
	})

	t.Run("error for org user is not member of", func(t *testing.T) {
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
		}
		user := &User{ID: "user-1"}

		_, err := NewOrgContextForOrg(ctx, store, user, "org-b")
		if err == nil {
			t.Fatal("expected error for non-member access")
		}
		if !strings.Contains(err.Error(),"not a member") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestOrgContext_CheckAddressInScope(t *testing.T) {
	ctx := context.Background()

	t.Run("allows address in same org", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				"0xcontract2": "org-a",
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckAddressInScope(ctx, "0xContract2")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("allows address in user's other org", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
				{Group: &Group{OrgID: "org-b"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				"0xcontract2": "org-b", // Different org but user is member
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckAddressInScope(ctx, "0xContract2")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("denies address in different org", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				"0xcontract2": "org-c", // User not member of org-c
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckAddressInScope(ctx, "0xContract2")
		if err == nil {
			t.Fatal("expected error for cross-org address")
		}
		if !strings.Contains(err.Error(), ErrContractAccessDenied) {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("denies unregistered non-precompile address (private by default)", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				// 0xPublic not in map = unregistered
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckAddressInScope(ctx, "0xPublic")
		if err == nil {
			t.Error("expected error for unregistered address (private by default)")
		}
	})

	t.Run("allows precompile address", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		// ecrecover precompile (0x01)
		err := orgCtx.CheckAddressInScope(ctx, "0x0000000000000000000000000000000000000001")
		if err != nil {
			t.Errorf("unexpected error for precompile address: %v", err)
		}
	})
}

func TestOrgContext_CheckMultiAddressesInScope(t *testing.T) {
	ctx := context.Background()

	t.Run("all registered addresses in scope succeeds", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				"0xcontract2": "org-a",
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckMultiAddressesInScope(ctx, []string{"0xContract1", "0xContract2"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("unregistered address in multi-check fails", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckMultiAddressesInScope(ctx, []string{"0xContract1", "0xPublic"})
		if err == nil {
			t.Error("expected error for unregistered address in multi-check (private by default)")
		}
	})

	t.Run("one cross-org address fails", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				"0xcrossorg":  "org-b", // User not in org-b
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckMultiAddressesInScope(ctx, []string{"0xContract1", "0xCrossOrg", "0xPublic"})
		if err == nil {
			t.Fatal("expected error for cross-org address")
		}
	})
}

func TestOrgContext_CheckDefaultClaimsAllowed(t *testing.T) {
	ctx := context.Background()

	t.Run("allows when user has explicit access", func(t *testing.T) {
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "")

		// hasExplicitAccess = true should skip all checks
		err := orgCtx.CheckDefaultClaimsAllowed(ctx, "0xAnyContract", true)
		if err != nil {
			t.Errorf("unexpected error with explicit access: %v", err)
		}
	})

	// RD-849: registered contracts always require an explicit grant, regardless
	// of the viewer's claims. admin/deploy claim no longer falls through to
	// "implicit access to all own-org contracts" — that contradicted the 3-tier
	// admin model (RD-817) and the explorer visibility layer.
	t.Run("denies registered own-org contract without explicit grant (RD-849)", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
			},
			addressOwnedByOrg: map[string]map[string]bool{
				"0xcontract1": {"org-a": true},
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		// No hasExplicitAccess — denied regardless of any claim the caller may hold.
		err := orgCtx.CheckDefaultClaimsAllowed(ctx, "0xContract1", false)
		if err == nil {
			t.Fatal("expected denial for own-org registered contract without explicit grant")
		}
		if !strings.Contains(err.Error(), ErrContractAccessDenied) {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("denies for contracts registered to other org", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
				"0xotherorgs": "org-b", // Owned by org-b
			},
			addressOwnedByOrg: map[string]map[string]bool{
				"0xcontract1": {"org-a": true},
				"0xotherorgs": {"org-b": true},
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckDefaultClaimsAllowed(ctx, "0xOtherOrgs", false)
		if err == nil {
			t.Fatal("expected error for cross-org contract")
		}
		if !strings.Contains(err.Error(), ErrContractAccessDenied) {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("denies unregistered non-precompile contracts (private by default)", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
			},
			addressOwnedByOrg: map[string]map[string]bool{
				"0xcontract1": {"org-a": true},
			},
			registeredToAnyOrg: map[string]bool{},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckDefaultClaimsAllowed(ctx, "0xPublic", false)
		if err == nil {
			t.Error("expected error for unregistered contract (private by default)")
		}
	})

	t.Run("allows precompile via CheckDefaultClaimsAllowed", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1": "org-a",
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		// ecrecover precompile (0x01)
		err := orgCtx.CheckDefaultClaimsAllowed(ctx, "0x0000000000000000000000000000000000000001", false)
		if err != nil {
			t.Errorf("unexpected error for precompile: %v", err)
		}
	})

	// RD-849: multi-org membership does not affect the rule. A registered
	// contract in ANY of the user's orgs still requires an explicit grant.
	t.Run("denies registered contract in user's other org without explicit grant", func(t *testing.T) {
		orgA := &Organization{ID: "org-a", Slug: "org-a"}
		store := &MockOrgContextStore{
			memberships: []*MembershipWithDetails{
				{Group: &Group{OrgID: "org-a"}},
				{Group: &Group{OrgID: "org-b"}},
			},
			organizations: map[string]*Organization{
				"org-a": orgA,
			},
			contractOwners: map[string]string{
				"0xcontract1":    "org-a",
				"0xorgbcontract": "org-b",
			},
			addressOwnedByOrg: map[string]map[string]bool{
				"0xcontract1":    {"org-a": true},
				"0xorgbcontract": {"org-b": true},
			},
		}
		user := &User{ID: "user-1"}

		orgCtx, _ := NewOrgContext(ctx, store, user, "0xContract1")

		err := orgCtx.CheckDefaultClaimsAllowed(ctx, "0xOrgBContract", false)
		if err == nil {
			t.Fatal("expected denial for registered contract in user's other org without explicit grant")
		}
	})
}

func TestOrgContext_Accessors(t *testing.T) {
	ctx := context.Background()

	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store := &MockOrgContextStore{
		memberships: []*MembershipWithDetails{
			{Group: &Group{OrgID: "org-a"}},
			{Group: &Group{OrgID: "org-b"}},
		},
		organizations: map[string]*Organization{
			"org-a": orgA,
		},
		contractOwners: map[string]string{
			"0xcontract1": "org-a",
		},
	}
	user := &User{ID: "user-1", ExternalID: "did:test:user1"}

	orgCtx, err := NewOrgContext(ctx, store, user, "0xContract1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("OrgID returns correct ID", func(t *testing.T) {
		if orgCtx.OrgID() != "org-a" {
			t.Errorf("expected org-a, got %s", orgCtx.OrgID())
		}
	})

	t.Run("Org returns organization", func(t *testing.T) {
		org := orgCtx.Org()
		if org == nil {
			t.Fatal("expected non-nil org")
		}
		if org.Name != "Org A" {
			t.Errorf("expected Org A, got %s", org.Name)
		}
	})

	t.Run("User returns user", func(t *testing.T) {
		u := orgCtx.User()
		if u.ExternalID != "did:test:user1" {
			t.Errorf("expected did:test:user1, got %s", u.ExternalID)
		}
	})

	t.Run("UserOrgIDs returns all orgs", func(t *testing.T) {
		orgs := orgCtx.UserOrgIDs()
		if len(orgs) != 2 {
			t.Errorf("expected 2 orgs, got %d", len(orgs))
		}
		if !orgs["org-a"] || !orgs["org-b"] {
			t.Error("expected org-a and org-b in user orgs")
		}
	})

	t.Run("IsPublicContext returns false when org set", func(t *testing.T) {
		if orgCtx.IsPublicContext() {
			t.Error("expected non-public context")
		}
	})

	t.Run("UserBelongsToOrg returns true", func(t *testing.T) {
		if !orgCtx.UserBelongsToOrg() {
			t.Error("expected user to belong to org")
		}
	})
}

func TestOrgContext_PublicContext(t *testing.T) {
	ctx := context.Background()

	store := &MockOrgContextStore{
		memberships: []*MembershipWithDetails{
			{Group: &Group{OrgID: "org-a"}},
		},
		contractOwners: map[string]string{
			// No contracts = public
		},
	}
	user := &User{ID: "user-1"}

	orgCtx, err := NewOrgContext(ctx, store, user, "0xPublicContract")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("OrgID returns empty for public", func(t *testing.T) {
		if orgCtx.OrgID() != "" {
			t.Errorf("expected empty OrgID, got %s", orgCtx.OrgID())
		}
	})

	t.Run("Org returns nil for public", func(t *testing.T) {
		if orgCtx.Org() != nil {
			t.Error("expected nil Org")
		}
	})

	t.Run("IsPublicContext returns true", func(t *testing.T) {
		if !orgCtx.IsPublicContext() {
			t.Error("expected public context")
		}
	})

	t.Run("UserBelongsToOrg returns true for public", func(t *testing.T) {
		// No org = no restriction
		if !orgCtx.UserBelongsToOrg() {
			t.Error("expected true for public context")
		}
	})
}

