package rbac

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// MockCrossOrgStore is a comprehensive mock store for testing cross-org isolation.
// It implements the full Store interface with configurable behaviors.
type MockCrossOrgStore struct {
	users              map[string]*User                    // externalID -> User
	organizations      map[string]*Organization            // orgID -> Organization
	memberships        map[string][]*MembershipWithDetails // userID -> memberships
	contractOwners     map[string]string                   // lowercase address -> orgID
	registeredToAnyOrg map[string]bool                     // lowercase address -> bool
	addressOwnedByOrg  map[string]map[string]bool          // address -> orgID -> bool
	groupAccess        map[string]*GroupAccess             // groupID -> GroupAccess
	cachedPermissions  map[string]*EffectivePermissions    // userID:orgID -> perms
	contractGrants     map[string][]*ContractGrant         // groupID -> grants
	contractDeployers  map[string]*string                  // lowercase address -> userID (deployer)
	preregisteredAddrs map[string]map[string]bool          // orgID -> address -> bool
}

func NewMockCrossOrgStore() *MockCrossOrgStore {
	m := &MockCrossOrgStore{
		users:              make(map[string]*User),
		organizations:      make(map[string]*Organization),
		memberships:        make(map[string][]*MembershipWithDetails),
		contractOwners:     make(map[string]string),
		registeredToAnyOrg: make(map[string]bool),
		addressOwnedByOrg:  make(map[string]map[string]bool),
		groupAccess:        make(map[string]*GroupAccess),
		cachedPermissions:  make(map[string]*EffectivePermissions),
		contractGrants:     make(map[string][]*ContractGrant),
		contractDeployers:  make(map[string]*string),
		preregisteredAddrs: make(map[string]map[string]bool),
	}
	// Seed the anonymous group's access (RD-870) — mirrors migration 044's
	// seeded row so the access controller can resolve no-JWT requests in
	// unit tests without standing up a real DB.
	m.groupAccess[AnonymousGroupID] = &GroupAccess{
		ID:      AnonymousGroupID,
		GroupID: AnonymousGroupID,
		AllowedMethods: []string{
			"eth_blockNumber",
			"eth_chainId",
			"eth_gasPrice",
			"net_version",
			"net_listening",
			"web3_clientVersion",
		},
		Claims: []Claim{},
	}
	return m
}

// User operations
func (m *MockCrossOrgStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	return m.users[externalID], nil
}

func (m *MockCrossOrgStore) CreateUser(ctx context.Context, user *User) error {
	m.users[user.ExternalID] = user
	return nil
}

func (m *MockCrossOrgStore) GetUser(ctx context.Context, id string) (*User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (m *MockCrossOrgStore) UpdateUser(ctx context.Context, user *User) error { return nil }
func (m *MockCrossOrgStore) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListUsersPaginated(ctx context.Context, limit, offset int) ([]*User, int, error) {
	return nil, 0, nil
}
func (m *MockCrossOrgStore) DeleteUser(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) SystemLinkEthAddress(_ context.Context, _, _ string) error { return nil }

// Organization operations
func (m *MockCrossOrgStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return m.organizations[id], nil
}

func (m *MockCrossOrgStore) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	for _, org := range m.organizations {
		if org.Slug == slug {
			return org, nil
		}
	}
	return nil, nil
}

func (m *MockCrossOrgStore) CreateOrganization(ctx context.Context, org *Organization) error {
	return nil
}
func (m *MockCrossOrgStore) UpdateOrganization(ctx context.Context, org *Organization) error {
	return nil
}
func (m *MockCrossOrgStore) ListOrganizations(ctx context.Context) ([]*Organization, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListOrganizationsPaginated(ctx context.Context, limit, offset int) ([]*Organization, int, error) {
	return nil, 0, nil
}
func (m *MockCrossOrgStore) DeleteOrganization(ctx context.Context, id string) error { return nil }

// Membership operations
func (m *MockCrossOrgStore) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	return m.memberships[userID], nil
}

func (m *MockCrossOrgStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	var result []*MembershipWithDetails
	for _, ms := range m.memberships[userID] {
		if ms.Group != nil && ms.Group.OrgID == orgID {
			result = append(result, ms)
		}
	}
	return result, nil
}

func (m *MockCrossOrgStore) CreateMembership(ctx context.Context, membership *UserMembership) error {
	return nil
}
func (m *MockCrossOrgStore) GetMembership(ctx context.Context, id string) (*UserMembership, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) UpdateMembership(ctx context.Context, membership *UserMembership) error {
	return nil
}
func (m *MockCrossOrgStore) ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) DeleteMembership(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) DeleteExpiredMemberships(ctx context.Context) (int64, error) {
	return 0, nil
}

// Contract ownership operations - CRITICAL for cross-org isolation
func (m *MockCrossOrgStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	return m.contractOwners[normalizeAddress(address)], nil
}

func (m *MockCrossOrgStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	return m.registeredToAnyOrg[normalizeAddress(address)], nil
}

func (m *MockCrossOrgStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	if orgMap, ok := m.addressOwnedByOrg[normalizeAddress(address)]; ok {
		return orgMap[orgID], nil
	}
	return false, nil
}

// Contract operations
func (m *MockCrossOrgStore) CreateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockCrossOrgStore) GetContract(ctx context.Context, id string) (*Contract, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) GetContractByAddressGlobal(ctx context.Context, address string) (*Contract, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) UpdateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockCrossOrgStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListContractsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Contract, int, error) {
	return nil, 0, nil
}
func (m *MockCrossOrgStore) DeleteContract(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) GetContractDeployerByAddress(ctx context.Context, address string) (*string, error) {
	return m.contractDeployers[normalizeAddress(address)], nil
}

// Group operations
func (m *MockCrossOrgStore) CreateGroup(ctx context.Context, group *Group) error     { return nil }
func (m *MockCrossOrgStore) GetGroup(ctx context.Context, id string) (*Group, error) { return nil, nil }
func (m *MockCrossOrgStore) GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) UpdateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockCrossOrgStore) ListGroups(ctx context.Context, orgID string) ([]*Group, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Group, int, error) {
	return nil, 0, nil
}
func (m *MockCrossOrgStore) ListGroupsWithAccessPaginated(ctx context.Context, orgID string, limit, offset int) ([]*GroupWithAccess, int, error) {
	return nil, 0, nil
}
func (m *MockCrossOrgStore) ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) DeleteGroup(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) {
	return []*Group{}, nil
}

// GroupAccess operations
func (m *MockCrossOrgStore) GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error) {
	return m.groupAccess[groupID], nil
}
func (m *MockCrossOrgStore) GetGroupAccessBatch(ctx context.Context, groupIDs []string) (map[string]*GroupAccess, error) {
	result := make(map[string]*GroupAccess)
	for _, id := range groupIDs {
		if a, ok := m.groupAccess[id]; ok {
			result[id] = a
		}
	}
	return result, nil
}
func (m *MockCrossOrgStore) CreateGroupAccess(ctx context.Context, access *GroupAccess) error {
	return nil
}
func (m *MockCrossOrgStore) UpdateGroupAccess(ctx context.Context, access *GroupAccess) error {
	return nil
}
func (m *MockCrossOrgStore) DeleteGroupAccess(ctx context.Context, groupID string) error { return nil }

// Contract grant operations
func (m *MockCrossOrgStore) CreateContractGrant(ctx context.Context, grant *ContractGrant) error {
	return nil
}
func (m *MockCrossOrgStore) GetContractGrant(ctx context.Context, id string) (*ContractGrant, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*ContractGrant, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) UpdateContractGrant(ctx context.Context, grant *ContractGrant) error {
	return nil
}
func (m *MockCrossOrgStore) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*ContractGrant, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error) {
	return m.contractGrants[groupID], nil
}
func (m *MockCrossOrgStore) ListContractGrantsBatch(ctx context.Context, groupIDs []string) (map[string][]*ContractGrant, error) {
	result := make(map[string][]*ContractGrant)
	for _, id := range groupIDs {
		if grants, ok := m.contractGrants[id]; ok {
			result[id] = grants
		}
	}
	return result, nil
}
func (m *MockCrossOrgStore) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) DeleteContractGrant(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) GetContractGrantSummary(ctx context.Context, orgID string) (map[string]*ContractGrantSummary, error) { return nil, nil }

// Cache operations
func (m *MockCrossOrgStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	return m.cachedPermissions[userID+":"+orgID], nil
}
func (m *MockCrossOrgStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	m.cachedPermissions[perms.UserID+":"+perms.OrgID] = perms
	return nil
}
func (m *MockCrossOrgStore) InvalidateCacheForUser(ctx context.Context, userID string) error {
	return nil
}
func (m *MockCrossOrgStore) InvalidateCacheForOrg(ctx context.Context, orgID string) error {
	return nil
}
func (m *MockCrossOrgStore) InvalidateCacheForGroup(ctx context.Context, groupID string) error {
	return nil
}
func (m *MockCrossOrgStore) CleanupExpiredCache(ctx context.Context) (int64, error) { return 0, nil }

// Audit log operations
func (m *MockCrossOrgStore) CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error {
	return nil
}
func (m *MockCrossOrgStore) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error) {
	return nil, nil
}

// Preregistered address operations
func (m *MockCrossOrgStore) PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error {
	return nil
}
func (m *MockCrossOrgStore) DeletePreregisteredAddressByAddress(ctx context.Context, address string) error {
	return nil
}
func (m *MockCrossOrgStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	if addrs, ok := m.preregisteredAddrs[orgID]; ok {
		return addrs[strings.ToLower(address)], nil
	}
	return false, nil
}
func (m *MockCrossOrgStore) MarkAddressUsed(ctx context.Context, address string) error { return nil }

// Shared infrastructure stubs
func (m *MockCrossOrgStore) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) {
	return false, nil
}
func (m *MockCrossOrgStore) CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error {
	return nil
}
func (m *MockCrossOrgStore) ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error) {
	return nil, nil
}
func (m *MockCrossOrgStore) DeleteSharedInfrastructure(ctx context.Context, address string) error {
	return nil
}

func (m *MockCrossOrgStore) GrantContractToDeployerGroup(ctx context.Context, orgID, contractID, deployerUserID string) error {
	return nil
}

func (m *MockCrossOrgStore) GetOrgIDsForEthAddress(ctx context.Context, address string) ([]string, error) {
	return nil, nil
}

// Helper to normalize address
func normalizeAddress(addr string) string {
	if len(addr) >= 2 && addr[:2] == "0x" {
		return "0x" + addr[2:]
	}
	return addr
}

// setupCrossOrgTestScenario creates a test scenario with two orgs and their contracts.
// OrgA has ContractA, OrgB has ContractB.
// UserA is member of OrgA only, UserB is member of OrgB only.
func setupCrossOrgTestScenario(store *MockCrossOrgStore) {
	// Create organizations
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	orgB := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
	store.organizations["org-a"] = orgA
	store.organizations["org-b"] = orgB

	// Create users
	userA := &User{ID: "user-a", ExternalID: "did:test:user-a", KYC: true, Banned: false}
	userB := &User{ID: "user-b", ExternalID: "did:test:user-b", KYC: true, Banned: false}
	store.users["did:test:user-a"] = userA
	store.users["did:test:user-b"] = userB

	// Create groups
	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	groupB := &Group{ID: "group-b", OrgID: "org-b", Slug: "group-b", Name: "Group B"}

	// Create memberships - UserA only in OrgA, UserB only in OrgB
	store.memberships["user-a"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-a", UserID: "user-a", GroupID: "group-a"}, Group: groupA},
	}
	store.memberships["user-b"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-b", UserID: "user-b", GroupID: "group-b"}, Group: groupB},
	}

	// Set up group access - both have default read claims
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		Claims:         []Claim{},
	}
	store.groupAccess["group-b"] = &GroupAccess{
		ID:             "access-b",
		GroupID:        "group-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		Claims:         []Claim{},
	}

	// Define contract addresses
	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"

	// Set up contract ownership - CRITICAL for cross-org isolation
	store.contractOwners[contractA] = "org-a"
	store.contractOwners[contractB] = "org-b"

	// Mark contracts as registered to orgs
	store.registeredToAnyOrg[contractA] = true
	store.registeredToAnyOrg[contractB] = true

	// Set up address ownership maps
	store.addressOwnedByOrg[contractA] = map[string]bool{"org-a": true}
	store.addressOwnedByOrg[contractB] = map[string]bool{"org-b": true}

	// Pre-cache permissions (optional, for faster tests)
	// These represent the computed permissions for users in their respective orgs
	// NOTE: Registered contracts require EXPLICIT grants (not just default_claims)
	// So we add explicit ContractAccess for contracts in the user's own org
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{
			contractA: {Claims: []Claim{}}, // Explicit grant for user's own org contract
		},
		Claims:     []Claim{},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	store.cachedPermissions["user-b:org-b"] = &EffectivePermissions{
		ID:             "perms-b",
		UserID:         "user-b",
		OrgID:          "org-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{
			contractB: {Claims: []Claim{}}, // Explicit grant for user's own org contract
		},
		Claims:     []Claim{},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
}

// TestCheckAccessCrossOrgIsolation tests the full CheckAccess flow for cross-org isolation.
// This is the critical test that validates the security fix.
func TestCheckAccessCrossOrgIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	// Create the access controller with a short cache TTL
	controller := NewAccessController(store, 5*time.Minute)

	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"
	publicContract := "0xcccc000000000000000000000000000000000003"

	t.Run("SECURITY-001: User A cannot access Contract B via eth_call", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID:   "did:test:user-a",
			Method:           "eth_call",
			Params:           []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:    contractB,
			FunctionSelector: "",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for cross-org contract")
		}
		if result.Reason == "" {
			t.Error("expected a reason for denial")
		}
		if !containsString(result.Reason, ErrContractAccessDenied) {
			t.Errorf("expected cross-org denial message, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-002: User B cannot access Contract A via eth_call", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID:   "did:test:user-b",
			Method:           "eth_call",
			Params:           []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:    contractA,
			FunctionSelector: "",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for cross-org contract")
		}
		if !containsString(result.Reason, ErrContractAccessDenied) {
			t.Errorf("expected cross-org denial message, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-003: User A CAN access their own Contract A", func(t *testing.T) {
		// contractA is registered to org-a. user-a has an explicit grant on it
		// via the setup fixture — registered contracts require explicit grants
		// regardless of org membership (RD-849).

		// Mark contractA as owned by org-a in addressOwnedByOrg (already done in setup)

		req := &AccessCheckRequest{
			UserExternalID:   "did:test:user-a",
			Method:           "eth_call",
			Params:           []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:    contractA,
			FunctionSelector: "",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// This should be allowed because user is in the org that owns the contract
		if !result.Allowed {
			t.Errorf("expected access to be allowed for user's own org contract, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-004: eth_getLogs on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": contractB, "fromBlock": "0x0", "toBlock": "latest"}},
			TargetAddress:  contractB, // Target address for single-contract getLogs
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getLogs on cross-org contract")
		}
	})

	t.Run("SECURITY-005: eth_getLogs with mixed-org addresses is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": []any{contractA, contractB}, "fromBlock": "0x0", "toBlock": "latest"}},
			TargetAddress:  "", // Multiple addresses, no single target
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getLogs with mixed-org addresses")
		}
	})

	t.Run("SECURITY-006: eth_getBalance on cross-org address is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getBalance",
			Params:         []any{contractB, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getBalance on cross-org address")
		}
	})

	t.Run("SECURITY-007: Unregistered contract denied (private by default)", func(t *testing.T) {
		// publicContract is NOT registered to any org — all contracts are private by default.
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": publicContract, "data": "0x"}, "latest"},
			TargetAddress:  publicContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be DENIED - unregistered contracts are private by default
		if result.Allowed {
			t.Errorf("expected unregistered contract to be denied (private by default)")
		}
	})

	t.Run("SECURITY-008: eth_getCode on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getCode",
			Params:         []any{contractB, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getCode on cross-org contract")
		}
	})

	t.Run("SECURITY-009: eth_getStorageAt on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getStorageAt",
			Params:         []any{contractB, "0x0", "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getStorageAt on cross-org contract")
		}
	})

	t.Run("SECURITY-010: eth_sendTransaction to cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractB, "from": "0x9999999999999999999999999999999999999999", "data": "0x"}},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_sendTransaction to cross-org contract")
		}
	})

	t.Run("SECURITY-011: eth_getTransactionCount on cross-org address is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getTransactionCount",
			Params:         []any{contractB, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getTransactionCount on cross-org address")
		}
	})

	t.Run("SECURITY-012: eth_getProof on cross-org address is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getProof",
			Params:         []any{contractB, []any{"0x0"}, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getProof on cross-org address")
		}
	})

	t.Run("SECURITY-013: eth_createAccessList on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_createAccessList",
			Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_createAccessList on cross-org contract")
		}
	})
}

// TestCheckAccessCrossOrgWithClaims tests that default_claims cannot be used
// to bypass cross-org isolation for registered contracts.
func TestCheckAccessCrossOrgWithClaims(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	// Give user-a very permissive default_claims (all claims)
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{},
		Claims:         []Claim{ClaimAdmin}, // Very permissive
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)
	contractB := "0xbbbb000000000000000000000000000000000002"

	t.Run("permissive default_claims cannot access cross-org contract", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied despite permissive default_claims")
		}
		if !containsString(result.Reason, ErrContractAccessDenied) {
			t.Errorf("expected cross-org denial message, got: %s", result.Reason)
		}
	})
}

// TestCheckAccessExplicitGrantRequirement tests that registered contracts (even in user's own org)
// require explicit grants and cannot be accessed via default_claims alone.
// This is a security feature: registering a contract means you want explicit access control.
func TestCheckAccessExplicitGrantRequirement(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	contractA := "0xaaaa000000000000000000000000000000000001"

	t.Run("SECURITY-011: Registered contract in own org WITHOUT explicit grant is denied (read-only)", func(t *testing.T) {
		// Set up user-a with read claim but NO explicit access to contractA.
		// Read-only users can't access unregistered contracts, so they also can't
		// reach the "requires explicit grant" check — they're denied earlier.
		store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
			ID:             "perms-a",
			UserID:         "user-a",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs"},
			ContractAccess: map[string]ContractAccess{}, // NO explicit grant for contractA
			Claims:         []Claim{},          // Has read claim only — no deploy/admin
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be DENIED - registered contracts require explicit grants
		if result.Allowed {
			t.Error("expected access to be denied for read-only user without explicit grant")
		}
		if !containsString(result.Reason, ErrContractAccessDenied) {
			t.Errorf("expected '%s' message, got: %s", ErrContractAccessDenied, result.Reason)
		}
	})

	t.Run("SECURITY-011b: Deploy/admin claim DENIED for registered contract in own org without explicit grant (RD-849)", func(t *testing.T) {
		// Per the 3-tier admin model (RD-817), tier 3 admin/deploy claim holders
		// do NOT automatically gain access to every contract in their org — they
		// must have an explicit contract_grant. Tier 2 org admins (is_org_admin)
		// keep org-wide access via materialized grants in computeOrgAdminPermissions.
		store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
			ID:             "perms-a",
			UserID:         "user-a",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs"},
			ContractAccess: map[string]ContractAccess{},       // NO explicit grant for contractA
			Claims:         []Claim{ClaimDeploy, ClaimAdmin},  // tier 3 admin/deploy claims
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected denial: tier 3 admin/deploy claim must not grant access without explicit contract_grant")
		}
		if !containsString(result.Reason, ErrContractAccessDenied) {
			t.Errorf("expected access-denied reason, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-012: Registered contract in own org WITH explicit grant is allowed", func(t *testing.T) {
		// Set up user-a WITH explicit grant for contractA
		store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
			ID:             "perms-a",
			UserID:         "user-a",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs"},
			ContractAccess: map[string]ContractAccess{
				contractA: {Claims: []Claim{}}, // Explicit grant for contractA
			},
			Claims:     []Claim{},
			ComputedAt: time.Now(),
			ExpiresAt:  time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be ALLOWED - has explicit grant
		if !result.Allowed {
			t.Errorf("expected access to be allowed for registered contract with explicit grant, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-013: Unregistered contract denied for read-only user (private by default)", func(t *testing.T) {
		publicContract := "0x1111111111111111111111111111111111111111"

		store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
			ID:             "perms-a",
			UserID:         "user-a",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs"},
			ContractAccess: map[string]ContractAccess{}, // No explicit grants
			Claims:         []Claim{},          // Read only
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": publicContract, "data": "0x"}, "latest"},
			TargetAddress:  publicContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be DENIED — all contracts are private by default
		if result.Allowed {
			t.Errorf("expected unregistered contract to be denied (private by default)")
		}
	})

	t.Run("SECURITY-013b: Unregistered contract denied for deploy user (private by default)", func(t *testing.T) {
		publicContract := "0x1111111111111111111111111111111111111111"

		store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
			ID:             "perms-a",
			UserID:         "user-a",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs"},
			ContractAccess: map[string]ContractAccess{}, // No explicit grants
			Claims:         []Claim{ClaimDeploy},
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": publicContract, "data": "0x"}, "latest"},
			TargetAddress:  publicContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be DENIED — all contracts are private by default
		if result.Allowed {
			t.Errorf("expected unregistered contract to be denied (private by default)")
		}
	})
}

// TestContractExistenceOracle verifies that both cross-org contracts and unregistered
// addresses are denied. With all-contracts-private-by-default, both cross-org and
// unregistered addresses return the same generic denial, preventing existence oracle attacks.
// Exception: basic address queries (eth_getCode, eth_getBalance) are allowed for unregistered
// addresses (wallet functionality preserved).
func TestContractExistenceOracle(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	controller := NewAccessController(store, 5*time.Minute)

	contractA := "0xaaaa000000000000000000000000000000000001" // registered to org-a
	nonExistentAddr := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// User B queries a registered cross-org contract (exists, but no access)
	resultExisting, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "did:test:user-b",
		Method:         "eth_getCode",
		Params:         []any{contractA, "latest"},
		TargetAddress:  contractA,
	})
	if err != nil {
		t.Fatalf("unexpected error for existing contract: %v", err)
	}
	if resultExisting.Allowed {
		t.Fatal("expected denial for cross-org contract")
	}

	// User B queries a completely non-existent (unregistered) address.
	// All unregistered addresses are now private by default — denied.
	resultNonExistent, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "did:test:user-b",
		Method:         "eth_getCode",
		Params:         []any{nonExistentAddr, "latest"},
		TargetAddress:  nonExistentAddr,
	})
	if err != nil {
		t.Fatalf("unexpected error for non-existent contract: %v", err)
	}
	// eth_getCode on unregistered is denied (all contracts private by default)
	if resultNonExistent.Allowed {
		t.Fatalf("expected eth_getCode on unregistered address to be denied, got allowed")
	}

	// eth_call on unregistered is also denied (private by default)
	resultCall, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "did:test:user-b",
		Method:         "eth_call",
		Params:         []any{map[string]any{"to": nonExistentAddr, "data": "0x"}, "latest"},
		TargetAddress:  nonExistentAddr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resultCall.Allowed {
		t.Fatal("expected eth_call on unregistered address to be denied (private by default)")
	}

	// Cross-org denial should use the generic constant
	if resultExisting.Reason != ErrContractAccessDenied {
		t.Errorf("expected %q, got %q", ErrContractAccessDenied, resultExisting.Reason)
	}
}

// TestCheckAccessMultiOrgUser tests that a user who is member of multiple orgs
// can access contracts from any of their orgs.
func TestCheckAccessMultiOrgUser(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	// Create two organizations
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	orgB := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
	store.organizations["org-a"] = orgA
	store.organizations["org-b"] = orgB

	// Create a multi-org user who is member of BOTH orgs
	multiUser := &User{ID: "multi-user", ExternalID: "did:test:multi-user", KYC: true, Banned: false}
	store.users["did:test:multi-user"] = multiUser

	// Create groups
	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	groupB := &Group{ID: "group-b", OrgID: "org-b", Slug: "group-b", Name: "Group B"}

	// User is member of BOTH orgs
	store.memberships["multi-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-a", UserID: "multi-user", GroupID: "group-a"}, Group: groupA},
		{Membership: &UserMembership{ID: "mem-b", UserID: "multi-user", GroupID: "group-b"}, Group: groupB},
	}

	// Set up group access
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []Claim{},
	}
	store.groupAccess["group-b"] = &GroupAccess{
		ID:             "access-b",
		GroupID:        "group-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []Claim{},
	}

	// Define contracts
	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"

	// Set up ownership
	store.contractOwners[contractA] = "org-a"
	store.contractOwners[contractB] = "org-b"
	store.registeredToAnyOrg[contractA] = true
	store.registeredToAnyOrg[contractB] = true
	store.addressOwnedByOrg[contractA] = map[string]bool{"org-a": true}
	store.addressOwnedByOrg[contractB] = map[string]bool{"org-b": true}

	// Cache permissions for multi-user in both orgs
	// NOTE: Registered contracts require EXPLICIT grants (not just default_claims)
	store.cachedPermissions["multi-user:org-a"] = &EffectivePermissions{
		ID:             "perms-multi-a",
		UserID:         "multi-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{
			contractA: {Claims: []Claim{}}, // Explicit grant for org-a contract
		},
		Claims:     []Claim{},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	store.cachedPermissions["multi-user:org-b"] = &EffectivePermissions{
		ID:             "perms-multi-b",
		UserID:         "multi-user",
		OrgID:          "org-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{
			contractB: {Claims: []Claim{}}, // Explicit grant for org-b contract
		},
		Claims:     []Claim{},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)

	t.Run("multi-org user can access Contract A (from org-a)", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:multi-user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected multi-org user to access contract from org-a, got: %s", result.Reason)
		}
	})

	t.Run("multi-org user can access Contract B (from org-b)", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:multi-user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected multi-org user to access contract from org-b, got: %s", result.Reason)
		}
	})
}

func TestUnregisteredAddressesDenied(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	publicContract := "0x1111111111111111111111111111111111111111"

	// User has deploy/read/write default claims but no explicit contract grant.
	// Unregistered contracts are now private by default — access should be denied.
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getLogs"},
		ContractAccess: map[string]ContractAccess{},
		Claims:         []Claim{ClaimDeploy},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	t.Run("denies unregistered contract access via eth_call (private by default)", func(t *testing.T) {
		controller := NewAccessController(store, 5*time.Minute)

		callReq := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": publicContract, "data": "0x"}, "latest"},
			TargetAddress:  publicContract,
		}
		callResult, err := controller.CheckAccess(ctx, callReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if callResult.Allowed {
			t.Fatal("expected eth_call on unregistered contract to be denied (private by default)")
		}
	})

	t.Run("denies unregistered contract access via eth_getLogs (private by default)", func(t *testing.T) {
		controller := NewAccessController(store, 5*time.Minute)

		logReq := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": publicContract}},
		}
		logResult, err := controller.CheckAccess(ctx, logReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if logResult.Allowed {
			t.Fatal("expected eth_getLogs on unregistered contract to be denied (private by default)")
		}
	})
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestCheckAccessDeployerAutoGrant tests that the deployer of a contract automatically
// gets read+write access to their deployed contract, even without explicit grants.
func TestCheckAccessDeployerAutoGrant(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	// Create organization
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store.organizations["org-a"] = orgA

	// Create deployer user and non-deployer user
	deployerUser := &User{ID: "deployer-user", ExternalID: "did:test:deployer", KYC: true, Banned: false}
	otherUser := &User{ID: "other-user", ExternalID: "did:test:other", KYC: true, Banned: false}
	store.users["did:test:deployer"] = deployerUser
	store.users["did:test:other"] = otherUser

	// Create group
	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}

	// Both users are members of org-a
	store.memberships["deployer-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-deployer", UserID: "deployer-user", GroupID: "group-a"}, Group: groupA},
	}
	store.memberships["other-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-other", UserID: "other-user", GroupID: "group-a"}, Group: groupA},
	}

	// Set up group access - NO default claims (users need explicit grants)
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getBalance", "eth_estimateGas"},
		Claims:         []Claim{}, // No default claims
	}

	// Define deployed contract - this is a PUBLIC contract (not registered to any org)
	// This tests that deployer auto-grant works even for public contracts.
	deployedContract := "0xdddd000000000000000000000000000000000001"

	// Contract is NOT owned by any org (public contract)
	// store.contractOwners[deployedContract] = "" is the default (empty)
	store.registeredToAnyOrg[deployedContract] = false
	// store.addressOwnedByOrg[deployedContract] is empty

	// Set deployer - THIS IS THE KEY: deployer-user deployed this contract
	deployerID := "deployer-user"
	store.contractDeployers[deployedContract] = &deployerID

	// Cache permissions - NO explicit contract access for either user, NO default claims
	store.cachedPermissions["deployer-user:org-a"] = &EffectivePermissions{
		ID:             "perms-deployer",
		UserID:         "deployer-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getBalance", "eth_estimateGas"},
		ContractAccess: map[string]ContractAccess{}, // NO explicit grants
		Claims:         []Claim{},                   // NO default claims
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	store.cachedPermissions["other-user:org-a"] = &EffectivePermissions{
		ID:             "perms-other",
		UserID:         "other-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getBalance", "eth_estimateGas"},
		ContractAccess: map[string]ContractAccess{}, // NO explicit grants
		Claims:         []Claim{},                   // NO default claims
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)

	t.Run("DEPLOYER-001: Deployer can read their deployed contract", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:deployer",
			OrgID:          "org-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": deployedContract, "data": "0x"}, "latest"},
			TargetAddress:  deployedContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected deployer to have read access to their deployed contract, got: %s", result.Reason)
		}
	})

	t.Run("DEPLOYER-002: Deployer can write to their deployed contract", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:deployer",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": deployedContract, "from": "0x9999999999999999999999999999999999999999", "data": "0xa9059cbb"}},
			TargetAddress:  deployedContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected deployer to have write access to their deployed contract, got: %s", result.Reason)
		}
	})

	t.Run("DEPLOYER-003: Non-deployer cannot access deployed contract without grant", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:other",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": deployedContract, "data": "0x"}, "latest"},
			TargetAddress:  deployedContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected non-deployer to be denied access without explicit grant")
		}
	})

	t.Run("DEPLOYER-004: Deployer does NOT get admin claim automatically", func(t *testing.T) {
		// Even though deployer can read/write, they don't automatically get admin claim
		// Admin claim must be granted explicitly
		req := &AccessCheckRequest{
			UserExternalID: "did:test:deployer",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": deployedContract, "data": "0x"}, "latest"},
			TargetAddress:  deployedContract,
			RequiredClaims: []Claim{ClaimAdmin}, // Require admin claim
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected deployer to NOT have admin claim automatically")
		}
	})

	t.Run("DEPLOYER-005: Deployer does NOT get upgrade claim automatically", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:deployer",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": deployedContract, "data": "0x"}, "latest"},
			TargetAddress:  deployedContract,
			RequiredClaims: []Claim{ClaimUpgrade}, // Require upgrade claim
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected deployer to NOT have upgrade claim automatically")
		}
	})
}

// TestCheckAccessDeployerAutoGrantMerge tests that deployer auto-grant properly
// merges with existing permissions when the user already has some claims.
func TestCheckAccessDeployerAutoGrantMerge(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	// Create organization
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store.organizations["org-a"] = orgA

	// Create deployer user
	deployerUser := &User{ID: "deployer-user", ExternalID: "did:test:deployer", KYC: true, Banned: false}
	store.users["did:test:deployer"] = deployerUser

	// Create group
	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}

	store.memberships["deployer-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-deployer", UserID: "deployer-user", GroupID: "group-a"}, Group: groupA},
	}

	// Set up group access with read-only default claims
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []Claim{}, // Only read by default
	}

	// Define deployed contract
	deployedContract := "0xdddd000000000000000000000000000000000002"

	// Set up contract - NOT registered to org (public contract) but deployed by user
	// This tests that deployer grant works even for public contracts
	store.contractOwners[deployedContract] = "" // Public contract
	store.registeredToAnyOrg[deployedContract] = false

	// Set deployer
	deployerID := "deployer-user"
	store.contractDeployers[deployedContract] = &deployerID

	// Cache permissions with read-only default claims
	store.cachedPermissions["deployer-user:org-a"] = &EffectivePermissions{
		ID:             "perms-deployer",
		UserID:         "deployer-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{},
		Claims:         []Claim{}, // Only read claim
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)

	t.Run("DEPLOYER-MERGE-001: Deployer gets write even with read-only defaults", func(t *testing.T) {
		// User has read via default_claims, but deployer auto-grant should add write
		req := &AccessCheckRequest{
			UserExternalID: "did:test:deployer",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": deployedContract, "from": "0x9999999999999999999999999999999999999999", "data": "0xa9059cbb"}},
			TargetAddress:  deployedContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected deployer to have write access (merged with read defaults), got: %s", result.Reason)
		}
	})
}

// TestCheckAccessUpgradeClaimEnforcement tests that eth_sendTransaction with an upgrade
// selector in calldata requires the upgrade claim, independent of proxy management state.
func TestCheckAccessUpgradeClaimEnforcement(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store.organizations["org-a"] = orgA

	user := &User{ID: "user-1", ExternalID: "did:test:user1", KYC: true, Banned: false}
	store.users["did:test:user1"] = user

	group := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	store.memberships["user-1"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-1", UserID: "user-1", GroupID: "group-a"}, Group: group},
	}

	contractAddr := "0xaaaa000000000000000000000000000000000001"

	// Build upgrade calldata: upgradeTo(address) = 0x3659cfe6 + padded address
	selectorBytes, _ := hex.DecodeString(SelectorUpgradeTo)
	implAddr, _ := hex.DecodeString("0000000000000000000000001234567890abcdef1234567890abcdef12345678")
	upgradeCalldata := append(selectorBytes, implAddr...)

	// Non-upgrade calldata: random function call
	regularCalldata, _ := hex.DecodeString("a9059cbb0000000000000000000000001234567890abcdef1234567890abcdef12345678")

	t.Run("UPGRADE-CLAIM-001: upgrade tx denied without upgrade claim", func(t *testing.T) {
		// Group has write but NOT upgrade
		store.groupAccess["group-a"] = &GroupAccess{
			ID:             "access-a",
			GroupID:        "group-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			Claims:         []Claim{}, // No upgrade
		}

		store.cachedPermissions["user-1:org-a"] = &EffectivePermissions{
			ID:             "perms-1",
			UserID:         "user-1",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractAddr: {Claims: []Claim{}}, // Explicit grant, no upgrade
			},
			Claims:     []Claim{},
			ComputedAt: time.Now(),
			ExpiresAt:  time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractAddr, "data": "0x" + hex.EncodeToString(upgradeCalldata)}, "latest"},
			TargetAddress:  contractAddr,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected upgrade tx to be denied without upgrade claim")
		}
		if result.Reason == "" {
			t.Error("expected denial reason")
		}
		// Generic denial — must not leak which specific claim is missing
		if !strings.Contains(result.Reason, ErrContractAccessDenied) && result.Reason != "access denied" {
			t.Errorf("expected generic denial, got: %s", result.Reason)
		}
	})

	t.Run("UPGRADE-CLAIM-002: upgrade tx allowed with upgrade claim", func(t *testing.T) {
		// Group has write AND upgrade
		store.groupAccess["group-a"] = &GroupAccess{
			ID:             "access-a",
			GroupID:        "group-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			Claims:         []Claim{ClaimUpgrade},
		}

		store.cachedPermissions["user-1:org-a"] = &EffectivePermissions{
			ID:             "perms-1",
			UserID:         "user-1",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractAddr: {Claims: []Claim{ClaimUpgrade}}, // Explicit grant with upgrade
			},
			Claims:     []Claim{ClaimUpgrade},
			ComputedAt: time.Now(),
			ExpiresAt:  time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractAddr, "data": "0x" + hex.EncodeToString(upgradeCalldata)}, "latest"},
			TargetAddress:  contractAddr,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should pass claim check (may still fail on proxy validation, which is OK)
		// The key: it should NOT fail with "missing upgrade claim"
		if !result.Allowed && strings.Contains(result.Reason, "upgrade claim") {
			t.Errorf("upgrade tx should not be denied for missing upgrade claim when user has it, got: %s", result.Reason)
		}
	})

	t.Run("UPGRADE-CLAIM-003: regular write tx not affected by upgrade claim check", func(t *testing.T) {
		// Group has write but NOT upgrade — regular tx should still work
		store.groupAccess["group-a"] = &GroupAccess{
			ID:             "access-a",
			GroupID:        "group-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			Claims:         []Claim{},
		}

		store.cachedPermissions["user-1:org-a"] = &EffectivePermissions{
			ID:             "perms-1",
			UserID:         "user-1",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				contractAddr: {Claims: []Claim{}}, // Explicit grant
			},
			Claims:     []Claim{},
			ComputedAt: time.Now(),
			ExpiresAt:  time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractAddr, "data": "0x" + hex.EncodeToString(regularCalldata)}, "latest"},
			TargetAddress:  contractAddr,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("regular write tx should be allowed without upgrade claim, got: %s", result.Reason)
		}
	})

	t.Run("UPGRADE-CLAIM-004: deploy claim does not grant upgrade", func(t *testing.T) {
		// Group has deploy (implies read+write) but NOT upgrade
		store.groupAccess["group-a"] = &GroupAccess{
			ID:             "access-a",
			GroupID:        "group-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			Claims:         []Claim{ClaimDeploy}, // No upgrade
		}

		store.cachedPermissions["user-1:org-a"] = &EffectivePermissions{
			ID:             "perms-1",
			UserID:         "user-1",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{},
			Claims:         []Claim{ClaimDeploy},
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		}

		controller := NewAccessController(store, 5*time.Minute)

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractAddr, "data": "0x" + hex.EncodeToString(upgradeCalldata)}, "latest"},
			TargetAddress:  contractAddr,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("upgrade tx should be denied when user has deploy but not upgrade")
		}
		if !strings.Contains(result.Reason, ErrContractAccessDenied) && result.Reason != "access denied" {
			t.Errorf("expected generic denial, got: %s", result.Reason)
		}
	})
}

// TestCheckAccessEOAValueTransfer tests that eth_sendTransaction to an unregistered
// EOA address (no calldata) is allowed with just the write claim, without requiring
// contract-level access grants.
func TestCheckAccessEOAValueTransfer(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store.organizations["org-a"] = orgA

	// User with write claim
	writeUser := &User{ID: "write-user", ExternalID: "did:test:writer", KYC: true, Banned: false}
	store.users["did:test:writer"] = writeUser

	// User with only read claim
	readUser := &User{ID: "read-user", ExternalID: "did:test:reader", KYC: true, Banned: false}
	store.users["did:test:reader"] = readUser

	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	groupB := &Group{ID: "group-b", OrgID: "org-a", Slug: "group-b", Name: "Group B"}

	store.memberships["write-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "m1", UserID: "write-user", GroupID: "group-a"}, Group: groupA},
	}
	store.memberships["read-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "m2", UserID: "read-user", GroupID: "group-b"}, Group: groupB},
	}

	store.groupAccess["group-a"] = &GroupAccess{
		ID: "ga-a", GroupID: "group-a",
		Claims:         []Claim{},
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas", "eth_getBalance"},
	}
	store.groupAccess["group-b"] = &GroupAccess{
		ID: "ga-b", GroupID: "group-b",
		Claims:         []Claim{},
		AllowedMethods: []string{"eth_call", "eth_getBalance"}, // No eth_sendTransaction — read-only
	}

	store.cachedPermissions["write-user:org-a"] = &EffectivePermissions{
		ID:             "perms-writer",
		UserID:         "write-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{},
		Claims:         []Claim{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	store.cachedPermissions["read-user:org-a"] = &EffectivePermissions{
		ID:             "perms-reader",
		UserID:         "read-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"}, // No eth_sendTransaction — read-only
		ContractAccess: map[string]ContractAccess{},
		Claims:         []Claim{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)

	// An unregistered EOA address (not in contractOwners, not registered anywhere)
	eoaAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	t.Run("EOA-001: User with write claim can send ETH to EOA", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:writer",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": eoaAddress, "from": "0x1111111111111111111111111111111111111111", "value": "0xde0b6b3a7640000"}},
			TargetAddress:  strings.ToLower(eoaAddress),
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected write user to send ETH to EOA, got: %s", result.Reason)
		}
	})

	t.Run("EOA-002: User without eth_sendTransaction in methods cannot send ETH to EOA", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:reader",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": eoaAddress, "from": "0x2222222222222222222222222222222222222222", "value": "0xde0b6b3a7640000"}},
			TargetAddress:  strings.ToLower(eoaAddress),
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected read-only user to be denied sending ETH")
		}
		if result.Reason != "method eth_sendTransaction not allowed" {
			t.Errorf("expected method-not-allowed denial, got: %s", result.Reason)
		}
	})

	t.Run("EOA-003: Value transfer with calldata to unregistered address is denied (private by default)", func(t *testing.T) {
		// If there's calldata, it goes through contract access check.
		// Unregistered addresses are now private by default — denied.
		req := &AccessCheckRequest{
			UserExternalID:   "did:test:writer",
			Method:           "eth_sendTransaction",
			Params:           []any{map[string]any{"to": eoaAddress, "from": "0x1111111111111111111111111111111111111111", "value": "0xde0b6b3a7640000", "data": "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001"}},
			TargetAddress:    strings.ToLower(eoaAddress),
			FunctionSelector: "0xa9059cbb",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be denied — unregistered addresses are private by default
		if result.Allowed {
			t.Error("expected calldata to unregistered address to be denied (private by default)")
		}
	})

	t.Run("EOA-004: Value transfer to registered contract goes through contract check", func(t *testing.T) {
		// Register the address as a contract owned by org-a
		contractAddr := "0xaaaa000000000000000000000000000000000001"
		store.contractOwners[strings.ToLower(contractAddr)] = "org-a"

		req := &AccessCheckRequest{
			UserExternalID: "did:test:writer",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractAddr, "from": "0x1111111111111111111111111111111111111111", "value": "0xde0b6b3a7640000"}},
			TargetAddress:  strings.ToLower(contractAddr),
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be denied because user has no explicit grant for this contract
		if result.Allowed {
			t.Error("expected value transfer to registered contract to go through contract access check and be denied")
		}
	})

	// RD-969: eth_estimateGas is the pre-flight step every mainstream wallet
	// (cast send, hardhat, ethers, viem) calls before signing. Without these
	// cases the bypass would refuse the estimate and break the happy path
	// even though sendTransaction would have been allowed.
	t.Run("EOA-005: eth_estimateGas on EOA value transfer is allowed (cast send pre-flight)", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:writer",
			OrgID:          "org-a",
			Method:         "eth_estimateGas",
			Params:         []any{map[string]any{"to": eoaAddress, "from": "0x1111111111111111111111111111111111111111", "value": "0xde0b6b3a7640000"}},
			TargetAddress:  strings.ToLower(eoaAddress),
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected eth_estimateGas on EOA value transfer to be allowed, got: %s", result.Reason)
		}
	})

	t.Run("EOA-006: eth_estimateGas with calldata to unregistered address is denied (carve-out doesn't widen)", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID:   "did:test:writer",
			OrgID:            "org-a",
			Method:           "eth_estimateGas",
			Params:           []any{map[string]any{"to": eoaAddress, "from": "0x1111111111111111111111111111111111111111", "value": "0x0", "data": "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001"}},
			TargetAddress:    strings.ToLower(eoaAddress),
			FunctionSelector: "0xa9059cbb",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected eth_estimateGas with calldata to unregistered address to be denied (carve-out is value-transfer-only)")
		}
	})

	t.Run("EOA-007: eth_estimateGas to registered contract still goes through contract access check", func(t *testing.T) {
		// EOA-004 covered eth_sendTransaction; this mirrors it for eth_estimateGas
		// to prove the bypass doesn't open registered-contract access.
		contractAddr := "0xaaaa000000000000000000000000000000000002"
		store.contractOwners[strings.ToLower(contractAddr)] = "org-a"

		req := &AccessCheckRequest{
			UserExternalID: "did:test:writer",
			OrgID:          "org-a",
			Method:         "eth_estimateGas",
			Params:         []any{map[string]any{"to": contractAddr, "from": "0x1111111111111111111111111111111111111111", "value": "0xde0b6b3a7640000"}},
			TargetAddress:  strings.ToLower(contractAddr),
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected eth_estimateGas to registered contract to go through contract access check and be denied (no grant)")
		}
	})
}

// TestBasicAddressQueryOnEOA verifies that eth_getBalance, eth_getTransactionCount,
// and eth_getCode on unregistered EOAs are allowed with just a read claim,
// while eth_getStorageAt on the same EOA is denied.
func TestBasicAddressQueryOnEOA(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store.organizations["org-a"] = orgA

	user := &User{ID: "reader-user", ExternalID: "did:test:reader", KYC: true}
	store.users["did:test:reader"] = user

	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "readers", Name: "Readers"}
	store.groupAccess["group-a"] = &GroupAccess{
		GroupID:        "group-a",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{},
	}
	store.memberships["reader-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-1", UserID: "reader-user", GroupID: "group-a"}, Group: groupA},
	}

	// Pre-populate cached permissions so the resolver doesn't need to compute
	store.cachedPermissions["reader-user:org-a"] = &EffectivePermissions{
		UserID:         "reader-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{},
		ContractAccess: map[string]ContractAccess{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	// EOA address — not registered to any org
	eoaAddr := "0x1111111111111111111111111111111111111111"

	controller := NewAccessController(store, 5*time.Minute)

	tests := []struct {
		name    string
		method  string
		allowed bool
	}{
		{"eth_getBalance on EOA allowed", "eth_getBalance", true},
		{"eth_getTransactionCount on EOA allowed", "eth_getTransactionCount", true},
		{"eth_getCode on EOA denied (all unregistered private)", "eth_getCode", false},
		{"eth_getStorageAt on EOA denied (not a basic address query)", "eth_getStorageAt", false},
		{"eth_getProof on EOA denied (all unregistered private)", "eth_getProof", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: "did:test:reader",
				OrgID:          "org-a",
				Method:         tt.method,
				TargetAddress:  eoaAddr,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed != tt.allowed {
				t.Errorf("expected allowed=%v, got allowed=%v (reason: %s)", tt.allowed, result.Allowed, result.Reason)
			}
		})
	}
}

// TestBasicAddressQueryOnOrgContract verifies that eth_getBalance on an address
// owned by another org is still denied (the EOA bypass only applies to unregistered addresses).
func TestBasicAddressQueryOnOrgContract(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	orgB := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
	store.organizations["org-a"] = orgA
	store.organizations["org-b"] = orgB

	user := &User{ID: "user-a", ExternalID: "did:test:user-a", KYC: true}
	store.users["did:test:user-a"] = user

	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "readers", Name: "Readers"}
	store.groupAccess["group-a"] = &GroupAccess{
		GroupID:        "group-a",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{},
	}
	store.memberships["user-a"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-1", UserID: "user-a", GroupID: "group-a"}, Group: groupA},
	}

	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{},
		ContractAccess: map[string]ContractAccess{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	// Contract owned by Org B — user is in Org A
	contractAddr := "0x2222222222222222222222222222222222222222"
	store.contractOwners[contractAddr] = "org-b"
	store.registeredToAnyOrg[contractAddr] = true

	controller := NewAccessController(store, 5*time.Minute)

	result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
		UserExternalID: "did:test:user-a",
		Method:         "eth_getBalance",
		TargetAddress:  contractAddr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected eth_getBalance on cross-org contract to be denied")
	}
}

// TestEthGetLogsOrgResolutionForMultiOrgUser verifies that eth_getLogs resolves
// to the correct org when a user belongs to multiple orgs. This was a real bug:
// GetTargetAddress returned "" for eth_getLogs, causing the resolver to use the
// user's default org instead of the contract's owning org, resulting in empty
// contract_access.
func TestEthGetLogsOrgResolutionForMultiOrgUser(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	// Two orgs: system default + demo
	systemOrg := &Organization{ID: "system-org", Slug: "default", Name: "System"}
	demoOrg := &Organization{ID: "demo-org", Slug: "demo", Name: "Demo Org"}
	store.organizations["system-org"] = systemOrg
	store.organizations["demo-org"] = demoOrg

	// Alice is in both orgs
	alice := &User{ID: "alice", ExternalID: "did:test:alice", KYC: true}
	store.users["did:test:alice"] = alice

	systemGroup := &Group{ID: "sys-group", OrgID: "system-org", Slug: "default", Name: "Default"}
	demoGroup := &Group{ID: "demo-group", OrgID: "demo-org", Slug: "admins", Name: "Admins"}

	store.memberships["alice"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-sys", UserID: "alice", GroupID: "sys-group"}, Group: systemGroup},
		{Membership: &UserMembership{ID: "mem-demo", UserID: "alice", GroupID: "demo-group"}, Group: demoGroup},
	}

	store.groupAccess["sys-group"] = &GroupAccess{
		GroupID:        "sys-group",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{},
	}
	store.groupAccess["demo-group"] = &GroupAccess{
		GroupID:        "demo-group",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{ClaimAdmin},
	}

	// A stablecoin contract owned by the demo org
	contractAddr := "0xstable0000000000000000000000000000000001"
	store.contractOwners[contractAddr] = "demo-org"
	store.registeredToAnyOrg[contractAddr] = true

	// Contract grant: demo-group has a grant to the stablecoin contract
	store.contractGrants["demo-group"] = []*ContractGrant{
		{ID: "grant-1", ContractID: "contract-stable", GroupID: "demo-group"},
	}

	// Pre-populate cached permissions for DEMO org (the correct one)
	store.cachedPermissions["alice:demo-org"] = &EffectivePermissions{
		UserID:         "alice",
		OrgID:          "demo-org",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{ClaimAdmin},
		ContractAccess: map[string]ContractAccess{
			contractAddr: {Claims: []Claim{ClaimAdmin}},
		},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	// Pre-populate cached permissions for SYSTEM org (the wrong one — no contract access)
	store.cachedPermissions["alice:system-org"] = &EffectivePermissions{
		UserID:         "alice",
		OrgID:          "system-org",
		AllowedMethods: []string{"*"},
		Claims:         []Claim{},
		ContractAccess: map[string]ContractAccess{}, // empty!
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	controller := NewAccessController(store, 5*time.Minute)

	t.Run("eth_getLogs resolves to contract owning org", func(t *testing.T) {
		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:alice",
			Method:         "eth_getLogs",
			Params: []any{
				map[string]any{
					"address":   contractAddr,
					"fromBlock": "0x0",
					"toBlock":   "latest",
				},
			},
			TargetAddress: contractAddr, // set by GetTargetAddress
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected eth_getLogs to be allowed for Alice on her org's contract, got denied: %s", result.Reason)
		}
		if result.OrgID != "demo-org" {
			t.Errorf("expected org_id=demo-org, got %s", result.OrgID)
		}
	})

	t.Run("eth_getLogs without address is denied", func(t *testing.T) {
		// No address in filter — denied on a private network (address filter required)
		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:alice",
			Method:         "eth_getLogs",
			Params: []any{
				map[string]any{
					"fromBlock": "0x0",
					"toBlock":   "latest",
				},
			},
			TargetAddress: "", // no target — GetTargetAddress returns ""
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected eth_getLogs without address filter to be denied on private network")
		}
	})
}

// TestPreregisteredAddressAccessGate locks in the access rule for preregistered
// addresses (RD-849 follow-up). Pre-reg access is reserved for users with the
// deploy or admin claim in the owning org — same gate that existed before the
// RD-849 rewrite. Regular read-only org members must not reach pre-reg
// addresses; cross-org users must not reach them; deploy/admin claim holders
// in the owning org must.
func TestPreregisteredAddressAccessGate(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	preregAddr := "0xdddd000000000000000000000000000000000001"
	// GetContractOwnerOrgID reads from contractOwners in the mock. In production
	// this column is unioned with preregistered_addresses, so pre-reg rows also
	// resolve here — mirror that by seeding both maps.
	store.contractOwners[strings.ToLower(preregAddr)] = "org-a"
	store.preregisteredAddrs["org-a"] = map[string]bool{
		strings.ToLower(preregAddr): true,
	}

	cases := []struct {
		name        string
		userID      string
		userDID     string
		orgID       string
		claims      []Claim
		wantAllowed bool
	}{
		{"deploy claim in owning org → allowed", "user-a", "did:test:user-a", "org-a", []Claim{ClaimDeploy}, true},
		{"admin claim in owning org → allowed", "user-a", "did:test:user-a", "org-a", []Claim{ClaimAdmin}, true},
		{"no operational claim in owning org → denied", "user-a", "did:test:user-a", "org-a", []Claim{}, false},
		{"deploy claim but cross-org → denied", "user-b", "did:test:user-b", "org-b", []Claim{ClaimDeploy}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store.cachedPermissions[c.userID+":"+c.orgID] = &EffectivePermissions{
				ID:             "perms-" + c.userID,
				UserID:         c.userID,
				OrgID:          c.orgID,
				AllowedMethods: []string{"eth_call"},
				ContractAccess: map[string]ContractAccess{},
				Claims:         c.claims,
				ComputedAt:     time.Now(),
				ExpiresAt:      time.Now().Add(1 * time.Hour),
			}

			// Fresh controller per subtest so the in-memory perms cache doesn't
			// carry over claims set by an earlier case.
			controller := NewAccessController(store, 5*time.Minute)

			result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: c.userDID,
				Method:         "eth_call",
				Params:         []any{map[string]any{"to": preregAddr, "data": "0x"}, "latest"},
				TargetAddress:  preregAddr,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed != c.wantAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v reason=%q", c.wantAllowed, result.Allowed, result.Reason)
			}
		})
	}
}

// TestEthGetLogsFilterShapeValidation ports the filter-shape edge cases that
// were previously asserted only against the removed test-only validator
// (ValidateGetLogsAccess) so they are enforced on the live path:
// CheckAccess → checkEthGetLogsAccess → validateGetLogsWithOrgContext.
// A single-org user is used so org resolution falls back to the user's org
// even when the malformed filter yields no target address.
func TestEthGetLogsFilterShapeValidation(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	org := &Organization{ID: "shape-org", Slug: "shape", Name: "Shape Org"}
	store.organizations["shape-org"] = org

	bob := &User{ID: "bob", ExternalID: "did:test:bob", KYC: true}
	store.users["did:test:bob"] = bob

	group := &Group{ID: "shape-group", OrgID: "shape-org", Slug: "default", Name: "Default"}
	store.memberships["bob"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-shape", UserID: "bob", GroupID: "shape-group"}, Group: group},
	}
	store.groupAccess["shape-group"] = &GroupAccess{
		GroupID:        "shape-group",
		AllowedMethods: []string{"eth_getLogs"},
		Claims:         []Claim{},
	}

	registered := "0xshape00000000000000000000000000000000aa"
	unregistered := "0xshape00000000000000000000000000000000bb"
	store.contractOwners[registered] = "shape-org"
	store.registeredToAnyOrg[registered] = true

	store.cachedPermissions["bob:shape-org"] = &EffectivePermissions{
		UserID:         "bob",
		OrgID:          "shape-org",
		AllowedMethods: []string{"eth_getLogs"},
		Claims:         []Claim{},
		ContractAccess: map[string]ContractAccess{
			registered: {Claims: []Claim{}},
		},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	controller := NewAccessController(store, 5*time.Minute)

	check := func(t *testing.T, params []any) *AccessCheckResult {
		t.Helper()
		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:bob",
			Method:         "eth_getLogs",
			Params:         params,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return result
	}

	// wantReason pins each denial to the getLogs filter-shape validation
	// specifically — without it, an unrelated earlier gate (method allowlist,
	// org resolution) denying the request would satisfy a bare Allowed=false
	// assertion. Reason is internal-only (never on the wire), so asserting
	// its text in tests is safe.
	denied := []struct {
		name       string
		params     []any
		wantReason string
	}{
		{"nil params", nil, "missing filter parameter"},
		{"empty params", []any{}, "missing filter parameter"},
		{"filter is not a map", []any{"not a map"}, "invalid filter parameter type"},
		{"no address field", []any{map[string]any{"fromBlock": "latest"}}, "address filter required"},
		{"null address", []any{map[string]any{"address": nil}}, "address filter required"},
		{"empty address array", []any{map[string]any{"address": []any{}}}, "address filter required"},
		{"empty string address", []any{map[string]any{"address": ""}}, "address filter required"},
		{"unregistered address", []any{map[string]any{"address": unregistered}}, ErrContractAccessDenied},
		{"mixed array, one unregistered", []any{map[string]any{"address": []any{registered, unregistered}}}, ErrContractAccessDenied},
	}
	for _, tt := range denied {
		t.Run("denied: "+tt.name, func(t *testing.T) {
			result := check(t, tt.params)
			if result.Allowed {
				t.Fatalf("expected denial for %s", tt.name)
			}
			if !strings.Contains(result.Reason, "eth_getLogs") || !strings.Contains(result.Reason, tt.wantReason) {
				t.Errorf("denial for %s came from the wrong gate: reason %q, want it to contain %q and %q",
					tt.name, result.Reason, "eth_getLogs", tt.wantReason)
			}
		})
	}

	t.Run("allowed: registered address, case-insensitive", func(t *testing.T) {
		upper := "0xSHAPE00000000000000000000000000000000AA"
		if result := check(t, []any{map[string]any{"address": upper}}); !result.Allowed {
			t.Errorf("expected uppercase spelling of a registered address to be allowed, got denied: %s", result.Reason)
		}
	})
}
