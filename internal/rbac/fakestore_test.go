package rbac

import "context"

// fakeStore implements every method of Store with an inert zero-value return
// (nil / false / 0 / ""), so a test double only has to write the methods whose
// behavior it actually asserts. Embed it and override:
//
//	type myStore struct {
//		fakeStore
//		groups map[string]*Group
//	}
//
//	func (m *myStore) GetGroup(_ context.Context, id string) (*Group, error) {
//		return m.groups[id], nil
//	}
//
// Why this exists (RD-1264): Store has 83 methods, and the package previously
// carried three independent full reimplementations of it — ~200 of those 249
// methods were identical inert stubs. Every method added to Store had to be
// hand-added to all three. Now it is added here once.
//
// Why it lives in package rbac rather than a `rbactest` package: the existing
// doubles expose their fixture state as *unexported* fields that tests write
// directly (`store.groups["root"] = g`, `store.groupsByOrg[...] = ...`, and so
// on across ~4,000 lines of test bodies). Promotion through an embedded type
// keeps that access legal only inside package rbac; moving the fake out would
// force every one of those fields to be exported and every test body rewritten
// — a large, risky diff for a test-only refactor. A separate package would also
// have to import rbac while rbac's own tests import it back, which is fine for
// an external test package but buys nothing here. `internal/testutil` was
// likewise rejected: it holds testcontainers/anvil helpers, and pulling that
// into rbac's unit tests would drag real-infra dependencies into a suite that
// runs in under a second.
//
// Deliberately stateless. Giving the fake state-backed defaults would silently
// hand behavior to doubles that previously returned nothing, which is exactly
// the kind of change a test-double refactor must not make.
type fakeStore struct{}

// Compile-time proof that the inert base alone satisfies the interface. If a
// method is added to Store, this is the single line that breaks.
var _ Store = fakeStore{}

func (fakeStore) CreateOrganization(context.Context, *Organization) error { return nil }
func (fakeStore) GetOrganization(context.Context, string) (*Organization, error) {
	return nil, nil
}
func (fakeStore) GetOrganizationBySlug(context.Context, string) (*Organization, error) {
	return nil, nil
}
func (fakeStore) UpdateOrganization(context.Context, *Organization) error { return nil }
func (fakeStore) ListOrganizations(context.Context) ([]*Organization, error) {
	return nil, nil
}
func (fakeStore) ListOrganizationsPaginated(context.Context, int, int) ([]*Organization, int, error) {
	return nil, 0, nil
}
func (fakeStore) DeleteOrganization(context.Context, string) error { return nil }

func (fakeStore) CreateGroup(context.Context, *Group) error        { return nil }
func (fakeStore) GetGroup(context.Context, string) (*Group, error) { return nil, nil }
func (fakeStore) UpdateGroup(context.Context, *Group) error        { return nil }
func (fakeStore) DeleteGroup(context.Context, string) error        { return nil }
func (fakeStore) GetGroupBySlug(context.Context, string, string) (*Group, error) {
	return nil, nil
}
func (fakeStore) ListGroups(context.Context, string) ([]*Group, error) { return nil, nil }
func (fakeStore) ListGroupsPaginated(context.Context, string, int, int) ([]*Group, int, error) {
	return nil, 0, nil
}
func (fakeStore) ListGroupsWithAccessPaginated(context.Context, string, int, int) ([]*GroupWithAccess, int, error) {
	return nil, 0, nil
}
func (fakeStore) ListGroupsByParent(context.Context, string) ([]*Group, error) {
	return nil, nil
}
func (fakeStore) GetGroupHierarchy(context.Context, string) ([]*Group, error) {
	return nil, nil
}

func (fakeStore) CreateGroupAccess(context.Context, *GroupAccess) error { return nil }
func (fakeStore) GetGroupAccess(context.Context, string) (*GroupAccess, error) {
	return nil, nil
}
func (fakeStore) GetGroupAccessBatch(context.Context, []string) (map[string]*GroupAccess, error) {
	return nil, nil
}
func (fakeStore) UpdateGroupAccess(context.Context, *GroupAccess) error { return nil }
func (fakeStore) DeleteGroupAccess(context.Context, string) error       { return nil }

func (fakeStore) CreateContract(context.Context, *Contract) error        { return nil }
func (fakeStore) GetContract(context.Context, string) (*Contract, error) { return nil, nil }
func (fakeStore) GetContractsByIDs(context.Context, []string) (map[string]*Contract, error) {
	return nil, nil
}
func (fakeStore) GetContractByAddress(context.Context, string, string) (*Contract, error) {
	return nil, nil
}
func (fakeStore) GetContractByAddressGlobal(context.Context, string) (*Contract, error) {
	return nil, nil
}
func (fakeStore) UpdateContract(context.Context, *Contract) error { return nil }
func (fakeStore) ListContracts(context.Context, string) ([]*Contract, error) {
	return nil, nil
}
func (fakeStore) ListContractsPaginated(context.Context, string, int, int) ([]*Contract, int, error) {
	return nil, 0, nil
}
func (fakeStore) DeleteContract(context.Context, string) error { return nil }
func (fakeStore) IsContractRegisteredToAnyOrg(context.Context, string) (bool, error) {
	return false, nil
}
func (fakeStore) IsAddressOwnedByOrg(context.Context, string, string) (bool, error) {
	return false, nil
}
func (fakeStore) GetContractOwnerOrgID(context.Context, string) (string, error) {
	return "", nil
}
func (fakeStore) GetContractDeployerByAddress(context.Context, string) (*string, error) {
	return nil, nil
}

func (fakeStore) CreateContractGrant(context.Context, *ContractGrant) error { return nil }
func (fakeStore) GetContractGrant(context.Context, string) (*ContractGrant, error) {
	return nil, nil
}
func (fakeStore) GetContractGrantByContractAndGroup(context.Context, string, string) (*ContractGrant, error) {
	return nil, nil
}
func (fakeStore) UpdateContractGrant(context.Context, *ContractGrant) error { return nil }
func (fakeStore) ListContractGrantsByContract(context.Context, string) ([]*ContractGrant, error) {
	return nil, nil
}
func (fakeStore) ListContractGrantsByGroup(context.Context, string) ([]*ContractGrant, error) {
	return nil, nil
}
func (fakeStore) ListContractGrantsBatch(context.Context, []string) (map[string][]*ContractGrant, error) {
	return nil, nil
}
func (fakeStore) ListContractGrantsByGroupWithContract(context.Context, string) ([]*ContractGrantWithGroup, error) {
	return nil, nil
}
func (fakeStore) DeleteContractGrant(context.Context, string) error { return nil }
func (fakeStore) GetContractGrantSummary(context.Context, string) (map[string]*ContractGrantSummary, error) {
	return nil, nil
}
func (fakeStore) GrantContractToDeployerGroup(context.Context, string, string, string) error {
	return nil
}

func (fakeStore) GetLinkedEthAddresses(context.Context, string) ([]string, error) {
	return nil, nil
}
func (fakeStore) SystemLinkEthAddress(context.Context, string, string) error { return nil }
func (fakeStore) GetOrgIDsForEthAddress(context.Context, string) ([]string, error) {
	return nil, nil
}

func (fakeStore) CreateUser(context.Context, *User) error        { return nil }
func (fakeStore) GetUser(context.Context, string) (*User, error) { return nil, nil }
func (fakeStore) GetUserByExternalID(context.Context, string) (*User, error) {
	return nil, nil
}
func (fakeStore) UpdateUser(context.Context, *User) error { return nil }
func (fakeStore) ListUsers(context.Context, int, int) ([]*User, error) {
	return nil, nil
}
func (fakeStore) ListUsersPaginated(context.Context, int, int) ([]*User, int, error) {
	return nil, 0, nil
}
func (fakeStore) DeleteUser(context.Context, string) error { return nil }

func (fakeStore) CreateMembership(context.Context, *UserMembership) error { return nil }
func (fakeStore) GetMembership(context.Context, string) (*UserMembership, error) {
	return nil, nil
}
func (fakeStore) GetMembershipByUserAndGroup(context.Context, string, string) (*UserMembership, error) {
	return nil, nil
}
func (fakeStore) UpdateMembership(context.Context, *UserMembership) error { return nil }
func (fakeStore) ListUserMemberships(context.Context, string) ([]*UserMembership, error) {
	return nil, nil
}
func (fakeStore) ListUserMembershipsInOrg(context.Context, string, string) ([]*MembershipWithDetails, error) {
	return nil, nil
}
func (fakeStore) ListUserMembershipsWithDetails(context.Context, string) ([]*MembershipWithDetails, error) {
	return nil, nil
}
func (fakeStore) ListGroupMembers(context.Context, string) ([]*UserMembership, error) {
	return nil, nil
}
func (fakeStore) DeleteMembership(context.Context, string) error          { return nil }
func (fakeStore) DeleteExpiredMemberships(context.Context) (int64, error) { return 0, nil }

func (fakeStore) GetCachedPermissions(context.Context, string, string) (*EffectivePermissions, error) {
	return nil, nil
}
func (fakeStore) SetCachedPermissions(context.Context, *EffectivePermissions) error { return nil }
func (fakeStore) InvalidateCacheForUser(context.Context, string) error              { return nil }
func (fakeStore) InvalidateCacheForOrg(context.Context, string) error               { return nil }
func (fakeStore) InvalidateCacheForGroup(context.Context, string) error             { return nil }
func (fakeStore) CleanupExpiredCache(context.Context) (int64, error)                { return 0, nil }

func (fakeStore) CreateAuditLog(context.Context, *AuditLogEntry) error { return nil }
func (fakeStore) ListAuditLogs(context.Context, string, *string, int, int) ([]*AuditLogEntry, error) {
	return nil, nil
}
func (fakeStore) ListAuditLogsByActor(context.Context, string, int, int) ([]*AuditLogEntry, error) {
	return nil, nil
}

func (fakeStore) IsAddressPreregistered(context.Context, string, string) (bool, error) {
	return false, nil
}
func (fakeStore) MarkAddressUsed(context.Context, string) error { return nil }
func (fakeStore) PreRegisterPlainCreate(context.Context, string, string, string) error {
	return nil
}
func (fakeStore) DeletePreregisteredAddressByAddress(context.Context, string) error { return nil }

func (fakeStore) IsSharedInfrastructure(context.Context, string) (bool, error) {
	return false, nil
}
func (fakeStore) CreateSharedInfrastructure(context.Context, *SharedInfrastructure) error {
	return nil
}
func (fakeStore) ListSharedInfrastructure(context.Context) ([]*SharedInfrastructure, error) {
	return nil, nil
}
func (fakeStore) DeleteSharedInfrastructure(context.Context, string) error { return nil }
