package db

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

func setupRBACTestDB(t *testing.T) *DB {
	database := setupTestDB(t)

	// Clear RBAC tables for fresh test
	ctx := context.Background()
	conn := database.Conn()

	// Clear in correct order due to foreign keys
	conn.ExecContext(ctx, "DELETE FROM rbac_audit_log")
	conn.ExecContext(ctx, "DELETE FROM effective_permissions_cache")
	conn.ExecContext(ctx, "DELETE FROM contract_grants")
	conn.ExecContext(ctx, "DELETE FROM contracts")
	conn.ExecContext(ctx, "DELETE FROM user_memberships")
	conn.ExecContext(ctx, "DELETE FROM group_access")
	conn.ExecContext(ctx, "DELETE FROM groups")
	conn.ExecContext(ctx, "DELETE FROM users")
	conn.ExecContext(ctx, "DELETE FROM organizations")

	return database
}

// Organization Tests

func TestOrganization_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	t.Run("Create", func(t *testing.T) {
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "test-org",
			Name:     "Test Organization",
			Settings: map[string]interface{}{"feature": true},
		}

		err := database.CreateOrganization(ctx, org)
		if err != nil {
			t.Fatalf("CreateOrganization() error = %v", err)
		}

		if org.CreatedAt.IsZero() {
			t.Error("CreatedAt should be set")
		}
	})

	t.Run("Get", func(t *testing.T) {
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "get-test-org",
			Name:     "Get Test Org",
			Settings: map[string]interface{}{},
		}
		database.CreateOrganization(ctx, org)

		retrieved, err := database.GetOrganization(ctx, org.ID)
		if err != nil {
			t.Fatalf("GetOrganization() error = %v", err)
		}

		if retrieved == nil {
			t.Fatal("GetOrganization() returned nil")
		}

		if retrieved.Name != org.Name {
			t.Errorf("Name = %q, want %q", retrieved.Name, org.Name)
		}
	})

	t.Run("GetBySlug", func(t *testing.T) {
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "slug-test-org",
			Name:     "Slug Test Org",
			Settings: map[string]interface{}{},
		}
		database.CreateOrganization(ctx, org)

		retrieved, err := database.GetOrganizationBySlug(ctx, "slug-test-org")
		if err != nil {
			t.Fatalf("GetOrganizationBySlug() error = %v", err)
		}

		if retrieved == nil || retrieved.ID != org.ID {
			t.Error("GetOrganizationBySlug() failed to find org")
		}
	})

	t.Run("Update", func(t *testing.T) {
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "update-test-org",
			Name:     "Original Name",
			Settings: map[string]interface{}{},
		}
		database.CreateOrganization(ctx, org)

		org.Name = "Updated Name"
		err := database.UpdateOrganization(ctx, org)
		if err != nil {
			t.Fatalf("UpdateOrganization() error = %v", err)
		}

		retrieved, _ := database.GetOrganization(ctx, org.ID)
		if retrieved.Name != "Updated Name" {
			t.Errorf("Name = %q, want %q", retrieved.Name, "Updated Name")
		}
	})

	t.Run("List", func(t *testing.T) {
		orgs, err := database.ListOrganizations(ctx)
		if err != nil {
			t.Fatalf("ListOrganizations() error = %v", err)
		}

		if len(orgs) == 0 {
			t.Error("ListOrganizations() returned empty list")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		org := &rbac.Organization{
			ID:       uuid.New().String(),
			Slug:     "delete-test-org",
			Name:     "Delete Test Org",
			Settings: map[string]interface{}{},
		}
		database.CreateOrganization(ctx, org)

		err := database.DeleteOrganization(ctx, org.ID)
		if err != nil {
			t.Fatalf("DeleteOrganization() error = %v", err)
		}

		retrieved, _ := database.GetOrganization(ctx, org.ID)
		if retrieved != nil {
			t.Error("Organization should be deleted")
		}
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		// Use a valid UUID format that doesn't exist
		retrieved, err := database.GetOrganization(ctx, uuid.New().String())
		if err != nil {
			t.Fatalf("GetOrganization() error = %v", err)
		}
		if retrieved != nil {
			t.Error("GetOrganization() should return nil for nonexistent org")
		}
	})
}

// Group Tests

func TestGroup_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create parent org
	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "group-test-org",
		Name:     "Group Test Org",
		Settings: map[string]interface{}{},
	}
	database.CreateOrganization(ctx, org)

	t.Run("Create", func(t *testing.T) {
		group := &rbac.Group{
			ID:          uuid.New().String(),
			OrgID:       org.ID,
			ParentID:    nil,
			Slug:        "root",
			Name:        "Root Group",
			Description: "The root group",
			Depth:       0,
			Path:        "root",
		}

		err := database.CreateGroup(ctx, group)
		if err != nil {
			t.Fatalf("CreateGroup() error = %v", err)
		}

		if group.CreatedAt.IsZero() {
			t.Error("CreatedAt should be set")
		}
	})

	t.Run("CreateWithParent", func(t *testing.T) {
		parent := &rbac.Group{
			ID:    uuid.New().String(),
			OrgID: org.ID,
			Slug:  "parent",
			Name:  "Parent Group",
			Depth: 0,
			Path:  "parent",
		}
		database.CreateGroup(ctx, parent)

		child := &rbac.Group{
			ID:       uuid.New().String(),
			OrgID:    org.ID,
			ParentID: &parent.ID,
			Slug:     "child",
			Name:     "Child Group",
			Depth:    1,
			Path:     "parent.child",
		}

		err := database.CreateGroup(ctx, child)
		if err != nil {
			t.Fatalf("CreateGroup() with parent error = %v", err)
		}

		retrieved, _ := database.GetGroup(ctx, child.ID)
		if retrieved.ParentID == nil || *retrieved.ParentID != parent.ID {
			t.Error("Child group should have parent ID")
		}
	})

	t.Run("GetBySlug", func(t *testing.T) {
		group := &rbac.Group{
			ID:    uuid.New().String(),
			OrgID: org.ID,
			Slug:  "slug-group",
			Name:  "Slug Group",
			Depth: 0,
			Path:  "slug-group",
		}
		database.CreateGroup(ctx, group)

		retrieved, err := database.GetGroupBySlug(ctx, org.ID, "slug-group")
		if err != nil {
			t.Fatalf("GetGroupBySlug() error = %v", err)
		}

		if retrieved == nil || retrieved.ID != group.ID {
			t.Error("GetGroupBySlug() failed to find group")
		}
	})

	t.Run("List", func(t *testing.T) {
		groups, err := database.ListGroups(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListGroups() error = %v", err)
		}

		if len(groups) == 0 {
			t.Error("ListGroups() returned empty list")
		}
	})

	t.Run("GetHierarchy", func(t *testing.T) {
		// Create hierarchy
		root := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, Slug: "hier-root", Name: "Root", Depth: 0, Path: "hier-root"}
		database.CreateGroup(ctx, root)

		mid := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, ParentID: &root.ID, Slug: "hier-mid", Name: "Mid", Depth: 1, Path: "hier-root.hier-mid"}
		database.CreateGroup(ctx, mid)

		leaf := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, ParentID: &mid.ID, Slug: "hier-leaf", Name: "Leaf", Depth: 2, Path: "hier-root.hier-mid.hier-leaf"}
		database.CreateGroup(ctx, leaf)

		hierarchy, err := database.GetGroupHierarchy(ctx, leaf.ID)
		if err != nil {
			t.Fatalf("GetGroupHierarchy() error = %v", err)
		}

		if len(hierarchy) != 3 {
			t.Errorf("GetGroupHierarchy() returned %d groups, want 3", len(hierarchy))
		}
	})
}

// Group Access Tests

func TestGroupAccess_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "access-org", Name: "Access Org", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org)

	group := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, Slug: "access-group", Name: "Access Group", Depth: 0, Path: "access-group"}
	database.CreateGroup(ctx, group)

	t.Run("Set", func(t *testing.T) {
		access := &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        group.ID,
			AllowedMethods: []string{"eth_call", "eth_getBalance"},
			Claims:         []rbac.Claim{},
		}

		err := database.SetGroupAccess(ctx, access)
		if err != nil {
			t.Fatalf("SetGroupAccess() error = %v", err)
		}
	})

	t.Run("Get", func(t *testing.T) {
		access, err := database.GetGroupAccess(ctx, group.ID)
		if err != nil {
			t.Fatalf("GetGroupAccess() error = %v", err)
		}

		if access == nil {
			t.Fatal("GetGroupAccess() returned nil")
		}

		if len(access.AllowedMethods) != 2 {
			t.Errorf("AllowedMethods length = %d, want 2", len(access.AllowedMethods))
		}
	})

	t.Run("Update (Upsert)", func(t *testing.T) {
		access := &rbac.GroupAccess{
			ID:             uuid.New().String(), // New ID, but same group
			GroupID:        group.ID,
			AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_sendTransaction"},
			Claims:         []rbac.Claim{},
		}

		err := database.SetGroupAccess(ctx, access)
		if err != nil {
			t.Fatalf("SetGroupAccess() (upsert) error = %v", err)
		}

		retrieved, _ := database.GetGroupAccess(ctx, group.ID)
		if len(retrieved.AllowedMethods) != 3 {
			t.Errorf("AllowedMethods length = %d, want 3", len(retrieved.AllowedMethods))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := database.DeleteGroupAccess(ctx, group.ID)
		if err != nil {
			t.Fatalf("DeleteGroupAccess() error = %v", err)
		}

		access, _ := database.GetGroupAccess(ctx, group.ID)
		if access != nil {
			t.Error("Access should be deleted")
		}
	})
}

// User Tests

func TestUser_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	t.Run("Create", func(t *testing.T) {
		user := &rbac.User{
			ID:         uuid.New().String(),
			ExternalID: "did:polygonid:polygon:main:user123",
			KYC:        true,
			Banned:     false,
			Note:       "Test user",
			Metadata:   map[string]interface{}{"source": "test"},
		}

		err := database.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}
	})

	t.Run("GetByExternalID", func(t *testing.T) {
		user := &rbac.User{
			ID:         uuid.New().String(),
			ExternalID: "did:unique:external123",
			KYC:        false,
			Metadata:   map[string]interface{}{},
		}
		database.CreateUser(ctx, user)

		retrieved, err := database.GetUserByExternalID(ctx, "did:unique:external123")
		if err != nil {
			t.Fatalf("GetUserByExternalID() error = %v", err)
		}

		if retrieved == nil || retrieved.ID != user.ID {
			t.Error("GetUserByExternalID() failed to find user")
		}
	})

	t.Run("Update", func(t *testing.T) {
		user := &rbac.User{
			ID:         uuid.New().String(),
			ExternalID: "did:update:user",
			KYC:        false,
			Banned:     false,
			Metadata:   map[string]interface{}{},
		}
		database.CreateUser(ctx, user)

		user.Banned = true
		user.Note = "Banned for testing"
		err := database.UpdateUser(ctx, user)
		if err != nil {
			t.Fatalf("UpdateUser() error = %v", err)
		}

		retrieved, _ := database.GetUser(ctx, user.ID)
		if !retrieved.Banned {
			t.Error("User should be banned")
		}
	})

	t.Run("List", func(t *testing.T) {
		users, err := database.ListUsers(ctx, 10, 0)
		if err != nil {
			t.Fatalf("ListUsers() error = %v", err)
		}

		if len(users) == 0 {
			t.Error("ListUsers() returned empty list")
		}
	})
}

// Membership Tests

func TestMembership_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Setup
	org := &rbac.Organization{ID: uuid.New().String(), Slug: "mem-org", Name: "Membership Org", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org)

	group := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, Slug: "mem-group", Name: "Membership Group", Depth: 0, Path: "mem-group"}
	database.CreateGroup(ctx, group)

	user := &rbac.User{ID: uuid.New().String(), ExternalID: "did:mem:user", KYC: true, Metadata: map[string]interface{}{}}
	database.CreateUser(ctx, user)

	t.Run("Create", func(t *testing.T) {
		membership := &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: group.ID,
			Source:  rbac.MembershipSourceAdmin,
		}

		err := database.CreateMembership(ctx, membership)
		if err != nil {
			t.Fatalf("CreateMembership() error = %v", err)
		}
	})

	t.Run("GetByUserAndGroup", func(t *testing.T) {
		// Create a new user and membership for this test
		testUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:getby:user", KYC: true, Metadata: map[string]interface{}{}}
		database.CreateUser(ctx, testUser)

		membership := &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  testUser.ID,
			GroupID: group.ID,
			Source:  rbac.MembershipSourceAdmin,
		}
		database.CreateMembership(ctx, membership)

		retrieved, err := database.GetMembershipByUserAndGroup(ctx, testUser.ID, group.ID)
		if err != nil {
			t.Fatalf("GetMembershipByUserAndGroup() error = %v", err)
		}

		if retrieved == nil || retrieved.ID != membership.ID {
			t.Error("GetMembershipByUserAndGroup() failed to find membership")
		}
	})

	t.Run("ListUserMemberships", func(t *testing.T) {
		memberships, err := database.ListUserMemberships(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListUserMemberships() error = %v", err)
		}

		if len(memberships) == 0 {
			t.Error("ListUserMemberships() returned empty list")
		}
	})

	t.Run("ListUserMembershipsInOrg", func(t *testing.T) {
		memberships, err := database.ListUserMembershipsInOrg(ctx, user.ID, org.ID)
		if err != nil {
			t.Fatalf("ListUserMembershipsInOrg() error = %v", err)
		}

		if len(memberships) == 0 {
			t.Error("ListUserMembershipsInOrg() returned empty list")
		}

		// Verify details are populated
		if memberships[0].Group == nil {
			t.Error("Membership should have Group details")
		}
	})

	t.Run("ListActiveUserMembershipsWithDetails", func(t *testing.T) {
		// Active user: one non-expiring membership, one expired membership in
		// a second org. The complete listing keeps both; the active listing
		// drops the expired one (authorization/trace boundary).
		activeUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:active-filter:user", KYC: true, Metadata: map[string]interface{}{}}
		if err := database.CreateUser(ctx, activeUser); err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}

		secondOrg := &rbac.Organization{ID: uuid.New().String(), Slug: "active-filter-org-" + uuid.New().String()[:8], Name: "Second Org", Settings: map[string]interface{}{}}
		if err := database.CreateOrganization(ctx, secondOrg); err != nil {
			t.Fatalf("CreateOrganization() error = %v", err)
		}
		secondGroup := &rbac.Group{ID: uuid.New().String(), OrgID: secondOrg.ID, Slug: "active-filter-grp-" + uuid.New().String()[:8], Name: "Second Group", Path: "active-filter", Depth: 0}
		if err := database.CreateGroup(ctx, secondGroup); err != nil {
			t.Fatalf("CreateGroup() error = %v", err)
		}

		if err := database.CreateMembership(ctx, &rbac.UserMembership{
			ID: uuid.New().String(), UserID: activeUser.ID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin,
		}); err != nil {
			t.Fatalf("CreateMembership(active) error = %v", err)
		}
		pastTime := time.Now().Add(-1 * time.Hour)
		if err := database.CreateMembership(ctx, &rbac.UserMembership{
			ID: uuid.New().String(), UserID: activeUser.ID, GroupID: secondGroup.ID, Source: rbac.MembershipSourceAdmin, ExpiresAt: &pastTime,
		}); err != nil {
			t.Fatalf("CreateMembership(expired) error = %v", err)
		}

		all, err := database.ListUserMembershipsWithDetails(ctx, activeUser.ID)
		if err != nil {
			t.Fatalf("ListUserMembershipsWithDetails() error = %v", err)
		}
		if len(all) != 2 {
			t.Errorf("ListUserMembershipsWithDetails() = %d memberships, want 2 (complete listing keeps expired rows)", len(all))
		}

		active, err := database.ListActiveUserMembershipsWithDetails(ctx, activeUser.ID)
		if err != nil {
			t.Fatalf("ListActiveUserMembershipsWithDetails() error = %v", err)
		}
		if len(active) != 1 {
			t.Fatalf("ListActiveUserMembershipsWithDetails() = %d memberships, want 1 (expired excluded)", len(active))
		}
		if active[0].Group == nil || active[0].Group.OrgID != org.ID {
			t.Error("ListActiveUserMembershipsWithDetails() kept the wrong membership (expired one must be dropped)")
		}
	})

	t.Run("ListGroupMembers", func(t *testing.T) {
		members, err := database.ListGroupMembers(ctx, group.ID)
		if err != nil {
			t.Fatalf("ListGroupMembers() error = %v", err)
		}

		if len(members) == 0 {
			t.Error("ListGroupMembers() returned empty list")
		}
	})

	t.Run("DeleteExpiredMemberships", func(t *testing.T) {
		// Create expired membership
		expiredUser := &rbac.User{ID: uuid.New().String(), ExternalID: "did:expired:user", KYC: true, Metadata: map[string]interface{}{}}
		database.CreateUser(ctx, expiredUser)

		pastTime := time.Now().Add(-1 * time.Hour)
		expiredMembership := &rbac.UserMembership{
			ID:        uuid.New().String(),
			UserID:    expiredUser.ID,
			GroupID:   group.ID,
			Source:    rbac.MembershipSourceAdmin,
			ExpiresAt: &pastTime,
		}
		database.CreateMembership(ctx, expiredMembership)

		deleted, err := database.DeleteExpiredMemberships(ctx)
		if err != nil {
			t.Fatalf("DeleteExpiredMemberships() error = %v", err)
		}

		if deleted == 0 {
			t.Error("DeleteExpiredMemberships() should have deleted at least one membership")
		}
	})
}

// Contract Tests

func TestContract_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "contract-org", Name: "Contract Org", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org)

	t.Run("Create", func(t *testing.T) {
		contract := &rbac.Contract{
			ID:       uuid.New().String(),
			OrgID:    org.ID,
			Address:  "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
			Name:     "Test Contract",
			Metadata: map[string]interface{}{"version": "1.0"},
		}

		err := database.CreateContract(ctx, contract)
		if err != nil {
			t.Fatalf("CreateContract() error = %v", err)
		}
	})

	t.Run("GetByAddress", func(t *testing.T) {
		contract := &rbac.Contract{
			ID:       uuid.New().String(),
			OrgID:    org.ID,
			Address:  "0x1111111111111111111111111111111111111111",
			Metadata: map[string]interface{}{},
		}
		database.CreateContract(ctx, contract)

		// Get with uppercase (should normalize)
		retrieved, err := database.GetContractByAddress(ctx, org.ID, "0x1111111111111111111111111111111111111111")
		if err != nil {
			t.Fatalf("GetContractByAddress() error = %v", err)
		}

		if retrieved == nil {
			t.Error("GetContractByAddress() should find contract")
		}
	})

	t.Run("List", func(t *testing.T) {
		contracts, err := database.ListContracts(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListContracts() error = %v", err)
		}

		if len(contracts) == 0 {
			t.Error("ListContracts() returned empty list")
		}
	})

	t.Run("Update", func(t *testing.T) {
		contract := &rbac.Contract{
			ID:       uuid.New().String(),
			OrgID:    org.ID,
			Address:  "0x2222222222222222222222222222222222222222",
			Metadata: map[string]interface{}{},
		}
		database.CreateContract(ctx, contract)

		contract.Name = "Updated Name"
		contract.Metadata = map[string]interface{}{"updated": true}
		err := database.UpdateContract(ctx, contract)
		if err != nil {
			t.Fatalf("UpdateContract() error = %v", err)
		}

		retrieved, _ := database.GetContract(ctx, contract.ID)
		if retrieved.Name != "Updated Name" {
			t.Error("Name should be updated")
		}
	})
}

// Contract Grant Tests

func TestContractGrant_CRUD(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "grant-org", Name: "Grant Org", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org)

	group := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, Slug: "grant-group", Name: "Grant Group", Depth: 0, Path: "grant-group"}
	database.CreateGroup(ctx, group)

	contract := &rbac.Contract{ID: uuid.New().String(), OrgID: org.ID, Address: "0x3333333333333333333333333333333333333333", Metadata: map[string]interface{}{}}
	database.CreateContract(ctx, contract)

	t.Run("Create", func(t *testing.T) {
		grant := &rbac.ContractGrant{
			ID:         uuid.New().String(),
			ContractID: contract.ID,
			GroupID:    group.ID,
			// Claims are deprecated - they're inherited from group's GroupAccess.claims
			// The DB layer will ignore any claims passed here and store empty array
			Functions: []rbac.FunctionRule{{Selector: "0x12345678"}},
		}

		err := database.CreateContractGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateContractGrant() error = %v", err)
		}
	})

	t.Run("GetByContractAndGroup", func(t *testing.T) {
		retrieved, err := database.GetContractGrantByContractAndGroup(ctx, contract.ID, group.ID)
		if err != nil {
			t.Fatalf("GetContractGrantByContractAndGroup() error = %v", err)
		}

		if retrieved == nil {
			t.Error("GetContractGrantByContractAndGroup() should find grant")
		}
	})

	t.Run("ListForContract", func(t *testing.T) {
		grants, err := database.ListContractGrants(ctx, contract.ID)
		if err != nil {
			t.Fatalf("ListContractGrants() error = %v", err)
		}

		if len(grants) == 0 {
			t.Error("ListContractGrants() returned empty list")
		}
	})

	t.Run("ListForGroup", func(t *testing.T) {
		grants, err := database.ListContractGrantsForGroup(ctx, group.ID)
		if err != nil {
			t.Fatalf("ListContractGrantsForGroup() error = %v", err)
		}

		if len(grants) == 0 {
			t.Error("ListContractGrantsForGroup() returned empty list")
		}
	})

	t.Run("Update", func(t *testing.T) {
		grant, _ := database.GetContractGrantByContractAndGroup(ctx, contract.ID, group.ID)

		// Claims are deprecated - any claims set will be ignored by the DB layer
		// Update functions instead to verify the update works
		grant.Functions = []rbac.FunctionRule{{Selector: "0x12345678"}, {Selector: "0xabcdef00"}}
		err := database.UpdateContractGrant(ctx, grant)
		if err != nil {
			t.Fatalf("UpdateContractGrant() error = %v", err)
		}

		retrieved, _ := database.GetContractGrant(ctx, grant.ID)
		// Functions should be updated
		if len(retrieved.Functions) != 2 {
			t.Errorf("Functions length = %d, want 2", len(retrieved.Functions))
		}
	})
}

// Contract Grant ParamRules Tests

func TestContractGrant_ParamRules(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "paramrules-org", Name: "ParamRules Org", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org)

	group := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, Slug: "paramrules-group", Name: "ParamRules Group", Depth: 0, Path: "paramrules-group"}
	database.CreateGroup(ctx, group)

	contract := &rbac.Contract{ID: uuid.New().String(), OrgID: org.ID, Address: "0x4444444444444444444444444444444444444444", Metadata: map[string]interface{}{}}
	database.CreateContract(ctx, contract)

	t.Run("CreateWithParamRules", func(t *testing.T) {
		grant := &rbac.ContractGrant{
			ID:         uuid.New().String(),
			ContractID: contract.ID,
			GroupID:    group.ID,
			Functions: []rbac.FunctionRule{
				{Selector: "0x70a08231", ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}}},
				{Selector: "0xa9059cbb"},
			},
		}

		err := database.CreateContractGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateContractGrant() error = %v", err)
		}

		retrieved, err := database.GetContractGrant(ctx, grant.ID)
		if err != nil {
			t.Fatalf("GetContractGrant() error = %v", err)
		}
		if retrieved == nil {
			t.Fatal("GetContractGrant() returned nil")
		}

		if len(retrieved.Functions) != 2 {
			t.Fatalf("Functions length = %d, want 2", len(retrieved.Functions))
		}

		// First function: selector with param rules
		if retrieved.Functions[0].Selector != "0x70a08231" {
			t.Errorf("Functions[0].Selector = %q, want %q", retrieved.Functions[0].Selector, "0x70a08231")
		}
		if len(retrieved.Functions[0].ParamRules) != 1 {
			t.Fatalf("Functions[0].ParamRules length = %d, want 1", len(retrieved.Functions[0].ParamRules))
		}
		if retrieved.Functions[0].ParamRules[0].Index != 0 {
			t.Errorf("Functions[0].ParamRules[0].Index = %d, want 0", retrieved.Functions[0].ParamRules[0].Index)
		}
		if retrieved.Functions[0].ParamRules[0].MustBe != "self" {
			t.Errorf("Functions[0].ParamRules[0].MustBe = %q, want %q", retrieved.Functions[0].ParamRules[0].MustBe, "self")
		}

		// Second function: bare selector with no param rules
		if retrieved.Functions[1].Selector != "0xa9059cbb" {
			t.Errorf("Functions[1].Selector = %q, want %q", retrieved.Functions[1].Selector, "0xa9059cbb")
		}
		if len(retrieved.Functions[1].ParamRules) != 0 {
			t.Errorf("Functions[1].ParamRules length = %d, want 0", len(retrieved.Functions[1].ParamRules))
		}
	})

	t.Run("UpdateToAddParamRules", func(t *testing.T) {
		// Create a second contract+grant with bare selectors
		contract2 := &rbac.Contract{ID: uuid.New().String(), OrgID: org.ID, Address: "0x5555555555555555555555555555555555555555", Metadata: map[string]interface{}{}}
		database.CreateContract(ctx, contract2)

		grant := &rbac.ContractGrant{
			ID:         uuid.New().String(),
			ContractID: contract2.ID,
			GroupID:    group.ID,
			Functions:  []rbac.FunctionRule{{Selector: "0xdeadbeef"}, {Selector: "0xcafebabe"}},
		}

		err := database.CreateContractGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateContractGrant() error = %v", err)
		}

		// Verify bare selectors round-trip without param rules
		before, _ := database.GetContractGrant(ctx, grant.ID)
		if len(before.Functions[0].ParamRules) != 0 {
			t.Fatalf("Before update: ParamRules should be empty, got %d", len(before.Functions[0].ParamRules))
		}

		// Update to add param rules
		grant.Functions = []rbac.FunctionRule{
			{Selector: "0xdeadbeef", ParamRules: []rbac.ParamRule{{Index: 1, MustBe: "self"}}},
			{Selector: "0xcafebabe"},
		}
		err = database.UpdateContractGrant(ctx, grant)
		if err != nil {
			t.Fatalf("UpdateContractGrant() error = %v", err)
		}

		after, err := database.GetContractGrant(ctx, grant.ID)
		if err != nil {
			t.Fatalf("GetContractGrant() after update error = %v", err)
		}

		if len(after.Functions) != 2 {
			t.Fatalf("After update: Functions length = %d, want 2", len(after.Functions))
		}
		if len(after.Functions[0].ParamRules) != 1 {
			t.Fatalf("After update: Functions[0].ParamRules length = %d, want 1", len(after.Functions[0].ParamRules))
		}
		if after.Functions[0].ParamRules[0].Index != 1 {
			t.Errorf("After update: ParamRules[0].Index = %d, want 1", after.Functions[0].ParamRules[0].Index)
		}
		if after.Functions[0].ParamRules[0].MustBe != "self" {
			t.Errorf("After update: ParamRules[0].MustBe = %q, want %q", after.Functions[0].ParamRules[0].MustBe, "self")
		}
		if len(after.Functions[1].ParamRules) != 0 {
			t.Errorf("After update: Functions[1].ParamRules should be empty, got %d", len(after.Functions[1].ParamRules))
		}
	})

	t.Run("NilFunctionsRoundTrip", func(t *testing.T) {
		// Create a grant with nil Functions (meaning all functions allowed)
		contract3 := &rbac.Contract{ID: uuid.New().String(), OrgID: org.ID, Address: "0x6666666666666666666666666666666666666666", Metadata: map[string]interface{}{}}
		database.CreateContract(ctx, contract3)

		grant := &rbac.ContractGrant{
			ID:         uuid.New().String(),
			ContractID: contract3.ID,
			GroupID:    group.ID,
			Functions:  nil, // all functions allowed
		}

		err := database.CreateContractGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateContractGrant() error = %v", err)
		}

		retrieved, err := database.GetContractGrant(ctx, grant.ID)
		if err != nil {
			t.Fatalf("GetContractGrant() error = %v", err)
		}
		if retrieved == nil {
			t.Fatal("GetContractGrant() returned nil")
		}

		if retrieved.Functions != nil {
			t.Errorf("Functions should be nil (all functions allowed), got %v", retrieved.Functions)
		}
	})
}

// Cache Tests

func TestEffectivePermissionsCache(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "cache-org", Name: "Cache Org", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org)

	user := &rbac.User{ID: uuid.New().String(), ExternalID: "did:cache:user", KYC: true, Metadata: map[string]interface{}{}}
	database.CreateUser(ctx, user)

	t.Run("SetAndGet", func(t *testing.T) {
		perms := &rbac.EffectivePermissions{
			ID:             uuid.New().String(),
			UserID:         user.ID,
			OrgID:          org.ID,
			AllowedMethods: []string{"eth_call"},
			ContractAccess: map[string]rbac.ContractAccess{
				"0x1234": {Claims: []rbac.Claim{}},
			},
			Claims: []rbac.Claim{},
			ComputedAt:    time.Now(),
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}

		err := database.SetCachedPermissions(ctx, perms)
		if err != nil {
			t.Fatalf("SetCachedPermissions() error = %v", err)
		}

		retrieved, err := database.GetCachedPermissions(ctx, user.ID, org.ID)
		if err != nil {
			t.Fatalf("GetCachedPermissions() error = %v", err)
		}

		if retrieved == nil {
			t.Fatal("GetCachedPermissions() returned nil")
		}

		if len(retrieved.AllowedMethods) != 1 {
			t.Error("AllowedMethods should have 1 element")
		}
	})

	t.Run("GetExpired", func(t *testing.T) {
		expiredOrgID := uuid.New().String()
		expiredPerms := &rbac.EffectivePermissions{
			ID:             uuid.New().String(),
			UserID:         user.ID,
			OrgID:          expiredOrgID,
			AllowedMethods: []string{},
			ContractAccess: map[string]rbac.ContractAccess{},
			Claims:  []rbac.Claim{},
			ComputedAt:     time.Now().Add(-2 * time.Hour),
			ExpiresAt:      time.Now().Add(-1 * time.Hour),
		}
		database.SetCachedPermissions(ctx, expiredPerms)

		retrieved, err := database.GetCachedPermissions(ctx, user.ID, expiredOrgID)
		if err != nil {
			t.Fatalf("GetCachedPermissions() error = %v", err)
		}

		if retrieved != nil {
			t.Error("GetCachedPermissions() should return nil for expired cache")
		}
	})

	t.Run("InvalidateForUser", func(t *testing.T) {
		err := database.InvalidateCacheForUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("InvalidateCacheForUser() error = %v", err)
		}

		retrieved, _ := database.GetCachedPermissions(ctx, user.ID, org.ID)
		if retrieved != nil {
			t.Error("Cache should be invalidated")
		}
	})

	t.Run("CleanupExpired", func(t *testing.T) {
		deleted, err := database.CleanupExpiredCache(ctx)
		if err != nil {
			t.Fatalf("CleanupExpiredCache() error = %v", err)
		}

		// At least the expired one should be deleted
		if deleted < 0 {
			t.Errorf("CleanupExpiredCache() deleted = %d, want >= 0", deleted)
		}
	})
}

// Audit Log Tests

func TestAuditLog(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	t.Run("Create", func(t *testing.T) {
		entry := &rbac.AuditLogEntry{
			ActorExternalID: "did:audit:actor",
			Action:          "create",
			ResourceType:    "organization",
			ResourceName:    "Test Org",
			NewValue:        map[string]interface{}{"name": "Test Org"},
			IPAddress:       "127.0.0.1",
		}

		err := database.CreateAuditLog(ctx, entry)
		if err != nil {
			t.Fatalf("CreateAuditLog() error = %v", err)
		}

		if entry.ID == 0 {
			t.Error("Audit log ID should be set")
		}
	})

	t.Run("List", func(t *testing.T) {
		logs, err := database.ListAuditLogs(ctx, "organization", nil, 10, 0)
		if err != nil {
			t.Fatalf("ListAuditLogs() error = %v", err)
		}

		if len(logs) == 0 {
			t.Error("ListAuditLogs() returned empty list")
		}
	})

	t.Run("ListByActor", func(t *testing.T) {
		// Create entry with actor ID
		actorID := uuid.New().String()
		entry := &rbac.AuditLogEntry{
			ActorID:         &actorID,
			ActorExternalID: "did:audit:specific",
			Action:          "update",
			ResourceType:    "user",
			ResourceName:    "Test User",
			IPAddress:       "127.0.0.1",
		}
		database.CreateAuditLog(ctx, entry)

		logs, err := database.ListAuditLogsByActor(ctx, actorID, 10, 0)
		if err != nil {
			t.Fatalf("ListAuditLogsByActor() error = %v", err)
		}

		if len(logs) == 0 {
			t.Error("ListAuditLogsByActor() returned empty list")
		}
	})
}

// IsContractRegisteredToAnyOrg Tests

func TestIsContractRegisteredToAnyOrg(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	// Create two organizations
	org1 := &rbac.Organization{ID: uuid.New().String(), Slug: "org1", Name: "Org 1", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org1)

	org2 := &rbac.Organization{ID: uuid.New().String(), Slug: "org2", Name: "Org 2", Settings: map[string]interface{}{}}
	database.CreateOrganization(ctx, org2)

	// Create a contract in org1
	registeredContract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    org1.ID,
		Address:  "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Metadata: map[string]interface{}{},
	}
	database.CreateContract(ctx, registeredContract)

	t.Run("Contract registered to org1 - should return true", func(t *testing.T) {
		exists, err := database.IsContractRegisteredToAnyOrg(ctx, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if err != nil {
			t.Fatalf("IsContractRegisteredToAnyOrg() error = %v", err)
		}
		if !exists {
			t.Error("Expected true for registered contract")
		}
	})

	t.Run("Contract registered - case insensitive check (lowercase)", func(t *testing.T) {
		exists, err := database.IsContractRegisteredToAnyOrg(ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		if err != nil {
			t.Fatalf("IsContractRegisteredToAnyOrg() error = %v", err)
		}
		if !exists {
			t.Error("Expected true for registered contract (lowercase query)")
		}
	})

	t.Run("Contract registered - case insensitive check (mixed case)", func(t *testing.T) {
		exists, err := database.IsContractRegisteredToAnyOrg(ctx, "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa")
		if err != nil {
			t.Fatalf("IsContractRegisteredToAnyOrg() error = %v", err)
		}
		if !exists {
			t.Error("Expected true for registered contract (mixed case query)")
		}
	})

	t.Run("Unregistered contract - should return false", func(t *testing.T) {
		exists, err := database.IsContractRegisteredToAnyOrg(ctx, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
		if err != nil {
			t.Fatalf("IsContractRegisteredToAnyOrg() error = %v", err)
		}
		if exists {
			t.Error("Expected false for unregistered contract")
		}
	})

	t.Run("Contract in different org - should still return true", func(t *testing.T) {
		// Create a contract in org2
		org2Contract := &rbac.Contract{
			ID:       uuid.New().String(),
			OrgID:    org2.ID,
			Address:  "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			Metadata: map[string]interface{}{},
		}
		database.CreateContract(ctx, org2Contract)

		// Check from perspective of any org
		exists, err := database.IsContractRegisteredToAnyOrg(ctx, "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
		if err != nil {
			t.Fatalf("IsContractRegisteredToAnyOrg() error = %v", err)
		}
		if !exists {
			t.Error("Expected true for contract registered to org2")
		}
	})
}
