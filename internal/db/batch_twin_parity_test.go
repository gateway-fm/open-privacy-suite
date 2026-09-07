package db

import (
	"context"
	"reflect"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// Single-row vs batch parity (RD-1257 follow-up): the batch variants are
// column-list twins of their single-row counterparts and had drifted the same
// way the *Tx twins did — ListContractGrantsBatch dropped event_rules (grants
// came back EventRules=nil, i.e. deny), GetGroupAccessBatch dropped
// verbose_errors. These tests pin batch output to the single-row output for
// identical fixtures.

func TestListContractGrantsBatch_ParityWithSingle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, groupID := txDivergenceFixtures(t, db, ctx)

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "22222222222222222222222222222222",
		Name:     "Batch Parity Contract",
		Metadata: map[string]any{},
	}
	if err := db.CreateContract(ctx, contract); err != nil {
		t.Fatalf("CreateContract failed: %v", err)
	}

	wildcard := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    groupID,
		Functions:  []rbac.FunctionRule{{Selector: "0xa9059cbb"}},
		EventRules: &rbac.EventRulesField{Wildcard: true},
	}
	if err := db.CreateContractGrant(ctx, wildcard); err != nil {
		t.Fatalf("CreateContractGrant (wildcard) failed: %v", err)
	}

	contract2 := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "33333333333333333333333333333333",
		Name:     "Batch Parity Contract 2",
		Metadata: map[string]any{},
	}
	if err := db.CreateContract(ctx, contract2); err != nil {
		t.Fatalf("CreateContract 2 failed: %v", err)
	}
	allowlist := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract2.ID,
		GroupID:    groupID,
		EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{{
			Topic0: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
			Name:   "Transfer",
		}}},
	}
	if err := db.CreateContractGrant(ctx, allowlist); err != nil {
		t.Fatalf("CreateContractGrant (allowlist) failed: %v", err)
	}

	single, err := db.ListContractGrantsByGroup(ctx, groupID)
	if err != nil {
		t.Fatalf("ListContractGrantsByGroup failed: %v", err)
	}
	batch, err := db.ListContractGrantsBatch(ctx, []string{groupID})
	if err != nil {
		t.Fatalf("ListContractGrantsBatch failed: %v", err)
	}

	if len(single) != 2 {
		t.Fatalf("single-row twin returned %d grants, want 2", len(single))
	}
	if !reflect.DeepEqual(single, batch[groupID]) {
		t.Errorf("batch grants diverge from single-row twin:\n single: %+v\n batch:  %+v",
			describeGrants(single), describeGrants(batch[groupID]))
	}
}

func describeGrants(grants []*rbac.ContractGrant) []rbac.ContractGrant {
	out := make([]rbac.ContractGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, *g)
	}
	return out
}

func TestGetGroupAccessBatch_ParityWithSingle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	_, groupID := txDivergenceFixtures(t, db, ctx)

	apiKey := "batch-parity-key"
	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		AllowedMethods: []string{"eth_blockNumber", "eth_chainId"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
		RPCAPIKey:      &apiKey,
		VerboseErrors:  true,
	}
	if err := db.CreateGroupAccess(ctx, access); err != nil {
		t.Fatalf("CreateGroupAccess failed: %v", err)
	}

	single, err := db.GetGroupAccess(ctx, groupID)
	if err != nil {
		t.Fatalf("GetGroupAccess failed: %v", err)
	}
	if single == nil {
		t.Fatal("GetGroupAccess returned nil for existing access")
	}
	batch, err := db.GetGroupAccessBatch(ctx, []string{groupID})
	if err != nil {
		t.Fatalf("GetGroupAccessBatch failed: %v", err)
	}
	got := batch[groupID]
	if got == nil {
		t.Fatal("GetGroupAccessBatch missing the group")
	}

	if !reflect.DeepEqual(single, got) {
		t.Errorf("batch access diverges from single-row twin:\n single: %+v\n batch:  %+v", *single, *got)
	}
}

// The two groups-with-access list queries (admin groups-list API) are joined
// twins of GetGroupAccess and had dropped ga.verbose_errors: a group saved
// with verbose_errors=true listed as false (human-audit finding on RD-1257).
func TestListGroupsWithAccess_ParityWithSingle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, groupID := txDivergenceFixtures(t, db, ctx)

	apiKey := "list-parity-key"
	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        groupID,
		AllowedMethods: []string{"eth_blockNumber"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
		RPCAPIKey:      &apiKey,
		VerboseErrors:  true,
	}
	if err := db.CreateGroupAccess(ctx, access); err != nil {
		t.Fatalf("CreateGroupAccess failed: %v", err)
	}

	single, err := db.GetGroupAccess(ctx, groupID)
	if err != nil {
		t.Fatalf("GetGroupAccess failed: %v", err)
	}
	if single == nil {
		t.Fatal("GetGroupAccess returned nil for existing access")
	}

	findAccess := func(t *testing.T, results []*rbac.GroupWithAccess) *rbac.GroupAccess {
		t.Helper()
		for _, gwa := range results {
			if gwa.Group != nil && gwa.Group.ID == groupID {
				if gwa.Access == nil {
					t.Fatal("group listed without its access row")
				}
				return gwa.Access
			}
		}
		t.Fatal("group missing from list result")
		return nil
	}

	paginated, _, err := db.ListGroupsWithAccessPaginated(ctx, orgID, 100, 0)
	if err != nil {
		t.Fatalf("ListGroupsWithAccessPaginated failed: %v", err)
	}
	if got := findAccess(t, paginated); !reflect.DeepEqual(single, got) {
		t.Errorf("ListGroupsWithAccessPaginated access diverges from GetGroupAccess:\n single: %+v\n list:   %+v", *single, *got)
	}

	filtered, _, err := db.ListGroupsWithAccessFiltered(ctx, orgID, 100, 0, GroupListFilter{})
	if err != nil {
		t.Fatalf("ListGroupsWithAccessFiltered failed: %v", err)
	}
	if got := findAccess(t, filtered); !reflect.DeepEqual(single, got) {
		t.Errorf("ListGroupsWithAccessFiltered access diverges from GetGroupAccess:\n single: %+v\n list:   %+v", *single, *got)
	}
}

// The membership-details and grant-with-group joins hydrate rbac.Group with a
// truncated column list (no is_org_readonly_admin / is_system / auto_created)
// — same partial-hydration disease, found by the RD-1257 sweep.
func TestJoinedGroupHydration_CarriesAllFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDB(t)
	ctx := context.Background()
	orgID, _ := txDivergenceFixtures(t, db, ctx)

	group := &rbac.Group{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		Slug:               "join-flags-" + uuid.New().String()[:8],
		Name:               "Join Flags Group",
		Depth:              0,
		Path:               "join-flags",
		IsOrgReadonlyAdmin: true,
	}
	if err := db.CreateGroup(ctx, group); err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	if _, err := db.Conn().ExecContext(ctx,
		`UPDATE groups SET is_system = true, auto_created = true WHERE id = $1`, group.ID); err != nil {
		t.Fatalf("failed to set is_system/auto_created: %v", err)
	}

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:join-flags-" + uuid.New().String()[:8],
		Metadata:   map[string]any{},
	}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if err := db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}); err != nil {
		t.Fatalf("CreateMembership failed: %v", err)
	}

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  "0x" + uuid.New().String()[:8] + "44444444444444444444444444444444",
		Name:     "Join Flags Contract",
		Metadata: map[string]any{},
	}
	if err := db.CreateContract(ctx, contract); err != nil {
		t.Fatalf("CreateContract failed: %v", err)
	}
	if err := db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    group.ID,
	}); err != nil {
		t.Fatalf("CreateContractGrant failed: %v", err)
	}

	assertFlags := func(t *testing.T, src string, g *rbac.Group) {
		t.Helper()
		if g == nil {
			t.Fatalf("%s returned nil group", src)
		}
		if !g.IsOrgReadonlyAdmin {
			t.Errorf("%s dropped is_org_readonly_admin", src)
		}
		if !g.IsSystem {
			t.Errorf("%s dropped is_system", src)
		}
		if !g.AutoCreated {
			t.Errorf("%s dropped auto_created", src)
		}
	}

	inOrg, err := db.ListUserMembershipsInOrg(ctx, user.ID, orgID)
	if err != nil {
		t.Fatalf("ListUserMembershipsInOrg failed: %v", err)
	}
	if len(inOrg) != 1 {
		t.Fatalf("ListUserMembershipsInOrg returned %d rows, want 1", len(inOrg))
	}
	assertFlags(t, "ListUserMembershipsInOrg", inOrg[0].Group)

	withDetails, err := db.ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserMembershipsWithDetails failed: %v", err)
	}
	if len(withDetails) != 1 {
		t.Fatalf("ListUserMembershipsWithDetails returned %d rows, want 1", len(withDetails))
	}
	assertFlags(t, "ListUserMembershipsWithDetails", withDetails[0].Group)

	grants, err := db.ListContractGrantsByGroupWithContract(ctx, group.ID)
	if err != nil {
		t.Fatalf("ListContractGrantsByGroupWithContract failed: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("ListContractGrantsByGroupWithContract returned %d rows, want 1", len(grants))
	}
	assertFlags(t, "ListContractGrantsByGroupWithContract", grants[0].Group)
}
