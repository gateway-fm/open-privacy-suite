package rbac

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingStore wraps MockStore and counts store calls made by the resolver's
// compute path, so tests can assert the query fan-out on a cache miss
// (RD-1263: the flat path used to issue 1+3N queries — one per group for
// GetGroupAccess, ListContractGrantsByGroup and GetContractsByIDs — while the
// batch APIs already existed and were used by the hierarchy path).
type countingStore struct {
	*MockStore
	mu    sync.Mutex
	calls map[string]int
}

func newCountingStore(m *MockStore) *countingStore {
	return &countingStore{MockStore: m, calls: make(map[string]int)}
}

func (c *countingStore) bump(name string) {
	c.mu.Lock()
	c.calls[name]++
	c.mu.Unlock()
}

func (c *countingStore) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[name]
}

// computeQueries returns the total number of store calls on the permission
// compute path (cache reads/writes excluded).
func (c *countingStore) computeQueries() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for name, n := range c.calls {
		if name == "GetCachedPermissions" || name == "SetCachedPermissions" {
			continue
		}
		total += n
	}
	return total
}

func (c *countingStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	c.bump("ListUserMembershipsInOrg")
	return c.MockStore.ListUserMembershipsInOrg(ctx, userID, orgID)
}

func (c *countingStore) GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error) {
	c.bump("GetGroupAccess")
	return c.MockStore.GetGroupAccess(ctx, groupID)
}

func (c *countingStore) GetGroupAccessBatch(ctx context.Context, groupIDs []string) (map[string]*GroupAccess, error) {
	c.bump("GetGroupAccessBatch")
	return c.MockStore.GetGroupAccessBatch(ctx, groupIDs)
}

func (c *countingStore) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error) {
	c.bump("ListContractGrantsByGroup")
	return c.MockStore.ListContractGrantsByGroup(ctx, groupID)
}

func (c *countingStore) ListContractGrantsBatch(ctx context.Context, groupIDs []string) (map[string][]*ContractGrant, error) {
	c.bump("ListContractGrantsBatch")
	return c.MockStore.ListContractGrantsBatch(ctx, groupIDs)
}

func (c *countingStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) {
	c.bump("GetContractsByIDs")
	return c.MockStore.GetContractsByIDs(ctx, ids)
}

func (c *countingStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) {
	c.bump("ListContracts")
	return c.MockStore.ListContracts(ctx, orgID)
}

func (c *countingStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	c.bump("GetCachedPermissions")
	return c.MockStore.GetCachedPermissions(ctx, userID, orgID)
}

func (c *countingStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	c.bump("SetCachedPermissions")
	return c.MockStore.SetCachedPermissions(ctx, perms)
}

// seedFlatOrg populates the mock with one org, one user and n groups; each
// group has its own access row (one distinct method + one shared method,
// deploy claim) and grantsPerGroup contract grants on distinct contracts.
// Returns the group IDs in membership order and the contract addresses.
func seedFlatOrg(m *MockStore, userID, orgID string, n, grantsPerGroup int, orgAdmin bool) (groupIDs []string, addresses []string) {
	var memberships []*MembershipWithDetails
	for i := 0; i < n; i++ {
		gid := fmt.Sprintf("group-%03d", i)
		groupIDs = append(groupIDs, gid)
		group := &Group{ID: gid, OrgID: orgID, Slug: gid, Name: gid}
		if orgAdmin && i == 0 {
			group.IsOrgAdmin = true
		}
		m.groups[gid] = group
		m.groupAccess[gid] = &GroupAccess{
			ID:             "access-" + gid,
			GroupID:        gid,
			AllowedMethods: []string{"eth_call", fmt.Sprintf("method_%03d", i)},
			Claims:         []Claim{ClaimDeploy},
		}
		for j := 0; j < grantsPerGroup; j++ {
			cid := fmt.Sprintf("contract-%03d-%d", i, j)
			addr := fmt.Sprintf("0x%040d", i*grantsPerGroup+j)
			m.contracts[cid] = &Contract{ID: cid, OrgID: orgID, Address: addr, Name: cid}
			m.contractGrants[gid] = append(m.contractGrants[gid], &ContractGrant{
				ID:         "grant-" + cid,
				ContractID: cid,
				GroupID:    gid,
			})
			addresses = append(addresses, addr)
		}
		memberships = append(memberships, &MembershipWithDetails{
			Membership: &UserMembership{ID: "m-" + gid, UserID: userID, GroupID: gid},
			Group:      group,
		})
	}
	m.groupsByOrg[userID+":"+orgID] = memberships
	return groupIDs, addresses
}

// TestComputePermissionsQueryCount_Member pins the cache-miss compute fan-out
// of the flat path at a constant 4 queries — ListUserMembershipsInOrg,
// GetGroupAccessBatch, ListContractGrantsBatch, GetContractsByIDs — regardless
// of how many groups the user belongs to (RD-1263; it used to be 1+3N, with
// GetGroupAccess + ListContractGrantsByGroup + GetContractsByIDs per group).
//
// The per-group assertions below are the regression guard: if anyone
// reintroduces a query inside the membership loop, the count stops being
// constant and this test fails.
func TestComputePermissionsQueryCount_Member(t *testing.T) {
	const nGroups = 7
	cs := newCountingStore(NewMockStore())
	_, addresses := seedFlatOrg(cs.MockStore, "user-1", "org-1", nGroups, 2, false)

	r := NewResolver(cs, time.Minute)
	perms, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}

	// Batched fan-out: no per-group queries at all.
	if got := cs.count("GetGroupAccess"); got != 0 {
		t.Errorf("per-group GetGroupAccess called %d times; want 0 (batched via GetGroupAccessBatch)", got)
	}
	if got := cs.count("ListContractGrantsByGroup"); got != 0 {
		t.Errorf("per-group ListContractGrantsByGroup called %d times; want 0 (batched via ListContractGrantsBatch)", got)
	}
	if got := cs.count("GetGroupAccessBatch"); got != 1 {
		t.Errorf("GetGroupAccessBatch called %d times; want exactly 1", got)
	}
	if got := cs.count("ListContractGrantsBatch"); got != 1 {
		t.Errorf("ListContractGrantsBatch called %d times; want exactly 1", got)
	}
	if got := cs.count("GetContractsByIDs"); got != 1 {
		t.Errorf("GetContractsByIDs called %d times; want exactly 1 (one batch for every group's grants)", got)
	}
	if got := cs.computeQueries(); got != 4 {
		t.Errorf("compute path issued %d store queries for %d groups; want a constant 4 (got: %v)", got, nGroups, cs.calls)
	}

	// Semantics: union across memberships, claims expanded, every granted
	// contract present with the group's claims.
	if len(perms.ContractAccess) != len(addresses) {
		t.Fatalf("ContractAccess has %d entries; want %d", len(perms.ContractAccess), len(addresses))
	}
	for _, addr := range addresses {
		access, ok := perms.ContractAccess[strings.ToLower(addr)]
		if !ok {
			t.Fatalf("missing ContractAccess for %s", addr)
		}
		if !HasClaim(access.Claims, ClaimDeploy) {
			t.Errorf("contract %s missing deploy claim", addr)
		}
	}
	if !HasClaim(perms.Claims, ClaimDeploy) {
		t.Errorf("perms.Claims missing deploy: %v", perms.Claims)
	}
	wantMethods := nGroups + 1 // one distinct method per group + the shared one
	if len(perms.AllowedMethods) != wantMethods {
		t.Errorf("AllowedMethods has %d entries; want %d: %v", len(perms.AllowedMethods), wantMethods, perms.AllowedMethods)
	}
}

// TestComputePermissionsQueryCount_OrgAdmin pins the org-admin path at a
// constant 3 queries: ListUserMembershipsInOrg, ListContracts and
// GetGroupAccessBatch. Org admins already hold every claim on every contract
// in the org, so the grants and contracts halves are never read here — the
// pre-RD-1263 path issued the full per-group trio (2+3N) and discarded the
// contract half of every one of them.
func TestComputePermissionsQueryCount_OrgAdmin(t *testing.T) {
	const nGroups = 6
	cs := newCountingStore(NewMockStore())
	seedFlatOrg(cs.MockStore, "admin-1", "org-1", nGroups, 1, true)

	r := NewResolver(cs, time.Minute)
	perms, err := r.ResolvePermissions(context.Background(), "admin-1", "org-1")
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}

	if got := cs.count("GetGroupAccess"); got != 0 {
		t.Errorf("per-group GetGroupAccess called %d times; want 0 (batched)", got)
	}
	if got := cs.count("ListContracts"); got != 1 {
		t.Errorf("ListContracts called %d times; want 1", got)
	}
	if got := cs.count("GetGroupAccessBatch"); got != 1 {
		t.Errorf("GetGroupAccessBatch called %d times; want exactly 1", got)
	}
	// The org-admin path must not read grants or contracts-by-id at all.
	if got := cs.count("ListContractGrantsBatch"); got != 0 {
		t.Errorf("ListContractGrantsBatch called %d times; want 0 (org admins get all contracts via ListContracts)", got)
	}
	if got := cs.count("GetContractsByIDs"); got != 0 {
		t.Errorf("GetContractsByIDs called %d times; want 0 (org admins get all contracts via ListContracts)", got)
	}
	if got := cs.computeQueries(); got != 3 {
		t.Errorf("org-admin compute path issued %d store queries for %d groups; want a constant 3 (got: %v)", got, nGroups, cs.calls)
	}

	// Org admins keep all claims and the union of allowed methods.
	for _, claim := range AllClaims() {
		if !HasClaim(perms.Claims, claim) {
			t.Errorf("org admin missing claim %s", claim)
		}
	}
	wantMethods := nGroups + 1
	if len(perms.AllowedMethods) != wantMethods {
		t.Errorf("AllowedMethods has %d entries; want %d: %v", len(perms.AllowedMethods), wantMethods, perms.AllowedMethods)
	}
}

// TestComputePermissionsQueryCount_NoGrants ensures GetContractsByIDs is
// skipped entirely when no group has contract grants, leaving 3 queries
// (memberships + the two batches). This preserved the pre-RD-1263 behaviour of
// not querying contracts when there is nothing to look up.
func TestComputePermissionsQueryCount_NoGrants(t *testing.T) {
	const nGroups = 3
	cs := newCountingStore(NewMockStore())
	seedFlatOrg(cs.MockStore, "user-2", "org-2", nGroups, 0, false)

	r := NewResolver(cs, time.Minute)
	if _, err := r.ResolvePermissions(context.Background(), "user-2", "org-2"); err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}
	if got := cs.count("GetContractsByIDs"); got != 0 {
		t.Errorf("GetContractsByIDs called %d times with zero grants; want 0", got)
	}
	if got := cs.computeQueries(); got != 3 {
		t.Errorf("compute path issued %d store queries; want a constant 3 (got: %v)", got, cs.calls)
	}
}

// TestComputePermissionsQueryCount_ConstantInGroupCount is the direct
// statement of the RD-1263 property: resolving a user with 3 groups and a user
// with 40 groups must cost the same number of queries.
func TestComputePermissionsQueryCount_ConstantInGroupCount(t *testing.T) {
	counts := make(map[int]int)
	for _, nGroups := range []int{3, 40} {
		cs := newCountingStore(NewMockStore())
		seedFlatOrg(cs.MockStore, "user-1", "org-1", nGroups, 2, false)

		r := NewResolver(cs, time.Minute)
		if _, err := r.ResolvePermissions(context.Background(), "user-1", "org-1"); err != nil {
			t.Fatalf("ResolvePermissions (%d groups): %v", nGroups, err)
		}
		counts[nGroups] = cs.computeQueries()
	}
	if counts[3] != counts[40] {
		t.Errorf("query count scales with group count: 3 groups → %d queries, 40 groups → %d; want equal", counts[3], counts[40])
	}
}
