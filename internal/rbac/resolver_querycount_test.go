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

// TestComputePermissionsQueryCount_Member characterizes the cache-miss
// compute fan-out: today the flat path issues 1+3N store queries (one
// ListUserMembershipsInOrg, then GetGroupAccess + ListContractGrantsByGroup +
// GetContractsByIDs per group).
//
// TODO(RD-1263): flip these assertions to the batched shape (no per-group
// calls, <= 4 total) once the migration lands. The migration is blocked on an
// internal/db fix: GetGroupAccessBatch omits the verbose_errors column and
// ListContractGrantsBatch omits event_rules, so routing the live path through
// them today silently drops event visibility (caught by
// TestExplorerRedactorWiring_FullStack) and verbose_errors. The batch APIs'
// only current caller is computeHierarchyPermissions, which is itself dead
// code — the drift was dormant.
func TestComputePermissionsQueryCount_Member(t *testing.T) {
	const nGroups = 7
	cs := newCountingStore(NewMockStore())
	_, addresses := seedFlatOrg(cs.MockStore, "user-1", "org-1", nGroups, 2, false)

	r := NewResolver(cs, time.Minute)
	perms, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}

	// Current (pre-RD-1263) fan-out: scales linearly with group count.
	if got := cs.count("GetGroupAccess"); got != nGroups {
		t.Errorf("per-group GetGroupAccess called %d times; current behavior is %d (one per group)", got, nGroups)
	}
	if got := cs.count("ListContractGrantsByGroup"); got != nGroups {
		t.Errorf("per-group ListContractGrantsByGroup called %d times; current behavior is %d (one per group)", got, nGroups)
	}
	if got := cs.computeQueries(); got != 1+3*nGroups {
		t.Errorf("compute path issued %d store queries for %d groups; current behavior is 1+3N = %d (got: %v)", got, nGroups, 1+3*nGroups, cs.calls)
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

// TestComputePermissionsQueryCount_OrgAdmin characterizes the org-admin
// path's fan-out: 2+3N today (ListUserMembershipsInOrg + ListContracts + the
// same three per-group queries). TODO(RD-1263): flip to <= 5 after the
// batched migration lands (see the member test above for the blocker).
func TestComputePermissionsQueryCount_OrgAdmin(t *testing.T) {
	const nGroups = 6
	cs := newCountingStore(NewMockStore())
	seedFlatOrg(cs.MockStore, "admin-1", "org-1", nGroups, 1, true)

	r := NewResolver(cs, time.Minute)
	perms, err := r.ResolvePermissions(context.Background(), "admin-1", "org-1")
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}

	if got := cs.count("GetGroupAccess"); got != nGroups {
		t.Errorf("per-group GetGroupAccess called %d times; current behavior is %d (one per group)", got, nGroups)
	}
	if got := cs.count("ListContracts"); got != 1 {
		t.Errorf("ListContracts called %d times; want 1", got)
	}
	if got := cs.computeQueries(); got != 2+3*nGroups {
		t.Errorf("org-admin compute path issued %d store queries for %d groups; current behavior is 2+3N = %d (got: %v)", got, nGroups, 2+3*nGroups, cs.calls)
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
// skipped entirely when no group has contract grants (1+2N today;
// TODO(RD-1263): <= 3 after the batched migration).
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
	if got := cs.computeQueries(); got != 1+2*nGroups {
		t.Errorf("compute path issued %d store queries; current behavior is 1+2N = %d (got: %v)", got, 1+2*nGroups, cs.calls)
	}
}
