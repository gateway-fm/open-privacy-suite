package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// errBatchStore is the sentinel injected into one batch query at a time.
var errBatchStore = errors.New("injected batch store failure")

// failingBatchStore wraps MockStore and fails exactly one named store method,
// recording which methods the resolver actually reached and whether it tried
// to publish anything to the cache.
//
// RD-1263 replaced the per-group query trio with three batch calls
// (GetGroupAccessBatch, ListContractGrantsBatch, GetContractsByIDs). Permission
// resolution must fail closed, so an error from any of them has to abort the
// whole resolution rather than yield a partial or empty permission set — an
// empty set returned *successfully* would be cached as "no access" and could
// equally mask a real grant. These tests pin that.
type failingBatchStore struct {
	*MockStore

	failOn string // store method that returns errBatchStore

	mu       sync.Mutex
	called   map[string]int
	setCalls int
}

func newFailingBatchStore(m *MockStore, failOn string) *failingBatchStore {
	return &failingBatchStore{MockStore: m, failOn: failOn, called: make(map[string]int)}
}

func (s *failingBatchStore) enter(name string) error {
	s.mu.Lock()
	s.called[name]++
	s.mu.Unlock()
	if s.failOn == name {
		return errBatchStore
	}
	return nil
}

func (s *failingBatchStore) timesCalled(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.called[name]
}

func (s *failingBatchStore) cachePublishes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setCalls
}

func (s *failingBatchStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	if err := s.enter("ListUserMembershipsInOrg"); err != nil {
		return nil, err
	}
	return s.MockStore.ListUserMembershipsInOrg(ctx, userID, orgID)
}

func (s *failingBatchStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) {
	if err := s.enter("ListContracts"); err != nil {
		return nil, err
	}
	return s.MockStore.ListContracts(ctx, orgID)
}

func (s *failingBatchStore) GetGroupAccessBatch(ctx context.Context, groupIDs []string) (map[string]*GroupAccess, error) {
	if err := s.enter("GetGroupAccessBatch"); err != nil {
		return nil, err
	}
	return s.MockStore.GetGroupAccessBatch(ctx, groupIDs)
}

func (s *failingBatchStore) ListContractGrantsBatch(ctx context.Context, groupIDs []string) (map[string][]*ContractGrant, error) {
	if err := s.enter("ListContractGrantsBatch"); err != nil {
		return nil, err
	}
	return s.MockStore.ListContractGrantsBatch(ctx, groupIDs)
}

func (s *failingBatchStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) {
	if err := s.enter("GetContractsByIDs"); err != nil {
		return nil, err
	}
	return s.MockStore.GetContractsByIDs(ctx, ids)
}

func (s *failingBatchStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	s.mu.Lock()
	s.setCalls++
	s.mu.Unlock()
	return s.MockStore.SetCachedPermissions(ctx, perms)
}

// assertFailedClosed checks the three properties a fail-closed resolution must
// have: an error is returned, no permissions are handed back, and nothing was
// published to the cache (neither via a write call nor as a readable entry).
func assertFailedClosed(t *testing.T, s *failingBatchStore, perms *EffectivePermissions, err error, userID, orgID string) {
	t.Helper()

	if err == nil {
		t.Fatalf("ResolvePermissions returned nil error; want the injected store failure to abort resolution (fail-closed). perms=%+v", perms)
	}
	if !errors.Is(err, errBatchStore) {
		t.Errorf("error = %v; want it to wrap the injected store failure", err)
	}
	if perms != nil {
		t.Errorf("perms = %+v; want nil on a failed resolution", perms)
	}
	if got := s.cachePublishes(); got != 0 {
		t.Errorf("SetCachedPermissions called %d times; want 0 — a failed resolution must never publish", got)
	}
	cached, cErr := s.MockStore.GetCachedPermissions(context.Background(), userID, orgID)
	if cErr != nil {
		t.Fatalf("GetCachedPermissions: %v", cErr)
	}
	if cached != nil {
		t.Errorf("cache holds %+v for %s:%s; want nothing cached after a failed resolution", cached, userID, orgID)
	}
}

// TestResolvePermissions_MemberPath_BatchQueryFailureFailsClosed injects an
// error into each batch query the flat (non-org-admin) path issues and asserts
// the resolution aborts without caching. The existing error-propagation
// coverage only failed ListUserMembershipsInOrg, which runs *before* the
// batching introduced by RD-1263, so none of these paths were exercised.
func TestResolvePermissions_MemberPath_BatchQueryFailureFailsClosed(t *testing.T) {
	for _, failOn := range []string{
		"GetGroupAccessBatch",
		"ListContractGrantsBatch",
		"GetContractsByIDs",
	} {
		t.Run(failOn, func(t *testing.T) {
			s := newFailingBatchStore(NewMockStore(), failOn)
			seedFlatOrg(s.MockStore, "user-1", "org-1", 3, 2, false)

			r := NewResolver(s, time.Minute)
			perms, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")

			assertFailedClosed(t, s, perms, err, "user-1", "org-1")

			// The injected method must actually have been reached, or the test
			// would pass vacuously.
			if got := s.timesCalled(failOn); got != 1 {
				t.Errorf("%s called %d times; want exactly 1 (otherwise this case proves nothing)", failOn, got)
			}
		})
	}
}

// TestResolvePermissions_OrgAdminPath_BatchQueryFailureFailsClosed covers the
// org-admin path, which reads a different subset: ListContracts plus
// GetGroupAccessBatch only. RD-1263 stopped it reading grants and contracts at
// all (org admins already hold every claim on every contract), so the last two
// subtests assert those queries are never reached — injecting a failure into
// them cannot affect the outcome, which is what makes the skip real rather
// than incidental.
func TestResolvePermissions_OrgAdminPath_BatchQueryFailureFailsClosed(t *testing.T) {
	t.Run("ListContracts", func(t *testing.T) {
		s := newFailingBatchStore(NewMockStore(), "ListContracts")
		seedFlatOrg(s.MockStore, "admin-1", "org-1", 3, 2, true)

		r := NewResolver(s, time.Minute)
		perms, err := r.ResolvePermissions(context.Background(), "admin-1", "org-1")

		assertFailedClosed(t, s, perms, err, "admin-1", "org-1")
	})

	t.Run("GetGroupAccessBatch", func(t *testing.T) {
		s := newFailingBatchStore(NewMockStore(), "GetGroupAccessBatch")
		seedFlatOrg(s.MockStore, "admin-1", "org-1", 3, 2, true)

		r := NewResolver(s, time.Minute)
		perms, err := r.ResolvePermissions(context.Background(), "admin-1", "org-1")

		assertFailedClosed(t, s, perms, err, "admin-1", "org-1")

		if got := s.timesCalled("GetGroupAccessBatch"); got != 1 {
			t.Errorf("GetGroupAccessBatch called %d times; want exactly 1", got)
		}
	})

	for _, notReached := range []string{"ListContractGrantsBatch", "GetContractsByIDs"} {
		t.Run("unreached_"+notReached, func(t *testing.T) {
			s := newFailingBatchStore(NewMockStore(), notReached)
			seedFlatOrg(s.MockStore, "admin-1", "org-1", 3, 2, true)

			r := NewResolver(s, time.Minute)
			perms, err := r.ResolvePermissions(context.Background(), "admin-1", "org-1")

			if err != nil {
				t.Fatalf("ResolvePermissions: %v (org-admin path must not consult %s, so failing it should be invisible)", err, notReached)
			}
			if perms == nil {
				t.Fatal("perms = nil on a successful resolution")
			}
			if got := s.timesCalled(notReached); got != 0 {
				t.Errorf("%s called %d times on the org-admin path; want 0 — RD-1263 stopped this path reading grants/contracts", notReached, got)
			}
		})
	}
}
