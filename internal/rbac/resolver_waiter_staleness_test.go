package rbac

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// waiterStalenessStore parks the FIRST publication attempt, which is what makes
// this test deterministic: while the computing goroutine is held inside
// SetCachedPermissionsAtGeneration it still owns the in-flight entry, so a
// second caller is guaranteed to arrive as a waiter rather than as a second
// computer. The generation is bumped and the underlying data mutated during
// that window, so a recompute is observably different from the stale set.
type waiterStalenessStore struct {
	*MockStore

	mu           sync.Mutex
	generation   int64
	computeCalls int
	getCalls     int

	pubOnce    sync.Once
	pubStarted chan struct{}
	pubRelease chan struct{}
	secondGet  chan struct{}
	secondOnce sync.Once
}

func newWaiterStalenessStore(m *MockStore) *waiterStalenessStore {
	return &waiterStalenessStore{
		MockStore:  m,
		generation: 1,
		pubStarted: make(chan struct{}),
		pubRelease: make(chan struct{}),
		secondGet:  make(chan struct{}),
	}
}

func (s *waiterStalenessStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	s.mu.Lock()
	s.getCalls++
	n := s.getCalls
	s.mu.Unlock()
	if n == 2 {
		// The second caller has passed the cache check and is about to take
		// the in-flight path.
		s.secondOnce.Do(func() { close(s.secondGet) })
	}
	return s.MockStore.GetCachedPermissions(ctx, userID, orgID)
}

func (s *waiterStalenessStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	s.mu.Lock()
	s.computeCalls++
	s.mu.Unlock()
	return s.MockStore.ListUserMembershipsInOrg(ctx, userID, orgID)
}

func (s *waiterStalenessStore) CacheGeneration(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation, nil
}

func (s *waiterStalenessStore) SetCachedPermissionsAtGeneration(ctx context.Context, perms *EffectivePermissions, generation int64) (bool, error) {
	gated := false
	s.pubOnce.Do(func() { gated = true })
	if gated {
		close(s.pubStarted)
		<-s.pubRelease
	}
	s.mu.Lock()
	moved := s.generation != generation
	s.mu.Unlock()
	if moved {
		return false, nil
	}
	return true, s.MockStore.SetCachedPermissions(ctx, perms)
}

// invalidateAndMutate is the admin mutation committing: bump the generation and
// change the underlying grant so a recompute yields a different permission set.
func (s *waiterStalenessStore) invalidateAndMutate(ctx context.Context, userID, groupID string) {
	s.mu.Lock()
	s.generation++
	s.mu.Unlock()
	s.MockStore.groupAccess[groupID] = &GroupAccess{
		ID:             "access-" + groupID,
		GroupID:        groupID,
		AllowedMethods: []string{"eth_getBalance"},
		Claims:         []Claim{ClaimDeploy},
	}
	_ = s.MockStore.InvalidateCacheForUser(ctx, userID)
}

func (s *waiterStalenessStore) computes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.computeCalls
}

// TestResolvePermissions_WaiterDoesNotInheritStalePermissions covers RD-1276
// defect 2. The requesting goroutine serving its own computed result is
// inherent to read-then-act and is fine. A WAITER is different: it never ran
// the compute, and inheriting a result the resolver positively determined to
// be pre-mutation means its own read is served from a known-stale compute —
// AccessController then makes the access decision from it, skipping only the
// cache write.
//
// Pre-fix this fails: the waiter receives the stale AllowedMethods.
func TestResolvePermissions_WaiterDoesNotInheritStalePermissions(t *testing.T) {
	m := NewMockStore()
	groupIDs, _ := seedFlatOrg(m, "user-1", "org-1", 1, 1, false)
	st := newWaiterStalenessStore(m)
	r := NewResolver(st, time.Minute)

	type res struct {
		perms *EffectivePermissions
		err   error
	}
	first := make(chan res, 1)
	go func() {
		p, _, err := r.ResolvePermissionsCacheable(context.Background(), "user-1", "org-1")
		first <- res{p, err}
	}()

	// The computing goroutine is parked inside its publication attempt and
	// still owns the in-flight entry.
	<-st.pubStarted

	// The admin mutation commits: generation moves and the data changes.
	st.invalidateAndMutate(context.Background(), "user-1", groupIDs[0])

	second := make(chan res, 1)
	go func() {
		p, _, err := r.ResolvePermissionsCacheable(context.Background(), "user-1", "org-1")
		second <- res{p, err}
	}()

	// The second caller has passed the cache check, so it is a waiter.
	<-st.secondGet

	close(st.pubRelease)

	r1 := <-first
	r2 := <-second
	if r1.err != nil || r2.err != nil {
		t.Fatalf("unexpected errors: first=%v second=%v", r1.err, r2.err)
	}

	// The computing goroutine legitimately holds the pre-mutation set.
	if !slices.Contains(r1.perms.AllowedMethods, "method_000") {
		t.Fatalf("computing goroutine should hold the pre-mutation set, got %v", r1.perms.AllowedMethods)
	}

	// The waiter must NOT be served the set already known to be stale.
	if slices.Contains(r2.perms.AllowedMethods, "method_000") {
		t.Errorf("waiter inherited permissions the resolver had already determined were stale: %v (computes=%d)",
			r2.perms.AllowedMethods, st.computes())
	}
	if !slices.Contains(r2.perms.AllowedMethods, "eth_getBalance") {
		t.Errorf("waiter should have recomputed post-mutation permissions, got %v (computes=%d)",
			r2.perms.AllowedMethods, st.computes())
	}
}
