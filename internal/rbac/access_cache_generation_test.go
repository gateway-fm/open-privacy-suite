package rbac

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// RD-1267 review finding P1 #1 — the guard must reach the UPPER cache too.
//
// Resolver.ResolvePermissions correctly refuses to publish into the shared SQL
// cache when an invalidation commits mid-compute. But AccessController then
// copied the very same permissions into its in-memory (or Redis)
// PermissionCache unconditionally, so the revoked grant stayed usable for the
// full TTL anyway — the exact fail-open outcome RD-1267 exists to prevent.
// The original tests drove Resolver directly and so never observed that
// second write.
//
// These tests drive AccessController.resolvePermissionsForRequest, which is
// the site that performs the second write, and assert on the controller's own
// cache.

// resolveVia runs the controller's resolve-and-cache path for user/org.
func resolveVia(t *testing.T, ctrl *AccessController, userID, orgID string) (*EffectivePermissions, error) {
	t.Helper()
	return ctrl.resolvePermissionsForRequest(
		context.Background(),
		&AccessCheckRequest{},
		&User{ID: userID, ExternalID: "did:test:" + userID, KYC: true},
		&Organization{ID: orgID, Slug: orgID, Name: orgID},
	)
}

// TestAccessController_DoesNotCacheDiscardedPublication pins the finding: when
// the SQL publication is discarded, the in-memory cache must stay empty.
func TestAccessController_DoesNotCacheDiscardedPublication(t *testing.T) {
	gs := newGenerationStore(NewMockStore())
	seedFlatOrg(gs.MockStore, "user-1", "org-1", 3, 1, false)
	ctrl := NewAccessController(gs, time.Minute)

	done := make(chan error, 1)
	go func() {
		_, err := resolveVia(t, ctrl, "user-1", "org-1")
		done <- err
	}()

	// Compute is parked on its first query — the window where an
	// invalidation's DELETE finds nothing to remove.
	<-gs.started
	gs.invalidate(context.Background(), "user-1")
	close(gs.release)

	if err := <-done; err != nil {
		t.Fatalf("resolve: unexpected error %v", err)
	}

	if _, discards, publishes := gs.counters(); publishes != 0 || discards != 1 {
		t.Fatalf("SQL publication: publishes=%d discards=%d, want 0/1", publishes, discards)
	}

	if cached := ctrl.cache.Get("user-1", "org-1"); cached != nil {
		t.Error("stale permissions were installed in the in-memory PermissionCache; " +
			"a revoked grant stays usable for the full TTL even though the SQL publication was discarded")
	}
}

// waiterGateStore adds a second gate to generationStore: the publication
// itself parks until the test releases it.
//
// This is what makes the waiter test deterministic. The resolver removes the
// in-flight entry only AFTER publishing, so while a compute is parked inside
// publication the entry is guaranteed to still be registered — giving the
// second caller a window it cannot miss. Gating only the compute is not
// enough: the second goroutine may not be scheduled before the first finishes
// and removes the entry, in which case it runs its own compute instead of
// waiting. That was an observed flake in this test, not a theoretical one.
type waiterGateStore struct {
	*generationStore

	pubOnce    sync.Once
	pubStarted chan struct{}
	pubRelease chan struct{}

	getCached atomic.Int64
}

func newWaiterGateStore(m *MockStore) *waiterGateStore {
	return &waiterGateStore{
		generationStore: newGenerationStore(m),
		pubStarted:      make(chan struct{}),
		pubRelease:      make(chan struct{}),
	}
}

func (s *waiterGateStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	s.getCached.Add(1)
	return s.generationStore.GetCachedPermissions(ctx, userID, orgID)
}

func (s *waiterGateStore) SetCachedPermissionsAtGeneration(ctx context.Context, perms *EffectivePermissions, generation int64) (bool, error) {
	s.pubOnce.Do(func() {
		close(s.pubStarted)
		<-s.pubRelease
	})
	return s.generationStore.SetCachedPermissionsAtGeneration(ctx, perms, generation)
}

// TestAccessController_DoesNotCacheDiscardedPublicationForWaiter covers the
// singleflight waiter path: a second caller that never ran the compute itself
// receives another goroutine's result and must inherit the same verdict.
func TestAccessController_DoesNotCacheDiscardedPublicationForWaiter(t *testing.T) {
	ws := newWaiterGateStore(NewMockStore())
	seedFlatOrg(ws.MockStore, "user-1", "org-1", 3, 1, false)
	ctrl := NewAccessController(ws, time.Minute)

	first := make(chan error, 1)
	go func() {
		_, err := resolveVia(t, ctrl, "user-1", "org-1")
		first <- err
	}()

	// Caller 1 is inside the compute. Invalidate so its publication will be
	// refused, then let the compute finish.
	<-ws.started
	ws.invalidate(context.Background(), "user-1")
	close(ws.release)

	// Caller 1 is now parked inside publication. The in-flight entry is still
	// registered and cannot be removed until we release this gate.
	<-ws.pubStarted
	beforeSecond := ws.getCached.Load()

	second := make(chan error, 1)
	go func() {
		_, err := resolveVia(t, ctrl, "user-1", "org-1")
		second <- err
	}()

	// Wait until caller 2 has consulted the store's cache — the last step
	// before it looks up the in-flight entry. Caller 1 stays parked
	// throughout, so the entry is guaranteed present when caller 2 gets there.
	for ws.getCached.Load() == beforeSecond {
		time.Sleep(time.Millisecond)
	}

	close(ws.pubRelease)

	if err := <-first; err != nil {
		t.Fatalf("first resolve: unexpected error %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second (waiter) resolve: unexpected error %v", err)
	}

	if computes, _, _ := ws.counters(); computes != 1 {
		t.Fatalf("computes = %d, want 1 (the second caller must have been a singleflight waiter)", computes)
	}
	if cached := ctrl.cache.Get("user-1", "org-1"); cached != nil {
		t.Error("the singleflight waiter installed the stale permissions in the in-memory cache")
	}
}

// TestAccessController_CachesWhenNotInvalidated is the companion guard: with no
// mutation in the window the controller must still populate its cache, or the
// fix would have silently disabled the hot path's caching.
func TestAccessController_CachesWhenNotInvalidated(t *testing.T) {
	gs := newGenerationStore(NewMockStore())
	seedFlatOrg(gs.MockStore, "user-1", "org-1", 3, 1, false)
	close(gs.release) // no gating
	ctrl := NewAccessController(gs, time.Minute)

	if _, err := resolveVia(t, ctrl, "user-1", "org-1"); err != nil {
		t.Fatalf("resolve: unexpected error %v", err)
	}

	if _, discards, publishes := gs.counters(); publishes != 1 || discards != 0 {
		t.Fatalf("SQL publication: publishes=%d discards=%d, want 1/0", publishes, discards)
	}
	if cached := ctrl.cache.Get("user-1", "org-1"); cached == nil {
		t.Error("in-memory cache was not populated on the clean path; the guard must not disable caching")
	}
}
