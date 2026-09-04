package rbac

import (
	"context"
	"sync"
	"testing"
	"time"
)

// generationStore embeds MockStore and adds the CacheGenerationStore
// capability, so the resolver takes the guarded publication path. It also
// gates the first compute query, which lets a test commit a "mutation"
// (bump + invalidate) precisely while a compute is in flight — the RD-1267
// race window.
//
// It deliberately does not modify the shared MockStore: everything here is
// additive, mirroring the countingBypassStore pattern.
type generationStore struct {
	*MockStore

	mu           sync.Mutex
	generation   int64
	computeCalls int
	// published records the permission sets that actually reached the cache.
	published []*EffectivePermissions
	// discarded counts publications refused because the generation moved.
	discarded int

	startedOnce sync.Once
	started     chan struct{}
	release     chan struct{}
}

func newGenerationStore(m *MockStore) *generationStore {
	return &generationStore{
		MockStore:  m,
		generation: 1,
		started:    make(chan struct{}),
		release:    make(chan struct{}),
	}
}

// ListUserMembershipsInOrg is the first query of computePermissions: signal
// that the compute has begun, then block until the test releases it.
func (s *generationStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	s.mu.Lock()
	s.computeCalls++
	s.mu.Unlock()
	s.startedOnce.Do(func() { close(s.started) })
	<-s.release
	return s.MockStore.ListUserMembershipsInOrg(ctx, userID, orgID)
}

func (s *generationStore) CacheGeneration(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation, nil
}

func (s *generationStore) SetCachedPermissionsAtGeneration(ctx context.Context, perms *EffectivePermissions, generation int64) (bool, error) {
	s.mu.Lock()
	if s.generation != generation {
		s.discarded++
		s.mu.Unlock()
		return false, nil
	}
	s.published = append(s.published, perms)
	s.mu.Unlock()
	return true, s.MockStore.SetCachedPermissions(ctx, perms)
}

// invalidate simulates an admin mutation committing: the cache rows for the
// user are removed and the generation is bumped, both as one step, exactly as
// the invalidating SQL transaction does.
func (s *generationStore) invalidate(ctx context.Context, userID string) {
	s.mu.Lock()
	s.generation++
	s.mu.Unlock()
	_ = s.MockStore.InvalidateCacheForUser(ctx, userID)
}

func (s *generationStore) counters() (computes, discards, publishes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.computeCalls, s.discarded, len(s.published)
}

// TestResolvePermissions_DiscardsPublishWhenInvalidatedMidCompute is the
// RD-1267 regression test. A mutation commits while the compute is in flight;
// the compute therefore returns pre-mutation permissions. The caller may have
// them (they were true when read), but they must NOT be left in the shared
// cache, or a revoked grant stays usable for the whole TTL.
//
// On the pre-fix resolver this fails: the publication is unconditional, so the
// stale entry lands and the following resolve serves it from cache without
// recomputing.
func TestResolvePermissions_DiscardsPublishWhenInvalidatedMidCompute(t *testing.T) {
	gs := newGenerationStore(NewMockStore())
	seedFlatOrg(gs.MockStore, "user-1", "org-1", 3, 1, false)

	r := NewResolver(gs, time.Minute)

	type res struct {
		perms *EffectivePermissions
		err   error
	}
	first := make(chan res, 1)
	go func() {
		p, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")
		first <- res{p, err}
	}()

	// The compute has started and is parked on its first query — this is the
	// window in which a mutation's DELETE finds nothing to invalidate.
	<-gs.started
	gs.invalidate(context.Background(), "user-1")
	close(gs.release)

	got := <-first
	if got.err != nil {
		t.Fatalf("first resolve: unexpected error %v", got.err)
	}
	if got.perms == nil {
		t.Fatal("first resolve returned nil permissions")
	}

	_, discards, publishes := gs.counters()
	if publishes != 0 {
		t.Errorf("stale permissions were published to the cache (%d publishes); a revoked grant would stay usable for the TTL", publishes)
	}
	if discards != 1 {
		t.Errorf("discarded publications = %d, want 1", discards)
	}

	// And the proof it matters: because nothing stale was cached, the next
	// resolve must recompute rather than serve the pre-mutation entry.
	computesBefore, _, _ := gs.counters()
	if _, err := r.ResolvePermissions(context.Background(), "user-1", "org-1"); err != nil {
		t.Fatalf("second resolve: unexpected error %v", err)
	}
	computesAfter, _, _ := gs.counters()
	if computesAfter == computesBefore {
		t.Error("second resolve served the stale cache entry instead of recomputing")
	}
}

// TestResolvePermissions_PublishesWhenNoInvalidation is the companion: with no
// mutation in the window the entry must still be published, otherwise the
// guard would have silently disabled caching altogether.
func TestResolvePermissions_PublishesWhenNoInvalidation(t *testing.T) {
	gs := newGenerationStore(NewMockStore())
	seedFlatOrg(gs.MockStore, "user-1", "org-1", 3, 1, false)
	close(gs.release) // no gating needed

	r := NewResolver(gs, time.Minute)
	if _, err := r.ResolvePermissions(context.Background(), "user-1", "org-1"); err != nil {
		t.Fatalf("resolve: unexpected error %v", err)
	}

	_, discards, publishes := gs.counters()
	if publishes != 1 {
		t.Errorf("publishes = %d, want 1 (the guard must not disable caching)", publishes)
	}
	if discards != 0 {
		t.Errorf("discards = %d, want 0", discards)
	}

	// Second resolve must be served from cache — no extra compute.
	computesBefore, _, _ := gs.counters()
	if _, err := r.ResolvePermissions(context.Background(), "user-1", "org-1"); err != nil {
		t.Fatalf("second resolve: unexpected error %v", err)
	}
	computesAfter, _, _ := gs.counters()
	if computesAfter != computesBefore {
		t.Error("second resolve recomputed; the published entry was not used")
	}
}

// generationErrorStore reports a failure when asked for the baseline
// generation. The resolver must then refuse to publish at all: without a
// baseline it cannot tell whether an invalidation raced the compute, and
// guessing in the permissive direction is what RD-1267 is about.
type generationErrorStore struct {
	*MockStore
	mu        sync.Mutex
	publishes int
}

func (s *generationErrorStore) CacheGeneration(ctx context.Context) (int64, error) {
	return 0, context.DeadlineExceeded
}

func (s *generationErrorStore) SetCachedPermissionsAtGeneration(ctx context.Context, perms *EffectivePermissions, generation int64) (bool, error) {
	s.mu.Lock()
	s.publishes++
	s.mu.Unlock()
	return true, nil
}

func TestResolvePermissions_SkipsPublishWhenGenerationUnknown(t *testing.T) {
	es := &generationErrorStore{MockStore: NewMockStore()}
	seedFlatOrg(es.MockStore, "user-1", "org-1", 2, 1, false)

	r := NewResolver(es, time.Minute)
	perms, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")
	if err != nil {
		t.Fatalf("resolve must still succeed for the caller: %v", err)
	}
	if perms == nil {
		t.Fatal("resolve returned nil permissions")
	}

	es.mu.Lock()
	defer es.mu.Unlock()
	if es.publishes != 0 {
		t.Errorf("published %d entries with an unknown baseline generation; must fail safe and skip", es.publishes)
	}
}
