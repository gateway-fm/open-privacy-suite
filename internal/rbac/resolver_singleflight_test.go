package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// blockingStore wraps MockStore so the first compute query
// (ListUserMembershipsInOrg) signals entry and then blocks until released.
// It counts compute entries so tests can prove the singleflight in
// Resolver.ResolvePermissions collapses a stampede into one computation.
type blockingStore struct {
	*MockStore
	mu           sync.Mutex
	computeCalls int
	startedOnce  sync.Once
	started      chan struct{}
	release      chan struct{}
	failCompute  bool
}

func newBlockingStore(m *MockStore) *blockingStore {
	return &blockingStore{
		MockStore: m,
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
}

func (s *blockingStore) computeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.computeCalls
}

func (s *blockingStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	s.mu.Lock()
	s.computeCalls++
	fail := s.failCompute
	s.mu.Unlock()
	s.startedOnce.Do(func() { close(s.started) })
	<-s.release
	if fail {
		return nil, errors.New("injected compute failure")
	}
	return s.MockStore.ListUserMembershipsInOrg(ctx, userID, orgID)
}

// TestResolvePermissions_SingleflightCollapsesStampede proves N concurrent
// cache-miss resolutions for the same user+org run the compute exactly once
// and every caller receives the same result.
func TestResolvePermissions_SingleflightCollapsesStampede(t *testing.T) {
	const goroutines = 20
	bs := newBlockingStore(NewMockStore())
	seedFlatOrg(bs.MockStore, "user-1", "org-1", 3, 1, false)

	r := NewResolver(bs, time.Minute)
	ctx := context.Background()

	results := make([]*EffectivePermissions, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.ResolvePermissions(ctx, "user-1", "org-1")
		}(i)
	}

	// Wait until one goroutine is inside the compute, give the rest time to
	// park on the in-flight entry, then release the compute.
	<-bs.started
	time.Sleep(100 * time.Millisecond)
	close(bs.release)
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, errs[i])
		}
		if results[i] == nil {
			t.Fatalf("goroutine %d: nil permissions", i)
		}
	}
	// All callers must observe the same computation (same permissions ID:
	// waiters receive the in-flight result, stragglers hit the cache the
	// computing goroutine wrote).
	for i := 1; i < goroutines; i++ {
		if results[i].ID != results[0].ID {
			t.Errorf("goroutine %d got a different computation (ID %s vs %s)", i, results[i].ID, results[0].ID)
		}
	}
	if got := bs.computeCount(); got != 1 {
		t.Errorf("compute ran %d times for %d concurrent callers; want 1", got, goroutines)
	}
}

// TestResolvePermissions_SingleflightErrorFanout proves a failed compute is
// delivered to all waiters and the in-flight entry is cleaned up so the next
// call recomputes instead of being stuck with the stale error.
func TestResolvePermissions_SingleflightErrorFanout(t *testing.T) {
	const goroutines = 8
	bs := newBlockingStore(NewMockStore())
	seedFlatOrg(bs.MockStore, "user-1", "org-1", 2, 1, false)
	bs.failCompute = true

	r := NewResolver(bs, time.Minute)
	ctx := context.Background()

	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.ResolvePermissions(ctx, "user-1", "org-1")
		}(i)
	}

	<-bs.started
	time.Sleep(100 * time.Millisecond)
	close(bs.release)
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		if errs[i] == nil {
			t.Fatalf("goroutine %d: expected the injected compute failure, got nil", i)
		}
	}
	firstRound := bs.computeCount()
	if firstRound == 0 {
		t.Fatal("compute never ran")
	}

	// Entry must be cleaned up: a later call recomputes (and succeeds once
	// the store stops failing) instead of reusing the dead entry.
	bs.mu.Lock()
	bs.failCompute = false
	bs.mu.Unlock()
	perms, err := r.ResolvePermissions(ctx, "user-1", "org-1")
	if err != nil {
		t.Fatalf("post-failure resolve: %v", err)
	}
	if perms == nil {
		t.Fatal("post-failure resolve returned nil permissions")
	}
	if got := bs.computeCount(); got != firstRound+1 {
		t.Errorf("post-failure resolve ran compute %d times total; want %d (stale in-flight entry not cleaned up?)", got, firstRound+1)
	}
}

// cacheWriteGateStore wraps blockingStore and additionally gates the FIRST
// SetCachedPermissions call: it signals writeStarted, records whether the
// resolver still holds the in-flight entry at that moment, and blocks until
// writeRelease. Later writes pass straight through. Used to pin the ordering
// invariant: the cache write must complete BEFORE the in-flight entry is
// removed, otherwise a caller arriving between removal and write completion
// sees cache-miss + no entry and recomputes (audit finding on RD-1263).
type cacheWriteGateStore struct {
	*blockingStore
	resolver *Resolver // set after NewResolver; read only inside Set

	writeOnce        sync.Once
	writeStarted     chan struct{}
	writeRelease     chan struct{}
	entryLiveAtWrite bool
}

func newCacheWriteGateStore(bs *blockingStore) *cacheWriteGateStore {
	return &cacheWriteGateStore{
		blockingStore: bs,
		writeStarted:  make(chan struct{}),
		writeRelease:  make(chan struct{}),
	}
}

func (s *cacheWriteGateStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	gated := false
	s.writeOnce.Do(func() {
		gated = true
		s.resolver.inFlightMu.RLock()
		_, s.entryLiveAtWrite = s.resolver.inFlight[perms.UserID+":"+perms.OrgID]
		s.resolver.inFlightMu.RUnlock()
		close(s.writeStarted)
	})
	if gated {
		<-s.writeRelease
	}
	return s.blockingStore.SetCachedPermissions(ctx, perms)
}

// TestResolvePermissions_NoRecomputeDuringCacheWrite pins the close of the
// duplicate-compute window: while the first resolution's synchronous cache
// write (RD-984) is still in progress, a new caller must find the in-flight
// entry and wait — not recompute. On the pre-fix ordering (entry deleted
// before the cache write) this test fails with computeCalls == 2 and
// entryLiveAtWrite == false.
func TestResolvePermissions_NoRecomputeDuringCacheWrite(t *testing.T) {
	bs := newBlockingStore(NewMockStore())
	seedFlatOrg(bs.MockStore, "user-1", "org-1", 3, 1, false)
	gs := newCacheWriteGateStore(bs)

	r := NewResolver(gs, time.Minute)
	gs.resolver = r
	close(bs.release) // compute itself must not block in this test

	type res struct {
		perms *EffectivePermissions
		err   error
	}
	first := make(chan res, 1)
	go func() {
		p, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")
		first <- res{p, err}
	}()

	// First resolution has computed and is now parked inside the cache write.
	<-gs.writeStarted

	second := make(chan res, 1)
	go func() {
		p, err := r.ResolvePermissions(context.Background(), "user-1", "org-1")
		second <- res{p, err}
	}()

	// On the buggy ordering the second caller completes a full recompute
	// while the first write is still parked; give it the chance to do so.
	select {
	case <-second:
		t.Fatalf("second caller completed while the cache write was still in progress: it recomputed instead of waiting (computeCalls=%d)", bs.computeCount())
	case <-time.After(100 * time.Millisecond):
		// Fixed ordering: the second caller is waiting on the in-flight entry.
	}

	close(gs.writeRelease)

	r1 := <-first
	r2 := <-second
	if r1.err != nil || r2.err != nil {
		t.Fatalf("unexpected errors: first=%v second=%v", r1.err, r2.err)
	}
	if !gs.entryLiveAtWrite {
		t.Fatalf("in-flight entry was already removed when the cache write started — duplicate-compute window is open")
	}
	if got := bs.computeCount(); got != 1 {
		t.Fatalf("compute ran %d times, want 1 (stampede window during cache write)", got)
	}
}
