package middleware

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrencyLimiter_AcquireRelease(t *testing.T) {
	cl := NewConcurrencyLimiter(2, 0)

	if !cl.TryAcquire("user1") {
		t.Error("first acquire should succeed")
	}
	if !cl.TryAcquire("user1") {
		t.Error("second acquire should succeed (limit is 2)")
	}
	if cl.TryAcquire("user1") {
		t.Error("third acquire should fail (limit is 2)")
	}

	cl.Release("user1")
	if !cl.TryAcquire("user1") {
		t.Error("acquire after release should succeed")
	}
}

func TestConcurrencyLimiter_PerUser(t *testing.T) {
	cl := NewConcurrencyLimiter(1, 0)

	if !cl.TryAcquire("user1") {
		t.Error("user1 first acquire should succeed")
	}
	if cl.TryAcquire("user1") {
		t.Error("user1 second acquire should fail")
	}
	// Different user should not be affected
	if !cl.TryAcquire("user2") {
		t.Error("user2 should not be affected by user1's limit")
	}

	cl.Release("user1")
	cl.Release("user2")
}

func TestConcurrencyLimiter_Disabled(t *testing.T) {
	cl := NewConcurrencyLimiter(0, 0)

	// Should always succeed when disabled
	for range 100 {
		if !cl.TryAcquire("user1") {
			t.Error("disabled limiter should always allow")
		}
	}
}

func TestConcurrencyLimiter_AnonymousCapDisabled(t *testing.T) {
	// Anonymous cap disabled (second arg 0): empty-user requests are unbounded,
	// matching the historical behavior when the cap is turned off.
	cl := NewConcurrencyLimiter(1, 0)

	for range 100 {
		if !cl.TryAcquire("") {
			t.Error("empty user should always be allowed when the anon cap is disabled")
		}
	}
}

func TestConcurrencyLimiter_Anonymous(t *testing.T) {
	// RD-1164 #3: anonymous (empty userID) traffic shares one global bucket
	// sized by the second arg. Before the fix, anonymous requests bypassed the
	// limiter entirely, so an unauthenticated flood was never concurrency-bounded.
	cl := NewConcurrencyLimiter(10, 2)

	if !cl.TryAcquire("") {
		t.Fatal("first anonymous acquire should succeed")
	}
	if !cl.TryAcquire("") {
		t.Fatal("second anonymous acquire should succeed (anon limit is 2)")
	}
	if cl.TryAcquire("") {
		t.Error("third anonymous acquire should be rejected (anon limit is 2)")
	}

	// An authenticated user draws from its own per-user bucket, never the shared
	// anonymous one, so it must not be blocked by anonymous saturation.
	if !cl.TryAcquire("user1") {
		t.Error("authenticated user must not be blocked by the anonymous cap")
	}

	// Releasing an anonymous slot frees shared capacity.
	cl.Release("")
	if !cl.TryAcquire("") {
		t.Error("anonymous acquire after release should succeed")
	}

	cl.Release("")
	cl.Release("")
	cl.Release("user1")
}

func TestConcurrencyLimiter_Concurrent(t *testing.T) {
	cl := NewConcurrencyLimiter(3, 0)

	// Acquire all 3 slots first so concurrent goroutines will be rejected
	for range 3 {
		if !cl.TryAcquire("user1") {
			t.Fatal("pre-acquire should succeed")
		}
	}

	var acquired atomic.Int32
	var rejected atomic.Int32

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cl.TryAcquire("user1") {
				acquired.Add(1)
				defer cl.Release("user1")
			} else {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()

	// All 3 slots were pre-acquired, so all 20 goroutines should be rejected
	if rejected.Load() != 20 {
		t.Errorf("expected 20 rejections, got %d (acquired %d)", rejected.Load(), acquired.Load())
	}

	// Release pre-acquired slots
	for range 3 {
		cl.Release("user1")
	}
}

func TestConcurrencyLimiter_AnonymousConcurrent(t *testing.T) {
	// The shared anonymous bucket must hold under concurrent contention: with a
	// cap of 3 and all slots pre-acquired, every racing anonymous acquire fails.
	cl := NewConcurrencyLimiter(0, 3)

	for range 3 {
		if !cl.TryAcquire("") {
			t.Fatal("pre-acquire of anon slot should succeed")
		}
	}

	var acquired atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cl.TryAcquire("") {
				acquired.Add(1)
				defer cl.Release("")
			} else {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()

	if rejected.Load() != 20 {
		t.Errorf("expected 20 anonymous rejections, got %d (acquired %d)", rejected.Load(), acquired.Load())
	}

	for range 3 {
		cl.Release("")
	}
}
