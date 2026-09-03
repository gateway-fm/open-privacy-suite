package rbac

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCacheBasicOperations(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	perms := &EffectivePermissions{
		UserID:         "user1",
		OrgID:          "org1",
		AllowedMethods: []string{"eth_call"},
		Claims:         []Claim{},
	}

	// Test Set and Get
	cache.Set(perms)

	got := cache.Get("user1", "org1")
	if got == nil {
		t.Fatal("Expected to get cached permissions")
	}
	if len(got.AllowedMethods) != 1 || got.AllowedMethods[0] != "eth_call" {
		t.Errorf("Got unexpected permissions: %v", got)
	}

	// Test Get for non-existent entry
	got = cache.Get("user2", "org1")
	if got != nil {
		t.Error("Expected nil for non-existent entry")
	}
}

func TestCacheExpiration(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        50 * time.Millisecond,
		MaxEntries: 100,
	})

	perms := &EffectivePermissions{
		UserID:         "user1",
		OrgID:          "org1",
		AllowedMethods: []string{"eth_call"},
	}

	cache.Set(perms)

	// Should exist immediately
	got := cache.Get("user1", "org1")
	if got == nil {
		t.Fatal("Expected to get cached permissions immediately")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired now
	got = cache.Get("user1", "org1")
	if got != nil {
		t.Error("Expected nil for expired entry")
	}
}

func TestCacheInvalidateUser(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	// Add entries for same user in different orgs
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org2"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})

	// Invalidate user1
	cache.InvalidateUser("user1")

	// user1 entries should be gone
	if cache.Get("user1", "org1") != nil {
		t.Error("Expected user1:org1 to be invalidated")
	}
	if cache.Get("user1", "org2") != nil {
		t.Error("Expected user1:org2 to be invalidated")
	}

	// user2 should still exist
	if cache.Get("user2", "org1") == nil {
		t.Error("Expected user2:org1 to still exist")
	}
}

func TestCacheInvalidateOrg(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	// Add entries for different users in same org
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org2"})

	// Invalidate org1
	cache.InvalidateOrg("org1")

	// org1 entries should be gone
	if cache.Get("user1", "org1") != nil {
		t.Error("Expected user1:org1 to be invalidated")
	}
	if cache.Get("user2", "org1") != nil {
		t.Error("Expected user2:org1 to be invalidated")
	}

	// org2 should still exist
	if cache.Get("user1", "org2") == nil {
		t.Error("Expected user1:org2 to still exist")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	// The cache uses approximate (sampled) LRU to keep Get on an O(1) read path
	// (RD-1112): recency is a per-entry timestamp and eviction samples up to
	// evictSampleSize entries and drops the oldest. When the entry count is
	// <= evictSampleSize the sample covers every entry, so eviction is exact;
	// the 1ms spacing below guarantees distinct access timestamps so "least
	// recently used" is unambiguous and this test is deterministic.
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 3,
	})

	// Add 3 entries with distinct access timestamps.
	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	time.Sleep(time.Millisecond)
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})
	time.Sleep(time.Millisecond)
	cache.Set(&EffectivePermissions{UserID: "user3", OrgID: "org1"})
	time.Sleep(time.Millisecond)

	// Access user1 to make it the most recently used.
	_ = cache.Get("user1", "org1")
	time.Sleep(time.Millisecond)

	// Add 4th entry - should evict user2 (least recently used).
	cache.Set(&EffectivePermissions{UserID: "user4", OrgID: "org1"})

	// user2 is the LRU victim and must be gone.
	if cache.Get("user2", "org1") != nil {
		t.Error("Expected user2:org1 to be evicted (least recently used)")
	}

	// user1 should still exist (accessed recently)
	if cache.Get("user1", "org1") == nil {
		t.Error("Expected user1:org1 to still exist (recently accessed)")
	}

	// user3 should still exist (added after user2)
	if cache.Get("user3", "org1") == nil {
		t.Error("Expected user3:org1 to still exist")
	}

	// user4 should exist
	if cache.Get("user4", "org1") == nil {
		t.Error("Expected user4:org1 to exist")
	}

	// Check size
	if cache.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cache.Size())
	}
}

func TestCacheClear(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})

	if cache.Size() != 2 {
		t.Errorf("Expected size 2 before clear, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}
}

func TestCacheStats(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	cache.Set(&EffectivePermissions{UserID: "user1", OrgID: "org1"})
	cache.Set(&EffectivePermissions{UserID: "user2", OrgID: "org1"})

	stats := cache.Stats()

	if stats.Entries != 2 {
		t.Errorf("Expected 2 entries, got %d", stats.Entries)
	}
	if stats.MaxEntries != 100 {
		t.Errorf("Expected max entries 100, got %d", stats.MaxEntries)
	}
}

func TestCacheSetWithCustomTTL(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 100,
	})

	perms := &EffectivePermissions{
		UserID: "user1",
		OrgID:  "org1",
	}

	// Set with short TTL
	cache.SetWithTTL(perms, 50*time.Millisecond)

	// Should exist immediately
	if cache.Get("user1", "org1") == nil {
		t.Fatal("Expected entry to exist immediately")
	}

	// Wait for custom TTL expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cache.Get("user1", "org1") != nil {
		t.Error("Expected entry to be expired after custom TTL")
	}
}

func TestCacheConcurrency(t *testing.T) {
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 1000,
	})
	defer cache.Stop()

	const numGoroutines = 100
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 4) // Set, Get, InvalidateUser, InvalidateOrg

	// Concurrent Sets
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				cache.Set(&EffectivePermissions{
					UserID:         fmt.Sprintf("user%d", workerID),
					OrgID:          fmt.Sprintf("org%d", j%10),
					AllowedMethods: []string{"eth_call"},
					Claims:         []Claim{},
				})
			}
		}(i)
	}

	// Concurrent Gets
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				cache.Get(fmt.Sprintf("user%d", workerID), fmt.Sprintf("org%d", j%10))
			}
		}(i)
	}

	// Concurrent InvalidateUser
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine/10; j++ {
				cache.InvalidateUser(fmt.Sprintf("user%d", (workerID+j)%numGoroutines))
			}
		}(i)
	}

	// Concurrent InvalidateOrg
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine/10; j++ {
				cache.InvalidateOrg(fmt.Sprintf("org%d", j%10))
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - no data race or deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out - possible deadlock")
	}
}

func TestCacheConcurrentEviction(t *testing.T) {
	// Test concurrent access with LRU eviction happening
	cache := NewCache(CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 10, // Small cache to force evictions
	})
	defer cache.Stop()

	const numGoroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// This will cause many evictions due to small cache size
				cache.Set(&EffectivePermissions{
					UserID:         fmt.Sprintf("user%d_%d", workerID, j),
					OrgID:          "org1",
					AllowedMethods: []string{"eth_call"},
				})
				cache.Get(fmt.Sprintf("user%d_%d", workerID, j), "org1")
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - no data race or deadlock under eviction pressure
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out - possible deadlock during eviction")
	}

	// Verify cache is still in valid state
	stats := cache.Stats()
	if stats.Entries > stats.MaxEntries {
		t.Errorf("Cache size %d exceeds max entries %d", stats.Entries, stats.MaxEntries)
	}
}

// TestCacheZeroValueMaxEntriesMatchesDefault pins the NewCache zero-value
// fallback to DefaultCacheConfig().MaxEntries. The two once drifted apart
// (fallback stayed at 10000 after the default was raised to 50000), which
// silently defeated the raise for the only production construction site,
// NewAccessController, which leaves MaxEntries unset.
func TestCacheZeroValueMaxEntriesMatchesDefault(t *testing.T) {
	cache := NewCache(CacheConfig{})
	defer cache.Stop()

	got := cache.Stats().MaxEntries
	want := DefaultCacheConfig().MaxEntries
	if got != want {
		t.Errorf("NewCache(CacheConfig{}) effective MaxEntries = %d, want DefaultCacheConfig().MaxEntries = %d", got, want)
	}
	if want != 50000 {
		t.Errorf("DefaultCacheConfig().MaxEntries = %d, want 50000 (raised intentionally by the perf pass)", want)
	}
}
