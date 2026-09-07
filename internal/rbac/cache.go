package rbac

import (
	"sync"
	"sync/atomic"
	"time"
)

// Cache provides an in-memory cache for effective permissions.
// It uses a TTL-based expiration with approximate-LRU eviction at capacity.
//
// Read path (Get) is the proxy hot path: it takes a shared read lock and does
// an O(1) map lookup, recording recency via a per-entry atomic timestamp (no
// list mutation). Eviction (write path, only at capacity) samples a small set
// of entries and drops the oldest — O(sample), not O(n). This keeps Get cheap
// and contention-free under concurrency (RD-1112); TTL remains the correctness
// boundary, eviction is purely memory management so approximate LRU is fine.
type Cache struct {
	mu         sync.RWMutex
	wg         sync.WaitGroup
	entries    map[string]*cacheEntry
	ttl        time.Duration
	maxEntries int
	stopCh     chan struct{}
}

type cacheEntry struct {
	permissions *EffectivePermissions
	expiresAt   time.Time
	// lastAccess is unix-nanos of the most recent read, updated atomically so
	// the Get fast path can record recency while holding only a read lock.
	lastAccess atomic.Int64
}

// CacheConfig holds configuration for the permission cache.
type CacheConfig struct {
	TTL        time.Duration // Default TTL for cache entries (default: 5 minutes)
	MaxEntries int           // Maximum number of entries (default: 50000)
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		TTL:        5 * time.Minute,
		MaxEntries: 50000,
	}
}

// evictSampleSize is the number of entries sampled when choosing a victim for
// eviction at capacity. Go map iteration order is randomized, so sampling a
// small fixed set and dropping the oldest approximates LRU in O(sample) time
// without scanning the whole map. Mirrors Redis's sampled-LRU approach.
const evictSampleSize = 8

// NewCache creates a new permission cache.
func NewCache(config CacheConfig) *Cache {
	if config.TTL == 0 {
		config.TTL = 5 * time.Minute
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = 50000
	}

	c := &Cache{
		entries:    make(map[string]*cacheEntry),
		ttl:        config.TTL,
		maxEntries: config.MaxEntries,
		stopCh:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	c.wg.Add(1)
	go c.cleanupLoop()

	return c
}

// cacheKey creates a unique key for a user+org combination.
func cacheKey(userID, orgID string) string {
	return userID + ":" + orgID
}

// Get retrieves cached permissions for a user in an organization.
// Returns nil if not found or expired.
//
// Hot path: takes only a read lock for the map lookup, then records recency via
// an atomic store on the (immutable-after-construction) entry. expiresAt and
// permissions are never mutated in place — Set installs a fresh *cacheEntry —
// so they are safe to read after releasing the lock.
func (c *Cache) Get(userID, orgID string) *EffectivePermissions {
	key := cacheKey(userID, orgID)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	entry.lastAccess.Store(time.Now().UnixNano())
	return entry.permissions
}

// Set stores permissions in the cache using the default TTL.
func (c *Cache) Set(perms *EffectivePermissions) {
	c.SetWithTTL(perms, c.ttl)
}

// SetWithTTL stores permissions with a custom TTL.
func (c *Cache) SetWithTTL(perms *EffectivePermissions, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(perms.UserID, perms.OrgID)

	// Check if we need to evict entries
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		c.evictLRU()
	}

	expiresAt := time.Now().Add(ttl)
	// Never cache past the permissions' own expiry. computePermissions caps
	// EffectivePermissions.ExpiresAt at the soonest membership expires_at, so a
	// time-boxed access window (RD-1145) revokes promptly: this in-memory
	// entry — checked before the resolver on the hot path — cannot outlive the
	// window, so once it lapses the next lookup re-resolves and the expired
	// membership is filtered out. Without this cap the cache would keep serving
	// stale perms for the full TTL after the window closed (the DB-backed cache
	// already stores perms.ExpiresAt, so only this layer needed the cap).
	if !perms.ExpiresAt.IsZero() && perms.ExpiresAt.Before(expiresAt) {
		expiresAt = perms.ExpiresAt
	}

	entry := &cacheEntry{
		permissions: perms,
		expiresAt:   expiresAt,
	}
	entry.lastAccess.Store(time.Now().UnixNano())
	c.entries[key] = entry
}

// InvalidateUser removes all cached permissions for a user.
func (c *Cache) InvalidateUser(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find and delete all entries for this user
	for key := range c.entries {
		if len(key) > len(userID) && key[:len(userID)] == userID && key[len(userID)] == ':' {
			delete(c.entries, key)
		}
	}
}

// InvalidateOrg removes all cached permissions for an organization.
func (c *Cache) InvalidateOrg(orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	suffix := ":" + orgID
	for key := range c.entries {
		if len(key) > len(suffix) && key[len(key)-len(suffix):] == suffix {
			delete(c.entries, key)
		}
	}
}

// Invalidate removes a specific user+org entry from the cache.
func (c *Cache) Invalidate(userID, orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, cacheKey(userID, orgID))
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
}

// Size returns the current number of entries in the cache.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Stats returns cache statistics.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var expired int
	now := time.Now()
	for _, entry := range c.entries {
		if now.After(entry.expiresAt) {
			expired++
		}
	}

	return CacheStats{
		Entries:        len(c.entries),
		ExpiredPending: expired,
		MaxEntries:     c.maxEntries,
	}
}

// CacheStats contains cache statistics.
type CacheStats struct {
	Entries        int `json:"entries"`
	ExpiredPending int `json:"expired_pending"`
	MaxEntries     int `json:"max_entries"`
}

// evictLRU removes an approximately least-recently-used entry.
// Must be called with the write lock held. Samples up to evictSampleSize
// entries and drops the one with the oldest recorded access time — O(sample),
// not O(n). Because eviction only runs at capacity and recency is approximate,
// this is sufficient for memory management without scanning the whole map.
func (c *Cache) evictLRU() {
	var victim string
	var oldest int64
	seen := 0
	for key, entry := range c.entries {
		access := entry.lastAccess.Load()
		if seen == 0 || access < oldest {
			victim = key
			oldest = access
		}
		seen++
		if seen >= evictSampleSize {
			break
		}
	}
	if victim != "" {
		delete(c.entries, victim)
	}
}

// cleanupLoop periodically removes expired entries.
func (c *Cache) cleanupLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (c *Cache) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

// cleanup removes expired entries from the cache.
func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}
