package rbac

import (
	"context"
	"time"
)

// PermissionCache abstracts permission caching for horizontal scaling.
type PermissionCache interface {
	Get(userID, orgID string) *EffectivePermissions
	Set(perms *EffectivePermissions)
	SetWithTTL(perms *EffectivePermissions, ttl time.Duration)
	InvalidateUser(userID string)
	InvalidateOrg(orgID string)
	Invalidate(userID, orgID string)
	Clear()
	Size() int
	Stats() CacheStats
	Stop()
}

// Verify that the concrete type implements the interface.
var _ PermissionCache = (*Cache)(nil)

// CacheGenerationStore is the generation-guarded publication capability, and
// it is a MANDATORY part of Store (embedded there): a store reports a
// monotonic cache generation, and publishes a computed permission set only if
// that generation has not moved since the compute began (RD-1267).
//
// Why the counter cannot live in this process: the permission cache is a
// shared SQL table, and invalidation is a DELETE issued from inside the
// transaction that performs the mutation — usually from internal/db tx helpers
// or the admin_rbac_* handlers, which never call through the Resolver, and
// possibly from a different replica than the one computing. An in-process
// counter would therefore be blind to the dominant invalidation path even in a
// single-process deployment. The generation is bumped by the invalidating
// transaction itself, which is what makes the guard correct across both code
// paths and processes.
//
// SetCachedPermissionsAtGeneration reports whether the entry was published.
// false means the generation moved and the write was deliberately discarded:
// not an error, just a recompute on the next request. The failure direction is
// always discard-and-recompute, never serve-stale.
//
// It is embedded in Store rather than type-asserted at runtime (RD-1276). It
// was originally optional so that test doubles need not implement it, and the
// resolver fell back to an unconditional publish when the assertion failed —
// which is precisely the fail-open behaviour this guard exists to remove, and
// it would have been inherited silently by any second Store implementation
// (a Redis-backed cache being the motivating case). Making it mandatory turns
// "no guard" into a compile error; the cost that justified optionality
// disappeared when the three hand-written test doubles were consolidated into
// one shared fake (RD-1264).
type CacheGenerationStore interface {
	CacheGeneration(ctx context.Context) (int64, error)
	SetCachedPermissionsAtGeneration(ctx context.Context, perms *EffectivePermissions, generation int64) (bool, error)
}
