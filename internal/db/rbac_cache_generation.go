package db

import (
	"context"
	"fmt"

	"privacy-proxy/internal/rbac"
)

// The permission cache is a shared SQL table, and a compute that started
// before a mutation committed must not publish its now-stale result
// (RD-1267). rbac_cache_generation holds one monotonic counter that every
// invalidation increments inside its own transaction; the resolver reads it
// before computing and publishes only if it has not moved.
//
// The counter is in the database rather than in process memory on purpose:
// invalidation is issued from inside DB transactions that never call through
// the resolver (see the Tx variants in tx_rbac.go and the admin_rbac_*
// handlers), and the table is shared by every replica, so an in-process
// counter would miss the dominant invalidation path even single-process.
var _ rbac.CacheGenerationStore = (*DB)(nil)

// cacheGenerationRowID pins the single row. The table's CHECK (id = 1)
// enforces it in the schema too, so the counter cannot silently split.
const cacheGenerationRowID = 1

// CacheGeneration returns the current permission-cache generation.
func (d *DB) CacheGeneration(ctx context.Context) (int64, error) {
	var generation int64
	err := d.conn.QueryRowContext(ctx,
		`SELECT generation FROM rbac_cache_generation WHERE id = $1`,
		cacheGenerationRowID,
	).Scan(&generation)
	if err != nil {
		return 0, fmt.Errorf("failed to read rbac cache generation: %w", err)
	}
	return generation, nil
}

// bumpCacheGeneration increments the generation counter. It MUST run in the
// same transaction as the invalidating DELETE, so that a publisher which
// observes the old generation is guaranteed to be serialized behind this
// UPDATE's row lock (see SetCachedPermissionsAtGeneration).
func bumpCacheGeneration(ctx context.Context, q DBTX) error {
	if _, err := q.ExecContext(ctx,
		`UPDATE rbac_cache_generation SET generation = generation + 1 WHERE id = $1`,
		cacheGenerationRowID,
	); err != nil {
		return fmt.Errorf("failed to bump rbac cache generation: %w", err)
	}
	return nil
}

// SetCachedPermissionsAtGeneration publishes perms only if the cache
// generation still equals wantGeneration, i.e. no invalidation committed
// while the permissions were being computed. It reports whether the entry was
// published; false is a normal outcome, not an error, and simply means the
// next request will recompute.
//
// Correctness of the two orderings, which is the whole point of the FOR SHARE:
//
//   - Invalidator commits first: the SELECT sees the bumped generation,
//     the comparison fails, nothing is written.
//   - Invalidator has not committed yet: its UPDATE already holds an
//     exclusive row lock on the counter, so this FOR SHARE blocks until it
//     commits — and then observes the bumped generation and refuses. Without
//     the lock, a plain read under READ COMMITTED would see the old value,
//     publish, and the invalidator's already-executed DELETE would not remove
//     the row that appeared after it scanned — leaving stale permissions
//     cached for the full TTL.
//
// Publishers do not contend with each other: FOR SHARE is shared, so only an
// actual in-flight invalidation ever blocks a publication.
func (d *DB) SetCachedPermissionsAtGeneration(ctx context.Context, perms *rbac.EffectivePermissions, wantGeneration int64) (bool, error) {
	published := false
	err := d.WithTx(ctx, func(tx *Tx) error {
		var current int64
		if err := tx.tx.QueryRowContext(ctx,
			`SELECT generation FROM rbac_cache_generation WHERE id = $1 FOR SHARE`,
			cacheGenerationRowID,
		).Scan(&current); err != nil {
			return fmt.Errorf("failed to lock rbac cache generation: %w", err)
		}
		if current != wantGeneration {
			// Invalidated during the compute — discard the publication.
			return nil
		}
		if err := setCachedPermissions(ctx, tx.tx, perms); err != nil {
			return err
		}
		published = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return published, nil
}
