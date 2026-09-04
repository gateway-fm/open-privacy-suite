package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Effective Permissions Cache operations

func (d *DB) GetCachedPermissions(ctx context.Context, userID, orgID string) (*rbac.EffectivePermissions, error) {
	query := `SELECT id, user_id, org_id, allowed_methods, contract_access, claims, computed_at, expires_at
	          FROM effective_permissions_cache WHERE user_id = $1 AND org_id = $2 AND expires_at > $3`

	perms := &rbac.EffectivePermissions{}
	var allowedMethods, claimsArr pq.StringArray
	var contractAccess []byte

	err := d.conn.QueryRowContext(ctx, query, userID, orgID, time.Now()).Scan(
		&perms.ID, &perms.UserID, &perms.OrgID,
		&allowedMethods, &contractAccess, &claimsArr,
		&perms.ComputedAt, &perms.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cached permissions: %w", err)
	}

	perms.AllowedMethods = allowedMethods
	perms.Claims = make([]rbac.Claim, len(claimsArr))
	for i, c := range claimsArr {
		perms.Claims[i] = rbac.Claim(c)
	}

	if len(contractAccess) > 0 {
		if err := json.Unmarshal(contractAccess, &perms.ContractAccess); err != nil {
			return nil, fmt.Errorf("failed to unmarshal contract_access: %w", err)
		}
	} else {
		perms.ContractAccess = make(map[string]rbac.ContractAccess)
	}

	return perms, nil
}

func (d *DB) SetCachedPermissions(ctx context.Context, perms *rbac.EffectivePermissions) error {
	return setCachedPermissions(ctx, d.conn, perms)
}

// setCachedPermissions is the single definition of the cache upsert, shared by
// the plain path and the generation-guarded path in rbac_cache_generation.go
// (which runs it inside a transaction that holds the generation row).
func setCachedPermissions(ctx context.Context, q DBTX, perms *rbac.EffectivePermissions) error {
	query := `INSERT INTO effective_permissions_cache (id, user_id, org_id, allowed_methods, contract_access, claims, computed_at, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	          ON CONFLICT (user_id, org_id) DO UPDATE SET
	          allowed_methods = EXCLUDED.allowed_methods,
	          contract_access = EXCLUDED.contract_access,
	          claims = EXCLUDED.claims,
	          computed_at = EXCLUDED.computed_at,
	          expires_at = EXCLUDED.expires_at`

	claimsArr := make([]string, len(perms.Claims))
	for i, c := range perms.Claims {
		claimsArr[i] = string(c)
	}

	contractAccess, _ := json.Marshal(perms.ContractAccess)

	_, err := q.ExecContext(ctx, query,
		perms.ID, perms.UserID, perms.OrgID,
		pq.Array(perms.AllowedMethods), contractAccess, pq.Array(claimsArr),
		perms.ComputedAt, perms.ExpiresAt,
	)
	return err
}

// Every invalidation also bumps the cache generation, in the same transaction
// as the DELETE, so a permission compute that is already in flight cannot
// publish its pre-mutation result afterwards (RD-1267,
// see rbac_cache_generation.go). The bump is deliberately inside the shared
// helpers, so the *Tx variants in tx_rbac.go inherit it and cannot forget.
//
// LOCK ORDER: the bump comes FIRST, before the DELETE. A publisher takes the
// generation row (FOR SHARE) and then touches cache rows; an invalidator that
// deleted cache rows first and only then reached for the counter would take
// the same two locks in the opposite order, which deadlocks when the two
// overlap (publisher holds the counter shared and waits on the invalidator's
// uncommitted delete of the row it is upserting, while the invalidator waits
// for exclusive access to the counter). Bumping first gives both paths the
// same order — counter, then cache rows — so the cycle cannot form. The
// outcome is unchanged either way, since both statements commit atomically.

func (d *DB) InvalidateCacheForUser(ctx context.Context, userID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := bumpCacheGeneration(ctx, tx.tx); err != nil {
			return err
		}
		_, err := tx.tx.ExecContext(ctx, `DELETE FROM effective_permissions_cache WHERE user_id = $1`, userID)
		return err
	})
}

func invalidateCacheForOrg(ctx context.Context, q DBTX, orgID string) error {
	if err := bumpCacheGeneration(ctx, q); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `DELETE FROM effective_permissions_cache WHERE org_id = $1`, orgID)
	return err
}

func (d *DB) InvalidateCacheForOrg(ctx context.Context, orgID string) error {
	return invalidateCacheForOrg(ctx, d.conn, orgID)
}

func invalidateCacheForGroup(ctx context.Context, q DBTX, groupID string) error {
	// Invalidate cache for all users who are members of this group
	if err := bumpCacheGeneration(ctx, q); err != nil {
		return err
	}
	query := `DELETE FROM effective_permissions_cache
	          WHERE user_id IN (SELECT user_id FROM user_memberships WHERE group_id = $1)`
	_, err := q.ExecContext(ctx, query, groupID)
	return err
}

func (d *DB) InvalidateCacheForGroup(ctx context.Context, groupID string) error {
	return invalidateCacheForGroup(ctx, d.conn, groupID)
}

func (d *DB) CleanupExpiredCache(ctx context.Context) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM effective_permissions_cache WHERE expires_at < $1`,
		time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
