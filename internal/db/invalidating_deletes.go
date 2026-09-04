// Revoke operations that commit the cache invalidation together with the
// authorization mutation (RD-1267).
//
// Why these exist: the admin handlers used to invalidate the permission cache
// and then delete the contract / grant / group in a SEPARATE statement. That
// ordering defeats the generation guard. A compute could read the generation
// AFTER the invalidation had bumped it, read the grant that was still present,
// and publish once the delete had committed — the generation it snapshotted
// was by then unchanged, so the publication was accepted and the revoked
// permissions persisted for the whole cache TTL.
//
// Wrapping both in one transaction closes it: the bump, the cache-row delete
// and the domain delete become visible at a single instant. A compute that
// snapshotted the pre-mutation generation is rejected at publication, and a
// publication that slipped in beforehand has its row removed by the same
// transaction's cache delete.
//
// The invalidation runs FIRST inside each transaction, because
// invalidateCacheForGroup resolves affected users through user_memberships —
// rows the delete may remove. Order within the transaction does not affect
// atomicity; both statements commit together either way. This mirrors
// DeleteGroupWithDependencies, which invalidates "while we still have
// membership info" for the same reason.
package db

import (
	"context"
	"fmt"
)

// DeleteContractAndInvalidate deletes a contract and invalidates the org's
// cached permissions in one transaction. orgID scopes the invalidation, since
// removing a contract can affect grants held by many groups in that org.
func (d *DB) DeleteContractAndInvalidate(ctx context.Context, contractID, orgID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InvalidateCacheForOrg(ctx, orgID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}
		if err := tx.DeleteContract(ctx, contractID); err != nil {
			return fmt.Errorf("failed to delete contract: %w", err)
		}
		return nil
	})
}

// DeleteContractGrantAndInvalidate deletes a single contract grant and
// invalidates the cached permissions of the granted group's members in one
// transaction.
func (d *DB) DeleteContractGrantAndInvalidate(ctx context.Context, grantID, groupID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InvalidateCacheForGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}
		if err := tx.DeleteContractGrant(ctx, grantID); err != nil {
			return fmt.Errorf("failed to delete grant: %w", err)
		}
		return nil
	})
}

// DeleteGroupAndInvalidate deletes a group and invalidates the cached
// permissions of its members in one transaction.
//
// This is the plain-delete counterpart to DeleteGroupWithDependencies: it does
// not remove memberships, grants or access rows itself, matching what the
// admin delete-group handler has always relied on the schema to do.
func (d *DB) DeleteGroupAndInvalidate(ctx context.Context, groupID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.InvalidateCacheForGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}
		if err := tx.DeleteGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete group: %w", err)
		}
		return nil
	})
}
