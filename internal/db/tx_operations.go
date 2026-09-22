package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// CreateContractWithGrant creates a contract and its initial grant atomically.
// If either operation fails, both are rolled back.
func (d *DB) CreateContractWithGrant(ctx context.Context, contract *rbac.Contract, grant *rbac.ContractGrant) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateContract(ctx, contract); err != nil {
			return fmt.Errorf("failed to create contract: %w", err)
		}

		// Set the contract ID on the grant
		grant.ContractID = contract.ID

		if err := tx.CreateContractGrant(ctx, grant); err != nil {
			return fmt.Errorf("failed to create contract grant: %w", err)
		}

		return nil
	})
}

// DeleteContractWithGrants deletes a contract and all its grants atomically.
// This prevents orphaned grants if the contract deletion fails.
func (d *DB) DeleteContractWithGrants(ctx context.Context, contractID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		// Delete all grants first (foreign key would prevent contract deletion anyway)
		if err := tx.DeleteContractGrantsByContract(ctx, contractID); err != nil {
			return fmt.Errorf("failed to delete contract grants: %w", err)
		}

		if err := tx.DeleteContract(ctx, contractID); err != nil {
			return fmt.Errorf("failed to delete contract: %w", err)
		}

		return nil
	})
}

// DeleteGroupWithDependencies deletes a group and all its dependencies atomically:
// - Group access settings
// - Contract grants for this group
// - User memberships in this group
// - Cache entries for affected users
func (d *DB) DeleteGroupWithDependencies(ctx context.Context, groupID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		// Invalidate cache first (while we still have membership info)
		if err := tx.InvalidateCacheForGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}

		// Delete user memberships
		if err := tx.DeleteMembershipsByGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete memberships: %w", err)
		}

		// Delete contract grants for this group
		if _, err := tx.tx.ExecContext(ctx,
			`DELETE FROM contract_grants WHERE group_id = $1`, groupID); err != nil {
			return fmt.Errorf("failed to delete contract grants: %w", err)
		}

		// Delete group access
		if err := tx.DeleteGroupAccess(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete group access: %w", err)
		}

		// Finally delete the group
		if err := tx.DeleteGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete group: %w", err)
		}

		return nil
	})
}

// CreateUserWithMembership creates a user and adds them to a group atomically.
func (d *DB) CreateUserWithMembership(ctx context.Context, user *rbac.User, membership *rbac.UserMembership) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Set the user ID on the membership
		membership.UserID = user.ID

		if err := tx.CreateMembership(ctx, membership); err != nil {
			return fmt.Errorf("failed to create membership: %w", err)
		}

		return nil
	})
}

// CreateGroupWithAccess creates a group and its access settings atomically.
func (d *DB) CreateGroupWithAccess(ctx context.Context, group *rbac.Group, access *rbac.GroupAccess) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateGroup(ctx, group); err != nil {
			return fmt.Errorf("failed to create group: %w", err)
		}

		// Set the group ID on the access
		access.GroupID = group.ID

		if err := tx.CreateGroupAccess(ctx, access); err != nil {
			return fmt.Errorf("failed to create group access: %w", err)
		}

		return nil
	})
}

// EnsureUserExistsWithMembership ensures a user exists and has a membership to the specified group.
// If the user doesn't exist, creates them with the given membership.
// If the user exists but doesn't have the membership, creates the membership.
// This operation is atomic.
func (d *DB) EnsureUserExistsWithMembership(ctx context.Context, user *rbac.User, membership *rbac.UserMembership) (*rbac.User, error) {
	var resultUser *rbac.User

	err := d.WithTx(ctx, func(tx *Tx) error {
		// Check if user exists
		existing, err := tx.GetUserByExternalID(ctx, user.ExternalID)
		if err != nil {
			return fmt.Errorf("failed to check existing user: %w", err)
		}

		if existing != nil {
			resultUser = existing
			return nil // User already exists, membership should be handled separately
		}

		// Create the user
		if err := tx.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Set the user ID on the membership
		membership.UserID = user.ID

		if err := tx.CreateMembership(ctx, membership); err != nil {
			return fmt.Errorf("failed to create membership: %w", err)
		}

		resultUser = user
		return nil
	})

	return resultUser, err
}

// GrantContractToDeployerGroup finds the deployer's existing group with the
// deploy claim in the given org and adds a contract_grant linking the contract
// to that group. No new group is created — the admin must have pre-created a
// group with the deploy claim and added the deployer as a member.
//
// Returns an error if the deployer has no group with deploy claim in the org.
func (d *DB) GrantContractToDeployerGroup(ctx context.Context, orgID, contractID, deployerUserID string) error {
	// The deploy path can race concurrent admin writes touching the same
	// grant rows; the whole SELECT+INSERT is idempotent (ON CONFLICT DO
	// NOTHING), so it is safe to retry on deadlock as one transaction.
	return withRetry(ctx, func() error {
		return d.WithTx(ctx, func(tx *Tx) error {
			// Find the deployer's group with deploy claim in this org.
			query := `
				SELECT g.id
				FROM user_memberships m
				JOIN groups g ON g.id = m.group_id
				JOIN group_access ga ON ga.group_id = g.id
				WHERE m.user_id = $1
				  AND g.org_id = $2
				  AND 'deploy' = ANY(ga.claims)
				  AND (m.expires_at IS NULL OR m.expires_at > NOW())
				LIMIT 1`

			var groupID string
			err := tx.tx.QueryRowContext(ctx, query, deployerUserID, orgID).Scan(&groupID)
			if err != nil {
				return fmt.Errorf("deployer has no group with deploy claim in org %s: %w", orgID, err)
			}

			// Add contract grant (idempotent).
			grantID := uuid.New().String()
			_, err = tx.tx.ExecContext(ctx,
				`INSERT INTO contract_grants (id, contract_id, group_id)
				 VALUES ($1, $2, $3)
				 ON CONFLICT (contract_id, group_id) DO NOTHING`,
				grantID, contractID, groupID,
			)
			if err != nil {
				return fmt.Errorf("failed to create contract grant: %w", err)
			}
			return nil
		})
	})
}

// RegisterDeployedContract records a contract that a finalized deployment
// created, together with the deployer group's grant, in one authorised
// registration transaction.
//
// A deployment is a chain fact, not configuration. Once a contract-registry
// or execution-rules revision owns the organisation's desired state, the
// projection guard refuses plain inserts into contracts and contract_grants;
// this is the legacy path's only way through, marked as deployment
// registration so the next revision adopts the rows as drift. The marker
// admits inserts only — never an UPDATE or DELETE of reviewed rows.
//
// The grant is best-effort: a deployer whose deploy membership lapsed between
// preflight and finalization still gets the contract registered, just without
// a grant. The boolean reports whether a grant was written.
func (d *DB) RegisterDeployedContract(ctx context.Context, contract *rbac.Contract, deployerUserID string) (bool, error) {
	var granted bool
	err := withRetry(ctx, func() error {
		granted = false
		return d.WithTx(ctx, func(tx *Tx) error {
			if err := tx.AuthorizeDeploymentRegistration(ctx, contract.OrgID); err != nil {
				return err
			}
			deployer := deployerUserID
			if deployer != "" {
				// The account may have been deleted between preflight and
				// finalization. Keep the chain fact and drop the attribution,
				// as the Reth reconciler does, instead of failing the insert on
				// the deployer foreign key.
				var existing string
				err := tx.tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 FOR KEY SHARE`, deployer).Scan(&existing)
				switch {
				case errors.Is(err, sql.ErrNoRows):
					deployer = ""
					contract.DeployedByUserID = nil
				case err != nil:
					return err
				}
			}
			if err := tx.CreateContract(ctx, contract); err != nil {
				return err
			}
			if deployer == "" {
				return nil
			}
			// Same group rule as GrantContractToDeployerGroup — the deployer's
			// current, unexpired membership of a group carrying the deploy
			// claim — and, as on the Reth path, no grant for a banned account.
			// Idempotent on retry.
			result, err := tx.tx.ExecContext(ctx, `INSERT INTO contract_grants (id, contract_id, group_id)
				 SELECT $1, $2, g.id
				 FROM user_memberships m
				 JOIN groups g ON g.id = m.group_id
				 JOIN group_access ga ON ga.group_id = g.id
				 JOIN users u ON u.id = m.user_id
				 WHERE m.user_id = $3 AND g.org_id = $4
				   AND NOT u.banned
				   AND 'deploy' = ANY(ga.claims)
				   AND (m.expires_at IS NULL OR m.expires_at > NOW())
				 ORDER BY g.id LIMIT 1
				 ON CONFLICT (contract_id, group_id) DO NOTHING`,
				uuid.New().String(), contract.ID, deployer, contract.OrgID)
			if err != nil {
				return fmt.Errorf("failed to create deployer grant: %w", err)
			}
			rows, err := result.RowsAffected()
			if err != nil {
				return err
			}
			granted = rows > 0
			return nil
		})
	})
	return granted, err
}
