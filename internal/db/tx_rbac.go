package db

import (
	"context"
	"encoding/json"
	"fmt"

	"privacy-proxy/internal/rbac"
)

// Every *Tx method that has a *DB counterpart delegates to the shared
// DBTX-based implementation living next to the *DB method in its domain file
// (rbac_store_contract.go, rbac_store_group.go, rbac_store_user.go,
// rbac_store_cache.go). Do not re-declare SQL here — hand-copied twins drift
// (RD-1257; see tx_twin_divergence_test.go for the divergences that shipped).
// Methods below without a *DB counterpart are tx-only composites/helpers.

// Contract operations on transaction

func (t *Tx) CreateContract(ctx context.Context, contract *rbac.Contract) error {
	return createContract(ctx, t.tx, contract)
}

func (t *Tx) GetContract(ctx context.Context, id string) (*rbac.Contract, error) {
	return getContract(ctx, t.tx, id)
}

func (t *Tx) GetContractByAddress(ctx context.Context, orgID, address string) (*rbac.Contract, error) {
	return getContractByAddress(ctx, t.tx, orgID, address)
}

func (t *Tx) DeleteContract(ctx context.Context, id string) error {
	return deleteContract(ctx, t.tx, id)
}

// GetContractDeployerByAddress returns the user ID that deployed a contract at the given address.
// Returns nil if the contract is not found or has no deployer recorded.
func (t *Tx) GetContractDeployerByAddress(ctx context.Context, address string) (*string, error) {
	return getContractDeployerByAddress(ctx, t.tx, address)
}

func (t *Tx) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*rbac.Contract, error) {
	return getContractsByIDs(ctx, t.tx, ids)
}

// Contract Grant operations on transaction

func (t *Tx) CreateContractGrant(ctx context.Context, grant *rbac.ContractGrant) error {
	return createContractGrant(ctx, t.tx, grant)
}

func (t *Tx) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*rbac.ContractGrant, error) {
	return getContractGrantByContractAndGroup(ctx, t.tx, contractID, groupID)
}

func (t *Tx) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	return listContractGrantsByContract(ctx, t.tx, contractID)
}

func (t *Tx) DeleteContractGrant(ctx context.Context, id string) error {
	return deleteContractGrant(ctx, t.tx, id)
}

// DeleteContractGrantsByContract deletes all grants for a contract (tx-only).
func (t *Tx) DeleteContractGrantsByContract(ctx context.Context, contractID string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM contract_grants WHERE contract_id = $1`, contractID)
	return err
}

// Group operations on transaction

func (t *Tx) CreateGroup(ctx context.Context, group *rbac.Group) error {
	return createGroup(ctx, t.tx, group)
}

func (t *Tx) GetGroup(ctx context.Context, id string) (*rbac.Group, error) {
	return getGroup(ctx, t.tx, id)
}

func (t *Tx) DeleteGroup(ctx context.Context, id string) error {
	return deleteGroup(ctx, t.tx, id)
}

// Group Access operations on transaction

func (t *Tx) CreateGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	return createGroupAccess(ctx, t.tx, access)
}

func (t *Tx) DeleteGroupAccess(ctx context.Context, groupID string) error {
	return deleteGroupAccess(ctx, t.tx, groupID)
}

// Membership operations on transaction

func (t *Tx) CreateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	return createMembership(ctx, t.tx, membership)
}

func (t *Tx) DeleteMembership(ctx context.Context, id string) error {
	return deleteMembership(ctx, t.tx, id)
}

// DeleteMembershipsByGroup deletes all memberships of a group (tx-only).
func (t *Tx) DeleteMembershipsByGroup(ctx context.Context, groupID string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM user_memberships WHERE group_id = $1`, groupID)
	return err
}

// User operations on transaction

func (t *Tx) CreateUser(ctx context.Context, user *rbac.User) error {
	return createUser(ctx, t.tx, user)
}

func (t *Tx) GetUserByExternalID(ctx context.Context, externalID string) (*rbac.User, error) {
	return getUserByExternalID(ctx, t.tx, externalID)
}

// Cache invalidation on transaction

func (t *Tx) InvalidateCacheForGroup(ctx context.Context, groupID string) error {
	return invalidateCacheForGroup(ctx, t.tx, groupID)
}

func (t *Tx) InvalidateCacheForOrg(ctx context.Context, orgID string) error {
	return invalidateCacheForOrg(ctx, t.tx, orgID)
}

// CreateContractGrantIfNotExists creates a contract grant, ignoring duplicates (tx-only).
func (t *Tx) CreateContractGrantIfNotExists(ctx context.Context, grant *rbac.ContractGrant) error {
	query := `INSERT INTO contract_grants (id, contract_id, group_id, functions, event_rules)
	          VALUES ($1, $2, $3, $4, $5)
	          ON CONFLICT (contract_id, group_id) DO NOTHING`

	var functions any
	if grant.Functions != nil {
		b, err := json.Marshal(grant.Functions)
		if err != nil {
			return fmt.Errorf("failed to marshal functions: %w", err)
		}
		functions = b
	}

	eventRules := marshalEventRulesForDB(grant.EventRules)

	_, err := t.tx.ExecContext(ctx, query,
		grant.ID, grant.ContractID, grant.GroupID, functions, eventRules,
	)
	return err
}

// DeleteContractGrantsByContractAndGroups deletes grants for a contract from specific groups (tx-only).
func (t *Tx) DeleteContractGrantsByContractAndGroups(ctx context.Context, contractID string, groupIDs []string) error {
	if len(groupIDs) == 0 {
		return nil
	}
	query := `DELETE FROM contract_grants WHERE contract_id = $1 AND group_id = ANY($2)`
	_, err := t.tx.ExecContext(ctx, query, contractID, groupIDs)
	return err
}

// CountContractGrantsByGroup returns the number of grants for a group (tx-only).
func (t *Tx) CountContractGrantsByGroup(ctx context.Context, groupID string) (int, error) {
	var count int
	err := t.tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM contract_grants WHERE group_id = $1`, groupID,
	).Scan(&count)
	return count, err
}

// GetGroupsByIDs returns groups matching the given IDs within an org (tx-only).
// Selects the full group column set — batchDeleteGroups gates the RD-1099 /
// RD-1107 rules on IsOrgAdmin / IsOrgReadonlyAdmin / IsSystem read here.
func (t *Tx) GetGroupsByIDs(ctx context.Context, orgID string, ids []string) ([]*rbac.Group, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE org_id = $1 AND id = ANY($2)`
	rows, err := t.tx.QueryContext(ctx, query, orgID, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to get groups by IDs: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

// GetAutoCreatedGroupIDsForContracts returns auto-created group IDs that have grants to any of the given contracts (tx-only).
func (t *Tx) GetAutoCreatedGroupIDsForContracts(ctx context.Context, contractIDs []string) ([]string, error) {
	if len(contractIDs) == 0 {
		return nil, nil
	}
	query := `SELECT DISTINCT g.id FROM groups g
	          JOIN contract_grants cg ON g.id = cg.group_id
	          WHERE g.auto_created = true AND cg.contract_id = ANY($1)`
	rows, err := t.tx.QueryContext(ctx, query, contractIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeleteGroupWithDependenciesTx deletes a group and all its dependencies within an existing transaction.
func (t *Tx) DeleteGroupWithDependenciesTx(ctx context.Context, groupID string) error {
	if err := t.InvalidateCacheForGroup(ctx, groupID); err != nil {
		return fmt.Errorf("failed to invalidate cache: %w", err)
	}
	if err := t.DeleteMembershipsByGroup(ctx, groupID); err != nil {
		return fmt.Errorf("failed to delete memberships: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		`DELETE FROM contract_grants WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("failed to delete contract grants: %w", err)
	}
	if err := t.DeleteGroupAccess(ctx, groupID); err != nil {
		return fmt.Errorf("failed to delete group access: %w", err)
	}
	if err := t.DeleteGroup(ctx, groupID); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}
