package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Contract operations

func (d *DB) CreateContract(ctx context.Context, contract *rbac.Contract) error {
	query := `INSERT INTO contracts (id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	          RETURNING created_at, updated_at`

	metadata, err := json.Marshal(contract.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal contract metadata: %w", err)
	}

	var abi *string
	if contract.ABI != "" {
		abi = &contract.ABI
	}

	return d.conn.QueryRowContext(ctx, query,
		contract.ID, contract.OrgID, strings.ToLower(contract.Address), contract.Name,
		abi, contract.DeployedByUserID, contract.DeployedAt, metadata,
	).Scan(&contract.CreatedAt, &contract.UpdatedAt)
}

func (d *DB) GetContract(ctx context.Context, id string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE id = $1`

	return scanContract(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetContractByAddress(ctx context.Context, orgID, address string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE org_id = $1 AND lower(address) = $2`

	return scanContract(d.conn.QueryRowContext(ctx, query, orgID, strings.ToLower(address)))
}

func (d *DB) GetContractByAddressGlobal(ctx context.Context, address string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE lower(address) = $1`

	return scanContract(d.conn.QueryRowContext(ctx, query, strings.ToLower(address)))
}

func (d *DB) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*rbac.Contract, error) {
	if len(ids) == 0 {
		return make(map[string]*rbac.Contract), nil
	}

	query := `SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE id = ANY($1)`

	rows, err := d.conn.QueryContext(ctx, query, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to get contracts by IDs: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*rbac.Contract)
	for rows.Next() {
		contract := &rbac.Contract{}
		var name, abi sql.NullString
		var deployedByUserID sql.NullString
		var deployedAt sql.NullTime
		var metadata []byte
		var methodPolicies []byte

		err := rows.Scan(
			&contract.ID, &contract.OrgID, &contract.Address, &name, &abi,
			&deployedByUserID, &deployedAt, &metadata, &contract.AllowVisibleToUnlock, &contract.EventsAllowDynamicPayload,
			&methodPolicies, &contract.CreatedAt, &contract.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan contract: %w", err)
		}

		contract.Name = name.String
		contract.ABI = abi.String
		if deployedByUserID.Valid {
			contract.DeployedByUserID = &deployedByUserID.String
		}
		if deployedAt.Valid {
			contract.DeployedAt = &deployedAt.Time
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &contract.Metadata)
		}
		if len(methodPolicies) > 0 {
			contract.MethodPolicies = methodPolicies
		}

		result[contract.ID] = contract
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contracts: %w", err)
	}

	return result, nil
}

func (d *DB) UpdateContract(ctx context.Context, contract *rbac.Contract) error {
	query := `UPDATE contracts SET name = $2, abi = $3, metadata = $4, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	metadata, err := json.Marshal(contract.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal contract metadata: %w", err)
	}

	var abi *string
	if contract.ABI != "" {
		abi = &contract.ABI
	}

	_, err = d.conn.ExecContext(ctx, query, contract.ID, contract.Name, abi, metadata)
	return err
}

func (d *DB) ListContracts(ctx context.Context, orgID string) ([]*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE org_id = $1 ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contracts: %w", err)
	}
	defer rows.Close()

	return scanContracts(rows)
}

func (d *DB) ListContractsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*rbac.Contract, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM contracts WHERE org_id = $1`
	if err := d.conn.QueryRowContext(ctx, countQuery, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count contracts: %w", err)
	}

	// Get paginated results
	query := `SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list contracts: %w", err)
	}
	defer rows.Close()

	contracts, err := scanContracts(rows)
	if err != nil {
		return nil, 0, err
	}

	return contracts, total, nil
}

// ContractListFilter contains optional filters for listing contracts.
type ContractListFilter struct {
	Search        string // ILIKE filter on name or address
	CreatedAfter  string // ISO8601 date — only contracts created on or after this date
	CreatedBefore string // ISO8601 date — only contracts created before this date
}

// ListContractsFiltered lists contracts with optional search filter.
func (d *DB) ListContractsFiltered(ctx context.Context, orgID string, limit, offset int, filter ContractListFilter) ([]*rbac.Contract, int, error) {
	where := "org_id = $1"
	args := []any{orgID}
	argIdx := 2

	if filter.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR address ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+escapeILIKE(filter.Search)+"%")
		argIdx++
	}
	if filter.CreatedAfter != "" {
		where += fmt.Sprintf(" AND created_at >= $%d", argIdx)
		args = append(args, filter.CreatedAfter)
		argIdx++
	}
	if filter.CreatedBefore != "" {
		where += fmt.Sprintf(" AND created_at < $%d", argIdx)
		args = append(args, filter.CreatedBefore)
		argIdx++
	}

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM contracts WHERE %s", where)
	if err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count contracts: %w", err)
	}

	query := fmt.Sprintf(`SELECT id, org_id, address, name, abi, deployed_by_user_id, deployed_at, metadata, allow_visibleto_unlock, events_allow_dynamic_payload, method_policies, created_at, updated_at
	          FROM contracts WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list contracts: %w", err)
	}
	defer rows.Close()

	contracts, err := scanContracts(rows)
	if err != nil {
		return nil, 0, err
	}

	return contracts, total, nil
}

// GetAllRegisteredAddresses returns all contract addresses registered to any org.
// This includes both finalized contracts and preregistered (pending) addresses.
// Used to build visibility filters — only org-registered addresses can be hidden.
func (d *DB) GetAllRegisteredAddresses(ctx context.Context) ([]string, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT LOWER(address) FROM contracts
		UNION
		SELECT LOWER(address) FROM preregistered_addresses`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, rows.Err()
}

func (d *DB) DeleteContract(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM contracts WHERE id = $1`, id)
	return err
}

// UpdateContractAllowVisibleToUnlock toggles the per-contract opt-in
// flag for the RD-874 visibleTo unlock semantic. Admin-only. Setting
// this true authorises tx senders on this contract to grant per-event
// access to anyone they list in `visibleTo`, scoped to that one tx.
// See decisions.md §12 for the full security implications.
func (d *DB) UpdateContractAllowVisibleToUnlock(ctx context.Context, id string, allow bool) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE contracts SET allow_visibleto_unlock = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
		id, allow)
	return err
}

// UpdateContractMethodPolicies persists (or clears) the per-contract method
// access policy document (RD-1206). policies is the raw validated JSON, or nil
// to clear (feature off). Validation against the contract's ABI happens in the
// admin handler before this is called; the store just persists.
func (d *DB) UpdateContractMethodPolicies(ctx context.Context, id string, policies []byte) error {
	var arg any
	if len(policies) > 0 {
		arg = policies
	} // else nil → SQL NULL
	_, err := d.conn.ExecContext(ctx,
		`UPDATE contracts SET method_policies = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
		id, arg)
	return err
}

// UpdateContractEventsAllowDynamicPayload toggles the per-contract
// opt-out for the M15 dynamic-payload event drop (security audit
// follow-up to RD-915). Admin-only. Setting this true tells
// RedactLogs / FilterEventLogs to pass through events with dynamic
// non-indexed parameters (bytes, string, dynamic arrays/structs)
// for this contract even when the viewer didn't earn Full visibility
// via admin claim, participant override, or visibleTo unlock.
//
// Operators should set this only after confirming that the
// contract's events DO NOT embed foreign-org addresses inside
// dynamic payloads (typical for standard ERC-20/ERC-721, dangerous
// for bridge / forwarder / smart-wallet flows).
func (d *DB) UpdateContractEventsAllowDynamicPayload(ctx context.Context, id string, allow bool) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE contracts SET events_allow_dynamic_payload = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
		id, allow)
	return err
}

// GetBatchEventsAllowDynamicPayload returns the M15 opt-out flag for
// each provided address (lowercase). Addresses not in the contracts
// table or with the flag unset map to false (default-deny: drop logs
// with dynamic payloads). Used by RedactLogs / FilterEventLogs to
// resolve the flag for every emitting contract in a batch.
func (d *DB) GetBatchEventsAllowDynamicPayload(ctx context.Context, addresses []string) (map[string]bool, error) {
	result := make(map[string]bool, len(addresses))
	if len(addresses) == 0 {
		return result, nil
	}
	lower := make([]string, len(addresses))
	for i, a := range addresses {
		lower[i] = strings.ToLower(a)
	}
	const query = `
		SELECT LOWER(address), events_allow_dynamic_payload
		FROM contracts
		WHERE LOWER(address) = ANY($1)
	`
	rows, err := d.conn.QueryContext(ctx, query, pq.Array(lower))
	if err != nil {
		return nil, fmt.Errorf("batch events_allow_dynamic_payload: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var addr string
		var allow bool
		if err := rows.Scan(&addr, &allow); err != nil {
			return nil, fmt.Errorf("scan events_allow_dynamic_payload: %w", err)
		}
		result[addr] = allow
	}
	return result, rows.Err()
}

// UpdateContractABI updates only the ABI field of a contract.
func (d *DB) UpdateContractABI(ctx context.Context, id string, abi string) error {
	var abiValue *string
	if abi != "" {
		abiValue = &abi
	}
	_, err := d.conn.ExecContext(ctx,
		`UPDATE contracts SET abi = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
		id, abiValue)
	return err
}

// IsContractRegisteredToAnyOrg checks if a contract address is registered in ANY organization.
// This is used for cross-org isolation to prevent users from accessing contracts belonging
// to other organizations via default_claims fallback.
func (d *DB) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM contracts WHERE LOWER(address) = LOWER($1))`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, address).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check contract registration: %w", err)
	}
	return exists, nil
}

// IsAddressOwnedByOrg checks if a contract address belongs to the given organization.
// This includes both registered contracts AND preregistered CREATE3 addresses.
// This is used to verify that call targets in deployed contracts are org-owned.
func (d *DB) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM contracts WHERE LOWER(address) = LOWER($1) AND org_id = $2
			UNION
			SELECT 1 FROM preregistered_addresses WHERE LOWER(address) = LOWER($1) AND org_id = $2
		)
	`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, address, orgID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check contract ownership: %w", err)
	}
	return exists, nil
}

// GetContractOwnerOrgID returns the org ID that owns a contract address.
// Returns empty string if the contract is not registered to any organization.
// This checks both registered contracts and preregistered addresses.
func (d *DB) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	query := `
		SELECT org_id FROM contracts WHERE LOWER(address) = LOWER($1)
		UNION
		SELECT org_id FROM preregistered_addresses WHERE LOWER(address) = LOWER($1)
		LIMIT 1
	`
	var orgID string
	err := d.conn.QueryRowContext(ctx, query, address).Scan(&orgID)
	if err == sql.ErrNoRows {
		return "", nil // Not registered to any org (public contract)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get contract owner org: %w", err)
	}
	return orgID, nil
}

// GetContractDeployerByAddress returns the user ID that deployed a contract at the given address.
// Returns nil if the contract is not found or has no deployer recorded.
// Used by the deployer auto-grant: the deployer's group is automatically granted access to the contract.
func (d *DB) GetContractDeployerByAddress(ctx context.Context, address string) (*string, error) {
	query := `SELECT deployed_by_user_id FROM contracts WHERE LOWER(address) = LOWER($1)`
	var deployerID sql.NullString
	err := d.conn.QueryRowContext(ctx, query, address).Scan(&deployerID)
	if err == sql.ErrNoRows {
		return nil, nil // Contract not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get contract deployer: %w", err)
	}
	if !deployerID.Valid {
		return nil, nil // No deployer recorded
	}
	return &deployerID.String, nil
}

// ViewerHasContractAccess checks if a user (identified by DID) is a member of any group
// that has a contract grant for the given contract ID.
func (d *DB) ViewerHasContractAccess(ctx context.Context, viewerDID, contractID string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM contract_grants cg
			JOIN user_memberships m ON m.group_id = cg.group_id
			JOIN users u ON u.id = m.user_id
			WHERE cg.contract_id = $1
			  AND u.external_id = $2
			  AND (m.expires_at IS NULL OR m.expires_at > NOW())
		)`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, contractID, viewerDID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func scanContract(row *sql.Row) (*rbac.Contract, error) {
	contract := &rbac.Contract{}
	var name, abi sql.NullString
	var deployedByUserID sql.NullString
	var deployedAt sql.NullTime
	var metadata []byte
	var methodPolicies []byte

	err := row.Scan(
		&contract.ID, &contract.OrgID, &contract.Address, &name, &abi,
		&deployedByUserID, &deployedAt, &metadata, &contract.AllowVisibleToUnlock, &contract.EventsAllowDynamicPayload,
		&methodPolicies, &contract.CreatedAt, &contract.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan contract: %w", err)
	}
	if len(methodPolicies) > 0 {
		contract.MethodPolicies = methodPolicies
	}

	if name.Valid {
		contract.Name = name.String
	}
	if abi.Valid {
		contract.ABI = abi.String
	}
	if deployedByUserID.Valid {
		contract.DeployedByUserID = &deployedByUserID.String
	}
	if deployedAt.Valid {
		contract.DeployedAt = &deployedAt.Time
	}

	if err := json.Unmarshal(metadata, &contract.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return contract, nil
}

func scanContracts(rows *sql.Rows) ([]*rbac.Contract, error) {
	var contracts []*rbac.Contract
	for rows.Next() {
		contract := &rbac.Contract{}
		var name, abi sql.NullString
		var deployedByUserID sql.NullString
		var deployedAt sql.NullTime
		var metadata []byte
		var methodPolicies []byte

		if err := rows.Scan(
			&contract.ID, &contract.OrgID, &contract.Address, &name, &abi,
			&deployedByUserID, &deployedAt, &metadata, &contract.AllowVisibleToUnlock, &contract.EventsAllowDynamicPayload,
			&methodPolicies, &contract.CreatedAt, &contract.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract: %w", err)
		}
		if len(methodPolicies) > 0 {
			contract.MethodPolicies = methodPolicies
		}

		if name.Valid {
			contract.Name = name.String
		}
		if abi.Valid {
			contract.ABI = abi.String
		}
		if deployedByUserID.Valid {
			contract.DeployedByUserID = &deployedByUserID.String
		}
		if deployedAt.Valid {
			contract.DeployedAt = &deployedAt.Time
		}

		if err := json.Unmarshal(metadata, &contract.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		contracts = append(contracts, contract)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contracts: %w", err)
	}

	return contracts, nil
}

// Contract Grant operations

func (d *DB) CreateContractGrant(ctx context.Context, grant *rbac.ContractGrant) error {
	query := `INSERT INTO contract_grants (id, contract_id, group_id, functions, event_rules)
	          VALUES ($1, $2, $3, $4, $5)
	          RETURNING created_at, updated_at`

	var functions any
	if grant.Functions != nil {
		b, err := json.Marshal(grant.Functions)
		if err != nil {
			return fmt.Errorf("failed to marshal functions: %w", err)
		}
		functions = b
	}

	eventRules := marshalEventRulesForDB(grant.EventRules)

	return d.conn.QueryRowContext(ctx, query,
		grant.ID, grant.ContractID, grant.GroupID, functions, eventRules,
	).Scan(&grant.CreatedAt, &grant.UpdatedAt)
}

func (d *DB) GetContractGrant(ctx context.Context, id string) (*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, functions, event_rules, created_at, updated_at
	          FROM contract_grants WHERE id = $1`

	return scanContractGrant(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, functions, event_rules, created_at, updated_at
	          FROM contract_grants WHERE contract_id = $1 AND group_id = $2`

	return scanContractGrant(d.conn.QueryRowContext(ctx, query, contractID, groupID))
}

func (d *DB) UpdateContractGrant(ctx context.Context, grant *rbac.ContractGrant) error {
	query := `UPDATE contract_grants SET functions = $2, event_rules = $3, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	var functions any
	if grant.Functions != nil {
		b, err := json.Marshal(grant.Functions)
		if err != nil {
			return fmt.Errorf("failed to marshal functions: %w", err)
		}
		functions = b
	}

	eventRules := marshalEventRulesForDB(grant.EventRules)

	_, err := d.conn.ExecContext(ctx, query, grant.ID, functions, eventRules)
	return err
}

func (d *DB) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, functions, event_rules, created_at, updated_at
	          FROM contract_grants WHERE contract_id = $1 ORDER BY created_at`

	rows, err := d.conn.QueryContext(ctx, query, contractID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants: %w", err)
	}
	defer rows.Close()

	return scanContractGrants(rows)
}

func (d *DB) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, functions, event_rules, created_at, updated_at
	          FROM contract_grants WHERE group_id = $1 ORDER BY created_at`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants: %w", err)
	}
	defer rows.Close()

	return scanContractGrants(rows)
}

func (d *DB) ListContractGrantsBatch(ctx context.Context, groupIDs []string) (map[string][]*rbac.ContractGrant, error) {
	if len(groupIDs) == 0 {
		return make(map[string][]*rbac.ContractGrant), nil
	}

	query := `SELECT id, contract_id, group_id, functions, created_at, updated_at
	          FROM contract_grants WHERE group_id = ANY($1) ORDER BY created_at`

	rows, err := d.conn.QueryContext(ctx, query, pq.Array(groupIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to batch list contract grants: %w", err)
	}
	defer rows.Close()

	result := make(map[string][]*rbac.ContractGrant)
	for rows.Next() {
		grant := &rbac.ContractGrant{}
		var functionsJSON []byte

		if err := rows.Scan(
			&grant.ID, &grant.ContractID, &grant.GroupID,
			&functionsJSON, &grant.CreatedAt, &grant.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract grant: %w", err)
		}

		if len(functionsJSON) > 0 {
			if err := json.Unmarshal(functionsJSON, &grant.Functions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal functions: %w", err)
			}
		}

		result[grant.GroupID] = append(result[grant.GroupID], grant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contract grants batch: %w", err)
	}

	return result, nil
}

func (d *DB) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*rbac.ContractGrantWithGroup, error) {
	query := `SELECT cg.id, cg.contract_id, cg.group_id, cg.functions, cg.event_rules, cg.created_at, cg.updated_at,
	                 g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.created_at, g.updated_at
	          FROM contract_grants cg
	          JOIN groups g ON cg.group_id = g.id
	          WHERE cg.group_id = $1 ORDER BY cg.created_at`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants with group: %w", err)
	}
	defer rows.Close()

	var results []*rbac.ContractGrantWithGroup
	for rows.Next() {
		result := &rbac.ContractGrantWithGroup{
			Grant: &rbac.ContractGrant{},
			Group: &rbac.Group{},
		}

		var functionsJSON, eventRulesJSON []byte
		var parentID, description sql.NullString

		if err := rows.Scan(
			&result.Grant.ID, &result.Grant.ContractID, &result.Grant.GroupID,
			&functionsJSON, &eventRulesJSON, &result.Grant.CreatedAt, &result.Grant.UpdatedAt,
			&result.Group.ID, &result.Group.OrgID, &parentID, &result.Group.Slug,
			&result.Group.Name, &description, &result.Group.Depth, &result.Group.Path, &result.Group.IsOrgAdmin,
			&result.Group.CreatedAt, &result.Group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract grant with group: %w", err)
		}

		if len(functionsJSON) > 0 {
			if err := json.Unmarshal(functionsJSON, &result.Grant.Functions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal functions: %w", err)
			}
		}
		result.Grant.EventRules = unmarshalEventRulesFromDB(eventRulesJSON)
		if parentID.Valid {
			result.Group.ParentID = &parentID.String
		}
		if description.Valid {
			result.Group.Description = description.String
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contract grants: %w", err)
	}

	return results, nil
}

func (d *DB) DeleteContractGrant(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM contract_grants WHERE id = $1`, id)
	return err
}

func scanContractGrant(row *sql.Row) (*rbac.ContractGrant, error) {
	grant := &rbac.ContractGrant{}
	var functionsJSON, eventRulesJSON []byte

	err := row.Scan(
		&grant.ID, &grant.ContractID, &grant.GroupID,
		&functionsJSON, &eventRulesJSON, &grant.CreatedAt, &grant.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan contract grant: %w", err)
	}

	if len(functionsJSON) > 0 {
		if err := json.Unmarshal(functionsJSON, &grant.Functions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal functions: %w", err)
		}
	}
	grant.EventRules = unmarshalEventRulesFromDB(eventRulesJSON)

	return grant, nil
}

func scanContractGrants(rows *sql.Rows) ([]*rbac.ContractGrant, error) {
	var grants []*rbac.ContractGrant
	for rows.Next() {
		grant := &rbac.ContractGrant{}
		var functionsJSON, eventRulesJSON []byte

		if err := rows.Scan(
			&grant.ID, &grant.ContractID, &grant.GroupID,
			&functionsJSON, &eventRulesJSON, &grant.CreatedAt, &grant.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract grant: %w", err)
		}

		if len(functionsJSON) > 0 {
			if err := json.Unmarshal(functionsJSON, &grant.Functions); err != nil {
				return nil, fmt.Errorf("failed to unmarshal functions: %w", err)
			}
		}
		grant.EventRules = unmarshalEventRulesFromDB(eventRulesJSON)

		grants = append(grants, grant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contract grants: %w", err)
	}

	return grants, nil
}

// ListContractGrants lists grants for a contract (alias for ListContractGrantsByContract).
func (d *DB) ListContractGrants(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	return d.ListContractGrantsByContract(ctx, contractID)
}

// ListContractGrantsForGroup lists grants for a group (alias for ListContractGrantsByGroup).
func (d *DB) ListContractGrantsForGroup(ctx context.Context, groupID string) ([]*rbac.ContractGrant, error) {
	return d.ListContractGrantsByGroup(ctx, groupID)
}

// GetContractGrantSummary returns grant counts and group names for all contracts in an org.
// Returns map of contractID -> {Count, Groups}.
func (d *DB) GetContractGrantSummary(ctx context.Context, orgID string) (map[string]*rbac.ContractGrantSummary, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT cg.contract_id, g.id, g.name
		FROM contract_grants cg
		JOIN contracts c ON c.id = cg.contract_id
		JOIN groups g ON g.id = cg.group_id
		WHERE c.org_id = $1
		ORDER BY cg.contract_id, g.name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]*rbac.ContractGrantSummary)
	for rows.Next() {
		var contractID, groupID, groupName string
		if err := rows.Scan(&contractID, &groupID, &groupName); err != nil {
			return nil, err
		}
		if _, ok := result[contractID]; !ok {
			result[contractID] = &rbac.ContractGrantSummary{Groups: []rbac.GroupSummary{}}
		}
		result[contractID].Count++
		result[contractID].Groups = append(result[contractID].Groups, rbac.GroupSummary{ID: groupID, Name: groupName})
	}
	return result, rows.Err()
}

// marshalEventRulesForDB converts an *EventRulesField to a value suitable for
// a JSONB column. Returns nil (SQL NULL) for deny state, or the JSON bytes
// for wildcard ("*") or allowlist ([{...}]).
func marshalEventRulesForDB(f *rbac.EventRulesField) any {
	if f == nil || f.IsDeny() {
		return nil // SQL NULL
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	return b
}

// unmarshalEventRulesFromDB converts raw JSONB bytes from the DB into an
// *EventRulesField. Returns nil (deny) when the DB value is NULL (empty bytes).
// Handles legacy array values and the new "*" wildcard string.
func unmarshalEventRulesFromDB(data []byte) *rbac.EventRulesField {
	if len(data) == 0 {
		return nil // SQL NULL → deny
	}
	var f rbac.EventRulesField
	if err := json.Unmarshal(data, &f); err != nil {
		// If unmarshal fails, treat as deny (fail-closed).
		return nil
	}
	// Normalize: if the parsed result is deny, return nil pointer for consistency.
	if f.IsDeny() {
		return nil
	}
	return &f
}
