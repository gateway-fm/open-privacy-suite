package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Group operations

func createGroup(ctx context.Context, q DBTX, group *rbac.Group) error {
	query := `INSERT INTO groups (id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, auto_created)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	          RETURNING created_at, updated_at`

	return q.QueryRowContext(ctx, query,
		group.ID, group.OrgID, group.ParentID, group.Slug, group.Name,
		group.Description, group.Depth, group.Path, group.IsOrgAdmin, group.IsOrgReadonlyAdmin, group.AutoCreated,
	).Scan(&group.CreatedAt, &group.UpdatedAt)
}

func (d *DB) CreateGroup(ctx context.Context, group *rbac.Group) error {
	return createGroup(ctx, d.conn, group)
}

func getGroup(ctx context.Context, q DBTX, id string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE id = $1`

	group := &rbac.Group{}
	var parentID sql.NullString
	var description sql.NullString

	err := q.QueryRowContext(ctx, query, id).Scan(
		&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
		&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.IsOrgReadonlyAdmin, &group.IsSystem, &group.AutoCreated, &group.CreatedAt, &group.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if parentID.Valid {
		group.ParentID = &parentID.String
	}
	if description.Valid {
		group.Description = description.String
	}

	return group, nil
}

func (d *DB) GetGroup(ctx context.Context, id string) (*rbac.Group, error) {
	return getGroup(ctx, d.conn, id)
}

func (d *DB) GetGroupBySlug(ctx context.Context, orgID, slug string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE org_id = $1 AND slug = $2`

	group := &rbac.Group{}
	var parentID sql.NullString
	var description sql.NullString

	err := d.conn.QueryRowContext(ctx, query, orgID, slug).Scan(
		&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
		&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.IsOrgReadonlyAdmin, &group.IsSystem, &group.AutoCreated, &group.CreatedAt, &group.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if parentID.Valid {
		group.ParentID = &parentID.String
	}
	if description.Valid {
		group.Description = description.String
	}

	return group, nil
}

func (d *DB) UpdateGroup(ctx context.Context, group *rbac.Group) error {
	query := `UPDATE groups SET slug = $2, name = $3, description = $4, is_org_admin = $5, is_org_readonly_admin = $6, auto_created = $7, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query, group.ID, group.Slug, group.Name, group.Description, group.IsOrgAdmin, group.IsOrgReadonlyAdmin, group.AutoCreated)
	return err
}

func (d *DB) ListGroups(ctx context.Context, orgID string) ([]*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE org_id = $1 ORDER BY path`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func (d *DB) ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*rbac.Group, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM groups WHERE org_id = $1`
	if err := d.conn.QueryRowContext(ctx, countQuery, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	// Get paginated results
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE org_id = $1 ORDER BY path LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	groups, err := scanGroups(rows)
	if err != nil {
		return nil, 0, err
	}

	return groups, total, nil
}

func (d *DB) ListGroupsWithAccessPaginated(ctx context.Context, orgID string, limit, offset int) ([]*rbac.GroupWithAccess, int, error) {
	var total int
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups WHERE org_id = $1`, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	query := `SELECT g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.is_org_readonly_admin, g.is_system, g.auto_created, g.created_at, g.updated_at,
	                 ga.id, ga.allowed_methods, ga.claims, ga.rpc_api_key, ga.created_at, ga.updated_at
	          FROM groups g
	          LEFT JOIN group_access ga ON g.id = ga.group_id
	          WHERE g.org_id = $1
	          ORDER BY g.path
	          LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups with access: %w", err)
	}
	defer rows.Close()

	var results []*rbac.GroupWithAccess
	for rows.Next() {
		group := &rbac.Group{}
		var parentID, description sql.NullString

		// Access fields (nullable from LEFT JOIN)
		var accessID sql.NullString
		var allowedMethods, claimsStr pq.StringArray
		var rpcAPIKey sql.NullString
		var accessCreatedAt, accessUpdatedAt sql.NullTime

		if err := rows.Scan(
			&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
			&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.IsOrgReadonlyAdmin, &group.IsSystem, &group.AutoCreated, &group.CreatedAt, &group.UpdatedAt,
			&accessID, &allowedMethods, &claimsStr, &rpcAPIKey, &accessCreatedAt, &accessUpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan group with access: %w", err)
		}

		if parentID.Valid {
			group.ParentID = &parentID.String
		}
		if description.Valid {
			group.Description = description.String
		}

		gwa := &rbac.GroupWithAccess{Group: group}

		if accessID.Valid {
			access := &rbac.GroupAccess{
				ID:             accessID.String,
				GroupID:        group.ID,
				AllowedMethods: []string(allowedMethods),
				CreatedAt:      accessCreatedAt.Time,
				UpdatedAt:      accessUpdatedAt.Time,
			}
			access.Claims = make([]rbac.Claim, len(claimsStr))
			for i, c := range claimsStr {
				access.Claims[i] = rbac.Claim(c)
			}
			if rpcAPIKey.Valid {
				access.RPCAPIKey = &rpcAPIKey.String
			}
			gwa.Access = access
		}

		results = append(results, gwa)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating groups with access: %w", err)
	}

	return results, total, nil
}

// escapeILIKE escapes PostgreSQL ILIKE metacharacters (%, _, \) in a search string.
func escapeILIKE(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// GroupListFilter contains optional filters for listing groups.
type GroupListFilter struct {
	Search string // ILIKE filter on name or slug
}

// ListGroupsWithAccessFiltered lists groups with access settings, applying optional filters.
func (d *DB) ListGroupsWithAccessFiltered(ctx context.Context, orgID string, limit, offset int, filter GroupListFilter) ([]*rbac.GroupWithAccess, int, error) {
	// Build WHERE clause dynamically
	where := "g.org_id = $1"
	args := []any{orgID}
	argIdx := 2

	if filter.Search != "" {
		where += fmt.Sprintf(" AND (g.name ILIKE $%d OR g.slug ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+escapeILIKE(filter.Search)+"%")
		argIdx++
	}

	// Count total
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM groups g WHERE %s", where)
	if err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	// Query with joins
	query := fmt.Sprintf(`SELECT g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.is_org_readonly_admin, g.is_system, g.auto_created, g.created_at, g.updated_at,
	                 ga.id, ga.allowed_methods, ga.claims, ga.rpc_api_key, ga.created_at, ga.updated_at
	          FROM groups g
	          LEFT JOIN group_access ga ON g.id = ga.group_id
	          WHERE %s
	          ORDER BY g.path
	          LIMIT $%d OFFSET $%d`, where, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups with access: %w", err)
	}
	defer rows.Close()

	var results []*rbac.GroupWithAccess
	for rows.Next() {
		group := &rbac.Group{}
		var parentID, description sql.NullString
		var accessID sql.NullString
		var allowedMethods, claimsStr pq.StringArray
		var rpcAPIKey sql.NullString
		var accessCreatedAt, accessUpdatedAt sql.NullTime

		if err := rows.Scan(
			&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
			&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.IsOrgReadonlyAdmin, &group.IsSystem, &group.AutoCreated, &group.CreatedAt, &group.UpdatedAt,
			&accessID, &allowedMethods, &claimsStr, &rpcAPIKey, &accessCreatedAt, &accessUpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan group with access: %w", err)
		}

		if parentID.Valid {
			group.ParentID = &parentID.String
		}
		if description.Valid {
			group.Description = description.String
		}

		gwa := &rbac.GroupWithAccess{Group: group}
		if accessID.Valid {
			access := &rbac.GroupAccess{
				ID:             accessID.String,
				GroupID:        group.ID,
				AllowedMethods: []string(allowedMethods),
				CreatedAt:      accessCreatedAt.Time,
				UpdatedAt:      accessUpdatedAt.Time,
			}
			access.Claims = make([]rbac.Claim, len(claimsStr))
			for i, c := range claimsStr {
				access.Claims[i] = rbac.Claim(c)
			}
			if rpcAPIKey.Valid {
				access.RPCAPIKey = &rpcAPIKey.String
			}
			gwa.Access = access
		}

		results = append(results, gwa)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating groups with access: %w", err)
	}

	return results, total, nil
}

func (d *DB) ListGroupsByParent(ctx context.Context, parentID string) ([]*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE parent_id = $1 ORDER BY name`

	rows, err := d.conn.QueryContext(ctx, query, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func (d *DB) GetGroupHierarchy(ctx context.Context, groupID string) ([]*rbac.Group, error) {
	// Get the group's path first
	group, err := d.GetGroup(ctx, groupID)
	if err != nil || group == nil {
		return nil, err
	}

	// If path is empty (groups created without a path), use slug as the path
	groupPath := group.Path
	if groupPath == "" {
		groupPath = group.Slug
	}

	// Parse the path and get all groups in the hierarchy
	pathParts := strings.Split(groupPath, ".")

	// Build query with parameter placeholders
	placeholders := make([]string, len(pathParts))
	args := make([]any, len(pathParts)+1)
	args[0] = group.OrgID
	for i, part := range pathParts {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = part
	}

	query := fmt.Sprintf(`SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, is_org_readonly_admin, is_system, auto_created, created_at, updated_at
	          FROM groups WHERE org_id = $1 AND slug IN (%s) ORDER BY depth`, strings.Join(placeholders, ", "))

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get group hierarchy: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func deleteGroup(ctx context.Context, q DBTX, id string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM groups WHERE id = $1`, id)
	return err
}

func (d *DB) DeleteGroup(ctx context.Context, id string) error {
	return deleteGroup(ctx, d.conn, id)
}

func scanGroups(rows *sql.Rows) ([]*rbac.Group, error) {
	var groups []*rbac.Group
	for rows.Next() {
		group := &rbac.Group{}
		var parentID sql.NullString
		var description sql.NullString

		if err := rows.Scan(
			&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
			&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.IsOrgReadonlyAdmin, &group.IsSystem, &group.AutoCreated, &group.CreatedAt, &group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}

		if parentID.Valid {
			group.ParentID = &parentID.String
		}
		if description.Valid {
			group.Description = description.String
		}

		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating groups: %w", err)
	}

	return groups, nil
}

// Group Access operations

func createGroupAccess(ctx context.Context, q DBTX, access *rbac.GroupAccess) error {
	// rpc_api_key_header column is intentionally not written; it stays at its
	// schema DEFAULT 'Authorization' (migration 043) and is not consulted at
	// runtime. The header name is operator-wide via the RPC_API_KEY_HEADER env
	// var (see internal/config and SetDefaultRPCAPIKeyHeader).
	query := `INSERT INTO group_access (id, group_id, allowed_methods, claims, rpc_api_key, verbose_errors)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.Claims))
	for i, c := range access.Claims {
		claims[i] = string(c)
	}

	return q.QueryRowContext(ctx, query,
		access.ID, access.GroupID,
		pq.Array(access.AllowedMethods), pq.Array(claims),
		access.RPCAPIKey, access.VerboseErrors,
	).Scan(&access.CreatedAt, &access.UpdatedAt)
}

func (d *DB) CreateGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	return createGroupAccess(ctx, d.conn, access)
}

// groupAccessColumns is the single definition of the group_access column list
// every access SELECT must use (single-row and batch variants scan through
// scanGroupAccessRow). The batch variant had drifted to a shorter list and
// silently dropped verbose_errors (RD-1257).
const groupAccessColumns = `id, group_id, allowed_methods, claims, rpc_api_key, verbose_errors, created_at, updated_at`

// scanGroupAccessRow scans one group_access row. The scanner is either a
// *sql.Row or a *sql.Rows positioned on a row.
func scanGroupAccessRow(s interface{ Scan(dest ...any) error }) (*rbac.GroupAccess, error) {
	access := &rbac.GroupAccess{}
	var allowedMethods, defaultClaims pq.StringArray
	var rpcAPIKey sql.NullString

	err := s.Scan(
		&access.ID, &access.GroupID,
		&allowedMethods, &defaultClaims,
		&rpcAPIKey, &access.VerboseErrors,
		&access.CreatedAt, &access.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan group access: %w", err)
	}

	access.AllowedMethods = allowedMethods
	access.Claims = make([]rbac.Claim, len(defaultClaims))
	for i, c := range defaultClaims {
		access.Claims[i] = rbac.Claim(c)
	}

	if rpcAPIKey.Valid {
		access.RPCAPIKey = &rpcAPIKey.String
	}

	return access, nil
}

func (d *DB) GetGroupAccess(ctx context.Context, groupID string) (*rbac.GroupAccess, error) {
	query := `SELECT ` + groupAccessColumns + `
	          FROM group_access WHERE group_id = $1`

	return scanGroupAccessRow(d.conn.QueryRowContext(ctx, query, groupID))
}

func (d *DB) GetGroupAccessBatch(ctx context.Context, groupIDs []string) (map[string]*rbac.GroupAccess, error) {
	if len(groupIDs) == 0 {
		return make(map[string]*rbac.GroupAccess), nil
	}

	query := `SELECT ` + groupAccessColumns + `
	          FROM group_access WHERE group_id = ANY($1)`

	rows, err := d.conn.QueryContext(ctx, query, pq.Array(groupIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to batch get group access: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*rbac.GroupAccess)
	for rows.Next() {
		access, err := scanGroupAccessRow(rows)
		if err != nil {
			return nil, err
		}
		result[access.GroupID] = access
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group access batch: %w", err)
	}

	return result, nil
}

func (d *DB) UpdateGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	// rpc_api_key_header is left untouched; see CreateGroupAccess for the rationale.
	query := `INSERT INTO group_access (id, group_id, allowed_methods, claims, rpc_api_key, verbose_errors)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          ON CONFLICT (group_id) DO UPDATE SET
	          allowed_methods = EXCLUDED.allowed_methods,
	          claims = EXCLUDED.claims,
	          rpc_api_key = EXCLUDED.rpc_api_key,
	          verbose_errors = EXCLUDED.verbose_errors,
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.Claims))
	for i, c := range access.Claims {
		claims[i] = string(c)
	}

	return d.conn.QueryRowContext(ctx, query,
		access.ID, access.GroupID,
		pq.Array(access.AllowedMethods), pq.Array(claims),
		access.RPCAPIKey, access.VerboseErrors,
	).Scan(&access.CreatedAt, &access.UpdatedAt)
}

// GroupVerboseErrorsForUserOrg reports whether the user (by external ID / DID)
// belongs to at least one NON-EXPIRED membership in a group of orgID whose
// group_access has verbose_errors enabled (RD-1137 Part A). Used on the denial
// path to decide whether to return the curated reason code on the wire.
// Callers treat an error as false (fail closed → opaque).
func (d *DB) GroupVerboseErrorsForUserOrg(ctx context.Context, externalID, orgID string) (bool, error) {
	var ok bool
	err := d.conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM user_memberships um
			JOIN users u ON u.id = um.user_id
			JOIN groups g ON g.id = um.group_id
			JOIN group_access ga ON ga.group_id = g.id
			WHERE u.external_id = $1
			  AND g.org_id = $2
			  AND ga.verbose_errors = true
			  AND (um.expires_at IS NULL OR um.expires_at > NOW())
		)`, externalID, orgID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("verbose-errors lookup: %w", err)
	}
	return ok, nil
}

func deleteGroupAccess(ctx context.Context, q DBTX, groupID string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM group_access WHERE group_id = $1`, groupID)
	return err
}

func (d *DB) DeleteGroupAccess(ctx context.Context, groupID string) error {
	return deleteGroupAccess(ctx, d.conn, groupID)
}

// SetGroupAccess creates or updates group access settings (alias for UpdateGroupAccess).
func (d *DB) SetGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	return d.UpdateGroupAccess(ctx, access)
}
