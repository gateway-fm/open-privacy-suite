package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"privacy-proxy/internal/rbac"
)

// User role values accepted by UserFilter.Role.
const (
	UserRoleOrgAdmin = "org_admin" // member of any group with is_org_admin=true
	UserRoleAdmin    = "admin"     // member of any group with a contract_grant carrying 'admin' claim
	UserRoleMember   = "member"    // has memberships but is neither org_admin nor admin
)

// User operations

func createUser(ctx context.Context, q DBTX, user *rbac.User) error {
	query := `INSERT INTO users (id, external_id, kyc, banned, note, metadata, auth_tenant_id)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING created_at, updated_at`

	metadata, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return q.QueryRowContext(ctx, query,
		user.ID, user.ExternalID, user.KYC, user.Banned, user.Note, metadata, user.AuthTenantID,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
}

func (d *DB) CreateUser(ctx context.Context, user *rbac.User) error {
	return createUser(ctx, d.conn, user)
}

func (d *DB) GetUser(ctx context.Context, id string) (*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, auth_tenant_id, created_at, updated_at
	          FROM users WHERE id = $1`

	return scanUserRow(d.conn.QueryRowContext(ctx, query, id))
}

func getUserByExternalID(ctx context.Context, q DBTX, externalID string) (*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, auth_tenant_id, created_at, updated_at
	          FROM users WHERE external_id = $1`

	return scanUserRow(q.QueryRowContext(ctx, query, externalID))
}

func (d *DB) GetUserByExternalID(ctx context.Context, externalID string) (*rbac.User, error) {
	return getUserByExternalID(ctx, d.conn, externalID)
}

// UpdateUser updates mutable user fields. auth_tenant_id is deliberately
// excluded — use SetAuthTenantID to set it once (immutable after first write).
func (d *DB) UpdateUser(ctx context.Context, user *rbac.User) error {
	query := `UPDATE users SET kyc = $2, banned = $3, note = $4, metadata = $5, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	metadata, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query, user.ID, user.KYC, user.Banned, user.Note, metadata)
	return err
}

// SetAuthTenantID pins a user to an Azure AD tenant. The update only succeeds
// when auth_tenant_id is currently NULL, enforcing immutability at the DB level.
// Returns true if the value was set, false if it was already set (no-op).
func (d *DB) SetAuthTenantID(ctx context.Context, userID string, tenantID string) (bool, error) {
	result, err := d.conn.ExecContext(ctx,
		`UPDATE users SET auth_tenant_id = $2, updated_at = CURRENT_TIMESTAMP
		 WHERE id = $1 AND auth_tenant_id IS NULL`,
		userID, tenantID,
	)
	if err != nil {
		return false, fmt.Errorf("failed to set auth_tenant_id: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows > 0, nil
}

func (d *DB) ListUsers(ctx context.Context, limit, offset int) ([]*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, auth_tenant_id, created_at, updated_at
	          FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := d.conn.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	return scanUsers(rows)
}

// UserFilter contains filter options for listing users.
//
// All fields except ScopedOrgIDs are user-supplied query params.
// ScopedOrgIDs is set by the handler from the caller's auth context: nil
// for super-admin (X-Admin-Token), or the admin's accessible org IDs for
// JWT org-admins. When non-nil, results are restricted to users with at
// least one membership in those orgs and Role/GroupIDs scope-checks
// honour the same restriction.
type UserFilter struct {
	OrgID        string   // Filter by organization (users with memberships in this org)
	Search       string   // Search by DID (external_id) or linked ETH address
	GroupIDs     []string // Filter to users with membership in any of these groups
	Role         string   // Filter by role: org_admin, admin, member (empty = no filter)
	ScopedOrgIDs []string // Cross-org isolation: org IDs the caller may see (nil = unrestricted)
}

// buildUserFilterClauses assembles the FROM/WHERE fragments and parameterised
// args for a UserFilter. Returns (from, where, args, nextArgNum). All filter
// values are bound parameters; no string concatenation of user input.
func buildUserFilterClauses(filter UserFilter) (from string, where string, args []any, argNum int) {
	from = `FROM users u`
	argNum = 1
	var conditions []string

	if filter.OrgID != "" {
		from += `
		    JOIN user_memberships m_org ON u.id = m_org.user_id
		    JOIN groups g_org ON m_org.group_id = g_org.id`
		conditions = append(conditions, fmt.Sprintf("g_org.org_id = $%d", argNum))
		args = append(args, filter.OrgID)
		argNum++
	}

	if filter.Search != "" {
		from += `
		    LEFT JOIN eth_address_links e ON u.external_id = e.did`
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(u.external_id ILIKE $%d OR e.eth_address ILIKE $%d)", argNum, argNum+1))
		args = append(args, searchPattern, searchPattern)
		argNum += 2
	}

	if len(filter.GroupIDs) > 0 {
		conditions = append(conditions, fmt.Sprintf(`EXISTS (
		    SELECT 1 FROM user_memberships m_grp
		    WHERE m_grp.user_id = u.id AND m_grp.group_id = ANY($%d))`, argNum))
		args = append(args, filter.GroupIDs)
		argNum++
	}

	// ScopedOrgIDs (non-nil) restricts results to users with at least one
	// membership in those orgs. Used for JWT org-admin cross-org isolation.
	// Empty slice means "no orgs visible" -> no users match.
	if filter.ScopedOrgIDs != nil {
		conditions = append(conditions, fmt.Sprintf(`EXISTS (
		    SELECT 1 FROM user_memberships m_scope
		    JOIN groups g_scope ON m_scope.group_id = g_scope.id
		    WHERE m_scope.user_id = u.id AND g_scope.org_id = ANY($%d))`, argNum))
		args = append(args, filter.ScopedOrgIDs)
		argNum++
	}

	switch filter.Role {
	case UserRoleOrgAdmin:
		conditions = append(conditions, roleOrgAdminClause(filter.ScopedOrgIDs, &args, &argNum))
	case UserRoleAdmin:
		conditions = append(conditions, roleAdminClause(filter.ScopedOrgIDs, &args, &argNum))
	case UserRoleMember:
		// member = has at least one membership but is neither org_admin nor admin
		conditions = append(conditions, fmt.Sprintf(`EXISTS (
		    SELECT 1 FROM user_memberships m_mem WHERE m_mem.user_id = u.id)
		AND NOT %s
		AND NOT %s`,
			roleOrgAdminClause(filter.ScopedOrgIDs, &args, &argNum),
			roleAdminClause(filter.ScopedOrgIDs, &args, &argNum)))
	}

	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}
	return from, where, args, argNum
}

// roleOrgAdminClause returns an EXISTS predicate matching users with
// membership in any group with is_org_admin=true. When scopedOrgIDs is
// non-nil, the predicate is restricted to those orgs.
func roleOrgAdminClause(scopedOrgIDs []string, args *[]any, argNum *int) string {
	scope := ""
	if scopedOrgIDs != nil {
		scope = fmt.Sprintf(" AND g_role.org_id = ANY($%d)", *argNum)
		*args = append(*args, scopedOrgIDs)
		*argNum++
	}
	return fmt.Sprintf(`EXISTS (
	    SELECT 1 FROM user_memberships m_role
	    JOIN groups g_role ON m_role.group_id = g_role.id
	    WHERE m_role.user_id = u.id AND g_role.is_org_admin = true%s)`, scope)
}

// roleAdminClause returns an EXISTS predicate matching users in groups
// holding any contract grant with the 'admin' claim (tier-3 contract
// admin). Restricted to scopedOrgIDs when non-nil.
func roleAdminClause(scopedOrgIDs []string, args *[]any, argNum *int) string {
	scope := ""
	if scopedOrgIDs != nil {
		scope = fmt.Sprintf(" AND g_adm.org_id = ANY($%d)", *argNum)
		*args = append(*args, scopedOrgIDs)
		*argNum++
	}
	return fmt.Sprintf(`EXISTS (
	    SELECT 1 FROM user_memberships m_adm
	    JOIN groups g_adm ON m_adm.group_id = g_adm.id
	    JOIN contract_grants cg_adm ON cg_adm.group_id = g_adm.id
	    WHERE m_adm.user_id = u.id AND 'admin' = ANY(cg_adm.claims)%s)`, scope)
}

// ListUsersFiltered returns users matching the given filters
func (d *DB) ListUsersFiltered(ctx context.Context, filter UserFilter, limit, offset int) ([]*rbac.User, error) {
	from, where, args, argNum := buildUserFilterClauses(filter)
	query := fmt.Sprintf(`SELECT DISTINCT u.id, u.external_id, u.kyc, u.banned, u.note, u.metadata, u.auth_tenant_id, u.created_at, u.updated_at
	          %s%s ORDER BY u.created_at DESC LIMIT $%d OFFSET $%d`, from, where, argNum, argNum+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	return scanUsers(rows)
}

func (d *DB) ListUsersPaginated(ctx context.Context, limit, offset int) ([]*rbac.User, int, error) {
	var total int
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	users, err := d.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (d *DB) ListUsersFilteredPaginated(ctx context.Context, filter UserFilter, limit, offset int) ([]*rbac.User, int, error) {
	from, where, args, argNum := buildUserFilterClauses(filter)

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(DISTINCT u.id) %s%s", from, where)
	var total int
	if err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Data query
	dataQuery := fmt.Sprintf("SELECT DISTINCT u.id, u.external_id, u.kyc, u.banned, u.note, u.metadata, u.auth_tenant_id, u.created_at, u.updated_at %s%s ORDER BY u.created_at DESC LIMIT $%d OFFSET $%d", from, where, argNum, argNum+1)
	dataArgs := append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users, err := scanUsers(rows)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// scanUserRow scans one 9-column user row. The scanner is either a *sql.Row
// or a *sql.Rows positioned on a row — this is the single definition of the
// user column list; every user SELECT must scan through it (RD-1257).
func scanUserRow(s interface{ Scan(dest ...any) error }) (*rbac.User, error) {
	user := &rbac.User{}
	var note sql.NullString
	var metadata []byte

	err := s.Scan(
		&user.ID, &user.ExternalID, &user.KYC, &user.Banned, &note, &metadata, &user.AuthTenantID,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	if note.Valid {
		user.Note = note.String
	}

	if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return user, nil
}

func scanUsers(rows *sql.Rows) ([]*rbac.User, error) {
	var users []*rbac.User
	for rows.Next() {
		user, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// ListGroupMembershipsForUsers returns each given user's group memberships
// as a flat list of UserGroupMembership summaries, keyed by user ID.
//
// When scopedOrgIDs is non-nil, results are restricted to memberships in
// those orgs (cross-org isolation for JWT-based org admins). nil means
// unrestricted (super-admin).
//
// Users with no memberships in scope are absent from the returned map.
func (d *DB) ListGroupMembershipsForUsers(ctx context.Context, userIDs []string, scopedOrgIDs []string) (map[string][]rbac.UserGroupMembership, error) {
	if len(userIDs) == 0 {
		return map[string][]rbac.UserGroupMembership{}, nil
	}

	query := `SELECT m.user_id, g.id, g.slug, g.name, g.org_id, g.is_org_admin
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          WHERE m.user_id = ANY($1)`
	args := []any{userIDs}

	if scopedOrgIDs != nil {
		query += ` AND g.org_id = ANY($2)`
		args = append(args, scopedOrgIDs)
	}

	query += ` ORDER BY g.name ASC`

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships for users: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]rbac.UserGroupMembership, len(userIDs))
	for rows.Next() {
		var userID string
		var m rbac.UserGroupMembership
		if err := rows.Scan(&userID, &m.GroupID, &m.Slug, &m.Name, &m.OrgID, &m.IsOrgAdmin); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		out[userID] = append(out[userID], m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating memberships: %w", err)
	}
	return out, nil
}

// BanUsersByTenantID bans all users belonging to the given Azure AD tenant.
// Returns the number of users banned.
func (d *DB) BanUsersByTenantID(ctx context.Context, tenantID, reason string) (int64, error) {
	query := `UPDATE users SET banned = true, note = $2, updated_at = CURRENT_TIMESTAMP
	          WHERE auth_tenant_id = $1 AND banned = false`

	result, err := d.conn.ExecContext(ctx, query, tenantID, reason)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// RevokeRefreshTokensByTenantID revokes all active refresh tokens for users belonging
// to the given Azure AD tenant. Returns the number of tokens revoked.
func (d *DB) RevokeRefreshTokensByTenantID(ctx context.Context, tenantID string) (int64, error) {
	query := `UPDATE refresh_tokens
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE revoked = false
	            AND subject IN (SELECT external_id FROM users WHERE auth_tenant_id = $1)`

	result, err := d.conn.ExecContext(ctx, query, tenantID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (d *DB) DeleteUser(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// Membership operations

// utcPtr returns the time in UTC, preserving nil. user_memberships.expires_at
// is a plain TIMESTAMP (no zone); storing UTC keeps the wall-clock pgx writes
// aligned with the UTC session used by the `expires_at > NOW()` checks, so an
// expired membership can never read as active under a non-UTC process tz
// (RD-1005).
func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func createMembership(ctx context.Context, q DBTX, membership *rbac.UserMembership) error {
	query := `INSERT INTO user_memberships (id, user_id, group_id, source, zk_credential_ref, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	return q.QueryRowContext(ctx, query,
		membership.ID, membership.UserID, membership.GroupID,
		string(membership.Source), membership.ZKCredentialRef, utcPtr(membership.ExpiresAt),
	).Scan(&membership.CreatedAt, &membership.UpdatedAt)
}

func (d *DB) CreateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	return createMembership(ctx, d.conn, membership)
}

// CreateMembershipIfNotExists atomically inserts a membership if no row with the
// same (user_id, group_id) exists. Uses INSERT ... ON CONFLICT DO NOTHING to
// avoid TOCTOU races. Returns true if a new row was inserted, false if it
// already existed.
func (d *DB) CreateMembershipIfNotExists(ctx context.Context, membership *rbac.UserMembership) (bool, error) {
	query := `INSERT INTO user_memberships (id, user_id, group_id, source, zk_credential_ref, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          ON CONFLICT (user_id, group_id) DO NOTHING
	          RETURNING created_at, updated_at`

	err := d.conn.QueryRowContext(ctx, query,
		membership.ID, membership.UserID, membership.GroupID,
		string(membership.Source), membership.ZKCredentialRef, utcPtr(membership.ExpiresAt),
	).Scan(&membership.CreatedAt, &membership.UpdatedAt)
	if err == sql.ErrNoRows {
		// ON CONFLICT DO NOTHING — membership already exists
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to create membership: %w", err)
	}
	return true, nil
}

func (d *DB) GetMembership(ctx context.Context, id string) (*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE id = $1`

	return scanMembership(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE user_id = $1 AND group_id = $2`

	return scanMembership(d.conn.QueryRowContext(ctx, query, userID, groupID))
}

func (d *DB) UpdateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	query := `UPDATE user_memberships SET source = $2, zk_credential_ref = $3, expires_at = $4, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query,
		membership.ID, string(membership.Source),
		membership.ZKCredentialRef, utcPtr(membership.ExpiresAt),
	)
	return err
}

func (d *DB) ListUserMemberships(ctx context.Context, userID string) ([]*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE user_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	return scanMemberships(rows)
}

func (d *DB) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*rbac.MembershipWithDetails, error) {
	query := `SELECT m.id, m.user_id, m.group_id, m.source, m.zk_credential_ref, m.expires_at, m.created_at, m.updated_at,
	                 ` + prefixColumns("g", groupColumns) + `
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          WHERE m.user_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships with details: %w", err)
	}
	defer rows.Close()

	return scanMembershipsWithDetails(rows)
}

func (d *DB) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*rbac.MembershipWithDetails, error) {
	// Expired memberships are excluded so that a time-boxed grant (regulator
	// access window, RD-1145) is *enforced* at access-decision time:
	// computePermissions builds the user's effective methods/claims/visibility
	// from this list, so an expired row must contribute nothing. Same
	// fail-closed idiom as the IsOrgAdmin / IsOrgReadonlyAdmin / HasAdminClaim
	// checks (NULL = never expires; the DB session runs in UTC). The
	// background cleanup (expiredMembershipCleanupLoop) only tidies the rows
	// away afterwards — this filter is the actual revocation boundary, so an
	// expired window blocks access immediately, not at the next sweep.
	query := `SELECT m.id, m.user_id, m.group_id, m.source, m.zk_credential_ref, m.expires_at, m.created_at, m.updated_at,
	                 ` + prefixColumns("g", groupColumns) + `
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          WHERE m.user_id = $1 AND g.org_id = $2
	            AND (m.expires_at IS NULL OR m.expires_at > NOW())`

	rows, err := d.conn.QueryContext(ctx, query, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	return scanMembershipsWithDetails(rows)
}

func (d *DB) ListGroupMembers(ctx context.Context, groupID string) ([]*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE group_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list group members: %w", err)
	}
	defer rows.Close()

	return scanMemberships(rows)
}

func deleteMembership(ctx context.Context, q DBTX, id string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM user_memberships WHERE id = $1`, id)
	return err
}

func (d *DB) DeleteMembership(ctx context.Context, id string) error {
	return deleteMembership(ctx, d.conn, id)
}

// HasAdminClaim checks whether a user (identified by internal ID) has the "admin"
// claim via any of their group memberships.  It performs a single DB query joining
// user_memberships → group_access and checking the claims array.
func (d *DB) HasAdminClaim(ctx context.Context, userID string) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1
		FROM user_memberships m
		JOIN group_access ga ON ga.group_id = m.group_id
		WHERE m.user_id = $1
		  AND 'admin' = ANY(ga.claims)
		  AND (m.expires_at IS NULL OR m.expires_at > NOW())
	)`

	var exists bool
	if err := d.conn.QueryRowContext(ctx, query, userID).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check admin claim: %w", err)
	}
	return exists, nil
}

// Compile-time guarantee that the production store satisfies rbac's optional
// OrgAdminChecker extension (RD-1164 #14). AccessController's historical-state
// guard type-asserts the store to this interface and falls OPEN only when it is
// absent; making conformance a build requirement means the production store can
// never silently lose IsOrgAdmin and drop into that fail-open branch — a
// dropped/renamed method breaks the build instead.
var _ rbac.OrgAdminChecker = (*DB)(nil)

// IsOrgAdmin checks whether a user (identified by internal ID) is a member of
// any group with is_org_admin = true. Returns true if the user is an org admin
// in at least one org, along with the list of org IDs where they hold org admin
// status. This is stricter than HasAdminClaim: having 'admin' in group_access.claims
// alone (tier 3 contract admin) does NOT qualify — the group must have is_org_admin = true.
func (d *DB) IsOrgAdmin(ctx context.Context, userID string) (bool, []string, error) {
	query := `SELECT DISTINCT g.org_id
		FROM user_memberships m
		JOIN groups g ON g.id = m.group_id
		WHERE m.user_id = $1
		  AND g.is_org_admin = true
		  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to check org admin status: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return false, nil, fmt.Errorf("failed to scan org admin result: %w", err)
		}
		orgIDs = append(orgIDs, orgID)
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("error iterating org admin results: %w", err)
	}

	return len(orgIDs) > 0, orgIDs, nil
}

// IsOrgReadonlyAdmin checks whether a user (identified by internal ID) is a member of
// any group with is_org_readonly_admin = true. Returns true if the user is a readonly
// admin in at least one org, along with the org IDs where they hold that status.
// Readonly admins can call all GET admin endpoints in scoped orgs but cannot mutate
// (RD-866).
func (d *DB) IsOrgReadonlyAdmin(ctx context.Context, userID string) (bool, []string, error) {
	query := `SELECT DISTINCT g.org_id
		FROM user_memberships m
		JOIN groups g ON g.id = m.group_id
		WHERE m.user_id = $1
		  AND g.is_org_readonly_admin = true
		  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to check org readonly admin status: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			return false, nil, fmt.Errorf("failed to scan org readonly admin result: %w", err)
		}
		orgIDs = append(orgIDs, orgID)
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("error iterating org readonly admin results: %w", err)
	}

	return len(orgIDs) > 0, orgIDs, nil
}

func (d *DB) DeleteExpiredMemberships(ctx context.Context) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM user_memberships WHERE expires_at IS NOT NULL AND expires_at < $1`,
		time.Now().UTC(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func scanMembership(row *sql.Row) (*rbac.UserMembership, error) {
	membership := &rbac.UserMembership{}
	var zkCredRef sql.NullString
	var expiresAt sql.NullTime

	err := row.Scan(
		&membership.ID, &membership.UserID, &membership.GroupID,
		&membership.Source, &zkCredRef, &expiresAt,
		&membership.CreatedAt, &membership.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan membership: %w", err)
	}

	if zkCredRef.Valid {
		membership.ZKCredentialRef = zkCredRef.String
	}
	if expiresAt.Valid {
		membership.ExpiresAt = &expiresAt.Time
	}

	return membership, nil
}

func scanMemberships(rows *sql.Rows) ([]*rbac.UserMembership, error) {
	var memberships []*rbac.UserMembership
	for rows.Next() {
		membership := &rbac.UserMembership{}
		var zkCredRef sql.NullString
		var expiresAt sql.NullTime

		if err := rows.Scan(
			&membership.ID, &membership.UserID, &membership.GroupID,
			&membership.Source, &zkCredRef, &expiresAt,
			&membership.CreatedAt, &membership.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}

		if zkCredRef.Valid {
			membership.ZKCredentialRef = zkCredRef.String
		}
		if expiresAt.Valid {
			membership.ExpiresAt = &expiresAt.Time
		}

		memberships = append(memberships, membership)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating memberships: %w", err)
	}

	return memberships, nil
}

func scanMembershipsWithDetails(rows *sql.Rows) ([]*rbac.MembershipWithDetails, error) {
	var results []*rbac.MembershipWithDetails
	for rows.Next() {
		result := &rbac.MembershipWithDetails{
			Membership: &rbac.UserMembership{},
			Group:      &rbac.Group{},
		}

		var zkCredRef sql.NullString
		var expiresAt sql.NullTime
		var groupParentID, groupDescription sql.NullString

		if err := rows.Scan(
			&result.Membership.ID, &result.Membership.UserID, &result.Membership.GroupID,
			&result.Membership.Source, &zkCredRef, &expiresAt,
			&result.Membership.CreatedAt, &result.Membership.UpdatedAt,
			&result.Group.ID, &result.Group.OrgID, &groupParentID, &result.Group.Slug,
			&result.Group.Name, &groupDescription, &result.Group.Depth, &result.Group.Path, &result.Group.IsOrgAdmin,
			&result.Group.IsOrgReadonlyAdmin, &result.Group.IsSystem, &result.Group.AutoCreated,
			&result.Group.CreatedAt, &result.Group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}

		if zkCredRef.Valid {
			result.Membership.ZKCredentialRef = zkCredRef.String
		}
		if expiresAt.Valid {
			result.Membership.ExpiresAt = &expiresAt.Time
		}
		if groupParentID.Valid {
			result.Group.ParentID = &groupParentID.String
		}
		if groupDescription.Valid {
			result.Group.Description = groupDescription.String
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating memberships: %w", err)
	}

	return results, nil
}

// IsUserInOrg checks if a user (by DID) has any active membership in any group belonging to the given org.
func (d *DB) IsUserInOrg(ctx context.Context, userDID, orgID string) (bool, error) {
	var exists bool
	err := d.conn.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM user_memberships m
			JOIN users u ON u.id = m.user_id
			JOIN groups g ON g.id = m.group_id
			WHERE u.external_id = $1
			  AND g.org_id = $2
			  AND (m.expires_at IS NULL OR m.expires_at > NOW())
		)`, userDID, orgID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user org membership: %w", err)
	}
	return exists, nil
}
