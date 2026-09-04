package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"privacy-proxy/internal/rbac"
)

// Organization operations

func (d *DB) CreateOrganization(ctx context.Context, org *rbac.Organization) error {
	query := `INSERT INTO organizations (id, slug, name, settings)
	          VALUES ($1, $2, $3, $4)
	          RETURNING created_at, updated_at`

	settings, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	return d.conn.QueryRowContext(ctx, query,
		org.ID, org.Slug, org.Name, settings,
	).Scan(&org.CreatedAt, &org.UpdatedAt)
}

func (d *DB) GetOrganization(ctx context.Context, id string) (*rbac.Organization, error) {
	query := `SELECT id, slug, name, settings, is_system, created_at, updated_at
	          FROM organizations WHERE id = $1`

	org := &rbac.Organization{}
	var settings []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&org.ID, &org.Slug, &org.Name, &settings, &org.IsSystem, &org.CreatedAt, &org.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if err := json.Unmarshal(settings, &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return org, nil
}

func (d *DB) GetOrganizationBySlug(ctx context.Context, slug string) (*rbac.Organization, error) {
	query := `SELECT id, slug, name, settings, is_system, created_at, updated_at
	          FROM organizations WHERE slug = $1`

	org := &rbac.Organization{}
	var settings []byte

	err := d.conn.QueryRowContext(ctx, query, slug).Scan(
		&org.ID, &org.Slug, &org.Name, &settings, &org.IsSystem, &org.CreatedAt, &org.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if err := json.Unmarshal(settings, &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return org, nil
}

func (d *DB) UpdateOrganization(ctx context.Context, org *rbac.Organization) error {
	query := `UPDATE organizations SET slug = $2, name = $3, settings = $4, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	settings, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query, org.ID, org.Slug, org.Name, settings)
	return err
}

func (d *DB) ListOrganizations(ctx context.Context) ([]*rbac.Organization, error) {
	query := `SELECT id, slug, name, settings, is_system, created_at, updated_at
	          FROM organizations ORDER BY created_at DESC, name ASC`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*rbac.Organization
	for rows.Next() {
		org := &rbac.Organization{}
		var settings []byte

		if err := rows.Scan(&org.ID, &org.Slug, &org.Name, &settings, &org.IsSystem, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}

		if err := json.Unmarshal(settings, &org.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}

		orgs = append(orgs, org)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating organizations: %w", err)
	}

	return orgs, nil
}

func (d *DB) ListOrganizationsPaginated(ctx context.Context, limit, offset int) ([]*rbac.Organization, int, error) {
	var total int
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	query := `SELECT id, slug, name, settings, is_system, created_at, updated_at
	          FROM organizations ORDER BY created_at DESC, name ASC LIMIT $1 OFFSET $2`

	rows, err := d.conn.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*rbac.Organization
	for rows.Next() {
		org := &rbac.Organization{}
		var settings []byte

		if err := rows.Scan(&org.ID, &org.Slug, &org.Name, &settings, &org.IsSystem, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}

		if err := json.Unmarshal(settings, &org.Settings); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal settings: %w", err)
		}

		orgs = append(orgs, org)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating organizations: %w", err)
	}

	return orgs, total, nil
}

// ListOrganizationsByIDsPaginated returns organizations whose ID is in the
// allowedIDs set, ordered the same way as ListOrganizationsPaginated. The
// caller controls the visible org set (e.g. JWT admin's admin_org_ids ∪
// admin_readonly_org_ids), so this is used to scope the admin /orgs endpoint
// to the caller's membership without leaking other tenants (RD-916).
//
// When allowedIDs is empty the result is always (nil, 0, nil) — no orgs
// visible. Pagination is applied AFTER the membership filter so the total
// count reflects the membership-scoped set, not the global table.
func (d *DB) ListOrganizationsByIDsPaginated(ctx context.Context, allowedIDs []string, limit, offset int) ([]*rbac.Organization, int, error) {
	if len(allowedIDs) == 0 {
		return nil, 0, nil
	}

	var total int
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations WHERE id = ANY($1)`, allowedIDs).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count organizations: %w", err)
	}

	query := `SELECT id, slug, name, settings, is_system, created_at, updated_at
	          FROM organizations
	          WHERE id = ANY($1)
	          ORDER BY created_at DESC, name ASC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, allowedIDs, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*rbac.Organization
	for rows.Next() {
		org := &rbac.Organization{}
		var settings []byte
		if err := rows.Scan(&org.ID, &org.Slug, &org.Name, &settings, &org.IsSystem, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}
		if err := json.Unmarshal(settings, &org.Settings); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating organizations: %w", err)
	}
	return orgs, total, nil
}

func (d *DB) DeleteOrganization(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}
