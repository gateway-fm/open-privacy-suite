package db

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db/migrations"
	"privacy-proxy/internal/rbac"
)

func TestV2UpgradeFromMainPreservesPermissions(t *testing.T) {
	dsn, cleanup := SetupTestContainer(t)
	defer cleanup()
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	m, err := migrate.NewMigrator(ctx, conn, "schema_version")
	require.NoError(t, err)
	require.NoError(t, m.LoadMigrations(migrations.FS))
	require.Equal(t, "072_impersonation_log_indeterminate.sql", m.Migrations[71].Name)
	require.NoError(t, m.MigrateTo(ctx, 72))

	org, group := uuid.NewString(), uuid.NewString()
	_, err = conn.Exec(ctx, `INSERT INTO organizations(id,slug,name) VALUES($1,'v2-upgrade','V2 upgrade')`, org)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `INSERT INTO groups(id,org_id,slug,name,path) VALUES($1,$2,'members','Members','members')`, group, org)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,ARRAY['eth_call','eth_sendTransaction'],ARRAY['deploy'])`, uuid.NewString(), group)
	require.NoError(t, err)
	var auditCount int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM rbac_audit_log`).Scan(&auditCount))

	// Open the database exactly as the application does on upgrade. Main's
	// published migrations through 072 must not be reinterpreted as V2 ones.
	d, err := New(dsn)
	require.NoError(t, err)
	defer d.Close()
	access, err := d.GetGroupAccess(ctx, group)
	require.NoError(t, err)
	require.Equal(t, []string{"eth_call", "eth_sendTransaction"}, access.AllowedMethods)
	require.Equal(t, []rbac.Claim{rbac.ClaimDeploy}, access.Claims)
	view, err := d.GetConfigurationContext(ctx, configuration.Scope{Kind: "organization", ID: org}, configuration.Groups)
	require.NoError(t, err)
	require.Zero(t, view.Source.BaseRevision, "upgrade must not activate a configuration")
	require.Len(t, view.Source.Spec.(configuration.GroupsSpec).Groups, 1)
	var after int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM rbac_audit_log`).Scan(&after))
	require.Equal(t, auditCount, after, "migrations must not fabricate runtime audit entries")
	var version int32
	require.NoError(t, conn.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&version))
	require.Equal(t, int32(len(m.Migrations)), version)
}
