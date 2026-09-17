package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func TestConfigurationLegacyLockInversionRollsBackAndRetries(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	group := proposedGroup()
	require.NoError(t, d.CreateGroup(ctx, &rbac.Group{ID: group.ID, OrgID: scope.ID, Slug: group.Slug, Name: group.Name, Path: group.Slug}))
	group.Name = "Reviewed final name"
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	legacy, err := d.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer legacy.Rollback()
	var pid int
	require.NoError(t, legacy.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	var locked string
	require.NoError(t, legacy.QueryRowContext(ctx, `SELECT id FROM groups WHERE id=$1 FOR UPDATE`, group.ID).Scan(&locked))
	activation := make(chan error, 1)
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	go func() {
		_, err := d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
		activation <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting))
		if waiting {
			break
		}
		select {
		case err := <-activation:
			t.Fatalf("activation completed before legacy lock was released: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// The old order is group→org; activation is org→group. PostgreSQL must abort
	// one complete transaction, never leave a partly projected revision.
	_, legacyErr := legacy.ExecContext(ctx, `UPDATE groups SET name='unreviewed transient' WHERE id=$1`, group.ID)
	require.NoError(t, legacy.Rollback())
	activationErr := <-activation
	require.True(t, legacyErr != nil || activationErr != nil, "lock inversion must abort one contender")
	if activationErr != nil {
		_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
		require.NoError(t, err)
	}
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Equal(t, group.Name, stored.Name)
	var audits int
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT count(*) FROM rbac_audit_log WHERE resource_id=$1`, draft.ID).Scan(&audits))
	require.Equal(t, 1, audits)
}
