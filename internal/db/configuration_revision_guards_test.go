package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func TestConfigurationManagedGroupsRejectLegacyWritersButAllowSecretsAndMemberships(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	group := proposedGroup()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
	_, err = d.Conn().ExecContext(ctx, `UPDATE groups SET name='imperative overwrite' WHERE id=$1`, group.ID)
	require.ErrorContains(t, err, "configuration revision")
	other := proposedGroup()
	err = d.CreateGroup(ctx, &rbac.Group{ID: other.ID, OrgID: scope.ID, Slug: other.Slug, Name: other.Name, Path: other.Slug})
	require.ErrorContains(t, err, "configuration revision")
	_, err = d.Conn().ExecContext(ctx, `UPDATE group_access SET claims=ARRAY['admin'] WHERE group_id=$1`, group.ID)
	require.ErrorContains(t, err, "configuration revision")
	_, err = d.Conn().ExecContext(ctx, `UPDATE group_access SET rpc_api_key='rotated-secret' WHERE group_id=$1`, group.ID)
	require.NoError(t, err)
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: author.UserID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	group.Name = "Reviewed update"
	next, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, draft.Revision, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{next.ID}, reviewer, allow)
	require.NoError(t, err)
	access, err := d.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	require.Equal(t, "rotated-secret", *access.RPCAPIKey)
}

func TestConfigurationFirstActivationClosesAlreadyStartedLegacyInsert(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	group := proposedGroup()
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	legacy, err := d.Conn().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer legacy.Rollback()
	var pid int
	require.NoError(t, legacy.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	var managed bool
	require.NoError(t, legacy.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM configuration_revisions WHERE org_id=$1 AND kind='groups' AND status='active')`, scope.ID).Scan(&managed))
	require.False(t, managed)
	locked, release := make(chan struct{}), make(chan struct{})
	activation := make(chan error, 1)
	go func() {
		_, err := d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error {
			close(locked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		activation <- err
	}()
	select {
	case <-locked:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	write := make(chan error, 1)
	other := proposedGroup()
	go func() {
		_, err := legacy.ExecContext(ctx, `INSERT INTO groups(id,org_id,slug,name,path) VALUES($1,$2,$3,$4,$5)`, other.ID, scope.ID, other.Slug, other.Name, other.Slug)
		write <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		require.NoError(t, d.Conn().QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked))
		if blocked {
			break
		}
		select {
		case early := <-write:
			t.Fatalf("legacy insert completed before the locked activation: %v", early)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("legacy insert never blocked on the activation transaction")
		}
	}
	close(release)
	require.NoError(t, <-activation)
	require.ErrorContains(t, <-write, "configuration revision", "a pre-activation HTTP permission check cannot authorize a later write")
	require.NoError(t, legacy.Rollback())
	stored, err := d.GetGroup(ctx, other.ID)
	require.NoError(t, err)
	require.Nil(t, stored)
}
