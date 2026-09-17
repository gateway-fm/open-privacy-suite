package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func configurationFixture(t *testing.T) (*DB, configuration.Scope, ConfigurationActor, ConfigurationActor, *audit.HashChain) {
	t.Helper()
	d, org, author, reviewer, _ := policyActivationFixture(t)
	chain := audit.NewHashChain("")
	d.SetRBACAuditChain(chain)
	return d, configuration.Scope{Kind: "organization", ID: org},
		ConfigurationActor{UserID: author, ExternalID: "did:test:" + author, PrincipalKind: "human"},
		ConfigurationActor{UserID: reviewer, ExternalID: "did:test:" + reviewer, PrincipalKind: "human"}, chain
}
func configurationSource(t *testing.T, scope configuration.Scope, base int64, groups []configuration.Group) []byte {
	t.Helper()
	b, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Scope: scope, Kind: configuration.Groups,
		BaseRevision: base, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.GroupsSpec{Groups: groups}})
	require.NoError(t, err)
	return b
}
func proposedGroup() configuration.Group {
	id := uuid.NewString()
	return configuration.Group{ID: id, Slug: "payments-" + id, Name: "Payments " + id, AllowedMethods: []string{"eth_call"}, Claims: []string{}}
}

func TestConfigurationRevisionGroupLifecycleAndLockedAuthorization(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	group := proposedGroup()
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	require.Equal(t, PolicyStatusDraft, draft.Status)
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, stored, "a draft cannot project changes")
	called := false
	forbidden := errors.New("authority revoked")
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(ctx context.Context, tx *Tx, view ConfigurationActivation) error {
		called = true
		require.Equal(t, author.UserID, view.Candidates[0].CreatedBy)
		require.Equal(t, "create", view.GroupDiff.Changes[0].Action)
		var name string
		require.NoError(t, tx.tx.QueryRowContext(ctx, `SELECT name FROM organizations WHERE id = $1`, scope.ID).Scan(&name))
		return forbidden
	})
	require.ErrorIs(t, err, forbidden)
	require.True(t, called)
	stored, err = d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, stored)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, nil)
	require.Error(t, err, "missing authorization must fail closed")
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, author, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.Error(t, err, "the store enforces four-eyes independently of the callback")
	active, err := d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.NoError(t, err)
	require.Len(t, active, 1)
	stored, err = d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Equal(t, group.Name, stored.Name)
	access, err := d.GetGroupAccess(ctx, group.ID)
	require.NoError(t, err)
	require.Equal(t, group.AllowedMethods, access.AllowedMethods)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.Groups)
	require.NoError(t, err)
	require.Equal(t, draft.Revision, exported.Source.BaseRevision)
	require.Equal(t, group, exported.Source.Spec.(configuration.GroupsSpec).Groups[0])
	var auditHash string
	require.NoError(t, d.Conn().QueryRowContext(ctx, `SELECT entry_hash FROM rbac_audit_log WHERE resource_id = $1`, draft.ID).Scan(&auditHash))
	require.NotEmpty(t, auditHash)
	verified, err := audit.NewVerifier(d.Conn(), d).Verify(ctx, audit.ChainRBACAuditLog)
	require.NoError(t, err)
	require.True(t, verified.OK, "persisted audit content must reproduce the chain hash: %s", verified.FirstMismatchReason)
}

func TestConfigurationActivationRejectsStaleDependencyAndLateMembership(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	first, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	second, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{first.ID}, reviewer, allow)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{second.ID}, reviewer, allow)
	require.ErrorIs(t, err, ErrPolicyStaleBase)
	_, err = d.Conn().ExecContext(ctx, `UPDATE configuration_revisions SET source='{}' WHERE id=$1`, first.ID)
	require.Error(t, err, "reviewed source is immutable even to an accidental runtime UPDATE")
	foreign := scope
	foreign.ID = uuid.NewString()
	_, err = d.ActivateConfigurationRevisions(ctx, foreign, []string{second.ID}, reviewer, allow)
	require.Error(t, err)
	document, err := configuration.Parse(configurationSource(t, scope, first.Revision, []configuration.Group{group}))
	require.NoError(t, err)
	document.Dependencies[configuration.ContractRegistry] = "sha256:" + strings.Repeat("1", 64)
	raw, err := json.Marshal(document)
	require.NoError(t, err)
	dependent, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{dependent.ID}, reviewer, allow)
	require.ErrorContains(t, err, "dependency")
	document.Dependencies = map[configuration.Kind]string{}
	document.Spec = configuration.GroupsSpec{Groups: []configuration.Group{}}
	document.Deletions = []configuration.Deletion{{ID: group.ID}}
	raw, err = json.Marshal(document)
	require.NoError(t, err)
	removal, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: author.UserID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{removal.ID}, reviewer, allow)
	require.ErrorContains(t, err, "membership")
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
}

func TestConfigurationActivationAuditFailureRollsBackProjectionAndChain(t *testing.T) {
	d, scope, author, reviewer, chain := configurationFixture(t)
	ctx := t.Context()
	group := proposedGroup()
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.Conn().ExecContext(ctx, `CREATE FUNCTION reject_configuration_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
CREATE TRIGGER reject_configuration_audit BEFORE INSERT ON rbac_audit_log FOR EACH ROW EXECUTE FUNCTION reject_configuration_audit()`)
	require.NoError(t, err)
	head := chain.LastHash()
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.Error(t, err)
	require.Equal(t, head, chain.LastHash(), "rollback must not advance the in-memory chain")
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, stored, "an audit failure must roll back the projection")
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.Groups)
	require.NoError(t, err)
	require.Nil(t, exported.Active)
	_, err = d.Conn().ExecContext(ctx, `DROP TRIGGER reject_configuration_audit ON rbac_audit_log`)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.NoError(t, err)
	require.NotEqual(t, head, chain.LastHash())
}

func TestConfigurationActivationLocksMembershipParents(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	first, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{first.ID}, reviewer, allow)
	require.NoError(t, err)
	document, err := configuration.Parse(configurationSource(t, scope, first.Revision, []configuration.Group{}))
	require.NoError(t, err)
	document.Deletions = []configuration.Deletion{{ID: group.ID}}
	raw, err := json.Marshal(document)
	require.NoError(t, err)
	removal, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	locked, release := make(chan struct{}), make(chan struct{})
	activation := make(chan error, 1)
	go func() {
		_, err := d.ActivateConfigurationRevisions(ctx, scope, []string{removal.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error {
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
		t.Fatal("activation did not acquire locks")
	}
	membership := make(chan error, 1)
	go func() {
		membership <- d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: author.UserID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin})
	}()
	close(release)
	require.NoError(t, <-activation)
	require.Error(t, <-membership, "a new membership must not slip into a group approved for deletion at count zero")
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, stored)
}

func TestConfigurationActivationRejectsUnavailableOriginalAuthor(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{proposedGroup()}), author)
	require.NoError(t, err)
	_, err = d.Conn().ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, author.UserID)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.ErrorContains(t, err, "author", "banning the original author invalidates their pending review")
	_, err = d.Conn().ExecContext(ctx, `DELETE FROM users WHERE id=$1`, author.UserID)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.ErrorContains(t, err, "author", "deleting the original author must not leave an approvable draft")
}

func TestConfigurationActivationCannotRemoveLastLiveFullAdmin(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	admin := proposedGroup()
	admin.IsOrgAdmin = true
	require.NoError(t, d.CreateGroup(ctx, &rbac.Group{ID: admin.ID, OrgID: scope.ID, Slug: admin.Slug, Name: admin.Name, Path: admin.Slug, IsOrgAdmin: true}))
	_, err := d.Conn().ExecContext(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,$3,$4)`, uuid.NewString(), admin.ID, admin.AllowedMethods, admin.Claims)
	require.NoError(t, err)
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: reviewer.UserID, GroupID: admin.ID, Source: rbac.MembershipSourceAdmin}))
	admin.IsOrgAdmin = false
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{admin}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.ErrorContains(t, err, "last", "even a platform-authorized edit must leave a live full administrator")
	stored, err := d.GetGroup(ctx, admin.ID)
	require.NoError(t, err)
	require.True(t, stored.IsOrgAdmin)
}
