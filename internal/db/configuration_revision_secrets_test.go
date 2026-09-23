package db

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/crypto"
)

// A groups document may name the environment variable that holds a group's
// upstream RPC credential. The value itself is never part of the document:
// activation resolves the variable inside the projection transaction,
// encrypts it and stores it exactly where the rotation endpoint would, while
// the revision, its digest, the audit rows and the rendered current state
// carry only the variable's name.

func credentialVariable(scope configuration.Scope, suffix string) string {
	return "OPS_RPC_CREDENTIAL_" + strings.ToUpper(strings.ReplaceAll(scope.ID, "-", "")) + "_" + suffix
}

func testEncryptionKey() []byte { return []byte(strings.Repeat("k", 32)) }

func declaredGroup(variable string) configuration.Group {
	g := proposedGroup()
	g.RpcCredential = &configuration.SecretRef{FromEnv: variable}
	return g
}

func credentialColumns(t *testing.T, d *DB, groupID string) (key *string, source *string) {
	t.Helper()
	require.NoError(t, d.conn.QueryRowContext(context.Background(), `SELECT rpc_api_key, rpc_api_key_source FROM group_access WHERE group_id=$1`, groupID).Scan(&key, &source))
	return key, source
}

func TestConfigurationGroupCredentialPlaceholderResolvesInsideProjection(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	variable := credentialVariable(scope, "PAYMENTS")
	t.Setenv(variable, "upstream-secret-value")
	d.SetConfigurationSecretResolver(configuration.NewEnvSecretResolver(testEncryptionKey()))

	group := declaredGroup(variable)
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	// The reviewed text carries the name and never the value.
	require.Contains(t, draft.Source, variable)
	require.NotContains(t, draft.Source, "upstream-secret-value")

	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)

	key, source := credentialColumns(t, d, group.ID)
	require.NotNil(t, key)
	require.NotEqual(t, "upstream-secret-value", *key, "the stored credential must be ciphertext")
	plain, err := crypto.Decrypt(*key, testEncryptionKey())
	require.NoError(t, err)
	require.Equal(t, "upstream-secret-value", plain)
	require.NotNil(t, source)
	require.Equal(t, variable, *source)

	// The database barrier holds for a key-only write too: the exemption that
	// lets an operator rotate an operational key stops at a declared one, so
	// a racing legacy writer cannot leave "declared" pointing at its own value.
	_, err = d.conn.ExecContext(ctx, `UPDATE group_access SET rpc_api_key='operator-overwrite' WHERE group_id=$1`, group.ID)
	require.ErrorContains(t, err, "configuration revision")
	key, _ = credentialColumns(t, d, group.ID)
	plain, err = crypto.Decrypt(*key, testEncryptionKey())
	require.NoError(t, err)
	require.Equal(t, "upstream-secret-value", plain)

	// Current state renders the placeholder, and says the credential is declared.
	view, err := d.GetConfigurationContext(ctx, scope, configuration.Groups)
	require.NoError(t, err)
	var state *configuration.GroupState
	for i := range view.Groups.Groups {
		if view.Groups.Groups[i].Group.ID == group.ID {
			state = &view.Groups.Groups[i]
		}
	}
	require.NotNil(t, state)
	require.NotNil(t, state.Group.RpcCredential)
	require.Equal(t, variable, state.Group.RpcCredential.FromEnv)
	require.Equal(t, "declared", state.Credential)

	// Nothing durable carries the value: not the revision, not the audit chain.
	var leaked int
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM configuration_revisions WHERE source LIKE '%upstream-secret-value%') + (SELECT COUNT(*) FROM rbac_audit_log WHERE old_value::text LIKE '%upstream-secret-value%' OR new_value::text LIKE '%upstream-secret-value%')`).Scan(&leaked))
	require.Zero(t, leaked)

	// Re-activating with the same declaration re-resolves: rotation happens by
	// changing the variable and activating again. Fresh ciphertext, same value.
	next, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, draft.Revision, []configuration.Group{group}), author)
	require.NoError(t, err)
	t.Setenv(variable, "rotated-secret-value")
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{next.ID}, reviewer, allow)
	require.NoError(t, err)
	key2, _ := credentialColumns(t, d, group.ID)
	require.NotNil(t, key2)
	require.NotEqual(t, *key, *key2)
	plain, err = crypto.Decrypt(*key2, testEncryptionKey())
	require.NoError(t, err)
	require.Equal(t, "rotated-secret-value", plain)

	// The rotation endpoint's store method refuses a declared credential: the
	// document owns it now.
	other := "operational"
	err = d.RotateGroupRPCCredential(ctx, scope.ID, group.ID, &other)
	require.ErrorIs(t, err, ErrConfigurationConflict)
	key3, _ := credentialColumns(t, d, group.ID)
	require.Equal(t, *key2, *key3)

	// Withdrawing the declaration clears the credential the document wrote.
	plainGroup := group
	plainGroup.RpcCredential = nil
	cleared, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, next.Revision, []configuration.Group{plainGroup}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{cleared.ID}, reviewer, allow)
	require.NoError(t, err)
	key4, source4 := credentialColumns(t, d, group.ID)
	require.Nil(t, key4)
	require.Nil(t, source4)
}

func TestConfigurationGroupCredentialPlaceholderFailsClosed(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	variable := credentialVariable(scope, "TREASURY")
	group := declaredGroup(variable)
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)

	// Each refusal names the variable and says which precondition failed, so
	// the three cases are distinguishable to the operator reading the 409.
	refuse := func(t *testing.T, why string) {
		t.Helper()
		_, err := d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
		require.Error(t, err, why)
		require.Contains(t, err.Error(), variable, "the refusal names the variable")
		require.Contains(t, err.Error(), why, "the refusal says what is missing")
		require.NotContains(t, err.Error(), "treasury-secret-value", "the refusal never carries a value")
		stored, err := d.GetConfigurationRevision(ctx, scope, configuration.Groups, draft.ID)
		require.NoError(t, err)
		require.Equal(t, PolicyStatusDraft, stored.Status, "a refused activation leaves the draft untouched")
		var n int
		require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_access WHERE group_id=$1`, group.ID).Scan(&n))
		require.Zero(t, n, "nothing is projected when the credential cannot be resolved")
	}

	// No resolver installed: a declared credential cannot be honoured.
	refuse(t, "cannot resolve credentials")

	// Resolver installed, variable unset.
	d.SetConfigurationSecretResolver(configuration.NewEnvSecretResolver(testEncryptionKey()))
	refuse(t, "is not set")

	// Variable set, but encryption is not configured: never store plaintext.
	t.Setenv(variable, "treasury-secret-value")
	d.SetConfigurationSecretResolver(configuration.NewEnvSecretResolver(nil))
	refuse(t, "encryption is not configured")

	// Everything in place: the same draft activates.
	d.SetConfigurationSecretResolver(configuration.NewEnvSecretResolver(testEncryptionKey()))
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
}

func TestConfigurationGroupCredentialLeavesOperationalKeysAlone(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	d.SetConfigurationSecretResolver(configuration.NewEnvSecretResolver(testEncryptionKey()))

	// A group without a declaration, whose credential was set operationally.
	group := proposedGroup()
	draft, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
	operational := "operationally-set"
	require.NoError(t, d.RotateGroupRPCCredential(ctx, scope.ID, group.ID, &operational))

	// Re-applying the document does not touch what the document never owned.
	group.Name = "Renamed " + uuid.NewString()
	next, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, draft.Revision, []configuration.Group{group}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{next.ID}, reviewer, allow)
	require.NoError(t, err)
	key, source := credentialColumns(t, d, group.ID)
	require.NotNil(t, key)
	require.Equal(t, operational, *key)
	require.Nil(t, source)

	view, err := d.GetConfigurationContext(ctx, scope, configuration.Groups)
	require.NoError(t, err)
	for _, state := range view.Groups.Groups {
		if state.Group.ID == group.ID {
			require.Nil(t, state.Group.RpcCredential, "an operational credential is not rendered as source")
			require.Equal(t, "operational", state.Credential)
		}
	}
}
