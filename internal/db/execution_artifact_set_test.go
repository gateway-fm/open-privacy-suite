package db

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/policydsl"
)

func TestExecutionArtifactSetActivationAuditAndRemoval(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	one, two := proposedGroup(), proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{one, two}), author)
	require.NoError(t, err)
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID}, reviewer, allow)
	require.NoError(t, err)
	source := func(base int64, ids ...string) []byte {
		p := &policydsl.Policy{APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: scope.ID, NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{}}
		for _, id := range ids {
			p.Bindings = append(p.Bindings, policydsl.Binding{Group: id, Allow: []policydsl.FrameRule{{TargetClass: "eoa", Selector: "0x"}}})
		}
		raw, err := json.Marshal(p)
		require.NoError(t, err)
		b, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.ExecutionRules, Scope: scope, BaseRevision: base, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.ExecutionSpec{Policy: raw}})
		require.NoError(t, err)
		return b
	}
	export := func() nodepolicy.Snapshot {
		s, err := d.ExportNodePolicySnapshot(ctx, nodepolicy.Network{ChainID: 31337, DeploymentID: "group-test"}, time.Now(), time.Minute)
		require.NoError(t, err)
		return s
	}
	draft, err := d.SubmitConfigurationRevision(ctx, source(0, one.ID, two.ID), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, author, allow)
	require.Error(t, err, "one approval still covers the complete document and requires a second actor")
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
	before := export()
	require.Len(t, before.Policies, 2)
	var audit []byte
	require.NoError(t, d.Conn().QueryRowContext(ctx, `SELECT new_value FROM rbac_audit_log WHERE resource_id=$1`, draft.ID).Scan(&audit))
	for _, artifact := range before.Policies {
		require.Contains(t, string(audit), artifact.GroupID)
		require.Contains(t, string(audit), artifact.RuntimeDigest)
	}
	next, err := d.SubmitConfigurationRevision(ctx, source(draft.Revision, two.ID), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{next.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return errors.New("authority revoked") })
	require.ErrorContains(t, err, "authority revoked")
	require.Equal(t, before.Policies, export().Policies, "failed activation must publish none of the replacement")
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{next.ID}, reviewer, allow)
	require.NoError(t, err)
	after := export()
	require.Len(t, after.Policies, 1)
	require.Equal(t, two.ID, after.Policies[0].GroupID)
	// A deny-all revision is a real, reviewed empty set, not a missing artifact.
	empty, err := d.SubmitConfigurationRevision(ctx, source(next.Revision), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{empty.ID}, reviewer, allow)
	require.NoError(t, err)
	require.Empty(t, export().Policies)
}

func TestVerifyExecutionArtifactSetRejectsMissingExtraAndChangedGroups(t *testing.T) {
	p := &policydsl.Policy{APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: "org", NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{{Group: "a", Allow: []policydsl.FrameRule{}}, {Group: "b", Allow: []policydsl.FrameRule{}}}}
	v, err := policydsl.Validate(p, policydsl.Catalog{Org: "org", Groups: map[string]struct{}{"a": {}, "b": {}}})
	require.NoError(t, err)
	set, err := policydsl.NewCompiler().BuildSet(t.Context(), v)
	require.NoError(t, err)
	encoded, err := json.Marshal(set)
	require.NoError(t, err)
	_, err = verifyExecutionArtifacts(encoded, v)
	require.NoError(t, err)
	for _, kind := range []string{"missing", "extra", "swapped", "runtime", "null"} {
		t.Run(kind, func(t *testing.T) {
			copy, err := policydsl.DecodeArtifactSet(encoded)
			require.NoError(t, err)
			switch kind {
			case "missing":
				delete(copy.Groups, "b")
			case "extra":
				copy.Groups["c"] = copy.Groups["b"]
			case "swapped":
				copy.Groups["a"], copy.Groups["b"] = copy.Groups["b"], copy.Groups["a"]
			case "runtime":
				copy.Groups["a"].RuntimeBytecode[0] ^= 1
			case "null":
				copy.Groups["a"] = nil
			}
			raw, err := json.Marshal(copy)
			require.NoError(t, err)
			_, err = verifyExecutionArtifacts(raw, v)
			require.Error(t, err)
		})
	}
}
