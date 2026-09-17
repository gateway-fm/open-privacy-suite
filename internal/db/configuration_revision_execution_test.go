package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/policydsl"
)

const configurationExecutionABI = `[{"inputs":[],"name":"f","outputs":[],"stateMutability":"view","type":"function"}]`

func executionConfigurationSource(t *testing.T, scope configuration.Scope, base int64, group, address string, deps map[configuration.Kind]string) []byte {
	t.Helper()
	p := policydsl.Policy{APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: scope.ID, NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{{Group: group, Allow: []policydsl.FrameRule{{StorageAddress: address, Selector: "0x26121ff0", ABIDigest: policydsl.ABIDigest(configurationExecutionABI)}}}}}
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	source, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.ExecutionRules, Scope: scope, BaseRevision: base, Dependencies: deps, Deletions: []configuration.Deletion{}, Spec: configuration.ExecutionSpec{Policy: raw}})
	require.NoError(t, err)
	return source
}

func TestConfigurationExecutionCompilesDeclaredSiblingsAndProjectsApprovedArtifact(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	contract := configuration.Contract{ID: uuid.NewString(), Address: "0x" + strings.Repeat("12", 20), Name: "Payments", ABI: json.RawMessage(configurationExecutionABI), ReadGrants: []configuration.ReadGrant{}}
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{configuration.Groups: groups.Digest}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.SubmitConfigurationRevision(ctx, executionConfigurationSource(t, scope, 0, group.ID, contract.Address, map[configuration.Kind]string{}), author)
	require.Error(t, err, "undeclared drafts cannot supply compiler authority")
	source := executionConfigurationSource(t, scope, 0, group.ID, contract.Address, map[configuration.Kind]string{configuration.Groups: groups.Digest, configuration.ContractRegistry: registry.Digest})
	draft, err := d.SubmitConfigurationRevision(ctx, source, author)
	require.NoError(t, err)
	require.NotEmpty(t, draft.Artifact, "draft must retain actual compiled artifact")
	var artifact policydsl.Artifact
	require.NoError(t, json.Unmarshal(draft.Artifact, &artifact))
	require.NotEmpty(t, artifact.RuntimeBytecode)
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.Error(t, err)
	active, err := d.ActivateConfigurationRevisions(ctx, scope, []string{registry.ID, draft.ID, groups.ID}, reviewer, allow)
	require.NoError(t, err)
	require.Len(t, active, 3)
	projection, err := d.GetActiveExecutionPolicy(ctx, scope.ID)
	require.NoError(t, err)
	require.Equal(t, draft.ID, projection.ID)
	require.Equal(t, artifact.RuntimeDigest, projection.RuntimeDigest)
	require.Equal(t, artifact.RuntimeBytecode, projection.RuntimeBytecode)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.ExecutionRules)
	require.NoError(t, err)
	require.Equal(t, draft.Revision, exported.Source.BaseRevision)
	spec := exported.Source.Spec.(configuration.ExecutionSpec)
	var p policydsl.Policy
	require.NoError(t, json.Unmarshal(spec.Policy, &p))
	require.Equal(t, scope.ID, p.Org)
	_, err = d.Conn().ExecContext(ctx, `UPDATE configuration_revisions SET compiled_artifact='{}' WHERE id=$1`, draft.ID)
	require.Error(t, err, "approved artifact immutable")
	_, err = d.Conn().ExecContext(ctx, `UPDATE execution_policy_revisions SET status='superseded' WHERE id=$1`, draft.ID)
	require.Error(t, err, "legacy projection writer must close")
	// A registry-only ABI change must not leave the approved policy pinned to
	// bytes that no longer describe its execution target.
	contract.ABI = json.RawMessage(`[{"inputs":[],"name":"g","outputs":[],"stateMutability":"view","type":"function"}]`)
	changedRegistry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, registry.Revision, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{changedRegistry.ID}, reviewer, allow)
	require.ErrorContains(t, err, "invalidates active execution")
	stored, err := d.GetContract(ctx, contract.ID)
	require.NoError(t, err)
	require.JSONEq(t, configurationExecutionABI, stored.ABI, "failed activation must retain the old ABI")
	// The exact replacement can compile against and activate with that sibling.
	replacement, err := configuration.Parse(executionConfigurationSource(t, scope, draft.Revision, group.ID, contract.Address, map[configuration.Kind]string{configuration.ContractRegistry: changedRegistry.Digest}))
	require.NoError(t, err)
	p.Bindings[0].Allow[0].Selector = "0xe2179b8e"
	p.Bindings[0].Allow[0].ABIDigest = policydsl.ABIDigest(string(contract.ABI))
	policy, err := json.Marshal(p)
	require.NoError(t, err)
	replacement.Spec = configuration.ExecutionSpec{Policy: policy}
	replacementSource, err := json.Marshal(replacement)
	require.NoError(t, err)
	next, err := d.SubmitConfigurationRevision(ctx, replacementSource, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{next.ID, changedRegistry.ID}, reviewer, allow)
	require.NoError(t, err)
}

func TestConfigurationExecutionFirstAdoptionReviewsLegacyGrantRemoval(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	grantID := uuid.NewString()
	contract := configuration.Contract{ID: uuid.NewString(), Address: "0x" + strings.Repeat("21", 20), Name: "Legacy", ABI: json.RawMessage(configurationExecutionABI), ReadGrants: []configuration.ReadGrant{{ID: grantID, GroupID: group.ID, LegacyClaims: []string{}, EventRules: configuration.EventRules{Mode: "none", Rules: []configuration.EventRule{}}}}}
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID, registry.ID}, reviewer, allow)
	require.NoError(t, err)
	_, err = d.Conn().ExecContext(ctx, `UPDATE contract_grants SET functions=NULL WHERE id=$1`, grantID)
	require.NoError(t, err)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.ExecutionRules)
	require.NoError(t, err)
	require.NotNil(t, exported.ExecutionMigration)
	require.Contains(t, exported.ExecutionMigration.Diagnostics, policydsl.LegacyImportIssue{Reason: "Ordinary proxy relationships cannot be inferred safely. Review deployed proxy implementations and declare spec.proxyPairs, or write explicit code/storage DELEGATECALL rules, before migration."})
	baseline, err := policydsl.Parse(exported.Source.Spec.(configuration.ExecutionSpec).Policy)
	require.NoError(t, err)
	require.Equal(t, "*", baseline.Bindings[0].Allow[4].Selector)
	_, err = d.Conn().ExecContext(ctx, `UPDATE contract_grants SET functions='[]' WHERE id=$1`, grantID)
	require.NoError(t, err)
	eventsOnly, err := d.GetConfigurationContext(ctx, scope, configuration.ExecutionRules)
	require.NoError(t, err)
	eventsOnlyPolicy, err := policydsl.Parse(eventsOnly.Source.Spec.(configuration.ExecutionSpec).Policy)
	require.NoError(t, err)
	require.Len(t, eventsOnlyPolicy.Bindings[0].Allow, 4, "explicit empty functions must not import wildcard execution")
	_, err = d.Conn().ExecContext(ctx, `UPDATE contract_grants SET functions=NULL WHERE id=$1`, grantID)
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, executionConfigurationSource(t, scope, 0, group.ID, contract.Address, map[configuration.Kind]string{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(_ context.Context, _ *Tx, view ConfigurationActivation) error {
		require.NotNil(t, view.ExecutionDiff.Before, "initial migration must expose the permissions it replaces")
		wantDigest, err := policydsl.CanonicalDigest(baseline)
		require.NoError(t, err)
		gotDigest, err := policydsl.CanonicalDigest(view.ExecutionDiff.Before)
		require.NoError(t, err)
		require.Equal(t, wantDigest, gotDigest)
		require.Equal(t, "replace", view.ExecutionDiff.Changes[0].Action)
		return nil
	})
	require.NoError(t, err)
}

func TestConfigurationExecutionKeepsIndependentRevisionSequencesAndAtomicAudit(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	p := &policydsl.Policy{APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: scope.ID, NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{}}
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	v, err := policydsl.Validate(p, policydsl.Catalog{Org: scope.ID})
	require.NoError(t, err)
	artifact, err := policydsl.NewCompiler().Build(ctx, v)
	require.NoError(t, err)
	for range 3 {
		_, err = d.CreateExecutionPolicyRevision(ctx, scope.ID, 0, string(raw), artifact, &author.UserID)
		require.NoError(t, err)
	}
	source, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.ExecutionRules, Scope: scope, BaseRevision: 0, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.ExecutionSpec{Policy: raw}})
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, source, author)
	require.NoError(t, err)
	require.EqualValues(t, 1, draft.Revision)
	version, err := d.NodePolicyVersion(ctx)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(_ context.Context, _ *Tx, view ConfigurationActivation) error {
		require.EqualValues(t, 0, view.ExecutionDiff.PreviousProjectionRevision)
		require.EqualValues(t, 4, view.ExecutionDiff.ProjectionRevision)
		return nil
	})
	require.NoError(t, err)
	projected, err := d.GetActiveExecutionPolicy(ctx, scope.ID)
	require.NoError(t, err)
	require.EqualValues(t, 4, projected.Revision)
	require.EqualValues(t, 0, *projected.BaseRevision)
	current, err := d.NodePolicyVersion(ctx)
	require.NoError(t, err)
	require.Greater(t, current, version, "activation must atomically dirty the node fact stream")
	var auditValue []byte
	require.NoError(t, d.Conn().QueryRowContext(ctx, `SELECT new_value FROM rbac_audit_log WHERE resource_id=$1`, draft.ID).Scan(&auditValue))
	require.Contains(t, string(auditValue), artifact.RuntimeDigest)
	require.Contains(t, string(auditValue), "runtime_bytecode", "reviewed artifact must be retained in the same audit transaction")
}

func TestConfigurationExecutionLegacyRestrictionRequiresExplicitMigration(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	p := &policydsl.Policy{APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: scope.ID, NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{}}
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	v, err := policydsl.Validate(p, policydsl.Catalog{Org: scope.ID})
	require.NoError(t, err)
	artifact, err := policydsl.NewCompiler().Build(ctx, v)
	require.NoError(t, err)
	old, err := d.CreateExecutionPolicyRevision(ctx, scope.ID, 0, string(raw), artifact, &author.UserID)
	require.NoError(t, err)
	_, err = d.ActivateExecutionPolicyRevision(ctx, scope.ID, old.ID, &reviewer.UserID)
	require.NoError(t, err)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.ExecutionRules)
	require.NoError(t, err, "migration must remain editable without claiming an automatic intersection")
	require.Empty(t, exported.Source.Spec.(configuration.ExecutionSpec).LegacyRestrictionDigest)
	require.NotNil(t, exported.ExecutionMigration)
	require.Equal(t, old.PolicyDigest, exported.ExecutionMigration.LegacyRestriction.PolicyDigest)
	migration, err := configurationExecutionMigration(ctx, d.Conn(), scope)
	require.NoError(t, err)
	require.Equal(t, old.PolicyDigest, migration.LegacyRestriction.PolicyDigest)
	require.Equal(t, old.RuntimeBytecode, migration.LegacyRestriction.Artifact.RuntimeBytecode)
	require.NotEmpty(t, migration.Diagnostics)
	source, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.ExecutionRules, Scope: scope, BaseRevision: 0, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.ExecutionSpec{Policy: raw}})
	require.NoError(t, err)
	_, err = d.SubmitConfigurationRevision(ctx, source, author)
	require.ErrorContains(t, err, "legacy restriction")
	doc, err := configuration.Parse(source)
	require.NoError(t, err)
	spec := doc.Spec.(configuration.ExecutionSpec)
	spec.LegacyRestrictionDigest = old.PolicyDigest
	doc.Spec = spec
	source, err = json.Marshal(doc)
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, source, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(_ context.Context, _ *Tx, view ConfigurationActivation) error {
		require.NotNil(t, view.ExecutionDiff.Migration.LegacyRestriction)
		require.Equal(t, old.PolicyDigest, view.ExecutionDiff.Migration.LegacyRestriction.PolicyDigest)
		return nil
	})
	require.NoError(t, err)
	active, err := d.GetActiveExecutionPolicy(ctx, scope.ID)
	require.NoError(t, err)
	require.Equal(t, draft.ID, active.ID)
	exported, err = d.GetConfigurationContext(ctx, scope, configuration.ExecutionRules)
	require.NoError(t, err)
	require.Equal(t, old.PolicyDigest, exported.Source.Spec.(configuration.ExecutionSpec).LegacyRestrictionDigest, "editing source must retain the explicit migration acknowledgement")
}

func TestConfigurationExecutionProxyPairsExpandApprovedArtifactAndRoundtripSource(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	proxy := configuration.Contract{ID: uuid.NewString(), Address: "0x" + strings.Repeat("31", 20), Name: "Proxy", ABI: json.RawMessage(configurationExecutionABI), ReadGrants: []configuration.ReadGrant{}}
	impl := configuration.Contract{ID: uuid.NewString(), Address: "0x" + strings.Repeat("32", 20), Name: "Implementation", ABI: json.RawMessage(configurationExecutionABI), ReadGrants: []configuration.ReadGrant{}}
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{proxy, impl}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	doc, err := configuration.Parse(executionConfigurationSource(t, scope, 0, group.ID, proxy.Address, map[configuration.Kind]string{configuration.Groups: groups.Digest, configuration.ContractRegistry: registry.Digest}))
	require.NoError(t, err)
	spec := doc.Spec.(configuration.ExecutionSpec)
	p, err := policydsl.Parse(spec.Policy)
	require.NoError(t, err)
	rule := p.Bindings[0].Allow[0]
	rule.StorageAddress = impl.Address
	p.Bindings[0].Allow = append(p.Bindings[0].Allow, rule)
	spec.Policy, err = json.Marshal(p)
	require.NoError(t, err)
	spec.ProxyPairs = []policydsl.LegacyProxyPair{{StorageAddress: proxy.Address, CodeAddress: impl.Address}}
	doc.Spec = spec
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, source, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID, registry.ID, draft.ID}, reviewer, func(_ context.Context, _ *Tx, view ConfigurationActivation) error {
		require.Len(t, view.ExecutionDiff.After.Bindings[0].Allow, 3, "review must expose the actual expanded delegatecall rule")
		return nil
	})
	require.NoError(t, err)
	active, err := d.GetActiveExecutionPolicy(ctx, scope.ID)
	require.NoError(t, err)
	actual, err := policydsl.Parse([]byte(active.Source))
	require.NoError(t, err)
	require.Equal(t, impl.Address, actual.Bindings[0].Allow[2].CodeAddress)
	require.Equal(t, []policydsl.CallType{policydsl.CallTypeDelegateCall}, actual.Bindings[0].Allow[2].CallTypes)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.ExecutionRules)
	require.NoError(t, err)
	retained := exported.Source.Spec.(configuration.ExecutionSpec)
	require.Equal(t, spec.ProxyPairs, retained.ProxyPairs)
	base, err := policydsl.Parse(retained.Policy)
	require.NoError(t, err)
	require.Len(t, base.Bindings[0].Allow, 2, "source must not expand again on every edit")
}
