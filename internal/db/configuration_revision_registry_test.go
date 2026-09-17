package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func registrySource(t *testing.T, scope configuration.Scope, base int64, contracts []configuration.Contract, dependencies map[configuration.Kind]string, deletions []configuration.Deletion) []byte {
	t.Helper()
	b, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.ContractRegistry, Scope: scope, BaseRevision: base, Dependencies: dependencies, Deletions: deletions, Spec: configuration.RegistrySpec{Contracts: contracts}})
	require.NoError(t, err)
	return b
}

func TestConfigurationRegistryCoactivationAndLegacyExecutionPreservation(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	contract := configuration.Contract{ID: uuid.NewString(), Address: "0x1111111111111111111111111111111111111111", Name: "Vault", ABI: json.RawMessage(`[]`), ReadGrants: []configuration.ReadGrant{
		{ID: uuid.NewString(), GroupID: group.ID, LegacyClaims: []string{}, EventRules: configuration.EventRules{Mode: "none", Rules: []configuration.EventRule{}}},
	}}
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{configuration.Groups: groups.Digest}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{registry.ID}, reviewer, allow)
	require.Error(t, err, "dependent groups have not become active")
	active, err := d.ActivateConfigurationRevisions(ctx, scope, []string{registry.ID, groups.ID}, reviewer, allow)
	require.NoError(t, err)
	require.Len(t, active, 2)
	grant, err := d.GetContractGrant(ctx, contract.ReadGrants[0].ID)
	require.NoError(t, err)
	require.NotNil(t, grant.Functions)
	require.Empty(t, grant.Functions, "registry grants cannot grant execution as a side effect")
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.ContractRegistry)
	require.NoError(t, err)
	require.Equal(t, contract, exported.Source.Spec.(configuration.RegistrySpec).Contracts[0])
	_, err = d.Conn().ExecContext(ctx, `UPDATE contract_grants SET functions=NULL WHERE id=$1`, grant.ID)
	require.NoError(t, err)
	contract.Name = "Reviewed Vault"
	contract.ReadGrants[0].EventRules.Mode = "all"
	revision, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, registry.Revision, []configuration.Contract{contract}, map[configuration.Kind]string{configuration.Groups: groups.Digest}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{revision.ID}, reviewer, allow)
	require.NoError(t, err)
	grant, err = d.GetContractGrant(ctx, grant.ID)
	require.NoError(t, err)
	require.Nil(t, grant.Functions, "editing read visibility preserves legacy nil=all execution functions")
	require.True(t, grant.EventRules.Wildcard)
}

func TestConfigurationRegistryRejectsForeignGroupAndPreservesOperationalDrift(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	contract := configuration.Contract{ID: uuid.NewString(), Address: "0x1111111111111111111111111111111111111111", Name: "Vault", ABI: json.RawMessage(`[]`), ReadGrants: []configuration.ReadGrant{
		{ID: uuid.NewString(), GroupID: uuid.NewString(), LegacyClaims: []string{}, EventRules: configuration.EventRules{Mode: "none", Rules: []configuration.EventRule{}}},
	}}
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID, registry.ID}, reviewer, allow)
	require.ErrorContains(t, err, "group")
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, stored, "failed sibling must roll back every stream")
	contract.ReadGrants = []configuration.ReadGrant{}
	registry, err = d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{registry.ID}, reviewer, allow)
	require.NoError(t, err)
	drift := &rbac.Contract{ID: uuid.NewString(), OrgID: scope.ID, Address: "0x2222222222222222222222222222222222222222", Name: "Operational deployment", Metadata: map[string]any{"transaction": "retain"}}
	require.NoError(t, d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.AuthorizeDeploymentRegistration(ctx, scope.ID); err != nil {
			return err
		}
		return tx.CreateContract(ctx, drift)
	}))
	contract.Name = "Updated"
	revision, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, registry.Revision, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{revision.ID}, reviewer, allow)
	require.NoError(t, err)
	retained, err := d.GetContract(ctx, drift.ID)
	require.NoError(t, err)
	require.NotNil(t, retained)
	require.Equal(t, drift.Metadata, retained.Metadata)
}

func TestConfigurationRegistryCustomEventAddressMustBeScoped(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	contract := configuration.Contract{ID: uuid.NewString(), Address: "0x1111111111111111111111111111111111111111", Name: "Vault", ABI: json.RawMessage(`[{"type":"event","name":"Party","inputs":[{"name":"party","type":"address","indexed":true}],"anonymous":false}]`), ReadGrants: []configuration.ReadGrant{}}
	events, err := rbac.ExtractEventSignatures(string(contract.ABI))
	require.NoError(t, err)
	contract.ReadGrants = append(contract.ReadGrants, configuration.ReadGrant{ID: uuid.NewString(), GroupID: group.ID, LegacyClaims: []string{}, EventRules: configuration.EventRules{Mode: "allowlist", Rules: []configuration.EventRule{
		{Topic0: events[0].Topic0, Name: "Party", ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "0x2222222222222222222222222222222222222222"}}},
	}}})
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID, registry.ID}, reviewer, allow)
	require.ErrorContains(t, err, "address")
	contract.ReadGrants[0].EventRules.Rules[0].ParamRules[0].MustBe = contract.Address
	registry, err = d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID, registry.ID}, reviewer, allow)
	require.NoError(t, err)
}

func TestConfigurationRegistryAndGroupDeletionIsAtomic(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	group := proposedGroup()
	groups, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{group}), author)
	require.NoError(t, err)
	contract := configuration.Contract{ID: uuid.NewString(), Address: "0x1111111111111111111111111111111111111111", Name: "Vault", ABI: json.RawMessage(`[]`), ReadGrants: []configuration.ReadGrant{
		{ID: uuid.NewString(), GroupID: group.ID, LegacyClaims: []string{}, EventRules: configuration.EventRules{Mode: "none", Rules: []configuration.EventRule{}}},
	}}
	registry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{contract}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{groups.ID, registry.ID}, reviewer, allow)
	require.NoError(t, err)
	document, err := configuration.Parse(configurationSource(t, scope, groups.Revision, []configuration.Group{}))
	require.NoError(t, err)
	document.Deletions = []configuration.Deletion{{ID: group.ID}}
	raw, err := json.Marshal(document)
	require.NoError(t, err)
	removeGroup, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	removeRegistry, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, registry.Revision, []configuration.Contract{}, map[configuration.Kind]string{}, []configuration.Deletion{{ID: contract.ID}, {ID: contract.ReadGrants[0].ID}}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{removeGroup.ID}, reviewer, allow)
	require.Error(t, err, "retained grants still depend on this group")
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{removeGroup.ID, removeRegistry.ID}, reviewer, allow)
	require.NoError(t, err)
	stored, err := d.GetGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, stored)
	storedContract, err := d.GetContract(ctx, contract.ID)
	require.NoError(t, err)
	require.Nil(t, storedContract)
}
