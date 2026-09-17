package configuration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/rbac"
)

func registryDocument(contract Contract) *Document {
	return &Document{APIVersion: APIVersion, Kind: ContractRegistry, Scope: Scope{Kind: "organization", ID: orgID}, BaseRevision: 4,
		Dependencies: map[Kind]string{}, Deletions: []Deletion{}, Spec: RegistrySpec{Contracts: []Contract{contract}}}
}
func registryContract() Contract {
	return Contract{ID: groupOne, Address: "0x1111111111111111111111111111111111111111", Name: "Vault", ABI: json.RawMessage(`[]`), ReadGrants: []ReadGrant{
		{ID: groupTwo, GroupID: groupDrift, LegacyClaims: []string{}, EventRules: EventRules{Mode: "none", Rules: []EventRule{}}},
	}}
}

func TestRegistryDiffPreservesDriftAndRequiresExplicitNestedDeletion(t *testing.T) {
	contract := registryContract()
	doc := registryDocument(contract)
	snapshot := RegistrySnapshot{Scope: doc.Scope, ActiveRevision: 4, Contracts: []ContractState{{Contract: contract, Managed: true, ManagedGrantIDs: []string{groupTwo}}}}
	updated := contract
	updated.ReadGrants = []ReadGrant{}
	doc.Spec = RegistrySpec{Contracts: []Contract{updated}}
	_, err := DiffRegistry(doc, snapshot)
	require.ErrorContains(t, err, "deletion")
	doc.Deletions = []Deletion{{ID: groupTwo}}
	diff, err := DiffRegistry(doc, snapshot)
	require.NoError(t, err)
	require.Empty(t, diff.Projection[0].ReadGrants)
	require.Contains(t, diff.Changes, RegistryChange{Action: "delete", Resource: "readGrant", ID: groupTwo})
	snapshot.Contracts[0].ManagedGrantIDs = []string{}
	doc.Deletions = []Deletion{}
	diff, err = DiffRegistry(doc, snapshot)
	require.NoError(t, err)
	require.Equal(t, contract.ReadGrants, diff.Projection[0].ReadGrants)
	require.Contains(t, diff.PreservedDrift, groupTwo)
	doc.Deletions = []Deletion{{ID: groupTwo}}
	_, err = DiffRegistry(doc, snapshot)
	require.ErrorContains(t, err, "unmanaged")
}

func TestRegistryDiffIdentityAndLegacyMetadataAreImmutable(t *testing.T) {
	contract := registryContract()
	doc := registryDocument(contract)
	snapshot := RegistrySnapshot{Scope: doc.Scope, ActiveRevision: 4, Contracts: []ContractState{{Contract: contract, Managed: true, ManagedGrantIDs: []string{groupTwo}}}}
	for _, change := range []func(*Contract){
		func(c *Contract) { c.Address = "0x2222222222222222222222222222222222222222" },
		func(c *Contract) { c.ReadGrants[0].GroupID = orgID },
		func(c *Contract) { c.ReadGrants[0].LegacyClaims = []string{"admin"} },
	} {
		updated := contract
		updated.ReadGrants = append([]ReadGrant{}, contract.ReadGrants...)
		change(&updated)
		doc.Spec = RegistrySpec{Contracts: []Contract{updated}}
		_, err := DiffRegistry(doc, snapshot)
		require.ErrorContains(t, err, "immutable")
	}
}

func TestRegistryEventRulesValidateAgainstABI(t *testing.T) {
	contract := registryContract()
	contract.ABI = json.RawMessage(`[{"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}],"anonymous":false}]`)
	events, err := rbac.ExtractEventSignatures(string(contract.ABI))
	require.NoError(t, err)
	valid := EventRule{Topic0: events[0].Topic0, Name: "Transfer", ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}}}
	for name, rules := range map[string][]EventRule{
		"unknown topic":         {{Topic0: "0x" + strings.Repeat("1", 64), Name: "Transfer", ParamRules: []rbac.ParamRule{}}},
		"name mismatch":         {{Topic0: valid.Topic0, Name: "Fake", ParamRules: []rbac.ParamRule{}}},
		"duplicate topic":       {valid, valid},
		"self requires address": {{Topic0: valid.Topic0, Name: valid.Name, ParamRules: []rbac.ParamRule{{Index: 1, MustBe: "self"}}}},
		"duplicate parameter":   {{Topic0: valid.Topic0, Name: valid.Name, ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}, {Index: 0, MustBe: "self"}}}},
		"unsupported predicate": {{Topic0: valid.Topic0, Name: valid.Name, ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "anything"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			contract.ReadGrants[0].EventRules = EventRules{Mode: "allowlist", Rules: rules}
			b, err := json.Marshal(registryDocument(contract))
			require.NoError(t, err)
			_, err = Parse(b)
			require.Error(t, err)
		})
	}
	contract.ReadGrants[0].EventRules = EventRules{Mode: "allowlist", Rules: []EventRule{valid}}
	b, err := json.Marshal(registryDocument(contract))
	require.NoError(t, err)
	_, err = Parse(b)
	require.NoError(t, err)
}
