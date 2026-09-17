package configuration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/rbac"
)

const orgID = "11111111-1111-1111-1111-111111111111"
const groupOne = "22222222-2222-2222-2222-222222222221"
const groupTwo = "22222222-2222-2222-2222-222222222222"
const groupDrift = "22222222-2222-2222-2222-222222222223"

func group(id string) Group {
	return Group{ID: id, Slug: "group-" + id, Name: id, AllowedMethods: []string{"eth_call"}, Claims: []string{}}
}
func source(t *testing.T, groups []Group) []byte {
	t.Helper()
	b, err := json.Marshal(Document{APIVersion: APIVersion, Kind: Groups, Scope: Scope{Kind: "organization", ID: orgID},
		BaseRevision: 4, Dependencies: map[Kind]string{}, Deletions: []Deletion{}, Spec: GroupsSpec{Groups: groups}})
	require.NoError(t, err)
	return b
}

func TestDocumentStrictAndCanonical(t *testing.T) {
	good := source(t, []Group{group(groupTwo), group(groupOne)})
	doc, err := Parse(good)
	require.NoError(t, err)
	canonical, digest, err := doc.Canonical()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(digest, "sha256:"))
	reordered, err := Parse(source(t, []Group{group(groupOne), group(groupTwo)}))
	require.NoError(t, err)
	canonical2, digest2, err := reordered.Canonical()
	require.NoError(t, err)
	require.Equal(t, string(canonical), string(canonical2))
	require.Equal(t, digest, digest2)
	for name, bad := range map[string]string{
		"missing base":     strings.Replace(string(good), `"baseRevision":4,`, "", 1),
		"null groups":      strings.Replace(string(source(t, []Group{})), `"groups":[]`, `"groups":null`, 1),
		"case alias":       strings.Replace(string(good), `"isOrgAdmin"`, `"IsOrgAdmin"`, 1),
		"duplicate key":    strings.Replace(string(good), `"baseRevision":4`, `"baseRevision":4,"baseRevision":4`, 1),
		"missing methods":  strings.Replace(string(good), `"allowedMethods":["eth_call"],`, "", 1),
		"null claims":      strings.Replace(string(good), `"claims":[]`, `"claims":null`, 1),
		"unknown secret":   strings.Replace(string(good), `"verboseErrors":false`, `"verboseErrors":false,"rpc_api_key":"secret"`, 1),
		"cross scope":      strings.Replace(string(good), `"kind":"organization"`, `"kind":"platform"`, 1),
		"unsupported kind": strings.Replace(string(good), `"kind":"groups"`, `"kind":"whatever"`, 1),
		"trailing value":   string(good) + `{}`,
	} {
		t.Run(name, func(t *testing.T) { _, err := Parse([]byte(bad)); require.Error(t, err) })
	}
}

func TestGroupDiffExplicitDeletionsAndDrift(t *testing.T) {
	one, two, drift := group(groupOne), group(groupTwo), group(groupDrift)
	updated := one
	updated.Name = "Payments"
	doc, err := Parse(source(t, []Group{updated}))
	require.NoError(t, err)
	snapshot := GroupSnapshot{Scope: doc.Scope, ActiveRevision: 4, Groups: []GroupState{
		{Group: one, Managed: true}, {Group: two, Managed: true, LiveMemberships: 3}, {Group: drift},
	}}
	_, err = DiffGroups(doc, snapshot)
	require.ErrorContains(t, err, "deletion")
	wrong, exact := int64(2), int64(3)
	doc.Deletions = []Deletion{{ID: groupTwo, LiveMemberships: &wrong}}
	_, err = DiffGroups(doc, snapshot)
	require.ErrorContains(t, err, "membership")
	doc.Deletions[0].LiveMemberships = &exact
	diff, err := DiffGroups(doc, snapshot)
	require.NoError(t, err)
	require.Equal(t, []string{groupDrift}, diff.PreservedDrift)
	require.Len(t, diff.Changes, 2)
	require.Len(t, diff.Projection, 2)
	require.Equal(t, updated, diff.Projection[0])
	require.Equal(t, drift, diff.Projection[1])
	doc.Deletions = append(doc.Deletions, Deletion{ID: groupDrift})
	_, err = DiffGroups(doc, snapshot)
	require.ErrorContains(t, err, "unmanaged")
}

func TestGroupDiffScopeBaseProtectionAndAdoption(t *testing.T) {
	one := group(groupOne)
	doc, err := Parse(source(t, []Group{one}))
	require.NoError(t, err)
	snapshot := GroupSnapshot{Scope: doc.Scope, ActiveRevision: 4, Groups: []GroupState{{Group: one}}}
	diff, err := DiffGroups(doc, snapshot)
	require.NoError(t, err)
	require.Equal(t, "adopt", diff.Changes[0].Action)
	snapshot.ActiveRevision = 5
	_, err = DiffGroups(doc, snapshot)
	require.ErrorContains(t, err, "base")
	snapshot.ActiveRevision = 4
	snapshot.Scope.ID = groupOne
	_, err = DiffGroups(doc, snapshot)
	require.ErrorContains(t, err, "scope")
	snapshot.Scope = doc.Scope
	snapshot.Groups[0].Protected = true
	spec := doc.Spec.(GroupsSpec)
	spec.Groups[0].Name = "rewrite system group"
	doc.Spec = spec
	_, err = DiffGroups(doc, snapshot)
	require.ErrorContains(t, err, "protected")
}

func TestLegacyExportKeepsReadClaimsAndFunctionNullDistinction(t *testing.T) {
	secret := "do-not-export"
	exportedGroup := ExportGroup(&rbac.Group{ID: groupOne, Slug: "payments", Name: "Payments"},
		&rbac.GroupAccess{AllowedMethods: []string{"eth_call"}, Claims: []rbac.Claim{rbac.ClaimDeploy}, RPCAPIKey: &secret})
	b, err := json.Marshal(exportedGroup)
	require.NoError(t, err)
	require.NotContains(t, string(b), secret)
	require.Equal(t, []string{"deploy"}, exportedGroup.Claims)
	wildcard := &rbac.EventRulesField{Wildcard: true}
	registry, execution, err := ExportRegistry([]RegistryRow{{Contract: &rbac.Contract{ID: orgID, Address: "0x1111111111111111111111111111111111111111", Name: "Vault", ABI: "[]"}, Grants: []GrantRow{
		{Grant: &rbac.ContractGrant{ID: groupDrift, GroupID: groupOne, Functions: nil, EventRules: wildcard}, Claims: []string{"admin"}},
		{Grant: &rbac.ContractGrant{ID: groupTwo, GroupID: groupTwo, Functions: []rbac.FunctionRule{}}, Claims: []string{}},
	}}})
	require.NoError(t, err)
	require.Nil(t, execution[0].Functions)
	require.NotNil(t, execution[1].Functions)
	require.Empty(t, execution[1].Functions)
	require.Equal(t, []string{"admin"}, registry.Contracts[0].ReadGrants[0].LegacyClaims)
	require.Equal(t, "all", registry.Contracts[0].ReadGrants[0].EventRules.Mode)
	require.Equal(t, "none", registry.Contracts[0].ReadGrants[1].EventRules.Mode)
	b, err = json.Marshal(registry)
	require.NoError(t, err)
	require.NotContains(t, string(b), "functions")
	// Round-tripping the registry document cannot recreate the old setter for
	// executable functions or silently widen an events-only grant.
	d := Document{APIVersion: APIVersion, Kind: ContractRegistry, Scope: Scope{Kind: "organization", ID: orgID}, BaseRevision: 0, Dependencies: map[Kind]string{}, Deletions: []Deletion{}, Spec: registry}
	b, err = json.Marshal(d)
	require.NoError(t, err)
	_, err = Parse(b)
	require.NoError(t, err)
	_, err = Parse([]byte(strings.Replace(string(b), `"readGrants":`, `"functions":null,"readGrants":`, 1)))
	require.Error(t, err)
}

func TestGroupDocumentPreservesLegacyMethodAndClaimSemantics(t *testing.T) {
	g := group(groupOne)
	g.AllowedMethods = []string{"debug_traceTransaction"}
	_, err := Parse(source(t, []Group{g}))
	require.NoError(t, err, "RD-1121 decouples trace method allowlists from deployment claims")
	g.Claims = []string{"deploy"}
	_, err = Parse(source(t, []Group{g}))
	require.NoError(t, err)
	g.IsOrgAdmin = true
	g.Claims = []string{}
	g.AllowedMethods = []string{"*"}
	doc, err := Parse(source(t, []Group{g}))
	require.NoError(t, err)
	require.NotContains(t, doc.Spec.(GroupsSpec).Groups[0].AllowedMethods, "*", "wildcards expand to the current explicit allowlist as in the original setter")
	_, _, err = doc.Canonical()
	require.NoError(t, err, "expanded standard method names must remain valid source")
}
