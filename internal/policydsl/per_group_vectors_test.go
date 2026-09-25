package policydsl

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/nodepolicy"
)

// Rust executes these exact compiler outputs inside the guarded node EVM. The
// expected verdict comes from the previous whole-document compiled policy.
func TestPerGroupVectors(t *testing.T) {
	p, catalog := conformancePolicy(t)
	p.Bindings[1].Allow[0].CallTypes = []CallType{CallTypeCall, CallTypeStaticCall}
	v, err := Validate(p, catalog)
	require.NoError(t, err)
	c := requireCompiler(t)
	whole, err := c.Build(t.Context(), v)
	require.NoError(t, err)
	set, err := c.BuildSet(t.Context(), v)
	require.NoError(t, err)
	e, err := NewEVMEvaluator(whole)
	require.NoError(t, err)
	spec, err := abi.JSON(strings.NewReader(expectedFactsABI))
	require.NoError(t, err)
	snapshot := nodepolicy.Snapshot{Header: nodepolicy.Header{Network: nodepolicy.Network{ChainID: 31337, DeploymentID: "per-group-fixture"}, IssuedAt: 1800000000, ExpiresAt: 1800000060}, Version: 1,
		Principals: []nodepolicy.Principal{{ID: "fixture_principal", LinkedAddresses: []string{strings.ToLower(signerAddr.Hex()), strings.ToLower(linkedAddr.Hex())}, Memberships: []nodepolicy.Membership{{GroupID: groupID}, {GroupID: auditorsGroup}}}},
		Groups:     []nodepolicy.Group{{ID: groupID, OrgID: orgID}, {ID: auditorsGroup, OrgID: orgID}},
		Contracts:  []nodepolicy.Contract{{Address: vaultAddr, OrgID: orgID}, {Address: strings.ToLower(libraryAddr.Hex()), OrgID: orgID}},
	}
	for _, group := range v.Groups() {
		a := set.Groups[group]
		snapshot.Policies = append(snapshot.Policies, nodepolicy.PolicyArtifact{OrgID: orgID, GroupID: group, Revision: 1, PolicyDigest: a.PolicyDigest, RuntimeDigest: a.RuntimeDigest, Bytecode: a.RuntimeBytecode})
	}
	_, err = nodepolicy.Pin(snapshot)
	require.NoError(t, err)
	type vector struct {
		Name     string `json:"name"`
		Calldata string `json:"calldata"`
		Input    string `json:"input"`
		Expected uint64 `json:"expected"`
	}
	fixture := struct {
		Snapshot nodepolicy.Snapshot `json:"snapshot"`
		Cases    []vector            `json:"cases"`
	}{Snapshot: snapshot}
	for _, name := range []string{"second-group-allows", "second-group-argument-denial", "first-group-allows", "no-matching-rule", "malformed-calldata"} {
		facts, call := factsFixtures(t)
		facts.Groups = [][32]byte{GroupID(auditorsGroup), GroupID(groupID)}
		facts.GroupClaims = []uint8{0, 0}
		facts.CallerOrg = [32]byte{}
		call.Caller, call.Value, call.Depth = signerAddr, big.NewInt(0), big.NewInt(0)
		switch name {
		case "second-group-argument-denial":
			call.Data = transferCalldata(t, signerAddr, big.NewInt(101))
		case "first-group-allows":
			call.Data = balanceOfCalldata(t, signerAddr)
		case "no-matching-rule":
			call.Data = []byte{1, 2, 3, 4}
		case "malformed-calldata":
			call.Data = []byte{1}
		}
		want := executeFactsFixture(t, e, facts, call)
		var specific uint64
		fallback := uint64(1)
		allowed := false
		for _, group := range v.Groups() {
			part, err := NewEVMEvaluator(set.Groups[group])
			require.NoError(t, err)
			reason := executeFactsFixture(t, part, facts, call)
			if reason == 0 {
				allowed = true
				break
			}
			if reason >= 256 {
				fallback = reason - 256
			} else if specific == 0 {
				specific = reason
			}
		}
		got := fallback
		if specific != 0 {
			got = specific
		}
		if allowed {
			got = 0
		}
		require.Equal(t, want, got, name)
		input, err := spec.Pack("check", facts, call)
		require.NoError(t, err)
		fixture.Cases = append(fixture.Cases, vector{Name: name, Calldata: "0x" + hex.EncodeToString(call.Data), Input: "0x" + hex.EncodeToString(input), Expected: want})
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')
	path := "testdata/per-group-v1.json"
	if os.Getenv("OPS_DSL_UPDATE_FIXTURES") == "1" {
		require.NoError(t, os.WriteFile(path, encoded, 0644))
	}
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(stored), string(encoded), "regenerate intentionally with OPS_DSL_UPDATE_FIXTURES=1")
}
