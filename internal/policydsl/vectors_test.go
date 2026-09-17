package policydsl

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/nodepolicy"
)

// TestLifecycleVectors records inputs independently of production ABI packing.
// Rust consumes the same fixture to check its encoder and actual EVM adapter.
func TestLifecycleVectors(t *testing.T) {
	v, e := lifecyclePolicy(t,
		map[string]any{"targetClass": "org", "selector": "*", "allowUpgrade": true},
		map[string]any{"targetClass": "eoa", "selector": "0x"},
		map[string]any{"targetClass": "create", "selector": "*", "callTypes": []string{"create", "create2"}},
	)
	type vector struct {
		Name           string         `json:"name"`
		Facts          map[string]any `json:"facts"`
		Call           map[string]any `json:"call"`
		CalldataHex    string         `json:"calldata_hex"`
		ExpectedReason uint64         `json:"expected_reason"`
	}
	header := nodepolicy.Header{Network: nodepolicy.Network{ChainID: 31337, DeploymentID: "compiler-fixture"}, IssuedAt: 1_800_000_000, ExpiresAt: 1_800_000_060}
	snapshot := nodepolicy.Snapshot{Header: header, Version: 1,
		Principals: []nodepolicy.Principal{{ID: "fixture_principal", KYC: true, LinkedAddresses: []string{strings.ToLower(signerAddr.Hex()), strings.ToLower(linkedAddr.Hex())}, Memberships: []nodepolicy.Membership{{GroupID: groupID}}}},
		Groups:     []nodepolicy.Group{{ID: groupID, OrgID: orgID, OrgAdmin: true, Claims: 7}},
		Contracts:  []nodepolicy.Contract{{Address: vaultAddr, OrgID: orgID}},
		Policies:   []nodepolicy.PolicyArtifact{{OrgID: orgID, Revision: 1, PolicyDigest: e.artifact.PolicyDigest, RuntimeDigest: e.artifact.RuntimeDigest, Bytecode: e.artifact.RuntimeBytecode}},
	}
	if _, err := nodepolicy.Pin(snapshot); err != nil {
		t.Fatal(err)
	}
	fixture := struct {
		Schema    int                 `json:"schema"`
		Signature string              `json:"signature"`
		Snapshot  nodepolicy.Snapshot `json:"snapshot"`
		Cases     []vector            `json:"cases"`
	}{Schema: 1, Signature: CheckSignature, Snapshot: snapshot}
	spec, err := abi.JSON(strings.NewReader(expectedFactsABI))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"org-call", "native-transfer", "unknown-contract-denied", "create", "create2", "create-claim-revoked", "create-foreign-owner"} {
		facts, call := factsFixtures(t)
		facts.Claims = 7
		facts.GroupClaims = []uint8{7}
		call.Value, call.Depth = big.NewInt(0), big.NewInt(0)
		call.Caller = signerAddr
		want := uint64(0)
		switch name {
		case "native-transfer", "unknown-contract-denied":
			facts.CodeOrg, facts.StorageOrg = [32]byte{}, [32]byte{}
			facts.CodeKind = 1
			call.CodeAddress, call.StorageAddress = linkedAddr, linkedAddr
			call.Data = nil
			call.Value = big.NewInt(123)
			if name == "unknown-contract-denied" {
				facts.CodeKind = 2
				want = 4
			}
		case "create", "create2", "create-claim-revoked", "create-foreign-owner":
			facts.CodeKind = 1
			call.Kind = 4
			call.Data = []byte{0x60, 0, 0x60, 0, 0xf3}
			call.CodeAddress, call.StorageAddress = linkedAddr, linkedAddr
			if name == "create2" {
				call.Kind = 5
			}
			if name == "create-claim-revoked" {
				facts.GroupClaims = []uint8{0}
				want = 9
			}
			if name == "create-foreign-owner" {
				facts.StorageOrg = GroupID("foreign")
				want = 4
			}
		}
		if got := executeLifecycleFixture(t, v, e, facts, call); got != want {
			t.Fatalf("%s: got %d want %d", name, got, want)
		}
		wire, err := spec.Pack("check", facts, call)
		if err != nil {
			t.Fatal(err)
		}
		factJSON := map[string]any{"signer": facts.Signer.Hex(), "linked_addresses": []string{facts.LinkedAddresses[0].Hex(), facts.LinkedAddresses[1].Hex()},
			"groups": []string{common.Hash(facts.Groups[0]).Hex()}, "policy_org": common.Hash(facts.PolicyOrg).Hex(), "caller_org": common.Hash(facts.CallerOrg).Hex(),
			"code_org": common.Hash(facts.CodeOrg).Hex(), "storage_org": common.Hash(facts.StorageOrg).Hex(), "claims": facts.Claims, "code_shared": facts.CodeShared, "storage_shared": facts.StorageShared,
			"code_kind": facts.CodeKind, "upgrade_target_org": common.Hash(facts.UpgradeTargetOrg).Hex(), "group_claims": []int{int(facts.GroupClaims[0])}, "storage_deployer": facts.StorageDeployer, "storage_pending": facts.StoragePending}
		callJSON := map[string]any{"kind": call.Kind, "caller": call.Caller.Hex(), "code_address": call.CodeAddress.Hex(), "storage_address": call.StorageAddress.Hex(), "data_hex": "0x" + hex.EncodeToString(call.Data), "value": call.Value.String(), "depth": call.Depth.String()}
		fixture.Cases = append(fixture.Cases, vector{Name: name, Facts: factJSON, Call: callJSON, CalldataHex: "0x" + hex.EncodeToString(wire), ExpectedReason: want})
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "lifecycle-v1.json")
	if os.Getenv("OPS_DSL_UPDATE_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, encoded) {
		t.Fatal("cross-language fixture differs: review changes, then regenerate with OPS_DSL_UPDATE_FIXTURES=1")
	}
}
