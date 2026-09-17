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
)

// The node executes this same Solidity artifact against the supplied record
// code/state. It must observe state changes without updating directory facts.
func TestRecordPartyVectors(t *testing.T) {
	_, e, a := recordPolicyFixture(t)
	spec, err := abi.JSON(strings.NewReader(expectedFactsABI))
	if err != nil {
		t.Fatal(err)
	}
	facts, call := factsFixtures(t)
	call.Data = packCalldata(t, recordABI, "completePayment", "PAY-1")
	call.Caller = signerAddr
	call.Value = big.NewInt(0)
	call.Depth = big.NewInt(0)
	input, err := spec.Pack("check", facts, call)
	if err != nil {
		t.Fatal(err)
	}
	type vector struct {
		Name           string            `json:"name"`
		Storage        map[string]string `json:"storage"`
		ExpectedReason uint64            `json:"expected_reason"`
	}
	fixture := struct {
		Schema              int      `json:"schema"`
		Signature           string   `json:"signature"`
		OrgID               string   `json:"org_id"`
		GroupID             string   `json:"group_id"`
		Signer              string   `json:"signer"`
		Linked              []string `json:"linked_addresses"`
		Policy              *Policy  `json:"policy"`
		PolicyRuntimeHex    string   `json:"policy_runtime_hex"`
		PolicyDigest        string   `json:"policy_digest"`
		RecordAddress       string   `json:"record_address"`
		RecordRuntimeHex    string   `json:"record_runtime_hex"`
		RecordABI           string   `json:"record_abi"`
		CallDataHex         string   `json:"call_data_hex"`
		CheckCalldataHex    string   `json:"check_calldata_hex"`
		MutationCalldataHex string   `json:"mutation_calldata_hex"`
		Cases               []vector `json:"cases"`
	}{Schema: 1, Signature: CheckSignature, OrgID: orgID, GroupID: groupID, Signer: signerAddr.Hex(), Linked: []string{signerAddr.Hex(), linkedAddr.Hex()}, Policy: evaluateRecordDocument(t), PolicyRuntimeHex: "0x" + hex.EncodeToString(a.RuntimeBytecode), PolicyDigest: a.PolicyDigest, RecordAddress: vaultAddr, RecordRuntimeHex: "0x" + hex.EncodeToString(e.stateDB.GetCode(common.HexToAddress(vaultAddr))), RecordABI: recordABI, CallDataHex: "0x" + hex.EncodeToString(call.Data), CheckCalldataHex: "0x" + hex.EncodeToString(input), MutationCalldataHex: "0x" + hex.EncodeToString(packCalldata(t, recordABI, "setParties", strangerAddr, strangerAddr))}
	for _, name := range []string{"linked-party", "changed-party", "short-return", "revert", "out-of-gas", "noncanonical-address", "noncanonical-bool", "return-bomb"} {
		payer, payee, mode := strangerAddr, linkedAddr, int64(0)
		want := uint64(reasonArgumentConstraint)
		switch name {
		case "linked-party":
			want = 0
		case "changed-party":
			payee = strangerAddr
		case "short-return":
			mode = 1
		case "revert":
			mode = 2
		case "out-of-gas":
			mode = 3
		case "noncanonical-address":
			mode = 4
		case "noncanonical-bool":
			mode = 5
		case "return-bomb":
			mode = 6
		}
		storage := map[string]string{common.Hash{}.Hex(): common.BytesToHash(payer.Bytes()).Hex(), common.BigToHash(big.NewInt(1)).Hex(): common.BytesToHash(payee.Bytes()).Hex(), common.BigToHash(big.NewInt(2)).Hex(): common.BigToHash(big.NewInt(mode)).Hex()}
		for slot, value := range storage {
			e.stateDB.SetState(common.HexToAddress(vaultAddr), common.HexToHash(slot), common.HexToHash(value))
		}
		if got := executeFactsFixture(t, e, facts, call); got != want {
			t.Fatalf("vector %s: got %d want %d", name, got, want)
		}
		fixture.Cases = append(fixture.Cases, vector{Name: name, Storage: storage, ExpectedReason: want})
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "record-party-v1.json")
	if os.Getenv("OPS_DSL_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(path, encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, stored) {
		t.Fatal("record-party fixture differs: review, then regenerate with OPS_DSL_UPDATE_FIXTURES=1")
	}
}

func evaluateRecordDocument(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse(recordPolicyJSON(t, "getPaymentInfo", nil))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
