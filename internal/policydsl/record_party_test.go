package policydsl

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

const recordABI = `[
 {"type":"function","name":"completePayment","stateMutability":"nonpayable","inputs":[{"name":"id","type":"string"}],"outputs":[]},
 {"type":"function","name":"getPaymentInfo","stateMutability":"view","inputs":[{"name":"id","type":"string"}],"outputs":[{"name":"amount","type":"uint256"},{"name":"timestamp","type":"uint256"},{"name":"payer","type":"address"},{"name":"payee","type":"address"},{"name":"completed","type":"bool"}]},
 {"type":"function","name":"setParties","stateMutability":"nonpayable","inputs":[{"name":"payer","type":"address"},{"name":"payee","type":"address"}],"outputs":[]}
]`

const recordContractSource = `pragma solidity 0.8.35;
contract RecordFixture {
    address public payer;
    address public payee;
    uint256 public mode;
    function setParties(address a, address b) external { payer = a; payee = b; }
    function getPaymentInfo(string calldata id) external view returns(uint256,uint256,address,address,bool) {
        require(keccak256(bytes(id)) == keccak256("PAY-1"));
        if (mode == 1) { assembly { mstore(0,0) return(0,32) } }
        if (mode == 2) revert("private record");
        if (mode == 3) { assembly { for {} 1 {} {} } }
        if (mode == 4) { assembly { mstore(0,11) mstore(32,22) mstore(64,shl(160,1)) mstore(96,0) mstore(128,1) return(0,160) } }
        if (mode == 5) { assembly { mstore(0,11) mstore(32,22) mstore(64,sload(0)) mstore(96,sload(1)) mstore(128,2) return(0,160) } }
        if (mode == 6) { assembly { return(0,1048576) } }
        return (11,22,payer,payee,true);
    }
}`

func recordPolicyJSON(t *testing.T, getter string, extra map[string]any) []byte {
	t.Helper()
	spec, err := abi.JSON(strings.NewReader(recordABI))
	if err != nil {
		t.Fatal(err)
	}
	record := map[string]any{"getter": "0x" + hex.EncodeToString(spec.Methods[getter].ID), "abiDigest": ABIDigest(recordABI), "partyOutputs": []int{2, 3}}
	for k, v := range extra {
		record[k] = v
	}
	doc := map[string]any{"apiVersion": APIVersion, "kind": Kind, "org": orgID, "nestedCalls": NestedCallsRequireOwnRule, "bindings": []any{map[string]any{"group": groupID, "allow": []any{map[string]any{"storageAddress": vaultAddr, "selector": "0x" + hex.EncodeToString(spec.Methods["completePayment"].ID), "abiDigest": ABIDigest(recordABI), "args": []any{map[string]any{"index": 0, "recordParty": record}}}}}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func recordPolicyFixture(t *testing.T) (*Validated, *EVMEvaluator, *Artifact) {
	t.Helper()
	p, err := Parse(recordPolicyJSON(t, "getPaymentInfo", nil))
	if err != nil {
		t.Fatal(err)
	}
	cat := testCatalog(t)
	cat.Contracts[vaultAddr] = ContractInfo{ABI: recordABI}
	v, err := Validate(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	a, err := requireCompiler(t).Build(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEVMEvaluator(a)
	if err != nil {
		t.Fatal(err)
	}
	address := common.HexToAddress(vaultAddr)
	e.stateDB.CreateAccount(address)
	e.stateDB.SetCode(address, compileRecordContract(t), tracing.CodeChangeUnspecified)
	e.stateDB.SetState(address, common.Hash{}, common.BytesToHash(signerAddr.Bytes()))
	e.stateDB.SetState(address, common.BigToHash(big.NewInt(1)), common.BytesToHash(linkedAddr.Bytes()))
	return v, e, a
}

func compileRecordContract(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "RecordFixture.sol")
	if err := os.WriteFile(path, []byte(recordContractSource), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(requireCompiler(t).binary(), "--combined-json", "bin-runtime", "--base-path", dir, "--optimize", "--evm-version", EVMVersion, path)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result solcOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	for name, contract := range result.Contracts {
		if strings.HasSuffix(name, ":RecordFixture") {
			b, err := hex.DecodeString(contract.BinRuntime)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatal("missing compiled record fixture")
	return nil
}

func TestRecordPartyReadsLiveSameBlockStateAndAllLinkedAddresses(t *testing.T) {
	_, e, _ := recordPolicyFixture(t)
	facts, call := factsFixtures(t)
	call.Data = packCalldata(t, recordABI, "completePayment", "PAY-1")
	facts.LinkedAddresses = []common.Address{linkedAddr}
	if got := executeFactsFixture(t, e, facts, call); got != 0 {
		t.Fatalf("linked party denied: %d", got)
	}
	// A real state-changing EVM call in this same candidate state changes the
	// parties. The next policy call must observe it without a new snapshot.
	setter := packCalldata(t, recordABI, "setParties", strangerAddr, strangerAddr)
	evm := vm.NewEVM(e.blockCtx, e.stateDB, e.chainCfg, vm.Config{NoBaseFee: true})
	evm.SetTxContext(vm.TxContext{Origin: signerAddr, GasPrice: uint256.NewInt(0)})
	if _, _, err := evm.Call(signerAddr, common.HexToAddress(vaultAddr), setter, vm.GasBudget{RegularGas: 100_000}, uint256.NewInt(0)); err != nil {
		t.Fatal(err)
	}
	if got := executeFactsFixture(t, e, facts, call); got != reasonArgumentConstraint {
		t.Fatalf("stale party allowed after same-block change: %d", got)
	}
	facts.LinkedAddresses = []common.Address{strangerAddr}
	if got := executeFactsFixture(t, e, facts, call); got != 0 {
		t.Fatalf("new party denied: %d", got)
	}
	if e.stateDB.GetState(common.HexToAddress(vaultAddr), common.Hash{}) != common.BytesToHash(strangerAddr.Bytes()) {
		t.Fatal("policy changed record state")
	}
}

func TestRecordPartyGetterFailuresDeny(t *testing.T) {
	v, e, _ := recordPolicyFixture(t)
	facts, call := factsFixtures(t)
	call.Data = packCalldata(t, recordABI, "completePayment", "PAY-1")
	for _, mode := range []int64{1, 2, 3, 4, 5, 6} {
		e.stateDB.SetState(common.HexToAddress(vaultAddr), common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(mode)))
		if got := executeFactsFixture(t, e, facts, call); got != reasonArgumentConstraint {
			t.Fatalf("getter failure mode %d allowed or wrong reason: %d", mode, got)
		}
		ctx := memberCtx()
		ctx.ReadRecord = e.ReadContract
		if got := v.Evaluate(ctx, []Frame{vaultCall(call.Data)}); got.Allowed || got.Code != DenialArgumentConstraint {
			t.Fatalf("reference mode %d: %+v", mode, got)
		}
	}
}

func TestRecordPartyOfflineOracleRequiresLiveReaderAndUsesMappedID(t *testing.T) {
	v, e, _ := recordPolicyFixture(t)
	ctx := memberCtx()
	ctx.LinkedAddresses = []common.Address{linkedAddr}
	frame := vaultCall(packCalldata(t, recordABI, "completePayment", "PAY-1"))
	if v.Evaluate(ctx, []Frame{frame}).Allowed {
		t.Fatal("missing live reader allowed")
	}
	want := packCalldata(t, recordABI, "getPaymentInfo", "PAY-1")
	called := false
	ctx.ReadRecord = func(target common.Address, input []byte, gas uint64) ([]byte, error) {
		called = true
		if target != frame.StorageAddress || !bytes.Equal(input, want) || gas != RecordReadGas {
			t.Fatalf("wrong read target/input/budget: %s %x %d", target, input, gas)
		}
		return e.ReadContract(target, input, gas)
	}
	if got := v.Evaluate(ctx, []Frame{frame}); !got.Allowed || !called {
		t.Fatalf("offline record reader: %+v called=%v", got, called)
	}
	ctx.LinkedAddresses = nil
	if v.Evaluate(ctx, []Frame{frame}).Allowed {
		t.Fatal("signer alone borrowed party identity")
	}
}

func TestRecordPartyRejectsMalformedAndOversizeDynamicIDs(t *testing.T) {
	v, e, _ := recordPolicyFixture(t)
	facts, call := factsFixtures(t)
	valid := packCalldata(t, recordABI, "completePayment", "PAY-1")
	for _, name := range []string{"offset-head", "offset-unaligned", "offset-overflow", "length-overflow", "truncated", "dirty-padding", "oversize"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			switch name {
			case "offset-head":
				data[35] = 0
			case "offset-unaligned":
				data[35] = 33
			case "offset-overflow":
				data[4] = 0xff
			case "length-overflow":
				data[36] = 0xff
			case "truncated":
				data = data[:len(data)-1]
			case "dirty-padding":
				data[len(data)-1] = 1
			case "oversize":
				data = packCalldata(t, recordABI, "completePayment", strings.Repeat("x", MaxRecordIDBytes+1))
			}
			call.Data = data
			if got := executeFactsFixture(t, e, facts, call); got != reasonMalformedCalldata {
				t.Fatalf("malformed ID reason %d", got)
			}
			ctx := memberCtx()
			ctx.ReadRecord = e.ReadContract
			if got := v.Evaluate(ctx, []Frame{vaultCall(data)}); got.Allowed || got.Code != DenialMalformedCalldata {
				t.Fatalf("reference malformed ID: %+v", got)
			}
		})
	}
}

func TestRecordPartyStrictJSONAndClone(t *testing.T) {
	valid := recordPolicyJSON(t, "getPaymentInfo", nil)
	for _, input := range []string{
		strings.Replace(string(valid), `"index":0`, `"index":null`, 1),
		strings.Replace(string(valid), `"index":0`, `"index":0,"index":1`, 1),
		strings.Replace(string(valid), `"partyOutputs":[2,3]`, `"partyOutputs":null`, 1),
		strings.Replace(string(valid), `"partyOutputs":[2,3]`, `"partyOutputs":[2,3],"partyOutputs":[2]`, 1),
		strings.Replace(string(valid), `"partyOutputs"`, `"PartyOutputs"`, 1),
	} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatal("ambiguous record constraint accepted")
		}
	}
	v, _, _ := recordPolicyFixture(t)
	copy := v.Policy()
	copy.Bindings[0].Allow[0].Args[0].RecordParty.PartyOutputs[0] = 0
	if v.Policy().Bindings[0].Allow[0].Args[0].RecordParty.PartyOutputs[0] != 2 {
		t.Fatal("record constraints not deep copied")
	}
}

func TestRecordPartySupportedIDsMapExactlyAfterCompositeHead(t *testing.T) {
	for _, tc := range []struct {
		name, typ string
		value     any
	}{
		{"uint8", "uint8", uint8(7)},
		{"bytes32", "bytes32", [32]byte{1, 2, 3}},
		{"string", "string", "PAY-1"},
		{"bytes", "bytes", []byte("PAY-1")},
		{"bounded-string", "string", strings.Repeat("x", MaxRecordIDBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			abiText := fmt.Sprintf(`[{"type":"function","name":"act","inputs":[{"name":"prefix","type":"uint256[2]"},{"name":"id","type":"%s"}],"outputs":[]},{"type":"function","name":"party","stateMutability":"view","inputs":[{"name":"id","type":"%s"}],"outputs":[{"name":"party","type":"address"}]}]`, tc.typ, tc.typ)
			spec, err := abi.JSON(strings.NewReader(abiText))
			if err != nil {
				t.Fatal(err)
			}
			p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{{Group: groupID, Allow: []FrameRule{{StorageAddress: vaultAddr, Selector: "0x" + hex.EncodeToString(spec.Methods["act"].ID), ABIDigest: ABIDigest(abiText), Args: []ArgConstraint{{Index: 1, RecordParty: &RecordPartyMatch{Getter: "0x" + hex.EncodeToString(spec.Methods["party"].ID), ABIDigest: ABIDigest(abiText), PartyOutputs: []int{0}}}}}}}}}
			cat := testCatalog(t)
			cat.Contracts[vaultAddr] = ContractInfo{ABI: abiText}
			v, err := Validate(p, cat)
			if err != nil {
				t.Fatal(err)
			}
			a, err := requireCompiler(t).Build(context.Background(), v)
			if err != nil {
				t.Fatal(err)
			}
			e, err := NewEVMEvaluator(a)
			if err != nil {
				t.Fatal(err)
			}
			getterInput := packCalldata(t, abiText, "party", tc.value)
			address := common.HexToAddress(vaultAddr)
			e.stateDB.CreateAccount(address)
			e.stateDB.SetCode(address, recordExactInputGetter(getterInput, linkedAddr), tracing.CodeChangeUnspecified)
			data := packCalldata(t, abiText, "act", [2]*big.Int{big.NewInt(300), big.NewInt(400)}, tc.value)
			facts, call := factsFixtures(t)
			call.Data = data
			if got := executeFactsFixture(t, e, facts, call); got != 0 {
				t.Fatalf("compiled mapped ID denied: %d", got)
			}
			ctx := memberCtx()
			ctx.ReadRecord = e.ReadContract
			if got := v.Evaluate(ctx, []Frame{vaultCall(data)}); !got.Allowed {
				t.Fatalf("reference mapped ID denied: %+v", got)
			}
			if tc.typ == "uint8" {
				data[4+64] = 1
				call.Data = data
				if got := executeFactsFixture(t, e, facts, call); got != reasonMalformedCalldata {
					t.Fatalf("dirty uint ID accepted: %d", got)
				}
				if got := v.Evaluate(ctx, []Frame{vaultCall(data)}); got.Allowed || got.Code != DenialMalformedCalldata {
					t.Fatalf("reference dirty uint: %+v", got)
				}
			}
		})
	}
}

// Independent EVM fixture verifies the entire getter calldata hash before
// returning a party. A wrong ID, ABI offset, selector or padding reverts.
func recordExactInputGetter(input []byte, party common.Address) []byte {
	code := []byte{0x36, 0x60, 0, 0x60, 0, 0x37, 0x36, 0x60, 0, 0x20, 0x7f}
	code = append(code, crypto.Keccak256(input)...)
	code = append(code, 0x14, 0x60, 0, 0x57, 0x60, 0, 0x60, 0, 0xfd)
	code[45] = byte(len(code))
	code = append(code, 0x5b, 0x73)
	code = append(code, party.Bytes()...)
	return append(code, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3)
}

func TestRecordPartyGetterCannotWriteState(t *testing.T) {
	v, e, _ := recordPolicyFixture(t)
	address := common.HexToAddress(vaultAddr)
	before := e.stateDB.GetState(address, common.Hash{})
	// SSTORE would erase the payer if a reader accidentally used CALL.
	e.stateDB.SetCode(address, []byte{0x60, 0, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xf3}, tracing.CodeChangeUnspecified)
	facts, call := factsFixtures(t)
	call.Data = packCalldata(t, recordABI, "completePayment", "PAY-1")
	if got := executeFactsFixture(t, e, facts, call); got != reasonArgumentConstraint {
		t.Fatalf("writing getter allowed: %d", got)
	}
	ctx := memberCtx()
	ctx.ReadRecord = e.ReadContract
	if got := v.Evaluate(ctx, []Frame{vaultCall(call.Data)}); got.Allowed {
		t.Fatal("reference writing getter allowed")
	}
	if after := e.stateDB.GetState(address, common.Hash{}); after != before {
		t.Fatal("policy getter modified guarded storage")
	}
}

func TestRecordPartyValidationRejectsUnsafeGetters(t *testing.T) {
	for _, tc := range []struct {
		name, getter string
		fields       map[string]any
	}{
		{"non-view", "setParties", nil},
		{"wrong-digest", "getPaymentInfo", map[string]any{"abiDigest": strings.Repeat("0", 64)}},
		{"no-parties", "getPaymentInfo", map[string]any{"partyOutputs": []int{}}},
		{"not-address", "getPaymentInfo", map[string]any{"partyOutputs": []int{0}}},
		{"duplicate-output", "getPaymentInfo", map[string]any{"partyOutputs": []int{2, 2}}},
		{"unknown-output", "getPaymentInfo", map[string]any{"partyOutputs": []int{99}}},
		{"arbitrary-target", "getPaymentInfo", map[string]any{"target": vaultAddr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(recordPolicyJSON(t, tc.getter, tc.fields))
			if err == nil {
				cat := testCatalog(t)
				cat.Contracts[vaultAddr] = ContractInfo{ABI: recordABI}
				_, err = Validate(p, cat)
			}
			if err == nil {
				t.Fatal("unsafe record getter accepted")
			}
		})
	}
}
