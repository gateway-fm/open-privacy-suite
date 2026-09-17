package policydsl

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// This independent ABI fixture is the node/compiler agreement, not the
// production packing descriptor. Calling compiled bytecode catches any change
// in tuple ordering or field widths on either side of that agreement.
const expectedFactsABI = `[{"type":"function","name":"check","stateMutability":"pure","inputs":[
  {"name":"facts","type":"tuple","components":[
    {"name":"signer","type":"address"},{"name":"linkedAddresses","type":"address[]"},{"name":"groups","type":"bytes32[]"},
    {"name":"policyOrg","type":"bytes32"},{"name":"callerOrg","type":"bytes32"},{"name":"codeOrg","type":"bytes32"},{"name":"storageOrg","type":"bytes32"},
    {"name":"claims","type":"uint8"},{"name":"codeShared","type":"bool"},{"name":"storageShared","type":"bool"},{"name":"codeKind","type":"uint8"},{"name":"upgradeTargetOrg","type":"bytes32"},{"name":"groupClaims","type":"uint8[]"},{"name":"storageDeployer","type":"bool"},{"name":"storagePending","type":"bool"}]},
  {"name":"frame","type":"tuple","components":[
    {"name":"kind","type":"uint8"},{"name":"caller","type":"address"},{"name":"codeAddress","type":"address"},{"name":"storageAddress","type":"address"},
    {"name":"data","type":"bytes"},{"name":"value","type":"uint256"},{"name":"depth","type":"uint256"}]}],
  "outputs":[{"name":"reason","type":"uint256"}]}]`

type factsWireFixture struct {
	Signer           common.Address
	LinkedAddresses  []common.Address
	Groups           [][32]byte
	PolicyOrg        [32]byte
	CallerOrg        [32]byte
	CodeOrg          [32]byte
	StorageOrg       [32]byte
	Claims           uint8
	CodeShared       bool
	StorageShared    bool
	CodeKind         uint8
	UpgradeTargetOrg [32]byte
	GroupClaims      []uint8
	StorageDeployer  bool
	StoragePending   bool
}

type callWireFixture struct {
	Kind           uint8
	Caller         common.Address
	CodeAddress    common.Address
	StorageAddress common.Address
	Data           []byte
	Value          *big.Int
	Depth          *big.Int
}

func factsFixtures(t *testing.T) (factsWireFixture, callWireFixture) {
	t.Helper()
	org := [32]byte(GroupID(orgID))
	return factsWireFixture{
			Signer: signerAddr, LinkedAddresses: []common.Address{signerAddr, linkedAddr}, Groups: [][32]byte{GroupID(groupID)},
			PolicyOrg: org, CallerOrg: org, CodeOrg: org, StorageOrg: org, CodeKind: 2, GroupClaims: []uint8{0},
		}, callWireFixture{
			Kind: 0, Caller: libraryAddr, CodeAddress: common.HexToAddress(vaultAddr), StorageAddress: common.HexToAddress(vaultAddr),
			Data: transferCalldata(t, signerAddr, big.NewInt(1)), Value: big.NewInt(10), Depth: big.NewInt(2),
		}
}

func factsPolicyDocument(t *testing.T, extra map[string]any) []byte {
	t.Helper()
	rule := map[string]any{"storageAddress": vaultAddr, "selector": selTransfer, "abiDigest": ABIDigest(vaultABI)}
	for k, value := range extra {
		rule[k] = value
	}
	doc, err := json.Marshal(map[string]any{
		"apiVersion": APIVersion, "kind": Kind, "org": orgID, "nestedCalls": NestedCallsRequireOwnRule,
		"bindings": []any{map[string]any{"group": groupID, "allow": []any{rule}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func compileFactsFixture(t *testing.T, extra map[string]any) *EVMEvaluator {
	t.Helper()
	p, err := Parse(factsPolicyDocument(t, extra))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := requireCompiler(t).Build(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEVMEvaluator(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func executeFactsFixture(t *testing.T, e *EVMEvaluator, facts factsWireFixture, frame callWireFixture) uint64 {
	t.Helper()
	spec, err := abi.JSON(strings.NewReader(expectedFactsABI))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := spec.Pack("check", facts, frame)
	if err != nil {
		t.Fatal(err)
	}
	evm := vm.NewEVM(e.blockCtx, e.stateDB, e.chainCfg, vm.Config{NoBaseFee: true})
	evm.SetTxContext(vm.TxContext{Origin: callerAddress, GasPrice: uint256.NewInt(0)})
	// These representative policies must fit the agreed node-internal budget.
	ret, _, err := evm.StaticCall(callerAddress, policyAddress, wire, vm.GasBudget{RegularGas: 100_000})
	if err != nil {
		t.Fatalf("facts-based policy call failed: %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("facts-based policy returned %d bytes, want one uint256", len(ret))
	}
	reason := new(big.Int).SetBytes(ret)
	if !reason.IsUint64() {
		t.Fatalf("unexpected reason %s", reason)
	}
	return reason.Uint64()
}

func TestFactsABI_ExplicitOwnershipAndKinds(t *testing.T) {
	e := compileFactsFixture(t, nil)
	for _, name := range []string{"allow", "missing policy org", "foreign policy org", "missing code org", "foreign code org", "shared code cannot widen", "missing storage org", "shared storage cannot widen", "no groups", "create", "create2", "unknown kind"} {
		t.Run(name, func(t *testing.T) {
			facts, frame := factsFixtures(t)
			want := uint64(0)
			switch name {
			case "missing policy org":
				facts.PolicyOrg, want = [32]byte{}, 4
			case "foreign policy org":
				facts.PolicyOrg, want = GroupID("other"), 4
			case "missing code org":
				facts.CodeOrg, want = [32]byte{}, 4
			case "foreign code org":
				facts.CodeOrg, want = GroupID("other"), 4
			case "shared code cannot widen":
				facts.CodeOrg, facts.CodeShared, want = GroupID("other"), true, 4
			case "missing storage org":
				facts.StorageOrg, want = [32]byte{}, 4
			case "shared storage cannot widen":
				facts.StorageOrg, facts.StorageShared, want = GroupID("other"), true, 4
			case "no groups":
				facts.Groups, facts.GroupClaims, want = nil, nil, 1
			case "create":
				frame.Kind, want = 4, 7
			case "create2":
				frame.Kind, want = 5, 7
			case "unknown kind":
				frame.Kind, want = 255, 1
			}
			if got := executeFactsFixture(t, e, facts, frame); got != want {
				t.Errorf("reason=%d, want %d", got, want)
			}
		})
	}
}

func TestFactsABI_ValueDepthAndCaller(t *testing.T) {
	e := compileFactsFixture(t, map[string]any{"maxValue": "10", "maxDepth": 2, "callerAddress": libraryAddr.Hex()})
	for _, name := range []string{"at bounds", "value exceeds", "depth exceeds", "caller differs"} {
		t.Run(name, func(t *testing.T) {
			facts, frame := factsFixtures(t)
			want := uint64(0)
			switch name {
			case "value exceeds":
				frame.Value, want = big.NewInt(11), 5
			case "depth exceeds":
				frame.Depth, want = big.NewInt(3), 6
			case "caller differs":
				frame.Caller, want = strangerAddr, 8
			}
			if got := executeFactsFixture(t, e, facts, frame); got != want {
				t.Errorf("reason=%d, want %d", got, want)
			}
		})
	}
}

func TestFactsSchema_OptionalFrameConstraints(t *testing.T) {
	for _, extra := range []map[string]any{{"maxValue": "0"}, {"maxDepth": 0}, {"callerAddress": libraryAddr.Hex()}, {"maxValue": new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)).String()}} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			p, err := Parse(factsPolicyDocument(t, extra))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Validate(p, testCatalog(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, extra := range []map[string]any{{"maxValue": "-1"}, {"maxValue": "1e2"}, {"maxValue": ""}, {"maxValue": new(big.Int).Lsh(big.NewInt(1), 256).String()}, {"maxValue": nil}, {"maxDepth": -1}, {"maxDepth": 0.5}, {"maxDepth": nil}, {"callerAddress": "0x01"}, {"callerAddress": nil}} {
		t.Run("reject "+fmt.Sprint(extra), func(t *testing.T) {
			p, err := Parse(factsPolicyDocument(t, extra))
			if err == nil {
				_, err = Validate(p, testCatalog(t))
			}
			if err == nil {
				t.Fatal("invalid constraint accepted")
			}
		})
	}
}

func TestFactsSchema_RejectsAmbiguousBounds(t *testing.T) {
	base := factsPolicyDocument(t, map[string]any{"maxValue": "0"})
	for _, replacement := range []string{`"maxValue":"0","MaxValue":null`, `"maxValue":null,"maxValue":"100"`} {
		doc := strings.Replace(string(base), `"maxValue":"0"`, replacement, 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("ambiguous bound accepted: %s", replacement)
		}
	}
}

func TestFactsABI_OfflineOracleAndPacking(t *testing.T) {
	p, err := Parse(factsPolicyDocument(t, map[string]any{"maxValue": "10", "maxDepth": 2, "callerAddress": libraryAddr.Hex()}))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	e := compileFactsFixture(t, map[string]any{"maxValue": "10", "maxDepth": 2, "callerAddress": libraryAddr.Hex()})
	facts, wireFrame := factsFixtures(t)
	frame := vaultCall(wireFrame.Data)
	frame.CodeKind = 2
	frame.CallerOrg, frame.CodeOrg, frame.StorageOrg = orgID, orgID, orgID
	frame.CallerAddress, frame.Value, frame.Depth = libraryAddr, big.NewInt(10), 2
	spec, err := abi.JSON(strings.NewReader(expectedFactsABI))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Methods["check"].Sig != CheckSignature {
		t.Fatal("public facts signature differs from independent fixture")
	}
	wantWire, err := spec.Pack("check", facts, wireFrame)
	if err != nil {
		t.Fatal(err)
	}
	gotWire, err := packCheck(memberCtx(), frame)
	if err != nil || string(wantWire) != string(gotWire) {
		t.Fatalf("production ABI packing differs from independent fixture: %v", err)
	}
	for _, name := range []string{"allow", "value", "depth", "caller", "missing ownership", "foreign shared ownership", "negative value", "value overflow"} {
		t.Run(name, func(t *testing.T) {
			f := frame
			var want DenialCode
			switch name {
			case "value":
				f.Value, want = big.NewInt(11), DenialValue
			case "depth":
				f.Depth, want = 3, DenialDepth
			case "caller":
				f.CallerAddress, want = strangerAddr, DenialCaller
			case "missing ownership":
				f.CodeOrg, want = "", DenialOwnership
			case "foreign shared ownership":
				f.CodeOrg, f.CodeShared, want = "other", true, DenialOwnership
			case "negative value":
				f.Value, want = big.NewInt(-1), DenialInvalidContext
			case "value overflow":
				f.Value, want = new(big.Int).Lsh(big.NewInt(1), 256), DenialInvalidContext
			}
			for oracle, got := range map[string]Decision{"Go": v.Evaluate(memberCtx(), []Frame{f}), "Solidity": e.Evaluate(orgID, memberCtx(), []Frame{f})} {
				if got.Allowed != (want == "") || got.Code != want {
					t.Errorf("%s decision=%+v, want %s", oracle, got, want)
				}
			}
		})
	}
}

func TestFactsABI_LegacyWrapperCannotEraseFrameConstraints(t *testing.T) {
	for _, constrained := range []bool{false, true} {
		var extra map[string]any
		if constrained {
			extra = map[string]any{"maxValue": "10"}
		}
		e := compileFactsFixture(t, extra)
		allowed, _, err := e.checkFrame(memberCtx(), vaultCall(transferCalldata(t, signerAddr, big.NewInt(1))))
		if err != nil || allowed == constrained {
			t.Fatalf("legacy wrapper: constrained=%v allowed=%v err=%v", constrained, allowed, err)
		}
	}
}

func TestFactsABI_StrictReasonDecoding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason *big.Int
		size   byte
		valid  bool
	}{
		{"allow", big.NewInt(0), 32, true},
		{"caller denial", big.NewInt(8), 32, true},
		{"unknown reason", big.NewInt(11), 32, false},
		{"high bits", new(big.Int).Lsh(big.NewInt(1), 200), 32, false},
		{"empty", big.NewInt(0), 0, false},
		{"old tuple", big.NewInt(1), 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewEVMEvaluator(&Artifact{RuntimeBytecode: returnPolicyWords(tc.reason, big.NewInt(0), tc.size)})
			if err != nil {
				t.Fatal(err)
			}
			reason, err := e.checkFacts(memberCtx(), vaultCall(nil))
			if (err == nil) != tc.valid || (tc.valid && uint64(reason) != tc.reason.Uint64()) {
				t.Fatalf("reason=%d err=%v, want valid=%v", reason, err, tc.valid)
			}
		})
	}
}

func TestFactsABI_ZeroBoundsAndImmutableDraft(t *testing.T) {
	p, err := Parse(factsPolicyDocument(t, map[string]any{"maxValue": "0", "maxDepth": 0}))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	*p.Bindings[0].Allow[0].MaxValue = "100"
	*p.Bindings[0].Allow[0].MaxDepth = 100
	returned := v.Policy()
	if *returned.Bindings[0].Allow[0].MaxValue != "0" || *returned.Bindings[0].Allow[0].MaxDepth != 0 {
		t.Fatal("mutating the source changed the validated document")
	}
	*returned.Bindings[0].Allow[0].MaxValue = "200"
	*returned.Bindings[0].Allow[0].MaxDepth = 200
	artifact, err := requireCompiler(t).Build(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEVMEvaluator(artifact)
	if err != nil {
		t.Fatal(err)
	}
	facts, f := factsFixtures(t)
	f.Value, f.Depth = big.NewInt(0), big.NewInt(0)
	if got := executeFactsFixture(t, e, facts, f); got != 0 {
		t.Fatalf("zero value/root frame denied: %d", got)
	}
	f.Value = big.NewInt(1)
	if got := executeFactsFixture(t, e, facts, f); got != 5 {
		t.Fatalf("zero maxValue did not deny one wei: %d", got)
	}
	f.Value, f.Depth = big.NewInt(0), big.NewInt(1)
	if got := executeFactsFixture(t, e, facts, f); got != 6 {
		t.Fatalf("zero maxDepth did not deny nested frame: %d", got)
	}
}
