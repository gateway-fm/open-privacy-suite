package policydsl

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func TestBuildRejectsRuntimeLargerThanNodeLimit(t *testing.T) {
	p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: "size-test", NestedCalls: NestedCallsRequireOwnRule}
	v, err := Validate(p, Catalog{Org: p.Org})
	if err != nil {
		t.Fatal(err)
	}
	// solc reports oversized contracts as a warning, not a compilation error.
	// Exercise that output boundary independently of optimizer size heuristics.
	output, err := json.Marshal(map[string]any{"contracts": map[string]any{"Policy.sol:" + ContractName: map[string]string{"bin": "00", "bin-runtime": strings.Repeat("00", 24577)}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'Version: 0.8.35+test'\nelse\n  printf '%s\\n' '" + string(output) + "'\nfi\n"
	path := filepath.Join(dir, "solc")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	artifact, err := (&Compiler{Path: path}).Build(t.Context(), v)
	// Assert the sentinel, not the wording: callers classify on ErrPolicyTooLarge
	// to tell "the author must simplify this" from "the compiler broke".
	if artifact != nil || !errors.Is(err, ErrPolicyTooLarge) {
		t.Fatalf("oversized artifact must fail before publication: artifact=%v, error=%v", artifact != nil, err)
	}
}

// These inputs are encoded by go-ethereum's ABI encoder, independently of the
// policy's head-offset calculation. Agreement between our two evaluators alone
// would miss an offset mistake shared by the generator and reference evaluator.
const compositeHeadABI = `[
  {"type":"function","name":"f","inputs":[{"name":"prefix","type":"uint256[2]"},{"name":"amount","type":"uint256"},{"name":"memo","type":"bytes"}],"outputs":[]},
  {"type":"function","name":"tuple","inputs":[{"name":"prefix","type":"tuple","components":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256[2]"}]},{"name":"amount","type":"uint256"},{"name":"memo","type":"bytes"}],"outputs":[]},
  {"type":"function","name":"nested","inputs":[{"name":"prefix","type":"uint256[2][2]"},{"name":"recipient","type":"address"},{"name":"memo","type":"bytes"}],"outputs":[]},
  {"type":"function","name":"staticOnly","inputs":[{"name":"prefix","type":"uint256[2]"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"dynamicTuple","inputs":[{"name":"prefix","type":"tuple","components":[{"name":"a","type":"uint256"},{"name":"b","type":"bytes"}]},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"dynamicArray","inputs":[{"name":"prefix","type":"bytes[2]"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"unconstrained","inputs":[{"name":"prefix","type":"uint256[2]"}],"outputs":[]}
]`

func TestABIHeadOffsets_CompositeInputs(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(compositeHeadABI))
	if err != nil {
		t.Fatal(err)
	}
	bound := "100"
	var rules []FrameRule
	for _, name := range []string{"f", "tuple", "nested", "staticOnly", "dynamicTuple", "dynamicArray", "unconstrained"} {
		method := parsed.Methods[name]
		rule := FrameRule{StorageAddress: vaultAddr, Selector: "0x" + hex.EncodeToString(method.ID), ABIDigest: ABIDigest(compositeHeadABI)}
		if name == "nested" {
			rule.Args = []ArgConstraint{{Index: 1, AddressEquals: &AddressMatch{Source: AddressSourceSigner}}}
		} else if name != "unconstrained" {
			rule.Args = []ArgConstraint{{Index: 1, UintAtMost: &bound}}
		}
		rules = append(rules, rule)
	}
	policy := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{{Group: groupID, Allow: rules}}}
	cat := testCatalog(t)
	cat.Contracts[vaultAddr] = ContractInfo{ABI: compositeHeadABI}
	validated, err := Validate(policy, cat)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := requireCompiler(t).Build(context.Background(), validated)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := NewEVMEvaluator(artifact)
	if err != nil {
		t.Fatal(err)
	}

	low := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	high := [2]*big.Int{big.NewInt(200), big.NewInt(300)}
	staticTuple := struct {
		A *big.Int
		B [2]*big.Int
	}{big.NewInt(1), low}
	dynamicTuple := struct {
		A *big.Int
		B []byte
	}{big.NewInt(1), []byte("prefix")}
	cases := []struct {
		name    string
		method  string
		args    []any
		allowed bool
	}{
		{"array cannot hide excessive amount", "f", []any{low, big.NewInt(101), []byte("memo")}, false},
		{"array values do not constrain amount", "f", []any{high, big.NewInt(100), []byte("memo")}, true},
		{"tuple cannot hide excessive amount", "tuple", []any{staticTuple, big.NewInt(101), []byte("memo")}, false},
		{"tuple amount at bound", "tuple", []any{staticTuple, big.NewInt(100), []byte("memo")}, true},
		{"nested array followed by signer", "nested", []any{[2][2]*big.Int{low, high}, signerAddr, []byte("memo")}, true},
		{"nested array followed by stranger", "nested", []any{[2][2]*big.Int{low, high}, strangerAddr, []byte("memo")}, false},
		{"fully static array amount at bound", "staticOnly", []any{high, big.NewInt(100)}, true},
		{"fully static array excessive amount", "staticOnly", []any{low, big.NewInt(101)}, false},
		{"dynamic tuple has one head offset", "dynamicTuple", []any{dynamicTuple, big.NewInt(100)}, true},
		{"dynamic tuple excessive amount", "dynamicTuple", []any{dynamicTuple, big.NewInt(101)}, false},
		{"array of dynamic values has one head offset", "dynamicArray", []any{[2][]byte{[]byte("a"), []byte("b")}, big.NewInt(100)}, true},
		{"array of dynamic values excessive amount", "dynamicArray", []any{[2][]byte{[]byte("a"), []byte("b")}, big.NewInt(101)}, false},
		{"unconstrained static array has full head length", "unconstrained", []any{low}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := packCalldata(t, compositeHeadABI, tc.method, tc.args...)
			frames := []Frame{vaultCall(data)}
			for name, got := range map[string]Decision{"Go": validated.Evaluate(memberCtx(), frames), "Solidity": compiled.Evaluate(orgID, memberCtx(), frames)} {
				if got.Allowed != tc.allowed {
					t.Errorf("%s: allowed=%v, want %v: %s", name, got.Allowed, tc.allowed, got.Reason)
				}
				if !tc.allowed && got.Code != DenialArgumentConstraint {
					t.Errorf("%s: denial=%s, want argument constraint", name, got.Code)
				}
			}
		})
	}
	t.Run("truncated static head", func(t *testing.T) {
		data := packCalldata(t, compositeHeadABI, "staticOnly", low, big.NewInt(100))
		frames := []Frame{vaultCall(data[:len(data)-32])}
		for name, got := range map[string]Decision{"Go": validated.Evaluate(memberCtx(), frames), "Solidity": compiled.Evaluate(orgID, memberCtx(), frames)} {
			if got.Allowed || got.Code != DenialMalformedCalldata {
				t.Errorf("%s: truncated calldata decision=%+v, want malformed denial", name, got)
			}
		}
	})
}

func TestBuild_ReproducibleAcrossDirectories(t *testing.T) {
	compiler := requireCompiler(t)
	p, cat := conformancePolicy(t)
	validated, err := Validate(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	var first *Artifact
	for i := 0; i < 2; i++ {
		t.Setenv("TMPDIR", t.TempDir())
		artifact, err := compiler.Build(context.Background(), validated)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = artifact
			continue
		}
		if artifact.Source != first.Source || artifact.PolicyDigest != first.PolicyDigest {
			t.Fatal("test inputs did not produce the same generated source/policy")
		}
		if !bytes.Equal(artifact.RuntimeBytecode, first.RuntimeBytecode) || artifact.RuntimeDigest != first.RuntimeDigest {
			t.Errorf("same source produced different runtime artifacts: %s != %s", first.RuntimeDigest, artifact.RuntimeDigest)
		}
		if !bytes.Equal(artifact.CreationBytecode, first.CreationBytecode) {
			t.Error("same source produced different creation bytecode")
		}
	}
}

// returnPolicyWords is a real EVM program returning deliberately chosen ABI
// words. It avoids depending on the Solidity generator to produce bad results.
func returnPolicyWords(allowed, reason *big.Int, size byte) []byte {
	code := []byte{0x7f} // PUSH32 allowed; PUSH1 0; MSTORE
	code = append(code, allowed.FillBytes(make([]byte, 32))...)
	code = append(code, 0x60, 0, 0x52, 0x7f)
	code = append(code, reason.FillBytes(make([]byte, 32))...)
	return append(code, 0x60, 0x20, 0x52, 0x60, size, 0x60, 0, 0xf3)
}

func TestEVMEvaluator_StrictResultDecoding(t *testing.T) {
	cases := []struct {
		name    string
		allowed *big.Int
		reason  *big.Int
		size    byte
		valid   bool
	}{
		{"canonical allow", big.NewInt(1), big.NewInt(0), 64, true},
		{"canonical no match", big.NewInt(0), big.NewInt(1), 64, true},
		{"canonical argument denial", big.NewInt(0), big.NewInt(2), 64, true},
		{"canonical malformed denial", big.NewInt(0), big.NewInt(3), 64, true},
		{"boolean two", big.NewInt(2), big.NewInt(0), 64, false},
		{"boolean high bits", new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(0), 64, false},
		{"reason overflows uint16", big.NewInt(0), big.NewInt(65537), 64, false},
		{"reason high bits", big.NewInt(0), new(big.Int).Lsh(big.NewInt(1), 200), 64, false},
		{"allow with denial reason", big.NewInt(1), big.NewInt(2), 64, false},
		{"deny with success reason", big.NewInt(0), big.NewInt(0), 64, false},
		{"unknown reason", big.NewInt(0), big.NewInt(4), 64, false},
		{"short return", big.NewInt(1), big.NewInt(0), 32, false},
		{"trailing return", big.NewInt(1), big.NewInt(0), 96, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator, err := NewEVMEvaluator(&Artifact{RuntimeBytecode: returnPolicyWords(tc.allowed, tc.reason, tc.size)})
			if err != nil {
				t.Fatal(err)
			}
			allowed, reason, err := evaluator.checkFrame(memberCtx(), vaultCall(nil))
			if (err == nil) != tc.valid {
				t.Fatalf("allowed=%v reason=%d err=%v, want valid=%v", allowed, reason, err, tc.valid)
			}
			if tc.valid && (allowed != (tc.allowed.Sign() != 0) || reason != uint16(tc.reason.Uint64())) {
				t.Fatalf("canonical result decoded incorrectly: allowed=%v reason=%d", allowed, reason)
			}
			if !tc.valid && evaluator.Evaluate(orgID, memberCtx(), []Frame{vaultCall(nil)}).Allowed {
				t.Fatal("malformed result allowed the execution")
			}
		})
	}
}
