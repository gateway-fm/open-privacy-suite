package policydsl

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func lifecyclePolicy(t *testing.T, rules ...map[string]any) (*Validated, *EVMEvaluator) {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"apiVersion": APIVersion, "kind": Kind, "org": orgID,
		"nestedCalls": NestedCallsRequireOwnRule, "bindings": []any{map[string]any{"group": groupID, "allow": rules}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Validate(p, testCatalog(t))
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
	return v, e
}

// Compare the bytecode with the offline oracle using independently packed
// wire facts. The malformed raw-array case has no representation in the
// offline map API and is intentionally checked at the ABI boundary only.
func executeLifecycleFixture(t *testing.T, v *Validated, e *EVMEvaluator, facts factsWireFixture, frame callWireFixture) uint64 {
	t.Helper()
	reason := executeFactsFixture(t, e, facts, frame)
	if len(facts.Groups) != len(facts.GroupClaims) {
		return reason
	}
	org := func(id [32]byte) string {
		if id == ([32]byte{}) {
			return ""
		}
		if id == GroupID(orgID) {
			return orgID
		}
		return "foreign"
	}
	ctx := Context{Org: org(facts.PolicyOrg), Signer: facts.Signer, LinkedAddresses: facts.LinkedAddresses, Claims: facts.Claims}
	f := Frame{CallerOrg: org(facts.CallerOrg), CodeOrg: org(facts.CodeOrg), StorageOrg: org(facts.StorageOrg),
		CodeShared: facts.CodeShared, StorageShared: facts.StorageShared, CodeKind: facts.CodeKind, UpgradeTargetOrg: org(facts.UpgradeTargetOrg), StorageDeployer: facts.StorageDeployer, StoragePending: facts.StoragePending,
		CallerAddress: frame.Caller, CodeAddress: frame.CodeAddress, StorageAddress: frame.StorageAddress, Calldata: frame.Data, Value: frame.Value, Depth: frame.Depth.Uint64(), GroupClaims: map[string]uint8{}}
	for i, g := range facts.Groups {
		name := "unbound-upgrader"
		if g == GroupID(groupID) {
			name = groupID
		}
		ctx.Groups = append(ctx.Groups, name)
		f.GroupClaims[name] = facts.GroupClaims[i]
	}
	for kind, ordinal := range callTypeOrdinal {
		if frame.Kind == ordinal {
			f.CallType = kind
		}
	}
	decision := v.Evaluate(ctx, []Frame{f})
	if decision.Allowed != (reason == 0) || (reason != 0 && decision.Code != reasonToDenialCode(uint16(reason))) {
		t.Fatalf("offline/wire mismatch: reason=%d decision=%+v", reason, decision)
	}
	return reason
}

func TestLifecycle_WildcardIncludesFallbackWithoutABI(t *testing.T) {
	v, e := lifecyclePolicy(t, map[string]any{"storageAddress": vaultAddr, "selector": "*"})
	for _, data := range [][]byte{nil, {1}, {1, 2, 3}, {0xde, 0xad, 0xbe, 0xef, 1}} {
		facts, frame := factsFixtures(t)
		frame.Data = data
		if got := executeLifecycleFixture(t, v, e, facts, frame); got != 0 {
			t.Fatalf("wildcard data %x denied: %d", data, got)
		}
	}
}

func TestLifecycle_TargetClasses(t *testing.T) {
	for _, class := range []string{"eoa", "precompile", "shared", "org"} {
		t.Run(class, func(t *testing.T) {
			selector := "*"
			if class == "eoa" {
				selector = "0x"
			}
			v, e := lifecyclePolicy(t, map[string]any{"targetClass": class, "selector": selector})
			facts, frame := factsFixtures(t)
			frame.CodeAddress = common.HexToAddress(relayAddr)
			frame.StorageAddress = frame.CodeAddress
			frame.Data = nil
			if class != "org" {
				facts.CodeOrg, facts.StorageOrg = [32]byte{}, [32]byte{}
			}
			switch class {
			case "eoa":
				facts.CodeKind = 1
			case "precompile":
				facts.CodeKind = 3
			case "shared":
				facts.CodeShared, facts.StorageShared = true, true
			}
			if got := executeLifecycleFixture(t, v, e, facts, frame); got != 0 {
				t.Fatalf("class %s denied: %d", class, got)
			}
			if class == "eoa" {
				facts.CodeKind = 2
				if got := executeLifecycleFixture(t, v, e, facts, frame); got == 0 {
					t.Fatal("unregistered receive contract accepted as EOA")
				}
				facts.CodeKind = 1
				frame.Data = []byte{1}
				if got := executeLifecycleFixture(t, v, e, facts, frame); got == 0 {
					t.Fatal("native empty-input rule accepted nonempty calldata")
				}
			}
			frame.Kind = 2
			if got := executeLifecycleFixture(t, v, e, facts, frame); got == 0 {
				t.Fatal("default target class implicitly allowed delegatecall")
			}
		})
	}
}

func TestLifecycle_CreateRequiresOwnGroupDeployAndInheritedOwner(t *testing.T) {
	v, e := lifecyclePolicy(t, map[string]any{"targetClass": "create", "selector": "*", "callTypes": []string{"create", "create2"}})
	facts, frame := factsFixtures(t)
	frame.Kind, frame.Data = 4, []byte{0x60, 0, 0x60, 0, 0xf3}
	facts.GroupClaims = []uint8{2}
	for _, kind := range []uint8{4, 5} {
		frame.Kind = kind
		if got := executeLifecycleFixture(t, v, e, facts, frame); got != 0 {
			t.Fatalf("create kind %d denied: %d", kind, got)
		}
	}
	facts.GroupClaims[0] = 0
	facts.Claims = 7
	if got := executeLifecycleFixture(t, v, e, facts, frame); got != 9 {
		t.Fatalf("aggregate claim bypassed group claim: %d", got)
	}
	facts.GroupClaims[0] = 1
	if got := executeLifecycleFixture(t, v, e, facts, frame); got != 0 {
		t.Fatalf("admin does not imply deploy: %d", got)
	}
	facts.StorageOrg = GroupID("foreign")
	if got := executeLifecycleFixture(t, v, e, facts, frame); got == 0 {
		t.Fatal("foreign deployment target permitted")
	}
}

func TestLifecycle_UpgradePointerWriteChecksClaimsAndTarget(t *testing.T) {
	v, e := lifecyclePolicy(t, map[string]any{"storageAddress": vaultAddr, "selector": "*", "allowUpgrade": true})
	for _, selector := range []string{"3659cfe6", "4f1ef286", "d784d426", "99a88ec4", "9623609d"} {
		t.Run(selector, func(t *testing.T) {
			facts, frame := factsFixtures(t)
			prefix, _ := hex.DecodeString(selector)
			index := 0
			if selector == "99a88ec4" || selector == "9623609d" {
				index = 1
			}
			frame.Data = append(prefix, make([]byte, 32*(index+1))...)
			copy(frame.Data[4+32*index+12:], libraryAddr.Bytes())
			facts.UpgradeTargetOrg, facts.GroupClaims = facts.PolicyOrg, []uint8{4}
			if got := executeLifecycleFixture(t, v, e, facts, frame); got != 0 {
				t.Fatalf("same-org upgrade denied: %d", got)
			}
			facts.GroupClaims[0], facts.Claims = 0, 7
			if got := executeLifecycleFixture(t, v, e, facts, frame); got != 9 {
				t.Fatalf("another group's aggregate upgrade claim permitted this grant: %d", got)
			}
			facts.GroupClaims[0] = 4
			facts.UpgradeTargetOrg = GroupID("foreign")
			if got := executeLifecycleFixture(t, v, e, facts, frame); got == 0 {
				t.Fatal("foreign implementation pointer accepted without nested execution")
			}
			facts.UpgradeTargetOrg = facts.PolicyOrg
			frame.Data[4+32*index] = 1
			if got := executeLifecycleFixture(t, v, e, facts, frame); got != 3 {
				t.Fatalf("noncanonical address accepted: %d", got)
			}
			frame.Data = frame.Data[:len(frame.Data)-1]
			if got := executeLifecycleFixture(t, v, e, facts, frame); got != 3 {
				t.Fatalf("truncated address accepted: %d", got)
			}
		})
	}
}

func TestLifecycle_GroupClaimsAlignmentAndRevocation(t *testing.T) {
	v, e := lifecyclePolicy(t, map[string]any{"storageAddress": vaultAddr, "selector": "*", "allowUpgrade": true})
	facts, frame := factsFixtures(t)
	frame.Data = append([]byte{0x36, 0x59, 0xcf, 0xe6}, common.LeftPadBytes(libraryAddr.Bytes(), 32)...)
	facts.UpgradeTargetOrg = facts.PolicyOrg
	facts.Groups = append(facts.Groups, GroupID("unbound-upgrader"))
	facts.GroupClaims = []uint8{0, 4}
	facts.Claims = 4
	if got := executeLifecycleFixture(t, v, e, facts, frame); got != 9 {
		t.Fatalf("revoked group borrowed other membership's upgrade: %d", got)
	}
	facts.GroupClaims = nil
	if got := executeLifecycleFixture(t, v, e, facts, frame); got != 10 {
		t.Fatalf("misaligned group facts accepted: %d", got)
	}
}

func TestLifecycle_RejectsAmbiguousClassRules(t *testing.T) {
	for _, rule := range []map[string]any{
		{"targetClass": "eoa", "selector": "*"},
		{"targetClass": "eoa", "selector": "0x", "storageAddress": vaultAddr},
		{"targetClass": "shared", "selector": "*", "callTypes": []string{"delegatecall"}},
		{"targetClass": "create", "selector": "*"},
		{"targetClass": "create", "selector": "*", "callTypes": []string{"call"}},
		{"targetClass": "create", "selector": "*", "callTypes": []string{"create", "create"}},
		{"targetClass": "create", "selector": "*", "callTypes": []string{"create"}, "allowUpgrade": true},
		{"targetClass": "mystery", "selector": "*"},
		{"storageAddress": vaultAddr, "selector": "*", "abiDigest": ABIDigest(vaultABI)},
		{"storageAddress": vaultAddr, "selector": "*", "args": []any{map[string]any{"index": 0, "uintAtMost": "1"}}},
		{"storageAddress": vaultAddr, "selector": "*", "maxValue": "-1"},
		{"storageAddress": vaultAddr, "selector": "*", "maxDepth": -1},
		{"storageAddress": vaultAddr, "selector": "*", "callerAddress": "broken"},
		{"storageAddress": vaultAddr, "selector": "*", "allowUpgrade": nil},
	} {
		doc, _ := json.Marshal(map[string]any{"apiVersion": APIVersion, "kind": Kind, "org": orgID, "nestedCalls": NestedCallsRequireOwnRule, "bindings": []any{map[string]any{"group": groupID, "allow": []any{rule}}}})
		p, err := Parse(doc)
		if err == nil {
			_, err = Validate(p, testCatalog(t))
		}
		if err == nil {
			t.Fatalf("ambiguous rule accepted: %s", doc)
		}
	}
}

func TestLifecycle_UpgradeRequiresExplicitRuleIntent(t *testing.T) {
	v, e := lifecyclePolicy(t, map[string]any{"storageAddress": vaultAddr, "selector": "*"})
	facts, frame := factsFixtures(t)
	frame.Data = append([]byte{0x36, 0x59, 0xcf, 0xe6}, common.LeftPadBytes(libraryAddr.Bytes(), 32)...)
	facts.GroupClaims = []uint8{7}
	facts.UpgradeTargetOrg = facts.PolicyOrg
	if got := executeLifecycleFixture(t, v, e, facts, frame); got != 9 {
		t.Fatalf("wildcard without upgrade intent authorized upgrade: %d", got)
	}
}
