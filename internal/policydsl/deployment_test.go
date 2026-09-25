package policydsl

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestDeploymentOwnershipClassesAndMembershipExceptions(t *testing.T) {
	otherGroup := "explicit-grant-group"
	cat := testCatalog(t)
	cat.Groups[otherGroup] = struct{}{}
	p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule,
		Bindings: []Binding{{Group: groupID, Allow: []FrameRule{
			{TargetClass: "deployer", Selector: "*", Except: []DeployerException{{StorageAddress: vaultAddr, Groups: []string{otherGroup}}}},
			{TargetClass: "pending", Selector: "*"},
		}}}}
	v, err := Validate(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	a, err := requireCompiler(t).Build(t.Context(), v)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEVMEvaluator(a)
	if err != nil {
		t.Fatal(err)
	}
	grouped, err := requireCompiler(t).BuildPerGroup(t.Context(), v)
	if err != nil {
		t.Fatal(err)
	}
	groupEvaluator, err := NewEVMEvaluator(grouped[groupID])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                       string
		deployer, pending, member  bool
		claims                     uint8
		foreign, upgrade, delegate bool
		want                       bool
	}{
		{name: "own deployed contract", deployer: true, want: true},
		{name: "shared signer is not deployer", want: false},
		{name: "existing target grant suppresses fallback", deployer: true, member: true, want: false},
		{name: "pending requires binding deploy claim", pending: true, claims: ClaimDeploy, want: true},
		{name: "pending cannot borrow aggregate deploy", pending: true, want: false},
		{name: "deployer cannot cross org", deployer: true, foreign: true, want: false},
		{name: "deployer does not imply upgrades", deployer: true, upgrade: true, want: false},
		{name: "deployer does not imply delegatecall", deployer: true, delegate: true, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := memberCtx()
			ctx.Claims = ClaimDeploy
			if tc.member {
				ctx.Groups = append(ctx.Groups, otherGroup)
			}
			frame := vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))
			frame.StorageDeployer, frame.StoragePending = tc.deployer, tc.pending
			frame.GroupClaims = map[string]uint8{groupID: tc.claims}
			if tc.foreign {
				frame.StorageOrg = "foreign"
			}
			if tc.delegate {
				frame.CallType = CallTypeDelegateCall
			}
			if tc.upgrade {
				frame.Calldata = append(common.FromHex("0x3659cfe6"), common.LeftPadBytes(libraryAddr.Bytes(), 32)...)
				frame.UpgradeTargetOrg = orgID
			}
			for label, got := range map[string]Decision{"reference": v.Evaluate(ctx, []Frame{frame}), "EVM": e.Evaluate(orgID, ctx, []Frame{frame}), "per-group EVM": groupEvaluator.Evaluate(orgID, ctx, []Frame{frame})} {
				if got.Allowed != tc.want {
					t.Fatalf("%s: %+v", label, got)
				}
			}
		})
	}
}

func TestDeploymentExceptionsAreClosedBoundedAndImmutable(t *testing.T) {
	for _, extra := range []string{`null`, `[{"storageAddress":"` + vaultAddr + `","groups":[]}]`, `[{"storageAddress":"` + vaultAddr + `","groups":["missing"]}]`, `[{"storageAddress":"` + vaultAddr + `","groups":["` + groupID + `"],"allow":true}]`} {
		raw := `{"apiVersion":"` + APIVersion + `","kind":"` + Kind + `","org":"` + orgID + `","nestedCalls":"requireOwnRule","bindings":[{"group":"` + groupID + `","allow":[{"targetClass":"deployer","selector":"*","except":` + extra + `}]}]}`
		p, err := Parse([]byte(raw))
		if err == nil {
			_, err = Validate(p, testCatalog(t))
		}
		if err == nil {
			t.Fatalf("invalid exception accepted: %s", extra)
		}
	}
	p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{{Group: groupID, Allow: []FrameRule{{TargetClass: "deployer", Selector: "*", Except: []DeployerException{{StorageAddress: vaultAddr, Groups: []string{groupID}}}}}}}}
	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	p.Bindings[0].Allow[0].Except[0].Groups[0] = "mutated"
	exported := v.Policy()
	exported.Bindings[0].Allow[0].Except[0].Groups[0] = "also-mutated"
	raw, _ := json.Marshal(v.Policy())
	if string(raw) == "" || v.Policy().Bindings[0].Allow[0].Except[0].Groups[0] != groupID {
		t.Fatal("exception mutated validated policy")
	}
}
