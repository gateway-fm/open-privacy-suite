package policydsl

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"testing"

	"privacy-proxy/internal/rbac"
)

func TestImportLegacy_RealGrantNullEmptyAndSelf(t *testing.T) {
	for _, tc := range []struct {
		name, functions string
		wantRules       int
		wantSelf        bool
	}{
		{"null is all", "null", 1, false},
		{"empty is none", "[]", 0, false},
		{"self constraint", `[{"selector":"0xa9059cbb","param_rules":[{"index":0,"must_be":"self"}]}]`, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var old rbac.ContractGrant
			if err := json.Unmarshal([]byte(`{"group_id":"`+groupID+`","contract_id":"contract-1","functions":`+tc.functions+`}`), &old); err != nil {
				t.Fatal(err)
			}
			grant := LegacyGrant{Address: vaultAddr}
			if old.Functions != nil {
				grant.Functions = make([]LegacyFunction, len(old.Functions))
			}
			for i, f := range old.Functions {
				grant.Functions[i].Selector = f.Selector
				for _, arg := range f.ParamRules {
					grant.Functions[i].ParamRules = append(grant.Functions[i].ParamRules, LegacyParamRule{Index: arg.Index, MustBe: arg.MustBe})
				}
			}
			p, err := ImportLegacy(LegacySnapshot{Groups: []LegacyGroup{{ID: groupID, Grants: []LegacyGrant{grant}}}}, testCatalog(t))
			if err != nil {
				t.Fatal(err)
			}
			var contractRules []FrameRule
			for _, r := range p.Bindings[0].Allow {
				if r.StorageAddress == vaultAddr {
					contractRules = append(contractRules, r)
				}
			}
			if len(contractRules) != tc.wantRules {
				t.Fatalf("got %d contract rules, want %d", len(contractRules), tc.wantRules)
			}
			if tc.wantSelf && (len(contractRules[0].Args) != 1 || contractRules[0].Args[0].AddressEquals.Source != AddressSourcePrincipalLinked) {
				t.Fatal("self did not retain principal-linked semantics")
			}
			v, err := Validate(p, testCatalog(t))
			if err != nil {
				t.Fatal(err)
			}
			good := vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))
			want := tc.wantRules > 0
			if got := v.Evaluate(memberCtx(), []Frame{good}); got.Allowed != want {
				t.Fatalf("import changed allowed call: %+v", got)
			}
			if tc.wantSelf {
				good.Calldata = transferCalldata(t, libraryAddr, big.NewInt(1))
				if v.Evaluate(memberCtx(), []Frame{good}).Allowed {
					t.Fatal("self grant widened")
				}
			}
		})
	}
}

func TestImportLegacy_OperationalClaimsAndOrgAdmin(t *testing.T) {
	for _, tc := range []struct {
		claim                            string
		adminRole                        bool
		wantCreate, wantOrg, wantUpgrade bool
	}{
		{"", false, false, false, false}, {"deploy", false, true, false, false}, {"upgrade", false, false, false, true},
		{"admin", false, true, false, true}, {"", true, true, true, true},
	} {
		t.Run(tc.claim+map[bool]string{true: "-org-admin"}[tc.adminRole], func(t *testing.T) {
			claims := []string{}
			if tc.claim != "" {
				claims = append(claims, tc.claim)
			}
			p, err := ImportLegacy(LegacySnapshot{Groups: []LegacyGroup{{ID: groupID, Claims: claims, OrgAdmin: tc.adminRole, Grants: []LegacyGrant{{Address: vaultAddr}}}}}, testCatalog(t))
			if err != nil {
				t.Fatal(err)
			}
			var create, org, upgrade bool
			for _, r := range p.Bindings[0].Allow {
				create = create || r.TargetClass == "create"
				org = org || r.TargetClass == "org"
				upgrade = upgrade || r.AllowUpgrade
			}
			if create != tc.wantCreate || org != tc.wantOrg || upgrade != tc.wantUpgrade {
				t.Fatalf("create/org/upgrade=%v/%v/%v", create, org, upgrade)
			}
		})
	}
}

func TestImportLegacy_UnsupportedNeverReturnsActivatablePolicy(t *testing.T) {
	for _, snapshot := range []LegacySnapshot{
		{Groups: []LegacyGroup{{ID: groupID, Claims: []string{"write"}}}},
		{Groups: []LegacyGroup{{ID: groupID, Grants: []LegacyGrant{{Address: vaultAddr, Functions: []LegacyFunction{{Selector: selTransfer, ParamRules: []LegacyParamRule{{Index: 0, MustBe: libraryAddr.Hex()}}}}}}}}},
		{IndividualDeployerAddresses: []string{"not-an-address"}},
		{PreregisteredAddresses: []string{"not-an-address"}},
	} {
		p, err := ImportLegacy(snapshot, testCatalog(t))
		var unsupported *LegacyImportError
		if p != nil || !errors.As(err, &unsupported) || len(unsupported.Issues) == 0 {
			t.Fatalf("unsupported source returned policy=%v error=%v", p, err)
		}
	}
}

func TestImportLegacyDeployerFallbackPreservesGrantUnionAndMembershipChanges(t *testing.T) {
	const fallbackGroup = "other-membership"
	cat := testCatalog(t)
	cat.Groups[fallbackGroup] = struct{}{}
	for _, tc := range []struct {
		name      string
		functions []LegacyFunction
		permitted bool
	}{
		{"nil wildcard", nil, true},
		{"empty denies", []LegacyFunction{}, false},
		{"restricted self", []LegacyFunction{{Selector: selTransfer, ParamRules: []LegacyParamRule{{Index: 0, MustBe: "self"}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ImportLegacy(LegacySnapshot{Groups: []LegacyGroup{{ID: groupID, Grants: []LegacyGrant{{Address: vaultAddr, Functions: tc.functions}}}, {ID: fallbackGroup}}, IndividualDeployerAddresses: []string{vaultAddr}, PreregisteredAddresses: []string{libraryAddr.Hex()}}, cat)
			if err != nil {
				t.Fatal(err)
			}
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
			f := vaultCall(transferCalldata(t, libraryAddr, big.NewInt(1)))
			f.StorageDeployer = true
			ctx := memberCtx()
			ctx.Groups = append(ctx.Groups, fallbackGroup)
			for _, evaluate := range []func(Context, []Frame) Decision{v.Evaluate, func(c Context, f []Frame) Decision { return e.Evaluate(orgID, c, f) }} {
				if got := evaluate(ctx, []Frame{f}); got.Allowed != tc.permitted {
					t.Fatalf("existing target grant must win over fallback: %+v", got)
				}
				ctx.Groups = []string{fallbackGroup}
				if !evaluate(ctx, []Frame{f}).Allowed {
					t.Fatal("removing grant-group membership must restore legacy individual fallback")
				}
				ctx.Groups = []string{groupID, fallbackGroup}
				f.StorageAddress = libraryAddr
				f.CodeAddress = libraryAddr
				if !evaluate(ctx, []Frame{f}).Allowed {
					t.Fatal("new deployment must not need a compiled literal address")
				}
				f.StorageAddress = common.HexToAddress(vaultAddr)
				f.CodeAddress = f.StorageAddress
			}
		})
	}
}
