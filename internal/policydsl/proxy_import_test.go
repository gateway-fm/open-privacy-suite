package policydsl

import (
	"math/big"
	"testing"
)

func TestImportLegacyExplicitProxyPairsRequireBothNamespaces(t *testing.T) {
	cat := testCatalog(t)
	// The implementation exposes the same callable interface as this proxy.
	cat.Contracts[libraryAddr.Hex()] = cat.Contracts[vaultAddr]
	cat.Contracts[catalogKey(libraryAddr.Hex())] = cat.Contracts[vaultAddr]
	snapshot := LegacySnapshot{Groups: []LegacyGroup{{ID: groupID, Grants: []LegacyGrant{{Address: vaultAddr}, {Address: libraryAddr.Hex(), Functions: []LegacyFunction{{Selector: selTransfer}}}}}}, ProxyPairs: []LegacyProxyPair{{StorageAddress: vaultAddr, CodeAddress: libraryAddr.Hex()}}}
	p, err := ImportLegacy(snapshot, cat)
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
	f := vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))
	f.CodeAddress = libraryAddr
	f.CallType = CallTypeDelegateCall
	for _, eval := range []func(Context, []Frame) Decision{v.Evaluate, func(c Context, f []Frame) Decision { return e.Evaluate(orgID, c, f) }} {
		if got := eval(memberCtx(), []Frame{f}); !got.Allowed {
			t.Fatalf("reviewed proxy pair denied: %+v", got)
		}
		f.StorageOrg = "foreign"
		if eval(memberCtx(), []Frame{f}).Allowed {
			t.Fatal("proxy pair crossed storage namespace")
		}
		f.StorageOrg = orgID
	}
	snapshot.ProxyPairs[0].CodeAddress = "0x9999999999999999999999999999999999999999"
	if p, err := ImportLegacy(snapshot, cat); p != nil || err == nil {
		t.Fatal("unregistered proxy code silently imported")
	}
}
