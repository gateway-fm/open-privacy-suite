package policydsl

import (
	"context"
	"fmt"
	"testing"
)

// An organisation's execution rules compile to one contract per GROUP, not one
// for the whole organisation. A frame only ever needs the groups its signer is
// in, so carrying every group's dispatch in one artifact made both the size and
// the per-frame check grow with the organisation until, at around thirty
// groups, nothing compiled at all. Per-group artifacts make both independent of
// how many other groups exist.
func TestBuildPerGroupScalesWithTheGroupNotTheOrganisation(t *testing.T) {
	compiler := requireCompiler(t)
	digest := abiDigest(t, vaultABI)

	build := func(groups int) (map[string]*Artifact, error) {
		catalog := Catalog{Org: orgID, Groups: map[string]struct{}{}, Contracts: map[string]ContractInfo{vaultAddr: {ABI: vaultABI}}}
		p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule}
		for g := 0; g < groups; g++ {
			id := fmt.Sprintf("grp_%04d", g)
			catalog.Groups[id] = struct{}{}
			p.Bindings = append(p.Bindings, Binding{Group: id, Allow: []FrameRule{
				{TargetClass: "eoa", Selector: "0x"},
				{StorageAddress: vaultAddr, Selector: selTransfer, ABIDigest: digest},
			}})
		}
		v, err := Validate(p, catalog)
		if err != nil {
			return nil, err
		}
		return compiler.BuildPerGroup(context.Background(), v)
	}

	// An organisation this size cannot be expressed as one artifact at all.
	small, err := build(7)
	if err != nil {
		t.Fatalf("seven groups: %v", err)
	}
	large, err := build(60)
	if err != nil {
		t.Fatalf("sixty groups must compile when each group stands alone: %v", err)
	}

	if len(small) != 7 || len(large) != 60 {
		t.Fatalf("one artifact per group: got %d and %d", len(small), len(large))
	}

	// A group's artifact does not grow because the organisation has more groups.
	a, b := small["grp_0000"], large["grp_0000"]
	if a == nil || b == nil {
		t.Fatal("every bound group must have an artifact")
	}
	if a.RuntimeDigest != b.RuntimeDigest {
		t.Errorf("the same group compiled to different code in a larger organisation:\n  7 groups:  %d bytes %s\n  60 groups: %d bytes %s",
			len(a.RuntimeBytecode), a.RuntimeDigest, len(b.RuntimeBytecode), b.RuntimeDigest)
	}
	for id, artifact := range large {
		if len(artifact.RuntimeBytecode) == 0 || len(artifact.RuntimeBytecode) > MaxRuntimeBytecode {
			t.Fatalf("group %s: %d bytes", id, len(artifact.RuntimeBytecode))
		}
	}
	t.Logf("60 groups -> 60 artifacts, each %d bytes", len(b.RuntimeBytecode))
}
