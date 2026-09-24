package policydsl

import (
	"context"
	"fmt"
	"math/big"
	"testing"
)

// How long does one policy check take, and how does that move as an
// organisation grows? The per-frame check gates every call the node admits, so
// the cost of a policy shape is a product question, not an implementation
// detail — and until now nothing measured it.
//
// The benchmark builds realistic shapes (groups × per-group function rules over
// a shared registry) and evaluates one permitted call against the compiled
// artifact, which is the same bytecode a node executes.
func BenchmarkPolicyCheck(b *testing.B) {
	compiler := NewCompiler()
	if err := compiler.Available(context.Background()); err != nil {
		b.Skipf("the pinned compiler is required: %v", err)
	}
	digest := abiDigest(b, vaultABI)

	build := func(groups, rulesPerGroup int) (*EVMEvaluator, int, error) {
		catalog := Catalog{Org: orgID, Groups: map[string]struct{}{}, Contracts: map[string]ContractInfo{vaultAddr: {ABI: vaultABI}}}
		exceptions := []DeployerException{{StorageAddress: vaultAddr, Groups: []string{groupID}}}
		p := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule}
		for g := 0; g < groups; g++ {
			id := groupID
			if g > 0 {
				id = fmt.Sprintf("grp_%03d", g)
			}
			catalog.Groups[id] = struct{}{}
			allow := []FrameRule{
				{TargetClass: "eoa", Selector: "0x"},
				{TargetClass: "deployer", Selector: "*", Except: cloneDeployerExceptions(exceptions)},
				{StorageAddress: vaultAddr, Selector: selTransfer, ABIDigest: digest},
			}
			for r := 1; r < rulesPerGroup; r++ {
				allow = append(allow, FrameRule{StorageAddress: vaultAddr, Selector: selBalanceOf, ABIDigest: digest, CallTypes: []CallType{CallTypeStaticCall}})
				break // one extra distinct selector is enough; more would collide
			}
			p.Bindings = append(p.Bindings, Binding{Group: id, Allow: allow})
		}
		v, err := Validate(p, catalog)
		if err != nil {
			b.Fatalf("validate: %v", err)
		}
		artifact, err := compiler.Build(context.Background(), v)
		if err != nil {
			// A shape that will not compile is a result, not a broken
			// benchmark: it is the ceiling, reported rather than hidden.
			return nil, 0, err
		}
		e, err := NewEVMEvaluator(artifact)
		if err != nil {
			b.Fatalf("evaluator: %v", err)
		}
		return e, len(artifact.RuntimeBytecode), nil
	}

	ctx := Context{Org: orgID, Groups: []string{groupID}, Signer: signerAddr}
	frames := []Frame{vaultCall(transferCalldata(b, signerAddr, big.NewInt(1)))}

	for _, shape := range []struct{ groups, rules int }{{1, 1}, {7, 2}, {30, 2}, {60, 2}} {
		e, size, err := build(shape.groups, shape.rules)
		if err != nil {
			b.Run(fmt.Sprintf("groups=%d_DOES_NOT_COMPILE", shape.groups), func(b *testing.B) { b.Skip(err.Error()) })
			continue
		}
		b.Run(fmt.Sprintf("groups=%d_bytes=%d", shape.groups, size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if d := e.Evaluate(orgID, ctx, frames); !d.Allowed {
					b.Fatalf("the benchmarked call must be permitted: %+v", d)
				}
			}
		})
	}
}
