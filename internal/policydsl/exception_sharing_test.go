package policydsl

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// An organisation's deployer exceptions are one table: every contract that is
// granted to some group, with the groups that may still reach it. The legacy
// import attaches that same table to every non-admin group's deployer rule, so
// the table is repeated once per group. Emitting it inline per rule multiplies
// it again in the bytecode, and a perfectly ordinary organisation — the demo's
// 28 contracts across 7 groups — then exceeds the 24576-byte limit and cannot
// have execution rules at all.
//
// The table must therefore be emitted once and shared by the rules that carry
// it, which is behaviour-preserving: the same addresses and groups decide the
// same way, they are just not copied.
func TestDeployerExceptionsAreSharedNotRepeatedPerGroup(t *testing.T) {
	compiler := requireCompiler(t)

	const groups, contracts = 7, 28
	catalog := Catalog{Org: orgID, Groups: map[string]struct{}{}, Contracts: map[string]ContractInfo{}}
	exceptions := make([]DeployerException, 0, contracts)
	for i := 0; i < contracts; i++ {
		address := fmt.Sprintf("0x%040x", i+1)
		catalog.Contracts[address] = ContractInfo{ABI: vaultABI}
		exceptions = append(exceptions, DeployerException{StorageAddress: address, Groups: []string{fmt.Sprintf("grp_%02d", i%groups)}})
	}
	policy := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule}
	for g := 0; g < groups; g++ {
		id := fmt.Sprintf("grp_%02d", g)
		catalog.Groups[id] = struct{}{}
		policy.Bindings = append(policy.Bindings, Binding{Group: id, Allow: []FrameRule{
			{TargetClass: "eoa", Selector: "0x"},
			{TargetClass: "deployer", Selector: "*", Except: cloneDeployerExceptions(exceptions)},
		}})
	}

	validated, err := Validate(policy, catalog)
	if err != nil {
		t.Fatalf("the policy must be valid: %v", err)
	}
	source, err := GenerateSolidity(validated)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}

	// Each address appears in the source a bounded number of times, not once
	// per group: that is the difference between a shared table and a copy.
	first := fmt.Sprintf("0x%040x", 1)
	if occurrences := strings.Count(strings.ToLower(source), strings.ToLower(first)); occurrences >= groups {
		t.Errorf("address %s appears %d times in the generated source; a shared table would emit it once", first, occurrences)
	}

	artifact, err := compiler.Build(context.Background(), validated)
	if err != nil {
		t.Fatalf("an organisation with %d contracts across %d groups must compile: %v", contracts, groups, err)
	}
	t.Logf("runtime bytecode: %d bytes of %d", len(artifact.RuntimeBytecode), MaxRuntimeBytecode)
}
