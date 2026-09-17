package configuration

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/policydsl"
)

func TestExecutionSpecPreservesClosedPolicyAndRejectsArtifactInput(t *testing.T) {
	for _, raw := range []string{
		`{"apiVersion":"privacy.gateway.fm/v1alpha1","kind":"ContractExecutionPolicy","org":"org-test","nestedCalls":"requireOwnRule","bindings":[],"runtimeBytecode":"0x00"}`,
		`null`,
		`{"apiVersion":"wrong","kind":"ContractExecutionPolicy","org":"org-test","nestedCalls":"requireOwnRule","bindings":[]}`,
	} {
		spec := ExecutionSpec{Policy: json.RawMessage(raw)}
		if err := normalizeExecution(&spec); err == nil {
			t.Fatalf("unsafe source accepted: %s", raw)
		}
	}
	p := &policydsl.Policy{APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: "org-test", NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{}}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	spec := ExecutionSpec{Policy: raw}
	if err := normalizeExecution(&spec); err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(p)
	if string(spec.Policy) != string(canonical) || spec.configurationKind() != ExecutionRules {
		t.Fatal("policy normalization changed meaning")
	}
}

func TestExecutionChangesExposeRemovedAndAddedBindingRules(t *testing.T) {
	before := &policydsl.Policy{Bindings: []policydsl.Binding{{Group: "removed", Allow: []policydsl.FrameRule{{TargetClass: "org", Selector: "*"}}}, {Group: "changed", Allow: []policydsl.FrameRule{{TargetClass: "eoa", Selector: "0x"}}}}}
	after := &policydsl.Policy{Bindings: []policydsl.Binding{{Group: "added", Allow: []policydsl.FrameRule{{TargetClass: "org", Selector: "*"}}}, {Group: "changed", Allow: []policydsl.FrameRule{}}}}
	changes := ExecutionChanges(before, after)
	if len(changes) != 3 || changes[0].GroupID != "added" || changes[0].Action != "add" || changes[1].GroupID != "changed" || changes[1].Action != "replace" || changes[2].GroupID != "removed" || changes[2].Action != "remove" {
		t.Fatalf("unreviewable changes: %+v", changes)
	}
}
