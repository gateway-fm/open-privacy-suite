package rbac

import (
	"strings"
	"testing"
)

// RD-1305 classifier coverage: method aliases, positional options, trace
// configuration, empty options, malformed values and case folding.

func tx() map[string]any {
	return map[string]any{"to": "0x" + strings.Repeat("11", 20), "data": "0x"}
}

func nonEmptyOverride() map[string]any {
	return map[string]any{
		"0x2222222222222222222222222222222222222222": map[string]any{"code": "0x00"},
	}
}

func TestDetectStateOverride(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params []any
		want   bool
	}{
		// eth_call — no override
		{"eth_call no override", "eth_call", []any{tx(), "latest"}, false},
		{"eth_call only tx", "eth_call", []any{tx()}, false},
		{"eth_call nil state", "eth_call", []any{tx(), "latest", nil}, false},
		{"eth_call empty state", "eth_call", []any{tx(), "latest", map[string]any{}}, false},
		{"eth_call nil state nil block", "eth_call", []any{tx(), "latest", nil, nil}, false},

		// eth_call — override present
		{"eth_call state override", "eth_call", []any{tx(), "latest", nonEmptyOverride()}, true},
		{"eth_call block override only", "eth_call", []any{tx(), "latest", nil, map[string]any{"number": "0x1"}}, true},
		{"eth_call both overrides", "eth_call", []any{tx(), "latest", nonEmptyOverride(), map[string]any{"time": "0x1"}}, true},

		// eth_call — malformed override positions fail closed
		{"eth_call state is string", "eth_call", []any{tx(), "latest", "0xdeadbeef"}, true},
		{"eth_call state is array", "eth_call", []any{tx(), "latest", []any{1, 2}}, true},
		{"eth_call block is string", "eth_call", []any{tx(), "latest", nil, "0xdead"}, true},

		// eth_call — params[1] block-position validation (block-position options)
		{"eth_call eip1898 blockNumber ok", "eth_call", []any{tx(), map[string]any{"blockNumber": "0x1"}}, false},
		{"eth_call eip1898 blockHash+canonical ok", "eth_call", []any{tx(), map[string]any{"blockHash": "0xabc", "requireCanonical": true}}, false},
		{"eth_call state options at index1", "eth_call", []any{tx(), nonEmptyOverride()}, true},
		{"eth_call too many params", "eth_call", []any{tx(), "latest", map[string]any{}, map[string]any{}, "extra"}, true},

		// eth_createAccessList accepts a state override at index 2
		{"createAccessList no override", "eth_createAccessList", []any{tx(), "latest"}, false},
		{"createAccessList state override", "eth_createAccessList", []any{tx(), "latest", nonEmptyOverride()}, true},
		{"createAccessList state options at index1", "eth_createAccessList", []any{tx(), nonEmptyOverride()}, true},
		// createAccessList retains the supported boolean optimization parameter.
		{"createAccessList bool optimize true", "eth_createAccessList", []any{tx(), "latest", true}, false},
		{"createAccessList bool optimize false", "eth_createAccessList", []any{tx(), "latest", false}, false},
		{"eth_call bool at index2 still malformed", "eth_call", []any{tx(), "latest", true}, true},

		// mixed case canonicalization
		{"eth_CALL override", "eth_CALL", []any{tx(), "latest", nonEmptyOverride()}, true},

		// eth_estimateGas — same positions
		{"estimateGas no override", "eth_estimateGas", []any{tx(), "latest"}, false},
		{"estimateGas state override", "eth_estimateGas", []any{tx(), "latest", nonEmptyOverride()}, true},
		{"estimateGas state options at index1", "eth_estimateGas", []any{tx(), nonEmptyOverride()}, true}, // [call, stateOverride] layout (Linea-style) — override at index 1
		{"estimateGas block override", "eth_estimateGas", []any{tx(), "latest", nil, map[string]any{"number": "0x1"}}, true},

		// debug_traceCall — config override keys
		{"debug no config", "debug_traceCall", []any{tx(), "latest"}, false},
		{"debug plain config", "debug_traceCall", []any{tx(), "latest", map[string]any{"tracer": "callTracer"}}, false},
		{"debug stateOverrides", "debug_traceCall", []any{tx(), "latest", map[string]any{"tracer": "callTracer", "stateOverrides": nonEmptyOverride()}}, true},
		{"debug blockOverrides", "debug_traceCall", []any{tx(), "latest", map[string]any{"blockOverrides": map[string]any{"number": "0x1"}}}, true},
		{"debug stateOverride singular", "debug_traceCall", []any{tx(), "latest", map[string]any{"stateOverride": nonEmptyOverride()}}, true},
		// Trace option keys must be absent, including when their value is empty.
		{"debug empty stateOverrides denied", "debug_traceCall", []any{tx(), "latest", map[string]any{"stateOverrides": map[string]any{}}}, true},
		{"debug null blockOverrides denied", "debug_traceCall", []any{tx(), "latest", map[string]any{"blockOverrides": nil}}, true},
		{"debug malformed stateOverrides", "debug_traceCall", []any{tx(), "latest", map[string]any{"stateOverrides": "garbage"}}, true},
		// Equivalent case-folded spellings follow the same presence rule.
		{"debug StateOverrides mixed case", "debug_traceCall", []any{tx(), "latest", map[string]any{"StateOverrides": nonEmptyOverride()}}, true},
		{"debug BLOCKOVERRIDES upper", "debug_traceCall", []any{tx(), "latest", map[string]any{"BLOCKOVERRIDES": map[string]any{"number": "0x1"}}}, true},
		{"debug long-s ſtateOverrides", "debug_traceCall", []any{tx(), "latest", map[string]any{"ſtateOverrides": nonEmptyOverride()}}, true},
		{"debug long-s blockOverrideſ", "debug_traceCall", []any{tx(), "latest", map[string]any{"blockOverrideſ": map[string]any{"number": "0x1"}}}, true},
		// Lowercase-equivalent spellings follow the same presence rule.
		{"debug dotted-I stateOverrİdes", "debug_traceCall", []any{tx(), "latest", map[string]any{"stateOverrİdes": nonEmptyOverride()}}, true},
		// Replay-position options are unsupported.
		{"debug txIndex", "debug_traceCall", []any{tx(), "latest", map[string]any{"tracer": "callTracer", "txIndex": "0x1"}}, true},
		{"debug TXINDEX upper", "debug_traceCall", []any{tx(), "latest", map[string]any{"TXINDEX": 1}}, true},

		// unrelated methods never flagged
		{"getStorageAt", "eth_getStorageAt", []any{"0xabc", "0x1", "latest"}, false},
		{"sendTransaction", "eth_sendTransaction", []any{tx()}, false},
		{"getBalance", "eth_getBalance", []any{"0xabc", "latest"}, false},
		{"getProof", "eth_getProof", []any{"0xabc", []any{"0x1"}, "latest"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, kind := DetectStateOverride(tt.method, tt.params)
			if got != tt.want {
				t.Fatalf("DetectStateOverride(%q) = %v (kind %q), want %v", tt.method, got, kind, tt.want)
			}
			if got && kind == "" {
				t.Fatalf("DetectStateOverride(%q) returned denied with empty kind", tt.method)
			}
			if !got && kind != "" {
				t.Fatalf("DetectStateOverride(%q) returned allowed with non-empty kind %q", tt.method, kind)
			}
		})
	}
}

func TestDetectStateOverride_Alias(t *testing.T) {
	restore := SnapshotMethodRegistriesForTest()
	defer restore()

	// Operator aliases linea_call → eth_call and linea_estimateGas → eth_estimateGas.
	if err := RegisterExtraNamespaces(
		map[string][]string{"Linea": {"linea_call", "linea_estimateGas"}},
		map[string]string{"linea_call": "eth_call", "linea_estimateGas": "eth_estimateGas"},
		nil,
	); err != nil {
		t.Fatalf("registering the aliases: %v", err)
	}

	if denied, _ := DetectStateOverride("linea_call", []any{tx(), "latest", nonEmptyOverride()}); !denied {
		t.Fatal("aliased linea_call with a state override must be detected")
	}
	if denied, _ := DetectStateOverride("linea_estimateGas", []any{tx(), "latest", nil, map[string]any{"number": "0x1"}}); !denied {
		t.Fatal("aliased linea_estimateGas with a block override must be detected")
	}
	// Aliased options supplied in the block position are also classified.
	if denied, _ := DetectStateOverride("linea_estimateGas", []any{tx(), nonEmptyOverride()}); !denied {
		t.Fatal("linea_estimateGas [call, stateOverride] (override at index 1) must be detected")
	}
	if denied, _ := DetectStateOverride("linea_call", []any{tx(), "latest"}); denied {
		t.Fatal("aliased linea_call without an override must be allowed")
	}
}

// TestDetectStateOverride_RawMethodPolicy pins the raw-method half of
// DetectStateOverride: a simulation method mapped onto a target with no option
// policy keeps its own policy. Config loading refuses a built-in method as an
// alias key, so the mapping is injected straight into the registry to reach
// the defence-in-depth branch.
func TestDetectStateOverride_RawMethodPolicy(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	methods := []string{"eth_call", "eth_estimateGas", "eth_createAccessList", "debug_traceCall"}

	aliases := make(map[string]string, len(methods))
	for _, m := range methods {
		aliases[m] = "eth_getBalance"
	}
	if err := RegisterExtraNamespaces(map[string][]string{"Example": methods}, aliases, nil); err == nil {
		t.Fatal("config loading must refuse a built-in method as an alias key")
	}

	for _, m := range methods {
		MethodAliases[m] = "eth_getBalance"
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			if got := ResolveMethodAlias(method); got != "eth_getBalance" {
				t.Fatalf("test setup: %s resolves to %q, want the injected eth_getBalance", method, got)
			}
			params := []any{tx(), "latest", nonEmptyOverride()}
			if method == "debug_traceCall" {
				params[2] = map[string]any{"stateOverrides": nonEmptyOverride()}
			}
			if denied, _ := DetectStateOverride(method, params); !denied {
				t.Fatal("the raw method's simulation-option policy must remain in effect")
			}
		})
	}
}

// TestDetectStateOverride_BlockSlotKind pins the audit label: an
// override object supplied in params[1] is a state override, not "malformed".
func TestDetectStateOverride_BlockSlotKind(t *testing.T) {
	denied, kind := DetectStateOverride("eth_call", []any{tx(), nonEmptyOverride()})
	if !denied || kind != overrideKindState {
		t.Fatalf("got (%v, %q), want (true, %q)", denied, kind, overrideKindState)
	}
}

// TestGlobalBlock_SimulationMethods covers RD-1305's unsupported bundled methods.
func TestGlobalBlock_SimulationMethods(t *testing.T) {
	blocked := []string{
		"eth_simulateV1", "eth_simulate", "eth_multicallV1", "eth_callMany", "eth_callBundle",
	}
	for _, m := range blocked {
		if !IsMethodBlocked(m) {
			t.Errorf("%s must be globally blocked", m)
		}
	}
	// Sanity: the single-call methods we still allow are not blocked.
	for _, m := range []string{"eth_call", "eth_estimateGas", "eth_createAccessList", "debug_traceCall", "debug_traceTransaction"} {
		if IsMethodBlocked(m) {
			t.Errorf("%s must NOT be globally blocked", m)
		}
	}
}
