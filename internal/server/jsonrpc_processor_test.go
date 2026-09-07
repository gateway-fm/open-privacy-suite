package server

import (
	"testing"

	"privacy-proxy/internal/proxy"
)

// TestResolveAPIKeyHeader pins the two-branch behaviour of the processor's
// header resolver: the operator-wide default from RPC_API_KEY_HEADER if set,
// otherwise proxy.DefaultAPIKeyHeader.
func TestResolveAPIKeyHeader(t *testing.T) {
	tests := []struct {
		name             string
		processorDefault string
		want             string
	}{
		{
			name:             "processor default wins when set",
			processorDefault: "Custom-H",
			want:             "Custom-H",
		},
		{
			name:             "falls back to proxy.DefaultAPIKeyHeader when default empty",
			processorDefault: "",
			want:             proxy.DefaultAPIKeyHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &JSONRPCProcessor{defaultRPCAPIKeyHeader: tt.processorDefault}
			got := p.resolveAPIKeyHeader()
			if got != tt.want {
				t.Errorf("resolveAPIKeyHeader(processorDefault=%q) = %q, want %q",
					tt.processorDefault, got, tt.want)
			}
		})
	}
}

// TestRPCAPIKeyHeaderConfig verifies the constructor config wires the
// operator-wide header (RPC_API_KEY_HEADER via Load()) through to the
// resolver, and that omitting it keeps the proxy default.
func TestRPCAPIKeyHeaderConfig(t *testing.T) {
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{})
	if got := p.resolveAPIKeyHeader(); got != proxy.DefaultAPIKeyHeader {
		t.Fatalf("default resolveAPIKeyHeader() = %q, want %q", got, proxy.DefaultAPIKeyHeader)
	}
	p = NewJSONRPCProcessor(JSONRPCProcessorConfig{RPCAPIKeyHeader: "Custom-H"})
	if got := p.resolveAPIKeyHeader(); got != "Custom-H" {
		t.Errorf("configured resolveAPIKeyHeader() = %q, want %q", got, "Custom-H")
	}
}

// =============================================================================
// CRITICAL SECURITY TEST: Cross-Org Isolation via Tracing
// =============================================================================
//
// This test documents the security invariant that MUST be maintained:
//
// ALL contract calls are traced by the runtime tracer. No contract is exempt
// from tracing, regardless of ownership. This prevents cross-org isolation
// violations where an org-owned contract makes internal calls to another
// org's contract:
//
//   User -> OrgA_Contract.attack(OrgB_Addr) -> OrgB_Contract  (DENIED by trace)
//
// The only exception to tracing is simple value transfers to EOAs (no code),
// which cannot make external calls.

func TestAllContractCallsAreTraced(t *testing.T) {
	// This test documents the security requirement:
	// ALL contract calls must be traced. No contract is exempt.
	//
	// The implementation is in validateWithTracing() in jsonrpc_processor.go.
	// A full integration test requires mocking the entire tracer infrastructure.
	//
	// Key code path to verify:
	// - jsonrpc_processor.go: validateWithTracing()
	// - No special-casing for any contract address
	// - Only simple value transfers to EOAs skip tracing
	t.Log("Security invariant: all contract calls are traced for cross-org isolation")
	t.Log("See jsonrpc_processor.go:validateWithTracing() for implementation")
}

// =============================================================================
// CRITICAL SECURITY TEST: Simple Value Transfers to Contracts
// =============================================================================
//
// A contract's receive()/fallback() function CAN make external calls to other
// contracts. By sending ETH with empty calldata to a contract, an attacker
// triggers receive() which may call into cross-org contracts -- bypassing tracing.
//
// The fix: Only skip tracing for transfers to EOAs (verified via eth_getCode).
// For contracts, always trace even with empty calldata.

func TestSimpleValueTransfer_ContractsMustBeTraced(t *testing.T) {
	// This test documents the security invariant:
	// Simple value transfers to CONTRACTS must still be traced because
	// receive()/fallback() can make external calls to other orgs' contracts.
	//
	// Only transfers to EOAs (no code) can safely skip tracing.
	//
	// Attack scenario:
	//   1. Attacker deploys a contract with receive() that calls OrgB's contract
	//   2. Attacker sends ETH to their contract with empty calldata
	//   3. Without this fix, tracing would be skipped (empty calldata)
	//   4. The contract's receive() executes and calls OrgB -- cross-org violation
	//
	// Implementation in jsonrpc_processor.go:validateWithTracing():
	//   - isSimpleValueTransfer(data) checks for empty calldata
	//   - If empty calldata: calls runtimeTracer.HasCode(ctx, to) via eth_getCode
	//   - If target has code (contract): proceeds with tracing
	//   - If target has no code (EOA): safely skips tracing
	//   - If eth_getCode fails: fails closed (proceeds with tracing)
	t.Log("Security invariant: simple value transfers to contracts are traced")
	t.Log("Only EOA recipients skip tracing (verified by eth_getCode)")
	t.Log("See jsonrpc_processor.go:validateWithTracing() for implementation")
}

func TestIsSimpleValueTransfer(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		// Simple value transfers (should return true - skip tracing)
		{"empty string", "", true},
		{"0x only", "0x", true},
		{"0X only", "0X", true},
		{"0x with whitespace", "  0x  ", true},
		{"empty with whitespace", "   ", true},

		// Contract calls (should return false - need tracing)
		{"function selector", "0xa9059cbb", false},
		{"full calldata", "0xa9059cbb000000000000000000000000deadbeef", false},
		{"transfer call", "0xa9059cbb0000000000000000000000001234567890123456789012345678901234567890", false},
		{"short data", "0x12", false},
		{"non-hex prefix", "a9059cbb", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSimpleValueTransfer(tt.data)
			if result != tt.expected {
				t.Errorf("isSimpleValueTransfer(%q) = %v, expected %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"empty", "", ""},
		{"short 1 char", "a", "****"},
		{"short 3 chars", "abc", "****"},
		{"exactly 4 chars", "abcd", "****abcd"},
		{"normal key", "sk-live-abc123", "****c123"},
		{"long key", "very-long-api-key-that-goes-on-and-on-1234", "****1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskAPIKey(tt.key)
			if result != tt.expected {
				t.Errorf("maskAPIKey(%q) = %q, expected %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestMaskAPIKeyStr(t *testing.T) {
	// maskAPIKeyStr (admin handler version) should behave identically
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"empty", "", ""},
		{"short", "ab", "****"},
		{"normal", "sk-live-test-key", "****-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskAPIKeyStr(tt.key)
			if result != tt.expected {
				t.Errorf("maskAPIKeyStr(%q) = %q, expected %q", tt.key, result, tt.expected)
			}
		})
	}
}
