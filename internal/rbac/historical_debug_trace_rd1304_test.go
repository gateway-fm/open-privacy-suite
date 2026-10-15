package rbac

import "testing"

// RD-1304: debug_traceCall runs the EVM like eth_call, so a historical block
// tag must trip the same historical-state guard (with eth_call's admin
// exemption, applied by CheckAccess). Its block is params[1], same as eth_call;
// params[2] is the trace config and must not be mistaken for the block.
// debug_traceTransaction replays a mined tx and has no block param — unaffected.
func TestIsHistoricalStateQuery_DebugTraceCall_RD1304(t *testing.T) {
	call := map[string]any{"to": "0x1111111111111111111111111111111111111111"}
	cfg := map[string]any{"tracer": "callTracer"}
	tests := []struct {
		name   string
		method string
		params []any
		want   bool
	}{
		{"latest is current", "debug_traceCall", []any{call, "latest"}, false},
		{"omitted block is current", "debug_traceCall", []any{call}, false},
		{"latest with trace config", "debug_traceCall", []any{call, "latest", cfg}, false},
		{"hex block is historical", "debug_traceCall", []any{call, "0x1"}, true},
		{"hex block with trace config", "debug_traceCall", []any{call, "0x1", cfg}, true},
		{"EIP-1898 object is historical", "debug_traceCall", []any{call, map[string]any{"blockNumber": "0x1"}}, true},
		{"mixed case method", "DEBUG_TRACECALL", []any{call, "0x1"}, true},
		{"traceTransaction not checked", "debug_traceTransaction", []any{"0xab", cfg}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := IsHistoricalStateQuery(tt.method, tt.params)
			if got != tt.want {
				t.Fatalf("IsHistoricalStateQuery(%q, %v) = %v, want %v", tt.method, tt.params, got, tt.want)
			}
			if got && reason != "historical state queries not permitted" {
				t.Fatalf("reason = %q", reason)
			}
		})
	}
}
