package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/rbac"
)

func TestNodePolicyRejectsApprovalModeAtStartup(t *testing.T) {
	for _, setting := range []string{"OPS_APPROVAL_TARGET", "OPS_APPROVAL_TARGETS"} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv("OPS_APPROVAL_TARGET", "")
			t.Setenv("OPS_APPROVAL_TARGETS", "")
			t.Setenv(setting, "127.0.0.1:50051")
			_, err := NewWithVerifier(&config.Config{NodePolicy: config.NodePolicyConfig{Mode: "reth"}}, nil)
			require.ErrorContains(t, err, "cannot combine")
		})
	}
}

func TestNodeExecutionRetainsSimulationOptionGuards(t *testing.T) {
	for _, tc := range []struct {
		method  string
		options any
		status  int
	}{
		{"eth_call", map[string]any{"0x2222222222222222222222222222222222222222": map[string]any{"code": "0x00"}}, http.StatusNotFound},
		{"debug_traceCall", map[string]any{"blockOverrides": map[string]any{"number": "0x10"}}, http.StatusNotFound},
		{"debug_traceCall", map[string]any{"tracer": "prestateTracer"}, http.StatusBadRequest},
		{"debug_traceCall", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": true}}, http.StatusBadRequest},
	} {
		t.Run(tc.method, func(t *testing.T) {
			p, store, node, _ := nodeRPCFixture(t)
			params := []any{map[string]any{"from": store.linked[0], "to": nodeRPCTarget}, "latest", tc.options}
			result := p.Process(t.Context(), &ProcessRequest{Method: tc.method, Params: params, UserID: store.user.ExternalID})
			require.NotNil(t, result.Error)
			require.Equal(t, tc.status, result.Error.StatusCode)
			require.Empty(t, node.prepared)
			require.Empty(t, node.requests)
		})
	}
}

func TestNodeExecutionStrictRejectsVisibleTo(t *testing.T) {
	for _, position := range []string{"top", "options"} {
		t.Run(position, func(t *testing.T) {
			p, store, node, raw := nodeRPCFixture(t)
			p.readProfile = rbac.ReadProfileStrict
			params := []any{raw}
			body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": params}
			if position == "top" {
				body["visibleTo"] = []string{}
			} else {
				params = append(params, map[string]any{"visibleTo": []string{}})
				body["params"] = params
			}
			encoded, err := json.Marshal(body)
			require.NoError(t, err)
			result := p.Process(t.Context(), &ProcessRequest{Method: "eth_sendRawTransaction", Params: params, Body: encoded, UserID: store.user.ExternalID})
			require.NotNil(t, result.Error)
			require.Equal(t, http.StatusBadRequest, result.Error.StatusCode)
			require.Empty(t, node.prepared)
			require.Empty(t, node.submissions)
		})
	}
}

func TestNodeExecutionTraceRetainsValuePrivacy(t *testing.T) {
	p, store, node, _ := nodeRPCFixture(t)
	node.result = json.RawMessage(`{"type":"CALL","from":"` + store.linked[0] + `","to":"` + nodeRPCTarget + `","input":"0x1234","output":"0x5678","calls":[{"type":"CALL","from":"` + nodeRPCTarget + `","to":"0x3333333333333333333333333333333333333333","input":"0xdeadbeef","output":"0xabcdef","value":"0x99"}]}`)
	req := nodeRPCRequest(t, "debug_traceCall", []any{map[string]any{"to": nodeRPCTarget}, "latest"})
	result := p.Process(t.Context(), req)
	require.Nil(t, result.Error)
	require.Contains(t, string(result.ResponseBody), "0x1234")
	for _, hidden := range []string{"0xdeadbeef", "0xabcdef", "0x99"} {
		require.NotContains(t, string(result.ResponseBody), hidden)
	}
	var wire struct {
		Params []json.RawMessage `json:"params"`
	}
	require.NoError(t, json.Unmarshal(node.requests[0], &wire))
	require.JSONEq(t, `{"tracer":"callTracer"}`, string(wire.Params[2]))
}
