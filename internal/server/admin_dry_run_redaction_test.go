package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/proxy"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-930 — the dry-run handler's response shape. This file holds:
//
//   - Unit tests on `extractLogsFromCallTrace`, the pure helper that
//     collects the logs of every trace frame.
//   - One integration test pinning that an allowed eth_call result is
//     returned unchanged.
//
// What the user is allowed to see (read admission, event rules, field
// redaction, logs_visible_to_user) goes through the production response
// filter since RD-1308 and is covered in admin_dry_run_response_filter_test.go.

// --- unit tests for extractLogsFromCallTrace --------------------------

// TestExtractLogsFromCallTrace_NestedFrames pins the recursion: logs
// emitted at the top frame AND inside arbitrarily nested `calls[]`
// frames must all surface. A regression here would silently make
// dry-run miss logs from internal CALL/STATICCALL/DELEGATECALL
// frames, which is exactly the cross-org hole RD-915 closed at
// runtime — dry-run must mirror it.
func TestExtractLogsFromCallTrace_NestedFrames(t *testing.T) {
	raw := json.RawMessage(`{
		"from":"0x1111111111111111111111111111111111111111",
		"to":"0xa000000000000000000000000000000000000000",
		"logs":[
			{"address":"0xa000000000000000000000000000000000000000","topics":["0xtopic_top"],"data":"0x"}
		],
		"calls":[
			{
				"from":"0xa000000000000000000000000000000000000000",
				"to":"0xb000000000000000000000000000000000000000",
				"logs":[
					{"address":"0xb000000000000000000000000000000000000000","topics":["0xtopic_n1"],"data":"0x"}
				],
				"calls":[
					{
						"from":"0xb000000000000000000000000000000000000000",
						"to":"0xc000000000000000000000000000000000000000",
						"logs":[
							{"address":"0xc000000000000000000000000000000000000000","topics":["0xtopic_n2"],"data":"0x"}
						]
					}
				]
			},
			{
				"from":"0xa000000000000000000000000000000000000000",
				"to":"0xd000000000000000000000000000000000000000",
				"logs":[
					{"address":"0xd000000000000000000000000000000000000000","topics":["0xtopic_sib"],"data":"0x"}
				]
			}
		]
	}`)

	logs := extractLogsFromCallTrace(raw)
	require.Len(t, logs, 4, "expected logs from top + 3 nested frames")

	got := make([]string, 0, len(logs))
	for _, l := range logs {
		var entry struct {
			Topics []string `json:"topics"`
		}
		require.NoError(t, json.Unmarshal(l, &entry))
		require.Len(t, entry.Topics, 1)
		got = append(got, entry.Topics[0])
	}
	assert.ElementsMatch(t, []string{"0xtopic_top", "0xtopic_n1", "0xtopic_n2", "0xtopic_sib"}, got)
}

// TestExtractLogsFromCallTrace_EmptyAndMalformed covers the defensive
// branches: empty raw, malformed JSON, frame without logs/calls. None
// of these may panic or surface nil pointers downstream — the function
// must always return either nil or a well-formed slice.
func TestExtractLogsFromCallTrace_EmptyAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"empty", "", 0},
		{"malformed", "{not-json", 0},
		{"frame with no logs and no calls", `{"from":"0x","to":"0x"}`, 0},
		{"frame with only nested empty calls", `{"calls":[{"calls":[{}]}]}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractLogsFromCallTrace(json.RawMessage(tc.raw))
			assert.Len(t, got, tc.want)
		})
	}
}

// --- integration test: eth_call result -------------------------------

// TestDryRun_EthCall_AllowedResultReturnedUnchanged: eth_call has no case in
// the production response filter, so once the call is allowed (CheckAccess
// and the nested-call gate) the node's result is the user's answer. The
// dry-run must return it byte for byte, as the user's own call would.
func TestDryRun_EthCall_AllowedResultReturnedUnchanged(t *testing.T) {
	f := setupDryRunFixture(t)

	// Sentinel payload — anything recognisable that no caller could
	// have constructed without seeing the upstream response.
	upstreamBody := `{"jsonrpc":"2.0","id":1,"result":"0xdeadbeefcafef00d"}`
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Verify we received an eth_call request (not a debug_traceCall).
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		assert.Equal(t, "eth_call", req.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	t.Cleanup(stub.Close)

	f.srv.proxy = proxy.New(stub.URL)

	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_call",
			"params": []any{
				map[string]any{"to": f.contractAddr, "data": "0xabcd"},
				"latest",
			},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp dryRunResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "allow", resp.Decision)

	// Response is stored as json.RawMessage in dryRunResponse — when
	// the outer struct is re-encoded to JSON for the HTTP response,
	// it's emitted as the embedded JSON object. So assert by
	// re-parsing the inner result rather than comparing raw bytes
	// (the wire form of a json.RawMessage round-tripped through gin
	// can re-arrange keys / whitespace).
	var inner struct {
		JSONRPC string `json:"jsonrpc"`
		Result  string `json:"result"`
		ID      int    `json:"id"`
	}
	require.NoError(t, json.Unmarshal(resp.Response, &inner))
	assert.Equal(t, "2.0", inner.JSONRPC)
	assert.Equal(t, "0xdeadbeefcafef00d", inner.Result)
	assert.Equal(t, 1, inner.ID)

	// The sentinel result must be present verbatim in the wire form.
	assert.Contains(t, string(resp.Response), "0xdeadbeefcafef00d",
		"an allowed eth_call result is returned unchanged, as on the user's own call")
}
