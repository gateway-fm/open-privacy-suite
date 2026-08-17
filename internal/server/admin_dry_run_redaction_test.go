package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-930 — the dry-run handler's response shape and per-user log
// redaction were not pinned by tests. The original RD-872 suite covered
// auth/method gates and audit logging but never asserted what the
// response actually contains. This file fills that gap with two layers:
//
//   - Unit tests on the pure helpers (`extractLogsFromCallTrace`,
//     `filterDryRunLogs`). They drive every redaction branch from
//     in-memory inputs without spinning up the DB or the proxy.
//   - One integration test on `forwardDryRunRead` that pins the
//     documented "raw upstream passthrough, no per-user redaction"
//     contract for read methods — if someone ever wires per-method
//     redaction into the read path, the test changes intentionally.
//
// The linked-address `must_be=self` hole in `filterDryRunLogs` (line
// 408 hardcodes `addrs := []string{}`) is pinned as documented
// behaviour — `TestFilterDryRunLogs_ParamRuleSelfAlwaysFails`. If the
// hole is closed in the future, that test will fail and demand a
// rewrite, which is exactly the signal we want.

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

// --- unit tests for filterDryRunLogs ---------------------------------

// helper: build an EffectivePermissions with one or more contract
// access entries. Contract addresses are normalised lowercase per the
// production resolver (and FilterEventLogs lookup).
func dryRunPermsWith(entries map[string]rbac.ContractAccess) *rbac.EffectivePermissions {
	access := make(map[string]rbac.ContractAccess, len(entries))
	for addr, ca := range entries {
		access[strings.ToLower(addr)] = ca
	}
	return &rbac.EffectivePermissions{
		ID:             uuid.New().String(),
		UserID:         uuid.New().String(),
		OrgID:          uuid.New().String(),
		ContractAccess: access,
	}
}

func mustLog(t *testing.T, addr, topic0 string, otherTopics ...string) json.RawMessage {
	t.Helper()
	topics := append([]string{topic0}, otherTopics...)
	out := map[string]any{
		"address":         addr,
		"topics":          topics,
		"data":            "0x",
		"transactionHash": "0xtxhash",
	}
	b, err := json.Marshal(out)
	require.NoError(t, err)
	return b
}

const (
	drrContractA = "0xa11111111111111111111111111111111111111a"
	drrContractB = "0xb22222222222222222222222222222222222222b"
	drrTopicX    = "0x1111111111111111111111111111111111111111111111111111111111111111"
	drrTopicY    = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

// TestFilterDryRunLogs_WildcardPassesAllOnContract pins wildcard
// event_rules: every log emitted from a contract the user has wildcard
// grant on must pass through; logs from any other contract are
// dropped. This is the most permissive grant shape and the simplest
// invariant — if it breaks, every dry-run trace would either
// over-redact (operator panic) or under-redact (privacy leak).
func TestFilterDryRunLogs_WildcardPassesAllOnContract(t *testing.T) {
	perms := dryRunPermsWith(map[string]rbac.ContractAccess{
		drrContractA: {EventRules: &rbac.EventRulesField{Wildcard: true}},
		// drrContractB intentionally absent — no access.
	})

	logs := []json.RawMessage{
		mustLog(t, drrContractA, drrTopicX),
		mustLog(t, drrContractB, drrTopicY),
		mustLog(t, drrContractA, drrTopicY),
	}

	user := &rbac.User{ExternalID: "did:dr:r-user"}
	got := filterDryRunLogs(logs, perms, user, "did:dr:r-user")

	require.Len(t, got, 2, "expected both contractA logs, contractB dropped")
	for _, l := range got {
		var entry struct {
			Address string `json:"address"`
		}
		require.NoError(t, json.Unmarshal(l, &entry))
		assert.Equal(t, drrContractA, entry.Address)
	}
}

// TestFilterDryRunLogs_NoGrantDenies pins the load-bearing invariant:
// a contract the user has no grant on (no entry in ContractAccess)
// must drop all of its logs from the dry-run answer. Without this,
// a tier-2 admin's dry-run would surface logs from contracts the
// impersonated user can't see — exactly the leak this test guards
// against.
func TestFilterDryRunLogs_NoGrantDenies(t *testing.T) {
	perms := dryRunPermsWith(map[string]rbac.ContractAccess{
		// only A — B is intentionally unmapped.
		drrContractA: {EventRules: &rbac.EventRulesField{Wildcard: true}},
	})

	logs := []json.RawMessage{
		mustLog(t, drrContractB, drrTopicX),
		mustLog(t, drrContractB, drrTopicY),
	}

	user := &rbac.User{ExternalID: "did:dr:r-user"}
	got := filterDryRunLogs(logs, perms, user, "did:dr:r-user")
	assert.Empty(t, got, "logs from contracts the user has no grant on must be dropped")
}

// TestFilterDryRunLogs_DenyEventRulesDropsAll pins the deny-all
// state: a grant whose EventRules is nil OR whose rules slice is
// empty means "no events visible". Wildcard and allowlist are
// covered separately; this is the third state.
func TestFilterDryRunLogs_DenyEventRulesDropsAll(t *testing.T) {
	cases := []struct {
		name  string
		rules *rbac.EventRulesField
	}{
		{"nil event rules", nil},
		{"empty allowlist", &rbac.EventRulesField{Wildcard: false, Rules: nil}},
		{"empty rules slice", &rbac.EventRulesField{Wildcard: false, Rules: []rbac.EventRule{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perms := dryRunPermsWith(map[string]rbac.ContractAccess{
				drrContractA: {EventRules: tc.rules},
			})
			logs := []json.RawMessage{
				mustLog(t, drrContractA, drrTopicX),
				mustLog(t, drrContractA, drrTopicY),
			}
			user := &rbac.User{ExternalID: "did:dr:r-user"}
			got := filterDryRunLogs(logs, perms, user, "did:dr:r-user")
			assert.Empty(t, got, "deny-state event_rules must drop every log on the contract")
		})
	}
}

// TestFilterDryRunLogs_AllowlistMatchesByTopic0 pins the allowlist
// state: only logs whose topic0 appears in the rule list pass. Tests
// both the positive (matching topic) and negative (non-matching topic)
// case in one call so the output ordering / index assumptions are
// also pinned.
func TestFilterDryRunLogs_AllowlistMatchesByTopic0(t *testing.T) {
	perms := dryRunPermsWith(map[string]rbac.ContractAccess{
		drrContractA: {EventRules: &rbac.EventRulesField{
			Wildcard: false,
			Rules: []rbac.EventRule{
				{Topic0: drrTopicX, Name: "AllowedEvent"},
			},
		}},
	})

	logs := []json.RawMessage{
		mustLog(t, drrContractA, drrTopicX), // matches → kept
		mustLog(t, drrContractA, drrTopicY), // does not match → dropped
		mustLog(t, drrContractA, drrTopicX), // matches → kept
	}

	user := &rbac.User{ExternalID: "did:dr:r-user"}
	got := filterDryRunLogs(logs, perms, user, "did:dr:r-user")
	require.Len(t, got, 2)
	for _, l := range got {
		var entry struct {
			Topics []string `json:"topics"`
		}
		require.NoError(t, json.Unmarshal(l, &entry))
		assert.Equal(t, drrTopicX, entry.Topics[0])
	}
}

// TestFilterDryRunLogs_VisibleIsSubsetOfEmitted is the property test:
// for any combination of perms + logs, the returned slice is a subset
// of the input. We can't prove the subset relation with one input, so
// we run a few representative combinations and assert the property
// holds in each. Catches regressions where a filter accidentally
// duplicates entries, mutates them, or returns unrelated logs.
func TestFilterDryRunLogs_VisibleIsSubsetOfEmitted(t *testing.T) {
	wildcardA := dryRunPermsWith(map[string]rbac.ContractAccess{
		drrContractA: {EventRules: &rbac.EventRulesField{Wildcard: true}},
	})
	denyA := dryRunPermsWith(map[string]rbac.ContractAccess{
		drrContractA: {EventRules: nil},
	})
	allowlistA := dryRunPermsWith(map[string]rbac.ContractAccess{
		drrContractA: {EventRules: &rbac.EventRulesField{
			Rules: []rbac.EventRule{{Topic0: drrTopicX}},
		}},
	})

	logs := []json.RawMessage{
		mustLog(t, drrContractA, drrTopicX),
		mustLog(t, drrContractA, drrTopicY),
		mustLog(t, drrContractB, drrTopicX),
	}

	user := &rbac.User{ExternalID: "did:dr:r-user"}
	cases := []*rbac.EffectivePermissions{wildcardA, denyA, allowlistA}
	for i, p := range cases {
		got := filterDryRunLogs(logs, p, user, "did:dr:r-user")
		assert.LessOrEqual(t, len(got), len(logs), "case %d: visible exceeds emitted", i)
		// Every entry in `got` must appear verbatim in `logs` (no
		// mutation, no fabrication). Compare on the marshalled bytes.
		seen := make(map[string]bool, len(logs))
		for _, l := range logs {
			seen[string(l)] = true
		}
		for _, l := range got {
			assert.True(t, seen[string(l)], "case %d: returned log not in input set", i)
		}
	}
}

// TestFilterDryRunLogs_ParamRuleSelfAlwaysFails pins the documented
// "best-effort: skip linked-address resolution" behaviour at
// admin_dry_run.go:408. Today filterDryRunLogs hardcodes
// `addrs := []string{}`, so any param_rule with `must_be=self`
// silently fails — even when the indexed parameter in the log
// IS the impersonated user's actual linked address. This test
// guards against the wrong direction of regression: if someone
// later wires linked-address resolution in, the test fails and
// the author has to consciously update it (which is the right
// signal — the redaction surface area changed and needs review).
func TestFilterDryRunLogs_ParamRuleSelfAlwaysFails(t *testing.T) {
	// Allowlist with one rule that requires param[0] == self.
	perms := dryRunPermsWith(map[string]rbac.ContractAccess{
		drrContractA: {EventRules: &rbac.EventRulesField{
			Rules: []rbac.EventRule{
				{
					Topic0: drrTopicX,
					Name:   "Transfer",
					ParamRules: []rbac.ParamRule{
						{Index: 1, MustBe: "self"},
					},
				},
			},
		}},
	})

	// Build a log whose topic[1] is the user's "real" linked address
	// padded to 32 bytes (indexed-address encoding). Even though this
	// would match `must_be=self` in the production filter, dry-run
	// strips linked addresses before calling FilterEventLogs.
	userAddr := "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	log := mustLog(t, drrContractA, drrTopicX, userAddr)

	user := &rbac.User{ExternalID: "did:dr:r-user"}
	got := filterDryRunLogs([]json.RawMessage{log}, perms, user, "did:dr:r-user")
	assert.Empty(t, got,
		"current dry-run behaviour: must_be=self always fails because filterDryRunLogs "+
			"passes empty userAddresses to FilterEventLogs (admin_dry_run.go:408 TODO). "+
			"If this assertion starts failing, linked-address resolution was wired in — "+
			"audit and update.")
}

// TestFilterDryRunLogs_NilOrEmptyInputs covers the early-return
// branches: nil perms or empty logs must always yield nil. Cheap
// safety check that prevents nil-deref regressions in the wrapper.
func TestFilterDryRunLogs_NilOrEmptyInputs(t *testing.T) {
	t.Run("nil perms", func(t *testing.T) {
		got := filterDryRunLogs([]json.RawMessage{mustLog(t, drrContractA, drrTopicX)}, nil, nil, "did:any")
		assert.Nil(t, got)
	})
	t.Run("empty logs", func(t *testing.T) {
		got := filterDryRunLogs(nil, dryRunPermsWith(nil), nil, "did:any")
		assert.Nil(t, got)
	})
}

// --- integration test for forwardDryRunRead passthrough --------------

// TestDryRun_ReadResponse_Passthrough_NoRedaction pins the documented
// design contract for read methods at admin_dry_run.go:232-238: the
// raw upstream JSON-RPC response body is returned in `Response`
// **without** per-user redaction. If someone ever wires redaction
// into forwardDryRunRead, this test must change intentionally —
// which is the right signal because the redaction surface changed.
//
// The fixture's user has access to f.contractAddr via grant; we send
// `eth_call` and intercept the upstream payload via a stubbed proxy
// that returns a known result. The test asserts the bytes round-trip
// verbatim into resp.Response.
func TestDryRun_ReadResponse_Passthrough_NoRedaction(t *testing.T) {
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

	// Confirm no obvious redaction happened: the sentinel result must
	// be present verbatim in the wire form. A future redactor that
	// substituted the result with placeholders would trip this.
	assert.Contains(t, string(resp.Response), "0xdeadbeefcafef00d",
		"upstream result must be passed through verbatim per the documented "+
			"no-redaction design at admin_dry_run.go:232-238")
}

// Target-address extraction is exercised indirectly by the passthrough
// test (above) — eth_call's target address comes from params[0].to. It
// now comes from rbac.GetTargetAddress, so the per-method branches are
// covered by the existing access-controller tests.
var _ = context.Background // keep package context import usable for future extensions
