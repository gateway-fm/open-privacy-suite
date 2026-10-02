package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTraceRootParticipant(t *testing.T) {
	const me = "0xa11ce00000000000000000000000000000000001"
	const other = "0xb0b0000000000000000000000000000000000002"
	const contract = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	root := func(typ, from, to string) *tracer.TraceResult {
		return &tracer.TraceResult{CallTargets: []tracer.CallTarget{
			{Type: typ, From: from, To: to, Depth: 0},
			{Type: "CALL", From: contract, To: me, Depth: 1}, // internal call to me: not participation
		}}
	}
	cases := []struct {
		name string
		tr   *tracer.TraceResult
		want bool
	}{
		{"sender", root("CALL", me, contract), true},
		{"recipient (EOA transfer)", root("CALL", other, me), true},
		{"internal-call recipient only", root("CALL", other, contract), false},
		{"deployer", root("CREATE", me, contract), true},
		{"created contract is not a participant", root("CREATE", other, me), false},
		{"no root frame", &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", From: me, To: contract, Depth: 1}}}, false},
		{"nil trace", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, traceRootParticipant(tc.tr, []string{me}))
		})
	}
}

// Under strict, debug_traceTransaction of a mined tx returns the trace only to
// a participant of that tx; another member of the same org gets an opaque 404.
// Under standard both receive it (the cross-org trace check still applies).
func TestReadProfile_Strict_DebugTraceTransactionParticipantOnly(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	orgID := uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "trc-" + orgID[:8], Name: "TRC", Settings: map[string]any{}}))
	gid := uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, gid, orgID, "trc-"+gid[:8], "TRC", "trc-"+gid[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"debug_traceTransaction"}}))
	const sender = "0xa11ce00000000000000000000000000000000001"
	const contract = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001"
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: uuid.New().String(), OrgID: orgID, Address: contract, Name: "TRC", Metadata: map[string]any{}}))
	member := func(did, addr string) {
		uid := uuid.New().String()
		require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: uid, ExternalID: did, KYC: true, Metadata: map[string]any{}}))
		require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: uid, GroupID: gid, Source: rbac.MembershipSourceAdmin}))
		require.NoError(t, ts.db.SystemLinkEthAddress(ctx, did, addr))
	}
	member("did:test:trc:sender", sender)
	member("did:test:trc:colleague", "0xb0b0000000000000000000000000000000000002")

	trace := map[string]any{"type": "CALL", "from": sender, "to": contract, "input": "0xa9059cbb", "value": "0x0", "calls": []any{}}
	const unknownHash = "0xdead"
	var mu sync.Mutex
	var nodeBodies [][]byte
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		nodeBodies = append(nodeBodies, b)
		mu.Unlock()
		if strings.Contains(string(b), unknownHash) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32000, "message": "transaction " + unknownHash + " not found"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": trace})
	}))
	resetNode := func() { mu.Lock(); nodeBodies = nil; mu.Unlock() }
	lastNodeBody := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		if len(nodeBodies) == 0 {
			return nil
		}
		return nodeBodies[len(nodeBodies)-1]
	}
	t.Cleanup(node.Close)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: node.URL, Enabled: true})
	t.Cleanup(rt.Stop)

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
			ReadProfile:        profile,
			RBACAccessCtrl:     ts.rbacAccessCtrl,
			RateLimiter:        &noopRateLimiter{},
			Proxy:              proxy.New(node.URL),
			AccessLogger:       ts.db,
			CircuitBreaker:     middleware.NewCircuitBreaker(),
			ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
			RuntimeTracer:      rt,
			TraceValidator:     rbac.NewTraceValidator(ts.db),
		})
		for _, did := range []string{"did:test:trc:sender", "did:test:trc:colleague"} {
			t.Run(profile.String()+"/"+did, func(t *testing.T) {
				res := p.processDebugTrace(ctx, &ProcessRequest{UserID: did, Method: "debug_traceTransaction", Params: []any{"0x" + "ab"}})
				if did == "did:test:trc:colleague" && profile.Strict() {
					require.NotNil(t, res.Error)
					assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)
					assert.NotContains(t, string(res.ResponseBody), sender[2:])
					return
				}
				require.Nil(t, res.Error, "%+v", res.Error)
				assert.Contains(t, string(res.ResponseBody), sender[2:])
			})
		}

		// Under strict the node is asked for the top-level call frame only,
		// without logs, whatever the participant sent; under standard the
		// caller's request is forwarded as sent.
		t.Run(profile.String()+"/forwarded tracer config", func(t *testing.T) {
			resetNode()
			body := []byte(`{"jsonrpc":"2.0","id":7,"method":"debug_traceTransaction","params":["0xab",{"tracer":"callTracer"}]}`)
			res := p.processDebugTrace(ctx, &ProcessRequest{UserID: "did:test:trc:sender", Method: "debug_traceTransaction",
				Params: []any{"0xab", map[string]any{"tracer": "callTracer"}}, Body: body})
			require.Nil(t, res.Error, "%+v", res.Error)
			var fwd struct {
				ID     json.RawMessage `json:"id"`
				Params []any           `json:"params"`
			}
			require.NoError(t, json.Unmarshal(lastNodeBody(), &fwd))
			if !profile.Strict() {
				assert.JSONEq(t, string(body), string(lastNodeBody()))
				return
			}
			assert.Equal(t, "7", string(fwd.ID), "the caller's id is kept")
			require.Len(t, fwd.Params, 2)
			assert.Equal(t, "0xab", fwd.Params[0])
			assert.Equal(t, map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"onlyTopCall": true, "withLog": false}}, fwd.Params[1])
		})

		// Under strict any other tracer is refused before the node is traced.
		t.Run(profile.String()+"/other tracer", func(t *testing.T) {
			resetNode()
			res := p.processDebugTrace(ctx, &ProcessRequest{UserID: "did:test:trc:sender", Method: "debug_traceTransaction",
				Params: []any{"0xab", map[string]any{"tracer": "prestateTracer"}}})
			if !profile.Strict() {
				require.Nil(t, res.Error, "%+v", res.Error)
				return
			}
			require.NotNil(t, res.Error)
			assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
			assert.Equal(t, strictTraceUnsupportedConfig, res.Error.Message)
			assert.Nil(t, lastNodeBody(), "nothing is traced or forwarded")
		})

		// Under strict an unknown hash answers exactly like a non-participant:
		// the response does not tell existing transactions from missing ones.
		t.Run(profile.String()+"/unknown hash", func(t *testing.T) {
			res := p.processDebugTrace(ctx, &ProcessRequest{UserID: "did:test:trc:colleague", Method: "debug_traceTransaction", Params: []any{unknownHash}})
			require.NotNil(t, res.Error)
			if !profile.Strict() {
				assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
				return
			}
			assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)
			assert.Equal(t, "transaction not found", res.Error.Message)
		})
	}
}

func TestStrictCallTracerOptions(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		want bool
	}{
		{"call tracer", map[string]any{"tracer": "callTracer"}, true},
		{"call tracer, top call only", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"onlyTopCall": true}}, true},
		{"call tracer, logs off", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": false}}, true},
		{"call tracer, null config", map[string]any{"tracer": "callTracer", "tracerConfig": nil}, true},
		{"empty options (opcode logger)", map[string]any{}, false},
		{"prestate tracer", map[string]any{"tracer": "prestateTracer"}, false},
		{"JS tracer", map[string]any{"tracer": "{result: function() { return 1 }}"}, false},
		{"call tracer with logs", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": true}}, false},
		{"call tracer, all frames", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"onlyTopCall": false}}, false},
		{"call tracer, unknown setting", map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"diffMode": true}}, false},
		{"call tracer, non-object config", map[string]any{"tracer": "callTracer", "tracerConfig": "x"}, false},
		{"call tracer, timeout", map[string]any{"tracer": "callTracer", "timeout": "60s"}, false},
		{"config without tracer", map[string]any{"tracerConfig": map[string]any{"withLog": false}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, strictCallTracerOptions(tc.opts))
		})
	}
}
