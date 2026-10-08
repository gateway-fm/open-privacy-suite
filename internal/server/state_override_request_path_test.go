package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1305 request-path coverage for simulation options, ordinary calls,
// node-request counts, and the shared access-log reason.

type canaryUpstream struct {
	srv    *httptest.Server
	hits   atomic.Int64
	result any
}

func newCanaryUpstream(t *testing.T) *canaryUpstream {
	t.Helper()
	c := &canaryUpstream{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		result := c.result
		if result == nil {
			result = "0x"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	t.Cleanup(c.srv.Close)
	return c
}

// setupProcessorWithCanary wires a processor that forwards to the canary with
// no RuntimeTracer, so the eth_call validation trace is skipped and a
// well-formed eth_call to a granted contract forwards (isolating the override
// gate as the only reason a call is blocked).
// The returned logger captures the access-log denial reason.
func setupProcessorWithCanary(t *testing.T, canary *canaryUpstream) (*JSONRPCProcessor, *testServerRBAC, *captureEnhancedLogger) {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		AccessLogger:       ts.db,
		Proxy:              proxy.New(canary.srv.URL),
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})
	cl := &captureEnhancedLogger{}
	proc.enhancedLogger = cl
	proc.hashChain = audit.NewHashChain("")
	return proc, ts, cl
}

// seedOverrideTestUser creates a KYC user in a group with the given method
// allowlist and a grant on a contract owned by the same org.
func seedOverrideTestUser(t *testing.T, ctx context.Context, ts *testServerRBAC, contractAddr string, methods []string) (did string) {
	t.Helper()
	orgID := uuid.New().String()
	groupID := uuid.New().String()
	userID := uuid.New().String()
	did = "did:privado:override-" + uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "ov-" + orgID[:8], Name: "Override Org"}))
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "ov-grp-"+groupID[:8], "Override Grp", "ov-grp-"+groupID[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID,
		Claims:         []rbac.Claim{},
		AllowedMethods: methods,
	}))
	contractID := uuid.New().String()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: contractID, OrgID: orgID, Address: strings.ToLower(contractAddr), Name: "ov-contract"}))
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: contractID, GroupID: groupID}))
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}))
	return did
}

// processRaw parses a raw JSON-RPC body exactly as the /rpc handler does, so
// valid Unicode-key payloads reach the processor with the canonical params
// and body used by the production request path.
func processRaw(t *testing.T, proc *JSONRPCProcessor, did, body string) *ProcessResult {
	t.Helper()
	method, params, canonicalBody, perr := ParseAndValidateBody([]byte(body))
	require.Nil(t, perr, "test body must parse")
	return proc.Process(context.Background(), &ProcessRequest{
		UserID: did, Method: method, Params: params, Body: canonicalBody, ClientIP: "203.0.113.5",
	})
}

func TestProcess_StateOverrideNeverReachesNode(t *testing.T) {
	canary := newCanaryUpstream(t)
	proc, ts, cl := setupProcessorWithCanary(t, canary)
	ctx := context.Background()

	contractAddr := "0x" + strings.Repeat("ab", 20)
	did := seedOverrideTestUser(t, ctx, ts, contractAddr, []string{"eth_call", "eth_estimateGas"})
	txObj := map[string]any{"to": contractAddr, "data": "0x"}
	codeOverride := map[string]any{contractAddr: map[string]any{"code": "0x00"}}

	denied := []struct {
		name   string
		method string
		params []any
	}{
		{"eth_call state override", "eth_call", []any{txObj, "latest", codeOverride}},
		// The option policy applies to every address in the supplied object.
		{"eth_call two-address override set", "eth_call", []any{txObj, "latest", map[string]any{
			contractAddr:                    map[string]any{"code": "0x" + strings.Repeat("60", 2)},
			"0x" + strings.Repeat("cd", 20): map[string]any{"code": "0x00"},
		}}},
		{"eth_call block override", "eth_call", []any{txObj, "latest", nil, map[string]any{"number": "0x1"}}},
		{"eth_call malformed override", "eth_call", []any{txObj, "latest", "0xdeadbeef"}},
		{"eth_call state options at block slot", "eth_call", []any{txObj, codeOverride}},
		{"eth_estimateGas state override", "eth_estimateGas", []any{txObj, "latest", codeOverride}},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			canary.hits.Store(0)
			cl.gotDenialReason = ""
			res := proc.Process(ctx, &ProcessRequest{
				UserID: did, Method: tc.method, Params: tc.params,
				Body:     mustJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": tc.method, "params": tc.params}),
				ClientIP: "203.0.113.5",
			})
			require.NotNil(t, res.Error, "%s must be denied", tc.name)
			assert.Equal(t, http.StatusNotFound, res.Error.StatusCode, "opaque 404 on the wire")
			assert.Equal(t, "method not found", res.Error.Message)
			assert.Equal(t, int64(0), canary.hits.Load(), "%s: a denied override must NOT reach the node", tc.name)
			assert.Equal(t, ReasonStateOverrideNotAllowed, cl.gotDenialReason, "%s: must be denied by the override gate", tc.name)
		})
	}

	t.Run("baseline: eth_call without override reaches the node", func(t *testing.T) {
		canary.hits.Store(0)
		res := proc.Process(ctx, &ProcessRequest{
			UserID: did, Method: "eth_call",
			Params:   []any{txObj, "latest"},
			Body:     mustJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []any{txObj, "latest"}}),
			ClientIP: "203.0.113.5",
		})
		require.Nil(t, res.Error, "plain eth_call should be allowed and forwarded")
		assert.Equal(t, int64(1), canary.hits.Load(), "plain eth_call must reach the node exactly once")
	})
}

// TestProcessDebugTrace_StateOverrideNeverReachesNode covers ordinary trace
// forwarding and unsupported options, including repeated and case-folded keys.
func TestProcessDebugTrace_StateOverrideNeverReachesNode(t *testing.T) {
	contractAddr := "0x" + strings.Repeat("ab", 20)
	scripted := newScriptedTracer(t, traceFrame{Type: "CALL", From: fixedAddr(0xee), To: contractAddr})
	canary := newCanaryUpstream(t)
	canary.result = map[string]any{"type": "CALL", "to": contractAddr}

	ts := setupTestServerForRBAC(t)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: scripted.srv.URL, Enabled: true, Timeout: 5 * time.Second})
	t.Cleanup(rt.Stop)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		AccessLogger:       ts.db,
		Proxy:              proxy.New(canary.srv.URL),
		RuntimeTracer:      rt,
		TraceValidator:     rbac.NewTraceValidator(ts.db),
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})
	cl := &captureEnhancedLogger{}
	proc.enhancedLogger = cl
	proc.hashChain = audit.NewHashChain("")

	ctx := context.Background()
	did := seedOverrideTestUser(t, ctx, ts, contractAddr, []string{"debug_traceCall"})

	call := `{"to":"` + contractAddr + `","data":"0x"}`
	override := `{"` + contractAddr + `":{"code":"0x00"}}`

	t.Run("baseline: debug_traceCall without override is traced and forwarded", func(t *testing.T) {
		scripted.hits.Store(0)
		canary.hits.Store(0)
		res := processRaw(t, proc, did, `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":[`+call+`,"latest",{"tracer":"callTracer"}]}`)
		require.Nil(t, res.Error, "plain debug_traceCall should be allowed")
		assert.Equal(t, int64(0), scripted.hits.Load(), "the forwarded result is validated without a separate internal trace")
		assert.Equal(t, int64(1), canary.hits.Load(), "plain debug_traceCall must reach the node exactly once")
	})

	denied := []struct {
		name, body    string
		parseRejected bool
	}{
		{"stateOverrides", `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":[` + call + `,"latest",{"tracer":"callTracer","stateOverrides":` + override + `}]}`, false},
		{"blockOverrides", `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":[` + call + `,"latest",{"blockOverrides":{"number":"0x1"}}]}`, false},
		// Repeated option keys follow the same presence rule.
		{"duplicate stateOverrides key", `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":[` + call + `,"latest",{"stateOverrides":` + override + `,"stateOverrides":{}}]}`, true},
		// Equivalent case-folded spellings follow the same presence rule.
		{"long-s stateOverrides key", `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":[` + call + `,"latest",{"ſtateOverrides":` + override + `}]}`, true},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			scripted.hits.Store(0)
			canary.hits.Store(0)
			cl.gotDenialReason = ""
			if tc.parseRejected {
				_, _, _, perr := ParseAndValidateBody([]byte(tc.body))
				require.NotNil(t, perr)
				assert.Equal(t, http.StatusBadRequest, perr.StatusCode)
				assert.Equal(t, int64(0), scripted.hits.Load())
				assert.Equal(t, int64(0), canary.hits.Load())
				assert.Empty(t, cl.gotDenialReason, "the request does not enter the processor")
				return
			}
			res := processRaw(t, proc, did, tc.body)
			require.NotNil(t, res.Error, "%s must be denied", tc.name)
			assert.Equal(t, http.StatusNotFound, res.Error.StatusCode, "opaque 404 on the wire")
			assert.Equal(t, int64(0), scripted.hits.Load(), "%s: no validation trace may run", tc.name)
			assert.Equal(t, int64(0), canary.hits.Load(), "%s: a denied override must NOT reach the node", tc.name)
			assert.Equal(t, ReasonStateOverrideNotAllowed, cl.gotDenialReason)
		})
	}
}
