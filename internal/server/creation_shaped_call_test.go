package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Request-path tests for creation-shaped eth_call / eth_estimateGas (a call
// object without `to`, which the node runs as contract-creation code).
//
// One canary upstream plays the node: it answers debug_traceCall with a
// scripted callTracer frame and counts every forwarded eth_call /
// eth_estimateGas. A refused request must leave the forward counter at zero.

const creationCode = "0x6080604052348015600f57600080fd5b50"

type creationCanary struct {
	srv          *httptest.Server
	mu           sync.Mutex
	frame        traceFrame
	traceErr     bool
	frameForCall func(map[string]any) traceFrame
	traced       []map[string]any // call objects received by debug_traceCall
	forwards     atomic.Int64
}

func newCreationCanary(t *testing.T) *creationCanary {
	t.Helper()
	c := &creationCanary{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "debug_traceCall" {
			c.mu.Lock()
			if len(req.Params) > 0 {
				if obj, ok := req.Params[0].(map[string]any); ok {
					c.traced = append(c.traced, obj)
				}
			}
			frame, fail := c.frame, c.traceErr
			if c.frameForCall != nil && len(req.Params) > 0 {
				if obj, ok := req.Params[0].(map[string]any); ok {
					frame = c.frameForCall(obj)
				}
			}
			c.mu.Unlock()
			if fail {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"the method debug_traceCall does not exist"}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(nodeReply{JSONRPC: "2.0", ID: 1, Result: frame})
			return
		}
		c.forwards.Add(1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x01"}`))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *creationCanary) setFrame(f traceFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frame = f
}

func (c *creationCanary) setFrameForCall(fn func(map[string]any) traceFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frameForCall = fn
}

func (c *creationCanary) tracedCalls() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.traced...)
}

type creationFixture struct {
	proc        *JSONRPCProcessor
	ts          *testServerRBAC
	canary      *creationCanary
	orgA        string
	callerDID   string // org A, eth_call/eth_estimateGas allowed, no claims
	deployerDID string // org A, same methods + deploy claim
	ownAddr     string // registered to org A
	foreignAddr string // registered to another org
	created     string // address the scripted creation frame reports
}

func seedCreationMember(t *testing.T, ctx context.Context, ts *testServerRBAC, orgID string, claims []rbac.Claim, methods []string) string {
	t.Helper()
	groupID := uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "g-"+groupID[:8], "G-"+groupID[:8], "g-"+groupID[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: claims, AllowedMethods: methods,
	}))
	userID := uuid.New().String()
	did := "did:test:creation-" + uuid.New().String()
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return did
}

func setupCreationFixture(t *testing.T) *creationFixture {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	canary := newCreationCanary(t)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: canary.srv.URL, Enabled: true, Timeout: 5 * time.Second})
	t.Cleanup(rt.Stop)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              proxy.New(canary.srv.URL),
		AccessLogger:       ts.db,
		RuntimeTracer:      rt,
		TraceValidator:     rbac.NewTraceValidator(ts.db),
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
		EthCallTracing:     &EthCallTracingConfig{Enabled: true, Timeout: 5 * time.Second},
	})

	ctx := context.Background()
	f := &creationFixture{proc: proc, ts: ts, canary: canary,
		ownAddr: fixedAddr(0xa1), foreignAddr: fixedAddr(0xb2), created: fixedAddr(0xc3)}
	f.orgA = registerForeignOrgContract(t, ctx, ts, f.ownAddr)
	registerForeignOrgContract(t, ctx, ts, f.foreignAddr)
	methods := []string{"eth_call", "eth_estimateGas", "eth_createAccessList", "linea_call"}
	f.callerDID = seedCreationMember(t, ctx, ts, f.orgA, []rbac.Claim{}, methods)
	f.deployerDID = seedCreationMember(t, ctx, ts, f.orgA, []rbac.Claim{rbac.ClaimDeploy}, methods)
	return f
}

// creationFrame is the callTracer shape of a creation call whose code makes
// the given internal calls.
func (f *creationFixture) creationFrame(calls ...traceFrame) traceFrame {
	return traceFrame{Type: "CREATE", From: fixedAddr(0x00), To: f.created, Calls: calls}
}

func (f *creationFixture) process(t *testing.T, did, method string, params []any) *ProcessResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	return f.proc.Process(context.Background(), &ProcessRequest{
		UserID: did, OrgID: f.orgA, Method: method, Params: params, Body: body,
	})
}

func creationParams(data string) []any {
	return []any{map[string]any{"data": data}, "latest"}
}

func TestCreationShapedCall_ExecutionInputsAffectTraceDecision(t *testing.T) {
	for _, field := range []string{"gas", "gasPrice", "nonce"} {
		t.Run(field, func(t *testing.T) {
			f := setupCreationFixture(t)
			f.canary.setFrameForCall(func(obj map[string]any) traceFrame {
				target := f.ownAddr
				if obj[field] == "0x40000" {
					target = f.foreignAddr
				}
				return f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: target})
			})
			obj := map[string]any{"data": creationCode, field: "0x40000"}
			res := f.process(t, f.deployerDID, "eth_call", []any{obj, "latest"})
			require.NotNil(t, res.Error, "the trace must see the input that selects the foreign contract")
			assert.Equal(t, ReasonCrossOrg, res.Error.Reason)
			assert.Zero(t, f.canary.forwards.Load())

			obj[field] = "0x80000"
			res = f.process(t, f.deployerDID, "eth_call", []any{obj, "latest"})
			require.Nil(t, res.Error, "the same-org branch must remain usable")
			assert.EqualValues(t, 1, f.canary.forwards.Load())
		})
	}
}

func TestCreationShapedCall_UnavailableTracerNeverForwards(t *testing.T) {
	for _, missing := range []string{"tracer", "validator", "disabled"} {
		t.Run(missing, func(t *testing.T) {
			f := setupCreationFixture(t)
			switch missing {
			case "tracer":
				f.proc.runtimeTracer = nil
			case "validator":
				f.proc.traceValidator = nil
			case "disabled":
				rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: f.canary.srv.URL})
				t.Cleanup(rt.Stop)
				f.proc.runtimeTracer = rt
			}
			for _, method := range []string{"eth_call", "eth_estimateGas", "eth_createAccessList"} {
				res := f.process(t, f.deployerDID, method, creationParams(creationCode))
				require.NotNil(t, res.Error, "creation must fail closed without tracing: %s", method)
				assert.Equal(t, ReasonTracingUnavailable, res.Error.Reason)
			}
			assert.Zero(t, f.canary.forwards.Load())
		})
	}
}

func TestCreationShapedCall_CallerWithoutDeployClaimNeverReachesNode(t *testing.T) {
	t.Cleanup(rbac.SnapshotMethodRegistriesForTest())
	rbac.MethodAliases["linea_call"] = "eth_call"
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))

	for _, method := range []string{"eth_call", "eth_estimateGas", "linea_call"} {
		for _, to := range []any{"<missing>", nil, "", "0x"} {
			obj := map[string]any{"data": creationCode}
			if to != "<missing>" {
				obj["to"] = to
			}
			res := f.process(t, f.callerDID, method, []any{obj, "latest"})
			require.NotNil(t, res.Error, "%s to=%#v must be refused", method, to)
			assert.Equal(t, http.StatusNotFound, res.Error.StatusCode, "RBAC denials are masked as method not found")
		}
	}
	assert.Zero(t, f.canary.forwards.Load(), "a refused creation-shaped call must never reach the node")
	assert.Empty(t, f.canary.tracedCalls(), "the RBAC refusal comes before any trace")
}

func TestCreationShapedCall_DeployHolderForeignReadDeniedByTrace(t *testing.T) {
	t.Cleanup(rbac.SnapshotMethodRegistriesForTest())
	rbac.MethodAliases["linea_call"] = "eth_call"
	f := setupCreationFixture(t)

	for _, kind := range []string{"STATICCALL", "CALL", "DELEGATECALL"} {
		f.canary.setFrame(f.creationFrame(traceFrame{Type: kind, From: f.created, To: f.foreignAddr}))
		for _, method := range []string{"eth_call", "eth_estimateGas", "linea_call"} {
			res := f.process(t, f.deployerDID, method, creationParams(creationCode))
			require.NotNil(t, res.Error, "%s %s into a foreign contract must be refused", method, kind)
			assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
			assert.Equal(t, ethCallDenyCrossOrg, res.Error.Message)
			assert.NotContains(t, res.Error.Message, strings.TrimPrefix(f.foreignAddr, "0x"))
		}
	}
	assert.Zero(t, f.canary.forwards.Load(), "a trace-denied creation call must never reach the node")

	// The trace replays the creation shape: no `to`, the creation code as data.
	traced := f.canary.tracedCalls()
	require.NotEmpty(t, traced)
	for _, obj := range traced {
		_, hasTo := obj["to"]
		assert.False(t, hasTo, "creation trace must not carry a `to`: %v", obj)
		assert.Equal(t, creationCode, obj["data"])
	}
}

func TestCreationShapedCall_UnregisteredInternalCallDenied(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: fixedAddr(0xd4)}))
	res := f.process(t, f.deployerDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error)
	assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
	assert.Zero(t, f.canary.forwards.Load())
}

func TestCreationShapedCall_DeployHolderSameOrgReadForwarded(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.ownAddr}))
	for i, method := range []string{"eth_call", "eth_estimateGas"} {
		res := f.process(t, f.deployerDID, method, creationParams(creationCode))
		require.Nil(t, res.Error, "%s: same-org creation read must be allowed", method)
		assert.Equal(t, int64(i+1), f.canary.forwards.Load())
	}
	assert.Len(t, f.canary.tracedCalls(), 2, "each allowed creation call is traced once")
}

func TestCreationShapedCall_PlainConstructorForwarded(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame())
	for _, to := range []any{"<missing>", nil, "", "0x"} {
		obj := map[string]any{"data": creationCode}
		if to != "<missing>" {
			obj["to"] = to
		}
		res := f.process(t, f.deployerDID, "eth_estimateGas", []any{obj})
		require.Nil(t, res.Error, "deployment gas estimate (to=%#v) must keep working", to)
	}
	assert.Equal(t, int64(4), f.canary.forwards.Load())
}

func TestCreationShapedCall_MalformedShapesNeverReachNode(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame())
	shapes := map[string][]any{
		"to number":   {map[string]any{"to": 7, "data": creationCode}},
		"to object":   {map[string]any{"to": map[string]any{"a": 1}, "data": creationCode}},
		"to array":    {map[string]any{"to": []any{"0x01"}, "data": creationCode}},
		"to bool":     {map[string]any{"to": true, "data": creationCode}},
		"string call": {"0xdeadbeef"},
		"null call":   {nil},
		"no bytecode": {map[string]any{"data": "0x"}},
		"no params":   {},
		// The node may run `input` (Anvil does); the traced code must be it.
		"data and input differ": {map[string]any{"data": "0x", "input": creationCode}},
		// Geth reads `To` as `to`; the proxy must not see a creation here.
		"to case variant": {map[string]any{"To": fixedAddr(0xb2), "data": creationCode}},
	}
	for _, method := range []string{"eth_call", "eth_estimateGas"} {
		for name, params := range shapes {
			res := f.process(t, f.deployerDID, method, params)
			require.NotNil(t, res.Error, "%s %s must be refused", method, name)
		}
	}
	assert.Zero(t, f.canary.forwards.Load(), "malformed call objects must never reach the node")
}

func TestCreationShapedCall_SpoofedFromRejected(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame())
	res := f.process(t, f.deployerDID, "eth_call",
		[]any{map[string]any{"from": fixedAddr(0xee), "data": creationCode}})
	require.NotNil(t, res.Error)
	assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
	assert.Zero(t, f.canary.forwards.Load())
}

func TestCreationShapedCall_TracerErrorFailsClosed(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.mu.Lock()
	f.canary.traceErr = true
	f.canary.mu.Unlock()
	res := f.process(t, f.deployerDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error)
	assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
	assert.Equal(t, ethCallDenyTracerError, res.Error.Message)
	assert.Zero(t, f.canary.forwards.Load())
}

func TestCreationShapedCall_AnonymousNeverReachesNode(t *testing.T) {
	f := setupCreationFixture(t)
	res := f.process(t, "", "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error)
	assert.Zero(t, f.canary.forwards.Load())
	assert.Empty(t, f.canary.tracedCalls())
}

// The eth_call tracing rollback knob covers targeted reads only. A call
// without `to` is a deployment, and deployments are traced whenever the
// runtime tracer is wired — the send-side deploy trace ignores the knob too.
func TestCreationShapedCall_TracedEvenWithEthCallKnobOff(t *testing.T) {
	f := setupCreationFixture(t)
	f.proc.SetEthCallTracing(false, 5*time.Second)

	res := f.process(t, f.callerDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error, "the deploy gate holds with the knob off")

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))
	res = f.process(t, f.deployerDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error, "a foreign read is refused with the knob off")
	assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
	assert.Zero(t, f.canary.forwards.Load())

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.ownAddr}))
	res = f.process(t, f.deployerDID, "eth_estimateGas", creationParams(creationCode))
	require.Nil(t, res.Error)
	assert.Equal(t, int64(1), f.canary.forwards.Load())
	assert.Len(t, f.canary.tracedCalls(), 2, "both creation calls were traced")
}

// eth_createAccessList without `to` runs creation code too, and its answer
// (touched addresses and slots) can carry what that code read.
func TestCreationShapedCall_CreateAccessListIsTreatedAlike(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))

	res := f.process(t, f.callerDID, "eth_createAccessList", creationParams(creationCode))
	require.NotNil(t, res.Error, "needs the deploy claim")
	assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)

	res = f.process(t, f.deployerDID, "eth_createAccessList", creationParams(creationCode))
	require.NotNil(t, res.Error, "a foreign read is refused by the trace")
	assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
	assert.Zero(t, f.canary.forwards.Load())

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.ownAddr}))
	res = f.process(t, f.deployerDID, "eth_createAccessList", creationParams(creationCode))
	require.Nil(t, res.Error)
	assert.Equal(t, int64(1), f.canary.forwards.Load())
}

// Shapes the node reads differently from the proxy are refused for a plain
// eth_call user even when the visible `to` is the caller's own contract.
func TestCreationShapedCall_AmbiguousCallObjectNeverReachesNode(t *testing.T) {
	f := setupCreationFixture(t)
	for name, obj := range map[string]map[string]any{
		"to plus null To":       {"to": f.ownAddr, "To": nil, "data": creationCode},
		"data and input differ": {"to": f.ownAddr, "data": "0x", "input": creationCode},
	} {
		res := f.process(t, f.callerDID, "eth_call", []any{obj, "latest"})
		require.NotNil(t, res.Error, name)
	}
	assert.Zero(t, f.canary.forwards.Load())
}

// The trace helper is also called directly (admin dry-run): a creation call
// without code is refused there too.
func TestCreationShapedCall_TraceHelperRefusesEmptyCreation(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame())
	for _, data := range []string{"0x", ""} {
		err := f.proc.validateEthCallWithTracing(context.Background(), &ProcessRequest{
			UserID: f.deployerDID, Method: "eth_call", Params: creationParams(data),
		}, "")
		require.NotNil(t, err, "data=%q", data)
		assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	}
	assert.Empty(t, f.canary.tracedCalls())
}

// /access/check and admin dry-run evaluate the same rule as /rpc.
func TestCreationShapedCall_AccessCheckAndDryRunParity(t *testing.T) {
	f := setupCreationFixture(t)
	ctx := context.Background()

	for _, tc := range []struct {
		did   string
		allow bool
	}{{f.callerDID, false}, {f.deployerDID, true}} {
		res, err := f.ts.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
			UserExternalID: tc.did, OrgID: f.orgA, Method: "eth_call",
			Params: creationParams(creationCode),
		})
		require.NoError(t, err)
		assert.Equal(t, tc.allow, res.Allowed, "access/check verdict for %s", tc.did)
	}

	// Dry-run as an org-A admin: the caller is refused by RBAC, the deploy
	// holder by the nested-call trace when the creation code reads a foreign
	// contract.
	adminGroup := drCreateGroup(t, f.ts.db, f.orgA, "creation-admins", nil, true)
	adminDID := "did:test:creation-admin"
	drCreateUserInGroup(t, f.ts.db, adminDID, adminGroup)
	dr := dryRunServerFor(f.ts)
	dr.jsonrpcProcessor = f.proc
	dr.proxy = proxy.New(f.canary.srv.URL)
	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))

	for _, did := range []string{f.callerDID, f.deployerDID} {
		w := dryRunPost(t, dr, f.orgA, "jwt_admin", adminDID, map[string]any{
			"user_did": did,
			"rpc":      apimodels.DryRunRPCBlock{Method: "eth_call", Params: creationParams(creationCode)},
		})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp dryRunResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "deny", resp.Decision, "dry-run as %s", did)
	}
	assert.Zero(t, f.canary.forwards.Load(), "a denied dry-run must not forward the call")
}

// Creation code that deploys a child and calls it (a constructor running
// `new Child()` then `child.init()`, or a deployless read) keeps working for a
// deploy holder; the child's own frames are still validated.
func TestCreationShapedCall_CreatedChildMayBeCalled(t *testing.T) {
	f := setupCreationFixture(t)
	child := fixedAddr(0xc4)
	f.canary.setFrame(f.creationFrame(
		traceFrame{Type: "CREATE", From: f.created, To: child},
		traceFrame{Type: "CALL", From: f.created, To: child,
			Calls: []traceFrame{{Type: "STATICCALL", From: child, To: f.ownAddr}}},
	))
	res := f.process(t, f.deployerDID, "eth_estimateGas", creationParams(creationCode))
	require.Nil(t, res.Error, "a created child is the caller's own code")
	assert.Equal(t, int64(1), f.canary.forwards.Load())

	f.canary.setFrame(f.creationFrame(
		traceFrame{Type: "CREATE", From: f.created, To: child},
		traceFrame{Type: "CALL", From: f.created, To: child,
			Calls: []traceFrame{{Type: "STATICCALL", From: child, To: f.foreignAddr}}},
	))
	res = f.process(t, f.deployerDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error, "the child's foreign read is still refused")
	assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)

	f.canary.setFrame(f.creationFrame(
		traceFrame{Type: "CREATE", From: f.created, To: child, Error: "contract address collision"},
		traceFrame{Type: "CALL", From: f.created, To: child},
	))
	res = f.process(t, f.deployerDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error, "a failed CREATE's address may hold existing code")
	assert.Equal(t, int64(1), f.canary.forwards.Load())
}

// The admin test-request and access-check endpoints resolve operator aliases
// like /rpc does, so an alias of eth_call without `to` is a deployment there
// too.
func TestCreationShapedCall_AdminProbesResolveAliases(t *testing.T) {
	t.Cleanup(rbac.SnapshotMethodRegistriesForTest())
	rbac.MethodAliases["linea_call"] = "eth_call"
	f := setupCreationFixture(t)
	f.ts.proxy = proxy.New(f.canary.srv.URL)
	f.canary.setFrame(f.creationFrame())

	token, err := f.ts.jwtService.IssueAccessToken(f.callerDID, true)
	require.NoError(t, err)
	router := gin.New()
	router.POST("/test-request", f.ts.handleTestRequest)
	for _, method := range []string{"eth_call", "linea_call"} {
		body, err := json.Marshal(apimodels.TestRequestInput{
			Method: method, Params: creationParams(creationCode), JWTToken: token, OrgID: f.orgA,
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/test-request", bytes.NewReader(body)))
		assert.Equal(t, http.StatusForbidden, w.Code, "test-request %s: %s", method, w.Body.String())
	}
	assert.Zero(t, f.canary.forwards.Load(), "a refused test-request must not reach the node")

	// Mixed case is canonicalized as on /rpc: the deploy holder is allowed.
	body, err := json.Marshal(map[string]any{
		"user_external_id": f.deployerDID, "org_id": f.orgA, "method": "ETH_CALL",
		"params": creationParams(creationCode),
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	f.ts.router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/access/check", bytes.NewReader(body)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var canon rbac.AccessCheckResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &canon))
	assert.True(t, canon.Allowed, "access/check ETH_CALL for a deploy holder: %s", canon.Reason)

	for _, method := range []string{"eth_call", "ETH_CALL", "linea_call"} {
		body, err := json.Marshal(map[string]any{
			"user_external_id": f.callerDID, "org_id": f.orgA, "method": method,
			"params": creationParams(creationCode),
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		f.ts.router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/access/check", bytes.NewReader(body)))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var res rbac.AccessCheckResult
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		assert.False(t, res.Allowed, "access/check %s", method)
	}
}

// An org-admin group carries no stored claims: its members get every claim
// from the resolver. Their deployment pre-flights must pass the trace's
// creation rule just as they pass CheckAccess.
func TestCreationShapedCall_OrgAdminDeploymentEstimate(t *testing.T) {
	f := setupCreationFixture(t)
	ctx := context.Background()
	groupID := uuid.New().String()
	require.NoError(t, f.ts.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "admins-" + groupID[:8], Name: "admins-" + groupID[:8], Path: "admins-" + groupID[:8], IsOrgAdmin: true,
	}))
	require.NoError(t, f.ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{},
		AllowedMethods: []string{"eth_call", "eth_estimateGas"},
	}))
	adminDID := "did:test:creation-orgadmin-" + uuid.New().String()
	drCreateUserInGroup(t, f.ts.db, adminDID, groupID)

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.ownAddr}))
	res := f.process(t, adminDID, "eth_estimateGas", creationParams(creationCode))
	require.Nil(t, res.Error, "an org admin's deployment estimate must be allowed")
	assert.Equal(t, int64(1), f.canary.forwards.Load())

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))
	res = f.process(t, adminDID, "eth_call", creationParams(creationCode))
	require.NotNil(t, res.Error, "an org admin's foreign read is still refused")
	assert.Equal(t, ethCallDenyCrossOrg, res.Error.Message)
}

// A trace that contains contract creation by a caller without the deploy
// claim records the precise reason for the access log, while the client sees
// the uniform cross-org message: whether some internal code path created a
// contract must not be observable.
func TestCreationShapedCall_DeployClaimDenialReason(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(traceFrame{Type: "CALL", From: fixedAddr(0x00), To: f.ownAddr,
		Calls: []traceFrame{{Type: "CREATE", From: f.ownAddr, To: fixedAddr(0xc5)}}})
	err := f.proc.validateEthCallWithTracing(context.Background(), &ProcessRequest{
		UserID: f.callerDID, Method: "eth_call",
		Params: []any{map[string]any{"to": f.ownAddr, "data": "0x01"}, "latest"},
	}, f.ownAddr)
	require.NotNil(t, err)
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, ethCallDenyCrossOrg, err.Message)
	assert.Equal(t, ReasonDeployClaimRequired, err.Reason)
}

// An expired membership grants nothing in the trace either: an org-admin
// membership that has expired does not make its holder a deploy holder.
func TestCreationShapedCall_ExpiredOrgAdminMembershipGrantsNoDeploy(t *testing.T) {
	f := setupCreationFixture(t)
	ctx := context.Background()
	user, err := f.ts.db.GetUserByExternalID(ctx, f.callerDID)
	require.NoError(t, err)
	otherOrg := registerForeignOrgContract(t, ctx, f.ts, fixedAddr(0xd7))
	groupID := uuid.New().String()
	require.NoError(t, f.ts.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: otherOrg, Slug: "admins-" + groupID[:8], Name: "admins-" + groupID[:8], Path: "admins-" + groupID[:8], IsOrgAdmin: true,
	}))
	require.NoError(t, f.ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{}, AllowedMethods: []string{"eth_call"},
	}))
	expired := time.Now().Add(-time.Hour)
	require.NoError(t, f.ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: user.ID, GroupID: groupID, Source: rbac.MembershipSourceAdmin, ExpiresAt: &expired,
	}))

	f.canary.setFrame(traceFrame{Type: "CALL", From: fixedAddr(0x00), To: f.ownAddr,
		Calls: []traceFrame{{Type: "CREATE", From: f.ownAddr, To: fixedAddr(0xc6)}}})
	terr := f.proc.validateEthCallWithTracing(ctx, &ProcessRequest{
		UserID: f.callerDID, Method: "eth_call",
		Params: []any{map[string]any{"to": f.ownAddr, "data": "0x01"}, "latest"},
	}, f.ownAddr)
	require.NotNil(t, terr, "runtime creation needs a live deploy grant")
	assert.Equal(t, ReasonDeployClaimRequired, terr.Reason)
}

// The admin test-request endpoint forwards to the node, so it runs the same
// nested-call trace as /rpc after CheckAccess.
func TestCreationShapedCall_TestRequestIsTraced(t *testing.T) {
	f := setupCreationFixture(t)
	f.ts.proxy = proxy.New(f.canary.srv.URL)
	f.ts.jsonrpcProcessor = f.proc
	token, err := f.ts.jwtService.IssueAccessToken(f.deployerDID, true)
	require.NoError(t, err)
	router := gin.New()
	router.POST("/test-request", f.ts.handleTestRequest)
	send := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(apimodels.TestRequestInput{
			Method: "eth_call", Params: creationParams(creationCode), JWTToken: token, OrgID: f.orgA,
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/test-request", bytes.NewReader(body)))
		return w
	}

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))
	w := send()
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), strings.TrimPrefix(f.foreignAddr, "0x"))
	assert.Zero(t, f.canary.forwards.Load())

	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.ownAddr}))
	w = send()
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, int64(1), f.canary.forwards.Load())
}

// seedOtherOrgMembership puts user into a fresh group of a new org, with the
// given claims / org-admin flag and an optional expiry. Returns the org ID.
func seedOtherOrgMembership(t *testing.T, ts *testServerRBAC, userDID string, claims []rbac.Claim, orgAdmin bool, expiresAt *time.Time, contract string) string {
	t.Helper()
	ctx := context.Background()
	user, err := ts.db.GetUserByExternalID(ctx, userDID)
	require.NoError(t, err)
	orgID := registerForeignOrgContract(t, ctx, ts, contract)
	groupID := uuid.New().String()
	require.NoError(t, ts.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: orgID, Slug: "g-" + groupID[:8], Name: "g-" + groupID[:8], Path: "g-" + groupID[:8], IsOrgAdmin: orgAdmin,
	}))
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: claims, AllowedMethods: []string{"eth_call"},
	}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: user.ID, GroupID: groupID, Source: rbac.MembershipSourceAdmin, ExpiresAt: expiresAt,
	}))
	return orgID
}

// targetedCreateTrace is a targeted read of the caller's own contract whose
// trace runs a contract creation.
func (f *creationFixture) targetedCreateTrace(t *testing.T, did, resolvedOrg string) *ProcessError {
	t.Helper()
	f.canary.setFrame(traceFrame{Type: "CALL", From: fixedAddr(0x00), To: f.ownAddr,
		Calls: []traceFrame{{Type: "CREATE", From: f.ownAddr, To: fixedAddr(0xc8)}}})
	req := &ProcessRequest{
		UserID: did, Method: "eth_call",
		Params: []any{map[string]any{"to": f.ownAddr, "data": "0x01"}, "latest"},
	}
	req.resolvedOrgID = resolvedOrg
	return f.proc.validateEthCallWithTracing(context.Background(), req, f.ownAddr)
}

// The trace's creation rule uses the deploy claim of the org the request was
// authorised in, like CheckAccess: an org-admin (or deploy) membership in
// another org does not count.
func TestCreationShapedCall_DeployClaimIsDecidedInTheResolvedOrg(t *testing.T) {
	f := setupCreationFixture(t)
	seedOtherOrgMembership(t, f.ts, f.callerDID, []rbac.Claim{}, true, nil, fixedAddr(0xe1))
	seedOtherOrgMembership(t, f.ts, f.callerDID, []rbac.Claim{rbac.ClaimDeploy}, false, nil, fixedAddr(0xe2))

	err := f.targetedCreateTrace(t, f.callerDID, f.orgA)
	require.NotNil(t, err, "no deploy claim in the resolved org")
	assert.Equal(t, ReasonDeployClaimRequired, err.Reason)

	require.Nil(t, f.targetedCreateTrace(t, f.deployerDID, f.orgA), "deploy claim in the resolved org")
}

// An expired membership grants nothing in the trace: not the deploy claim,
// and not membership of its org for the cross-org rule.
func TestCreationShapedCall_ExpiredMembershipsGrantNothingInTheTrace(t *testing.T) {
	f := setupCreationFixture(t)
	expired := time.Now().Add(-time.Hour)
	otherContract := fixedAddr(0xe3)
	seedOtherOrgMembership(t, f.ts, f.callerDID, []rbac.Claim{rbac.ClaimDeploy}, false, &expired, otherContract)

	err := f.targetedCreateTrace(t, f.callerDID, "")
	require.NotNil(t, err, "an expired deploy membership must not count")
	assert.Equal(t, ReasonDeployClaimRequired, err.Reason)

	f.canary.setFrame(traceFrame{Type: "CALL", From: fixedAddr(0x00), To: f.ownAddr,
		Calls: []traceFrame{{Type: "STATICCALL", From: f.ownAddr, To: otherContract}}})
	req := &ProcessRequest{UserID: f.callerDID, Method: "eth_call",
		Params: []any{map[string]any{"to": f.ownAddr, "data": "0x01"}, "latest"}}
	req.resolvedOrgID = f.orgA
	err = f.proc.validateEthCallWithTracing(context.Background(), req, f.ownAddr)
	require.NotNil(t, err, "the expired membership's org is foreign to the caller")
	assert.Equal(t, ReasonCrossOrg, err.Reason)
}

// "No params" is only how the proxy parsed the body; the node receives the
// original bytes. A request the proxy reads as having no call object is
// refused, so a body that another JSON parser reads differently (repeated or
// case-variant keys) never reaches the node.
func TestCreationShapedCall_NoCallObjectNeverReachesNode(t *testing.T) {
	f := setupCreationFixture(t)
	f.canary.setFrame(f.creationFrame(traceFrame{Type: "STATICCALL", From: f.created, To: f.foreignAddr}))
	bodies := []string{
		`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[]}`,
		`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"` + creationCode + `"},"latest"],"Params":[]}`,
		`{"jsonrpc":"2.0","id":1,"method":"eth_estimateGas","params":[{"data":"` + creationCode + `"}],"params":[]}`,
	}
	for _, body := range bodies {
		method, params, perr := ParseAndValidateBody([]byte(body))
		require.Nil(t, perr, body)
		require.Equal(t, rbac.CallShapeAbsent, rbac.ClassifyCallShape(params), "the proxy reads no call object: %s", body)
		res := f.proc.Process(context.Background(), &ProcessRequest{
			UserID: f.callerDID, OrgID: f.orgA, Method: method, Params: params, Body: []byte(body),
		})
		require.NotNil(t, res.Error, body)
		assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode, body)
	}
	assert.Zero(t, f.canary.forwards.Load())
	assert.Empty(t, f.canary.tracedCalls())
}
