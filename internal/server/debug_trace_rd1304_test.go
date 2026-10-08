package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1304 request-path coverage for trace configuration, access checks,
// upstream request construction, output shape and organization scope.

const storageMarker = "0x00000000000000000000000000000000000000000000000000000000005ec2e7"

type canaryReq struct {
	Method string
	Tracer string // "" when the request carried no tracer name
}

type traceCanary struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []canaryReq
	txFrom string // eth_getTransactionByHash from ("" → null result)
	txTo   string
	txIn   string       // eth_getTransactionByHash input (calldata)
	topTo  string       // callTracer top-frame `to`
	calls  []traceFrame // nested callTracer frames
	// callTracerBody, when non-nil, is returned verbatim as the `result` of
	// a callTracer request — models a node that answers callTracer with a
	// different / malformed body.
	callTracerBody any
	traceStatus    int
	// lastCallBlock is params[1] of the last debug_traceCall the node saw.
	lastCallBlock any
	// lastCallObject is params[0] of the last debug_traceCall the node saw.
	lastCallObject any
}

type traceContractLookupStore struct {
	rbac.Store
	failAddress string
}

func (s *traceContractLookupStore) GetContractByAddress(ctx context.Context, orgID, address string) (*rbac.Contract, error) {
	if strings.EqualFold(address, s.failAddress) {
		return nil, errors.New("contract lookup unavailable")
	}
	return s.Store.GetContractByAddress(ctx, orgID, address)
}

func newTraceCanary(t *testing.T) *traceCanary {
	t.Helper()
	c := &traceCanary{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
			ID     any    `json:"id"`
		}
		_ = json.Unmarshal(body, &env)
		tr := ""
		if n := len(env.Params); n > 0 {
			if m, ok := env.Params[n-1].(map[string]any); ok {
				if s, ok := m["tracer"].(string); ok {
					tr = s
				}
			}
		}
		c.mu.Lock()
		c.reqs = append(c.reqs, canaryReq{Method: env.Method, Tracer: tr})
		if env.Method == "debug_traceCall" && len(env.Params) > 1 {
			c.lastCallObject = env.Params[0]
			c.lastCallBlock = env.Params[1]
		}
		txFrom, txTo, txIn, topTo, calls, override, traceStatus := c.txFrom, c.txTo, c.txIn, c.topTo, c.calls, c.callTracerBody, c.traceStatus
		c.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(env.Method, "debug_trace") && traceStatus != 0 {
			w.WriteHeader(traceStatus)
		}
		reply := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": env.ID, "result": result})
		}
		switch {
		case env.Method == "eth_getTransactionByHash":
			if txFrom == "" {
				reply(nil)
				return
			}
			reply(map[string]any{"from": txFrom, "to": txTo, "input": txIn, "hash": "0x" + strings.Repeat("ab", 32)})
		case strings.HasPrefix(env.Method, "debug_trace"):
			switch tr {
			case "prestateTracer":
				reply(map[string]any{topTo: map[string]any{"balance": "0x0", "storage": map[string]any{
					"0x0000000000000000000000000000000000000000000000000000000000000001": storageMarker,
				}}})
			case "callTracer":
				if override != nil {
					reply(override)
					return
				}
				reply(traceFrame{Type: "CALL", From: txFrom, To: topTo, Calls: calls})
			default: // absent tracer = default struct logger, or a JS / unknown tracer
				reply(map[string]any{"structLogs": []any{map[string]any{"op": "SLOAD", "storage": map[string]any{"01": storageMarker}}}})
			}
		default:
			reply(nil)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *traceCanary) snapshot() []canaryReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]canaryReq(nil), c.reqs...)
}

// callerTracerReachedNode reports whether any debug_trace* request carrying a
// tracer other than callTracer reached the node — i.e. the caller's own
// (storage- or state-revealing) tracer was forwarded.
func (c *traceCanary) callerTracerReachedNode() bool {
	for _, r := range c.snapshot() {
		if strings.HasPrefix(r.Method, "debug_trace") && r.Tracer != "callTracer" {
			return true
		}
	}
	return false
}

func (c *traceCanary) traceRequests() int {
	n := 0
	for _, r := range c.snapshot() {
		if strings.HasPrefix(r.Method, "debug_trace") {
			n++
		}
	}
	return n
}

// setupTraceProcessor wires a processor whose runtime tracer AND forwarding
// proxy both point at the canary (as in production, where both hit one node).
func setupTraceProcessor(t *testing.T, c *traceCanary) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	return newTraceProcessor(t, ts, c), ts
}

// newTraceProcessor wires a trace-enabled processor onto an existing test
// server's database and access controller.
func newTraceProcessor(t *testing.T, ts *testServerRBAC, c *traceCanary) *JSONRPCProcessor {
	t.Helper()
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: c.srv.URL, Enabled: true, Timeout: 5 * time.Second})
	t.Cleanup(rt.Stop)
	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              proxy.New(c.srv.URL),
		AccessLogger:       ts.db,
		RuntimeTracer:      rt,
		TraceValidator:     rbac.NewTraceValidator(ts.db),
		TxVisibilityStore:  ts.db,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
		EthCallTracing:     &EthCallTracingConfig{Enabled: true, Timeout: 5 * time.Second},
	})
	return proc
}

type traceUser struct {
	did     string
	userID  string
	orgID   string
	groupID string
}

// newTraceUser creates an org (or reuses orgID when non-empty), a group with
// the given claims + allowlist, a KYC'd user, and the membership. linked is an
// optional ETH address linked to the user's DID.
func newTraceUser(t *testing.T, ctx context.Context, ts *testServerRBAC, orgID string, claims []rbac.Claim, methods []string, linked string) traceUser {
	t.Helper()
	if orgID == "" {
		orgID = uuid.New().String()
		require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "tr-" + orgID[:8], Name: "Trace Org"}))
	}
	groupID := uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "tg-"+groupID[:8], "Trace Grp", "tg-"+groupID[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: claims, AllowedMethods: methods,
	}))
	userID := uuid.New().String()
	did := "did:privado:tr-" + uuid.New().String()
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	if linked != "" {
		require.NoError(t, ts.db.SystemLinkEthAddress(ctx, did, linked))
	}
	return traceUser{did: did, userID: userID, orgID: orgID, groupID: groupID}
}

// addContract registers addr to orgID and, when grantGroup is non-empty,
// grants that group access to it. Returns the contract ID.
func addContract(t *testing.T, ctx context.Context, ts *testServerRBAC, orgID, addr, grantGroup string) {
	t.Helper()
	cid := uuid.New().String()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: cid, OrgID: orgID, Address: strings.ToLower(addr), Name: "C-" + addr[2:6]}))
	if grantGroup != "" {
		require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: cid, GroupID: grantGroup}))
	}
}

func traceReq(did, orgID, method string, params ...any) *ProcessRequest {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	return &ProcessRequest{UserID: did, OrgID: orgID, Method: method, Params: params, Body: body}
}

var traceMethods = []string{"debug_traceCall", "debug_traceTransaction", "eth_call"}

// denied reports whether the result is a denial (non-2xx or JSON-RPC-level null).
func denied(res *ProcessResult) bool { return res.Error != nil }

// ---------------------------------------------------------------------------
// Unsupported tracer requests are refused before forwarding.

// A contract grant does not enable unsupported tracer formats.
func TestRD1304_TraceCall_PrestateTracerDeniedAndNotForwarded(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc1)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr, "data": "0x6d4ce63c"}, "latest", map[string]any{"tracer": "prestateTracer"}))

	require.True(t, denied(res), "prestateTracer must be denied for a non-admin; body=%s", string(res.ResponseBody))
	assert.False(t, c.callerTracerReachedNode(), "the caller's prestateTracer must never be forwarded to the node")
	assert.NotContains(t, string(res.ResponseBody), storageMarker)
}

// Struct-logger configuration is not part of the client trace format.
func TestRD1304_TraceTransaction_DefaultStructLoggerNotForwarded(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc2)
	me := fixedAddr(0x11)
	c.txFrom, c.txTo, c.topTo = me, addr, addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // participant (sender)
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction",
		"0x"+strings.Repeat("ab", 32), map[string]any{"enableMemory": true}))

	require.True(t, denied(res), "struct-logger request must be denied; body=%s", string(res.ResponseBody))
	assert.False(t, c.callerTracerReachedNode(), "a struct-logger request must never reach the node")
	assert.NotContains(t, string(res.ResponseBody), storageMarker)
}

// JavaScript tracers are unsupported, including for a target's admin.
func TestRD1304_TraceCall_JSTracerDeniedEvenForAdmin(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc3)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", []rbac.Claim{rbac.ClaimAdmin}, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	js := "{result: function(ctx, db) { return 1; }, fault: function(){}, step: function(){}}"
	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": js}))

	require.True(t, denied(res), "a JS tracer must be denied even for a contract admin")
	assert.False(t, c.callerTracerReachedNode(), "the JS tracer must never reach the node")
}

// Unknown tracer names and malformed configs fail closed.
func TestRD1304_TraceCall_UnknownAndMalformedConfigsFailClosed(t *testing.T) {
	cases := map[string]any{
		"unknown tracer":         map[string]any{"tracer": "bogusTracer"},
		"4byteTracer":            map[string]any{"tracer": "4byteTracer"},
		"muxTracer":              map[string]any{"tracer": "muxTracer", "tracerConfig": map[string]any{"prestateTracer": map[string]any{}}},
		"withLog":                map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": true}},
		"withLog non-boolean":    map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"withLog": "true"}},
		"stateOverrides":         map[string]any{"tracer": "callTracer", "stateOverrides": map[string]any{}},
		"blockOverrides":         map[string]any{"tracer": "callTracer", "blockOverrides": map[string]any{}},
		"config not an object":   "callTracer",
		"tracerConfig non-obj":   map[string]any{"tracer": "callTracer", "tracerConfig": "x"},
		"tracer name non-string": map[string]any{"tracer": 42},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			addr := fixedAddr(0xc4)
			c.topTo = addr
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest", cfg))
			require.True(t, denied(res), "%s must fail closed", name)
			assert.Equal(t, 0, c.traceRequests(), "%s: nothing may reach the node", name)
		})
	}
}

// ---------------------------------------------------------------------------
// debug_traceCall runs the eth_call access checks.
// ---------------------------------------------------------------------------

// Same-org contract the caller has no grant on: eth_call is denied, so the
// trace twin must be too.
func TestRD1304_TraceCall_UngrantedSameOrgTargetDenied(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc5)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, "") // same org, NO grant

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "trace of an ungranted same-org contract must be denied")
	assert.Equal(t, 0, c.traceRequests(), "denied trace must not reach the node")
}

// Historical block: denied for a non-admin and served for an org admin,
// exactly like eth_call.
func TestRD1304_TraceCall_HistoricalBlockAdminOnly(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc6)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	// Control: the same non-admin may trace this call at the latest block, so
	// the denial below comes from the historical-block rule.
	latest := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": "callTracer"}))
	require.Nil(t, latest.Error, "control: the latest-block trace is allowed: %+v", latest.Error)
	require.Equal(t, 1, c.traceRequests())

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "0x1", map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "historical-block trace must be denied for a non-admin")
	assert.Equal(t, 1, c.traceRequests(), "the denied trace adds no upstream call")

	// Positive control: the same request from an org admin is traced at the
	// requested block.
	_, err := ts.db.Conn().ExecContext(ctx, `UPDATE groups SET is_org_admin = true WHERE id = $1`, u.groupID)
	require.NoError(t, err)
	require.NoError(t, ts.rbacAccessCtrl.InvalidateGroup(ctx, u.groupID))
	res = proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "0x1", map[string]any{"tracer": "callTracer"}))
	require.Nil(t, res.Error, "an org admin may trace at a historical block: %+v", res.Error)
	assert.Equal(t, 2, c.traceRequests())
	c.mu.Lock()
	block := c.lastCallBlock
	c.mu.Unlock()
	assert.Equal(t, "0x1", block, "the trace runs at the requested block")
}

// Banned user: CheckAccess's blanket ban gate must apply to the trace path.
func TestRD1304_TraceCall_BannedUserDenied(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc7)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)
	require.NoError(t, ts.db.UpdateUser(ctx, &rbac.User{ID: u.userID, ExternalID: u.did, KYC: true, Banned: true}))
	require.NoError(t, ts.rbacAccessCtrl.InvalidateUser(ctx, u.userID))

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "a banned user must not trace")
	assert.Equal(t, 0, c.traceRequests(), "denied trace must not reach the node")
}

// A user-supplied `from` that is not one of the caller's linked EOAs is
// rejected (it would reach msg.sender-gated branches), as for eth_call.
func TestRD1304_TraceCall_UnlinkedFromRejected(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc8)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, fixedAddr(0x12))
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"from": fixedAddr(0x99), "to": addr}, "latest", map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "a unlinked from must be rejected")
	assert.Equal(t, 0, c.traceRequests(), "denied trace must not reach the node")
}

// Path org pins the trace: a member of A and B calling /rpc/B cannot trace an
// A-owned contract.
func TestRD1304_TraceCall_PathOrgPinsTarget(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc9)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "") // org A
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)
	orgB := uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgB, Slug: "trb-" + orgB[:8], Name: "B"}))
	gB := uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, gB, orgB, "tgb-"+gB[:8], "B Grp", "tgb-"+gB[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: gB, AllowedMethods: traceMethods}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: u.userID, GroupID: gB, Source: rbac.MembershipSourceAdmin}))

	res := proc.Process(ctx, traceReq(u.did, orgB, "debug_traceCall",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "an org-A contract must not be traceable through /rpc/orgB")
	assert.Equal(t, 0, c.traceRequests(), "denied trace must not reach the node")
}

// Positive path: granted non-admin, plain callTracer → the call tree is
// returned, with the caller's JSON-RPC id, and no storage.
func TestRD1304_TraceCall_GrantedCallTracerAllowed(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xca)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr, "data": "0x6d4ce63c"}, "latest", map[string]any{"tracer": "callTracer"}))
	require.Nil(t, res.Error, "granted callTracer trace must be allowed: %+v", res.Error)
	var out struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(res.ResponseBody, &out))
	assert.Equal(t, 7, out.ID, "response must echo the caller's JSON-RPC id")
	assert.Contains(t, string(out.Result), strings.ToLower(addr))
	assert.NotContains(t, string(res.ResponseBody), storageMarker)
	assert.False(t, c.callerTracerReachedNode())
}

func TestRD1304_TraceCall_UpstreamHTTPStatusChecked(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			addr := fixedAddr(0xcb)
			c.topTo, c.traceStatus = addr, status
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest"))
			require.NotNil(t, res.Error, "a valid result does not make an unsuccessful HTTP response successful")
			if status == http.StatusTooManyRequests {
				assert.Equal(t, http.StatusTooManyRequests, res.Error.StatusCode)
				assert.Equal(t, ReasonRateLimited, res.Error.Reason)
			} else {
				assert.Equal(t, http.StatusBadGateway, res.Error.StatusCode)
				assert.Equal(t, ReasonUpstreamError, res.Error.Reason)
			}
			assert.Empty(t, res.ResponseBody)
		})
	}
}

func TestRD1304_TraceCall_RateLimitBeforeUpstream(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	limiter := middleware.NewRateLimiter(time.Hour)
	t.Cleanup(limiter.Stop)
	proc.rateLimiter = limiter
	ctx := context.Background()
	addr := fixedAddr(0xcc)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	first := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest"))
	require.Nil(t, first.Error)
	secondReq := traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest")
	second := proc.Process(ctx, secondReq)
	require.NotNil(t, second.Error)
	assert.Equal(t, http.StatusTooManyRequests, second.Error.StatusCode)
	assert.Equal(t, ReasonRateLimited, secondReq.denialReason)
	assert.Equal(t, 1, c.traceRequests(), "a rate-limited request must not reach the upstream tracer")
}

func TestRD1304_TraceCall_NestedFunctionRules(t *testing.T) {
	self, other := fixedAddr(0x71), fixedAddr(0x72)
	const balanceABI = `[{"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"}]`
	balanceCall := func(addr string) string {
		return "0x70a08231" + strings.Repeat("0", 24) + strings.TrimPrefix(addr, "0x")
	}
	for _, frameType := range []string{"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"} {
		for _, tc := range []struct {
			name, allowedInput, deniedInput, abi string
			rule                                 rbac.FunctionRule
		}{
			{name: "selector", allowedInput: "0x6d4ce63c", deniedInput: "0x60fe47b1" + strings.Repeat("00", 32), rule: rbac.FunctionRule{Selector: "0x6d4ce63c"}},
			{name: "parameter", allowedInput: balanceCall(self), deniedInput: balanceCall(other), abi: balanceABI, rule: rbac.FunctionRule{Selector: "0x70a08231", ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}}}},
		} {
			t.Run(frameType+"/"+tc.name, func(t *testing.T) {
				c := newTraceCanary(t)
				proc, ts := setupTraceProcessor(t, c)
				ctx := context.Background()
				wrapper, child := fixedAddr(0x73), fixedAddr(0x74)
				u := newTraceUser(t, ctx, ts, "", nil, traceMethods, self)
				storageAddress, entryInput := child, "0x"
				if frameType == "DELEGATECALL" || frameType == "CALLCODE" {
					storageAddress, entryInput = wrapper, tc.allowedInput
					addContract(t, ctx, ts, u.orgID, child, "")
				} else {
					addContract(t, ctx, ts, u.orgID, wrapper, u.groupID)
				}
				cid := uuid.New().String()
				require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: cid, OrgID: u.orgID, Address: storageAddress, Name: "Function scope", ABI: tc.abi}))
				require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: cid, GroupID: u.groupID, Functions: []rbac.FunctionRule{tc.rule}}))

				allowedParams := []any{map[string]any{"to": storageAddress, "data": tc.allowedInput}, "latest"}
				access, err := proc.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
					UserExternalID: u.did, OrgID: u.orgID, Method: "eth_call", Params: allowedParams,
					TargetAddress: storageAddress, FunctionSelector: rbac.GetFunctionSelector("eth_call", allowedParams),
				})
				require.NoError(t, err)
				require.True(t, access.Allowed, "the configured positive function/argument control must pass")
				direct := proc.Process(ctx, traceReq(u.did, u.orgID, "eth_call", map[string]any{"from": self, "to": storageAddress, "data": tc.deniedInput}, "latest"))
				require.NotNil(t, direct.Error, "the direct call must enforce the same function or argument restriction")
				assert.Equal(t, http.StatusNotFound, direct.Error.StatusCode)

				for _, input := range []string{tc.allowedInput, tc.deniedInput} {
					c.mu.Lock()
					c.txFrom, c.txTo, c.txIn = self, wrapper, entryInput
					c.callTracerBody = map[string]any{
						"type": "CALL", "from": self, "to": wrapper, "input": entryInput, "output": "0x",
						"calls": []any{map[string]any{"type": frameType, "from": wrapper, "to": child, "input": input, "output": "0x1234"}},
					}
					c.mu.Unlock()
					for _, method := range []string{"debug_traceCall", "debug_traceTransaction"} {
						params := []any{map[string]any{"from": self, "to": wrapper, "data": entryInput}, "latest"}
						if method == "debug_traceTransaction" {
							params = []any{traceHash}
						}
						res := proc.Process(ctx, traceReq(u.did, u.orgID, method, params...))
						if input == tc.allowedInput {
							require.Nil(t, res.Error, "a frame permitted by the storage contract's rules must be returned: %+v", res.Error)
							assert.Contains(t, string(res.ResponseBody), "0x1234")
						} else {
							require.NotNil(t, res.Error, "a frame must satisfy the storage contract's function and argument rules")
							assert.Empty(t, res.ResponseBody)
						}
					}
				}
				if frameType == "STATICCALL" && tc.name == "parameter" {
					controller := rbac.NewAccessController(&traceContractLookupStore{Store: ts.db, failAddress: child}, time.Minute)
					t.Cleanup(controller.Stop)
					proc.rbacAccessCtrl = controller
					c.mu.Lock()
					c.callTracerBody = map[string]any{
						"type": "CALL", "from": self, "to": wrapper, "input": entryInput,
						"calls": []any{map[string]any{"type": frameType, "from": wrapper, "to": child, "input": tc.allowedInput, "output": "0x1234"}},
					}
					c.mu.Unlock()
					before := c.traceRequests()
					res := proc.Process(ctx, traceReq(u.did, u.orgID, "debug_traceCall", map[string]any{"from": self, "to": wrapper}, "latest"))
					require.NotNil(t, res.Error)
					assert.Equal(t, http.StatusInternalServerError, res.Error.StatusCode)
					assert.Equal(t, traceDenyTracerError, res.Error.Message)
					assert.Empty(t, res.ResponseBody)
					assert.Equal(t, before+1, c.traceRequests(), "the required nested-frame lookup must be checked after receiving the tree")
				}
			})
		}
	}
}

func TestRD1304_TraceCall_InfrastructureFramesRemainSupported(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "precompile", true: "shared infrastructure"}[shared], func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			wrapper, target := fixedAddr(0x75), "0x0000000000000000000000000000000000000001"
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, wrapper, u.groupID)
			if shared {
				target = "0x" + strings.ReplaceAll(uuid.New().String(), "-", "") + "00000000"
				require.NoError(t, ts.db.CreateSharedInfrastructure(ctx, &rbac.SharedInfrastructure{Address: target, Name: "Trace infrastructure"}))
				t.Cleanup(func() { require.NoError(t, ts.db.DeleteSharedInfrastructure(ctx, target)) })
			}
			c.callTracerBody = map[string]any{
				"type": "CALL", "to": wrapper,
				"calls": []any{map[string]any{"type": "STATICCALL", "from": wrapper, "to": target, "input": "0x1234", "output": "0x1234"}},
			}
			res := proc.Process(ctx, traceReq(u.did, u.orgID, "debug_traceCall", map[string]any{"to": wrapper}, "latest"))
			require.Nil(t, res.Error, "validated infrastructure follows its existing access rules: %+v", res.Error)
			assert.Contains(t, string(res.ResponseBody), target)
		})
	}
}

// Cross-org internal frame: still denied, with an opaque message that names
// no address.
func TestRD1304_TraceCall_CrossOrgFrameDeniedOpaque(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xcb)
	foreign := fixedAddr(0xfb)
	c.topTo = addr
	c.calls = []traceFrame{{Type: "STATICCALL", From: addr, To: foreign}}
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)
	registerForeignOrgContract(t, ctx, ts, foreign)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "cross-org frame must be denied")
	assert.NotContains(t, res.Error.Message, strings.ToLower(foreign))
	assert.NotContains(t, res.Error.Message, "contract access denied", "validator reason must not be echoed")
}

// ---------------------------------------------------------------------------
// debug_traceTransaction requires eth_getTransactionByHash visibility.
// ---------------------------------------------------------------------------

func TestRD1304_TraceTransaction_NonParticipantDenied(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xd1)
	c.txFrom, c.txTo, c.topTo = fixedAddr(0x21), addr, addr // someone else's tx
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, fixedAddr(0x22))
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction",
		"0x"+strings.Repeat("ab", 32), map[string]any{"tracer": "callTracer"}))
	require.True(t, denied(res), "a non-participant must not replay another user's tx")
	assert.Equal(t, 0, c.traceRequests(), "a non-participant replay must not reach the node's tracer")
}

// A non-existent tx and a non-visible tx return the same response (no oracle).
func TestRD1304_TraceTransaction_MissingTxSameAsNotVisible(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xd2)
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, fixedAddr(0x23))
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	c.txFrom = "" // eth_getTransactionByHash → null
	missing := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", "0x"+strings.Repeat("cd", 32)))
	missingCalls := len(c.snapshot())
	c.mu.Lock()
	c.txFrom, c.txTo, c.topTo = fixedAddr(0x24), addr, addr
	c.mu.Unlock()
	hidden := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", "0x"+strings.Repeat("ab", 32)))
	hiddenCalls := len(c.snapshot()) - missingCalls

	require.True(t, denied(missing))
	require.True(t, denied(hidden))
	assert.Equal(t, missing.Error.StatusCode, hidden.Error.StatusCode)
	assert.Equal(t, missing.Error.Message, hidden.Error.Message, "missing vs hidden tx must be indistinguishable")
	assert.Equal(t, missing.Error.Reason, hidden.Error.Reason, "and carry the same reason")
	assert.Equal(t, 1, missingCalls, "a missing tx costs exactly one upstream lookup")
	assert.Equal(t, missingCalls, hiddenCalls, "and so does a hidden tx — no trace is run for either")
}

func TestRD1304_TraceTransaction_ParticipantAllowed(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xd3)
	me := fixedAddr(0x25)
	c.txFrom, c.txTo, c.topTo = me, addr, addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me)
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", "0x"+strings.Repeat("ab", 32)))
	require.Nil(t, res.Error, "the tx sender must be able to trace their own tx: %+v", res.Error)
	assert.NotContains(t, string(res.ResponseBody), storageMarker)
	assert.False(t, c.callerTracerReachedNode())
}

func TestRD1304_TraceTransaction_AdminOnToAllowed(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xd4)
	c.txFrom, c.txTo, c.topTo = fixedAddr(0x26), addr, addr
	u := newTraceUser(t, ctx, ts, "", []rbac.Claim{rbac.ClaimAdmin}, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", "0x"+strings.Repeat("ab", 32)))
	require.Nil(t, res.Error, "an admin of the tx's `to` contract may trace it: %+v", res.Error)
}

func TestRD1304_TraceTransaction_VisibleToAllowed(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xd5)
	hash := "0x" + strings.Repeat("ef", 32)
	c.txFrom, c.txTo, c.topTo = fixedAddr(0x27), addr, addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)
	require.NoError(t, ts.db.SaveTxVisibility(ctx, hash, []string{u.did}, "did:privado:sender", u.orgID))

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", hash))
	require.Nil(t, res.Error, "a visibleTo recipient may trace the tx: %+v", res.Error)
}

// ---------------------------------------------------------------------------
// Aliases and the admin test-request path.
// ---------------------------------------------------------------------------

// Mixed-case method name takes the same gate (RD-1180 canonicalization).
func TestRD1304_MixedCaseMethodTakesSameGate(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xe1)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "DEBUG_TRACECALL",
		map[string]any{"to": addr}, "latest", map[string]any{"tracer": "prestateTracer"}))
	require.True(t, denied(res), "mixed-case trace method must take the same gate")
	assert.False(t, c.callerTracerReachedNode())
}

// Operator trace aliases are outside the exact catalog registration contract.
func TestRD1304_OperatorTraceAliasRegistrationRejected(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	require.False(t, rbac.ExtraMethods["x_traceCall"])
	require.Empty(t, rbac.MethodAliases["x_traceCall"])
	err := rbac.RegisterExtraNamespaces(map[string][]string{"X": {"x_traceCall"}}, map[string]string{"x_traceCall": "debug_traceCall"}, nil)
	require.Error(t, err)
	assert.False(t, rbac.ExtraMethods["x_traceCall"], "failed registration must leave the method registry unchanged")
	assert.Empty(t, rbac.MethodAliases["x_traceCall"], "failed registration must leave the alias registry unchanged")

	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xe2)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, []string{"x_traceCall", "debug_traceCall", "eth_call"}, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "x_traceCall", map[string]any{"to": addr}, "latest"))
	require.NotNil(t, res.Error)
	assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)
	assert.Equal(t, "method not found", res.Error.Message)
	assert.Empty(t, c.snapshot(), "an unregistered method must not reach the node")

	res = proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest"))
	require.Nil(t, res.Error, "the canonical trace method remains available")
	assert.Equal(t, 1, c.traceRequests(), "the canonical trace uses one upstream request")
}

// The internal RD-915 eth_call trace keeps working (it does not go through
// the client debug_trace* path).
func TestRD1304_InternalEthCallTraceStillWorks(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xe3)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	perr := proc.validateEthCallWithTracing(ctx, &ProcessRequest{
		UserID: u.did, Method: "eth_call", Params: []any{map[string]any{"to": addr, "data": "0x"}},
	}, addr)
	require.Nil(t, perr, "internal eth_call trace must still validate a same-org call")
	assert.Equal(t, 1, c.traceRequests(), "the internal trace ran once, with the proxy's callTracer")
	assert.False(t, c.callerTracerReachedNode())
}

// The test-request diagnostic refuses trace methods. The fixture has an
// allowlisted, authenticated user so the method-specific refusal is tested.
func TestRD1304_TestRequestRefusesTraceMethods(t *testing.T) {
	for _, method := range []string{"debug_traceCall", "debug_traceTransaction", "Debug_TraceCall"} {
		t.Run(method, func(t *testing.T) {
			ts := setupTestServerForCompliance(t)
			c := newTraceCanary(t)
			ts.Server.proxy = proxy.New(c.srv.URL)
			ctx := context.Background()

			orgID := uuid.New().String()
			require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "trq-" + orgID[:8], Name: "TR Org"}))
			groupID := uuid.New().String()
			insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "trq-"+groupID[:8], "TR Grp", "trq-"+groupID[:8])
			require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
				ID: uuid.New().String(), GroupID: groupID, AllowedMethods: traceMethods,
			}))
			userID := uuid.New().String()
			did := "did:privado:trq-" + uuid.New().String()
			require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
			require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
				ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
			}))
			token, err := ts.jwtService.IssueAccessToken(did, true)
			require.NoError(t, err)

			params := []any{map[string]any{"to": fixedAddr(0xaa)}, "latest", map[string]any{"tracer": "prestateTracer"}}
			if strings.EqualFold(method, "debug_traceTransaction") {
				params = []any{"0x" + strings.Repeat("ab", 32), map[string]any{"tracer": "prestateTracer"}}
			}
			body, _ := json.Marshal(map[string]any{"method": method, "params": params, "jwt_token": token, "org_id": orgID})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/test-request", strings.NewReader(string(body)))
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			ts.router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code, "trace method must be refused on test-request; body=%s", w.Body.String())
			// The guidance must name the RPC endpoint, which serves trace
			// methods; dry-run rejects them. It must not suggest the operator
			// obtain an end user's credentials.
			var refusal struct {
				Error string `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refusal))
			assert.Contains(t, refusal.Error, "/rpc")
			assert.NotContains(t, refusal.Error, "dry-run")
			assert.NotContains(t, refusal.Error, "token")
			assert.Empty(t, c.snapshot(), "a refused test-request trace must never reach the node")
			assert.NotContains(t, w.Body.String(), storageMarker)
		})
	}
}

// ---------------------------------------------------------------------------
// Review fix-ups.
// ---------------------------------------------------------------------------

const traceHash = "0xabababababababababababababababababababababababababababababababab"

// addMembershipInNewOrg puts an existing user into a fresh second org.
func addMembershipInNewOrg(t *testing.T, ctx context.Context, ts *testServerRBAC, userID string, methods []string) (orgID, groupID string) {
	t.Helper()
	orgID = uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "tr2-" + orgID[:8], Name: "Trace Org 2"}))
	groupID = uuid.New().String()
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "tg2-"+groupID[:8], "Trace Grp 2", "tg2-"+groupID[:8])
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: groupID, AllowedMethods: methods}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}))
	return orgID, groupID
}

// The path org (and the org the view-as gate pins) scopes a replay: a user in
// orgs A and B cannot replay their org-B tx through org A, so an org-A admin
// viewing as that user sees no org-B frames. A multi-org user on bare /rpc
// must name the org, as for eth_getTransactionByHash.
func TestRD1304_TraceTransaction_PathOrgPinned(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	me := fixedAddr(0x31)
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // org A
	orgB, gB := addMembershipInNewOrg(t, ctx, ts, u.userID, traceMethods)
	bAddr := fixedAddr(0xb1)
	addContract(t, ctx, ts, orgB, bAddr, gB)
	c.txFrom, c.txTo, c.topTo = me, bAddr, bAddr // the user's own tx into an org-B contract

	viewAsA := traceReq(u.did, u.orgID, "debug_traceTransaction", traceHash)
	viewAsA.BypassPermsCache = true
	resA := proc.Process(ctx, viewAsA)
	require.True(t, denied(resA), "an org-B tx must not replay through org A")
	assert.Equal(t, 0, c.traceRequests(), "the org-B replay must not reach the node's tracer")

	resBare := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", traceHash))
	require.True(t, denied(resBare), "a multi-org user must name the org on bare /rpc")

	resB := proc.Process(ctx, traceReq(u.did, orgB, "debug_traceTransaction", traceHash))
	require.Nil(t, resB.Error, "the sender may replay it in the tx's own org: %+v", resB.Error)
}

// The same pinning through the View-as RPC surface over HTTP: the org named
// in the View-as URL scopes the replay. A user in orgs A and B sent a tx into
// an org-B contract; viewed as that user in org A it is not replayed, viewed
// in org B it is.
func TestRD1304_ViewAsTraceTransactionPinnedToNamedOrg(t *testing.T) {
	srv := setupImpersonationTestServer(t)
	c := newTraceCanary(t)
	srv.jsonrpcProcessor = newTraceProcessor(t, srv.testServerRBAC, c)
	ctx := context.Background()
	me := fixedAddr(0x39)
	u := newTraceUser(t, ctx, srv.testServerRBAC, "", nil, traceMethods, me) // org A
	orgB, gB := addMembershipInNewOrg(t, ctx, srv.testServerRBAC, u.userID, traceMethods)
	bAddr := fixedAddr(0xb2)
	addContract(t, ctx, srv.testServerRBAC, orgB, bAddr, gB)
	c.txFrom, c.txTo, c.topTo = me, bAddr, bAddr // the user's own tx into an org-B contract

	viewAs := func(orgID string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "debug_traceTransaction", "params": []any{traceHash}})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, impersonatePath(u.did, orgID, "/rpc"), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Auth-Method", "jwt_admin")
		req.Header.Set("X-Test-Admin-Subject", "did:privado:tr-viewas-admin")
		req.Header.Set("X-Test-Admin-Org-IDs", u.orgID+","+orgB)
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)
		return w
	}

	inA := viewAs(u.orgID)
	assert.Equal(t, http.StatusForbidden, inA.Code, "viewed in org A, the org-B tx must not be replayed; body=%s", inA.Body.String())
	assert.Contains(t, inA.Body.String(), traceDenyAccess, "refused by the replay rule, not by the View-as gate")
	assert.Equal(t, 0, c.traceRequests(), "the org-A view must not reach the node's tracer")

	inB := viewAs(orgB)
	require.Equal(t, http.StatusOK, inB.Code, "viewed in org B, the sender's own tx is replayed; body=%s", inB.Body.String())
	assert.Contains(t, inB.Body.String(), bAddr)
	assert.Equal(t, 1, c.traceRequests())
}

// Ban and KYC apply to the replay path too: a ban revokes refresh tokens
// only, so a still-valid access token must be refused here.
func TestRD1304_TraceTransaction_BannedOrNonKYCDenied(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kyc    bool
		banned bool
	}{
		{"banned", true, true},
		{"no KYC", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			me := fixedAddr(0x32)
			addr := fixedAddr(0xd6)
			c.txFrom, c.txTo, c.topTo = me, addr, addr
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // the sender
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)
			require.NoError(t, ts.db.UpdateUser(ctx, &rbac.User{ID: u.userID, ExternalID: u.did, KYC: tc.kyc, Banned: tc.banned}))
			require.NoError(t, ts.rbacAccessCtrl.InvalidateUser(ctx, u.userID))

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", traceHash))
			require.True(t, denied(res), "%s user must not replay", tc.name)
			assert.Empty(t, c.snapshot(), "%s: nothing may reach the node", tc.name)
		})
	}
}

// The payload returned must be the payload validated. A node that answers a
// callTracer request with a different or malformed body is refused.
func TestRD1304_TraceCall_NodeNonCallTracerBodyRefused(t *testing.T) {
	addr := fixedAddr(0xc0)
	cases := map[string]any{
		"null":            json.RawMessage("null"),
		"empty object":    map[string]any{},
		"prestate shape":  map[string]any{addr: map[string]any{"storage": map[string]any{"0x01": storageMarker}}},
		"lowercase type":  map[string]any{"type": "call", "from": fixedAddr(0xee), "to": addr, "output": storageMarker},
		"unknown subtype": map[string]any{"type": "CALL", "from": fixedAddr(0xee), "to": addr, "calls": []any{map[string]any{"type": "SLOAD", "to": addr}}},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			c.topTo = addr
			c.callTracerBody = body
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest"))
			require.True(t, denied(res), "%s must be refused", name)
			assert.NotContains(t, string(res.ResponseBody), storageMarker)
		})
	}
}

// Unknown fields on an otherwise well-formed frame are never passed through.
func TestRD1304_TraceCall_UnknownFrameFieldsStripped(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc0)
	c.topTo = addr
	c.callTracerBody = map[string]any{
		"type": "CALL", "from": fixedAddr(0xee), "to": addr, "output": "0x01",
		"logs":        []any{map[string]any{"address": addr, "data": storageMarker}},
		"vendorExtra": storageMarker,
	}
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest"))
	require.Nil(t, res.Error, "a well-formed frame is served: %+v", res.Error)
	body := string(res.ResponseBody)
	assert.NotContains(t, body, storageMarker, "unknown fields must not pass through")
	assert.NotContains(t, body, `"logs"`)
	assert.Contains(t, body, `"output":"0x01"`)
}

// The call object the node executes must be the one that was access-checked.
// An ambiguous data/input pair or a non-string field is refused before any
// upstream call.
func TestRD1304_TraceCall_AmbiguousCallObjectRefused(t *testing.T) {
	addr := fixedAddr(0xc1)
	cases := map[string]map[string]any{
		"data and input differ": {"to": addr, "data": "0x", "input": "0x6d4ce63c"},
		"non-string to":         {"to": 123, "data": "0x6d4ce63c"},
		"to as array":           {"to": []any{addr}},
		"non-string data":       {"to": addr, "data": 5},
		"non-string value":      {"to": addr, "value": 1},
		"decimal value":         {"to": addr, "value": "100"},
		"non-hex value":         {"to": addr, "value": "0xzz"},
		"empty hex value":       {"to": addr, "value": "0x"},
		"value over 256 bits":   {"to": addr, "value": "0x1" + strings.Repeat("0", 64)},
		"data without 0x":       {"to": addr, "data": "6d4ce63c"},
		"non-hex data":          {"to": addr, "data": "0x6d4ce63g"},
		"odd-length data":       {"to": addr, "data": "0x6d4ce63"},
		"non-hex input":         {"to": addr, "input": "0xzz"},
	}
	for name, callObj := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			c.topTo = addr
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", callObj, "latest"))
			require.True(t, denied(res), "%s must be refused", name)
			assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode, "%s is a malformed request", name)
			assert.Equal(t, ReasonInvalidRequestShape, res.Error.Reason)
			assert.Empty(t, c.snapshot(), "%s: nothing may reach the node", name)
		})
	}
}

// Well-formed hex values and calldata are accepted in any letter case or
// zero padding, and forwarded in canonical form (lowercase, 0x prefix, no
// leading zeros in the value) so every node parses them the same way.
func TestRD1304_TraceCall_HexValueAndDataAccepted(t *testing.T) {
	addr := fixedAddr(0xc8)
	cases := map[string]struct {
		call      map[string]any
		forwarded map[string]any
	}{
		"zero value":            {map[string]any{"to": addr, "value": "0x0"}, map[string]any{"to": addr, "value": "0x0"}},
		"zero-padded value":     {map[string]any{"to": addr, "value": "0x01"}, map[string]any{"to": addr, "value": "0x1"}},
		"all-zero value":        {map[string]any{"to": addr, "value": "0x000"}, map[string]any{"to": addr, "value": "0x0"}},
		"upper-case value":      {map[string]any{"to": addr, "value": "0X1F"}, map[string]any{"to": addr, "value": "0x1f"}},
		"256-bit value":         {map[string]any{"to": addr, "value": "0x" + strings.Repeat("f", 64)}, map[string]any{"to": addr, "value": "0x" + strings.Repeat("f", 64)}},
		"64-digit padded value": {map[string]any{"to": addr, "value": "0x" + strings.Repeat("0", 63) + "1"}, map[string]any{"to": addr, "value": "0x1"}},
		"empty data string":     {map[string]any{"to": addr, "data": ""}, map[string]any{"to": addr}},
		"upper-case calldata":   {map[string]any{"to": addr, "data": "0X6D4CE63C"}, map[string]any{"to": addr, "data": "0x6d4ce63c"}},
		"empty calldata":        {map[string]any{"to": addr, "data": "0x"}, map[string]any{"to": addr, "data": "0x"}},
		"matching input alias":  {map[string]any{"to": addr, "data": "0x6d4ce63c", "input": "0x6D4CE63C"}, map[string]any{"to": addr, "data": "0x6d4ce63c"}},
		"input without data":    {map[string]any{"to": addr, "input": "0x6D4CE63C"}, map[string]any{"to": addr, "data": "0x6d4ce63c"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			c.topTo = addr
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", tc.call, "latest"))
			require.Nil(t, res.Error, "%s must be accepted: %+v", name, res.Error)
			assert.Equal(t, 1, c.traceRequests())
			c.mu.Lock()
			forwarded := c.lastCallObject
			c.mu.Unlock()
			assert.Equal(t, tc.forwarded, forwarded, "%s: the node receives the canonical call object", name)
		})
	}
}

// Multicall batches let one call reach many contracts; eth_call refuses it, so
// the trace twin must too.
func TestRD1304_TraceCall_MulticallRefused(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	multicall3 := "0xca11bde05977b3631167028862be2a173976ca11"
	c.topTo = multicall3
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, multicall3, u.groupID) // registered + granted

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall",
		map[string]any{"to": multicall3, "data": "0x82ad56cb" + strings.Repeat("00", 64)}, "latest"))
	require.True(t, denied(res), "a Multicall batch must be refused on the trace path")
	assert.Equal(t, 0, c.traceRequests(), "denied trace must not reach the node")
}

// A trace shows every internal frame's input and output, which eth_call never
// returns. So every same-org frame must be a contract the viewer holds a
// grant on, whatever the global intra-org knob says (the explorer shows such a
// contract as private to the same viewer).
func TestRD1304_TraceCall_UngrantedSameOrgInternalFrameRefused(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	entry, inner := fixedAddr(0xc2), fixedAddr(0xc3)
	c.topTo = entry
	c.calls = []traceFrame{{Type: "STATICCALL", From: entry, To: inner}}
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, entry, u.groupID) // granted
	addContract(t, ctx, ts, u.orgID, inner, "")        // same org, NOT granted

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": entry}, "latest"))
	require.True(t, denied(res), "an ungranted same-org internal frame must not be revealed")

	// Positive control: grant the inner contract and the same trace is served.
	c2 := newTraceCanary(t)
	proc2, ts2 := setupTraceProcessor(t, c2)
	c2.topTo = entry
	c2.calls = []traceFrame{{Type: "STATICCALL", From: entry, To: inner}}
	u2 := newTraceUser(t, ctx, ts2, "", nil, traceMethods, "")
	addContract(t, ctx, ts2, u2.orgID, entry, u2.groupID)
	addContract(t, ctx, ts2, u2.orgID, inner, u2.groupID)
	res2 := proc2.Process(ctx, traceReq(u2.did, "", "debug_traceCall", map[string]any{"to": entry}, "latest"))
	require.Nil(t, res2.Error, "with a grant on every frame the trace is served: %+v", res2.Error)
}

func TestRD1304_TraceTransaction_UngrantedSameOrgInternalFrameRefused(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	me := fixedAddr(0x33)
	entry, inner := fixedAddr(0xc4), fixedAddr(0xc5)
	c.txFrom, c.txTo, c.topTo = me, entry, entry
	c.calls = []traceFrame{{Type: "CALL", From: entry, To: inner}}
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // the sender
	addContract(t, ctx, ts, u.orgID, entry, u.groupID)
	addContract(t, ctx, ts, u.orgID, inner, "") // same org, NOT granted

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", traceHash))
	require.True(t, denied(res), "even the sender must not see an ungranted same-org frame")
	// Denied by the frame check on the returned trace, not by a pre-trace gate.
	assert.Equal(t, 1, c.traceRequests(), "the trace ran; its frames were refused")
	assert.Equal(t, ReasonCrossOrg, res.Error.Reason)

	// Positive control: grant the inner contract and the same replay is served.
	c2 := newTraceCanary(t)
	proc2, ts2 := setupTraceProcessor(t, c2)
	c2.txFrom, c2.txTo, c2.topTo = me, entry, entry
	c2.calls = []traceFrame{{Type: "CALL", From: entry, To: inner}}
	u2 := newTraceUser(t, ctx, ts2, "", nil, traceMethods, me)
	addContract(t, ctx, ts2, u2.orgID, entry, u2.groupID)
	addContract(t, ctx, ts2, u2.orgID, inner, u2.groupID)
	res2 := proc2.Process(ctx, traceReq(u2.did, "", "debug_traceTransaction", traceHash))
	require.Nil(t, res2.Error, "with a grant on every frame the replay is served: %+v", res2.Error)
}

// A trace through an upgradeable proxy DELEGATECALLs into an implementation
// the viewer usually has no grant on (grants go on the proxy). That frame runs
// against the granted proxy's storage, so it is covered by the proxy's grant —
// as eth_call allows it. A DELEGATECALL into another org is still refused.
func TestRD1304_TraceCall_DelegatecallFromGrantedProxyServed(t *testing.T) {
	ctx := context.Background()
	proxyAddr, impl := fixedAddr(0xa1), fixedAddr(0xa2)

	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	c.topTo = proxyAddr
	c.calls = []traceFrame{{Type: "DELEGATECALL", From: proxyAddr, To: impl}}
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, proxyAddr, u.groupID) // granted
	addContract(t, ctx, ts, u.orgID, impl, "")             // same org, no grant
	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": proxyAddr}, "latest"))
	require.Nil(t, res.Error, "a DELEGATECALL from a granted proxy is covered: %+v", res.Error)

	// Calling the same implementation directly still requires its own grant.
	c.mu.Lock()
	c.calls = []traceFrame{
		{Type: "DELEGATECALL", From: proxyAddr, To: impl},
		{Type: "CALL", From: proxyAddr, To: impl},
	}
	c.mu.Unlock()
	direct := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": proxyAddr}, "latest"))
	require.True(t, denied(direct), "an ordinary call uses the implementation's own storage context")

	c2 := newTraceCanary(t)
	proc2, ts2 := setupTraceProcessor(t, c2)
	c2.topTo = proxyAddr
	c2.calls = []traceFrame{{Type: "DELEGATECALL", From: proxyAddr, To: impl}}
	u2 := newTraceUser(t, ctx, ts2, "", nil, traceMethods, "")
	addContract(t, ctx, ts2, u2.orgID, proxyAddr, u2.groupID)
	registerForeignOrgContract(t, ctx, ts2, impl) // implementation in ANOTHER org
	res2 := proc2.Process(ctx, traceReq(u2.did, "", "debug_traceCall", map[string]any{"to": proxyAddr}, "latest"))
	require.True(t, denied(res2), "a DELEGATECALL into another org is still refused")
	assert.Equal(t, ReasonCrossOrg, res2.Error.Reason)
}

// A replay checks the called contract the way eth_call would check that very
// call — including a grant restricted to specific functions.
func TestRD1304_TraceTransaction_FunctionRestrictedGrantReplayServed(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	me := fixedAddr(0x35)
	addr := fixedAddr(0xa3)
	getSel := "0x6d4ce63c"
	c.txFrom, c.txTo, c.txIn, c.topTo = me, addr, getSel, addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // the sender
	cid := uuid.New().String()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: cid, OrgID: u.orgID, Address: addr, Name: "Restricted"}))
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: cid, GroupID: u.groupID,
		Functions: []rbac.FunctionRule{{Selector: getSel}},
	}))

	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", traceHash))
	require.Nil(t, res.Error, "the sender may replay a call their function-restricted grant allows: %+v", res.Error)

	// The same grant does not cover a different function.
	c.mu.Lock()
	c.txIn = "0x60fe47b1" + strings.Repeat("00", 32) // set(uint256), not granted
	c.mu.Unlock()
	res2 := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", traceHash))
	require.True(t, denied(res2), "a replay of a function the grant does not allow is refused")
}

// A replay's registered created contracts require the viewer's access.
func TestRD1304_TraceTransaction_UngrantedCreatedChildRefused(t *testing.T) {
	ctx := context.Background()
	me := fixedAddr(0x36)
	factory, child := fixedAddr(0xa4), fixedAddr(0xa5)
	run := func(grantChild bool) *ProcessResult {
		c := newTraceCanary(t)
		proc, ts := setupTraceProcessor(t, c)
		c.txFrom, c.txTo, c.topTo = me, factory, factory
		c.calls = []traceFrame{{Type: "CREATE2", From: factory, To: child}}
		u := newTraceUser(t, ctx, ts, "", []rbac.Claim{rbac.ClaimDeploy}, traceMethods, me) // the sender
		addContract(t, ctx, ts, u.orgID, factory, u.groupID)
		grant := ""
		if grantChild {
			grant = u.groupID
		}
		addContract(t, ctx, ts, u.orgID, child, grant)
		return proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", traceHash))
	}
	refused := run(false)
	require.True(t, denied(refused), "an ungranted created child must not be revealed")
	assert.Equal(t, ReasonCrossOrg, refused.Error.Reason)
	served := run(true)
	require.Nil(t, served.Error, "with a grant on the child the replay is served: %+v", served.Error)
}

// A trace that creates a contract needs the deploy claim. Without it the
// caller sees the same message as any other internal-frame denial (a caller
// can steer which code paths run), while the access log records the precise
// reason rather than a cross-org one.
func TestRD1304_DeployClaimDenialLoggedPrecisely(t *testing.T) {
	for _, method := range []string{"debug_traceCall", "debug_traceTransaction"} {
		t.Run(method, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			me := fixedAddr(0x37)
			factory, child := fixedAddr(0xa6), fixedAddr(0xa7)
			c.txFrom, c.txTo, c.topTo = me, factory, factory
			c.calls = []traceFrame{{Type: "CREATE2", From: factory, To: child}}
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // no deploy claim
			addContract(t, ctx, ts, u.orgID, factory, u.groupID)

			params := []any{map[string]any{"from": me, "to": factory}, "latest"}
			if method == "debug_traceTransaction" {
				params = []any{traceHash}
			}
			req := traceReq(u.did, u.orgID, method, params...)
			res := proc.Process(ctx, req)
			require.True(t, denied(res), "a contract creation without the deploy claim must be refused")
			assert.Equal(t, 1, c.traceRequests(), "the refusal comes from the returned trace")
			assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
			assert.Equal(t, traceDenyCrossOrg, res.Error.Message, "the wire message stays uniform")
			assert.Equal(t, ReasonDeployClaimRequired, res.Error.Reason)
			assert.Equal(t, ReasonDeployClaimRequired, req.denialReason, "the access log records the precise reason")
			assert.Equal(t, ReasonWireGenericDenied, wireReason(req.denialReason), "verbose callers still get the generic reason")
		})
	}
}

// A caller can steer which internal calls run, so the response must not tell
// "an internal call reached a contract I cannot access" apart from "an
// internal call used a function or argument my grant does not allow". Both
// return the same status and message; the access log keeps the precise
// reason.
func TestRD1304_InternalFrameDenialsIndistinguishable(t *testing.T) {
	const getSel = "0x6d4ce63c"
	setCall := "0x60fe47b1" + strings.Repeat("00", 32)
	for _, method := range []string{"debug_traceCall", "debug_traceTransaction"} {
		t.Run(method, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			me := fixedAddr(0x38)
			entry, ungranted, restricted := fixedAddr(0xa8), fixedAddr(0xa9), fixedAddr(0xaa)
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me)
			addContract(t, ctx, ts, u.orgID, entry, u.groupID)
			addContract(t, ctx, ts, u.orgID, ungranted, "") // same org, no grant
			cid := uuid.New().String()
			require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: cid, OrgID: u.orgID, Address: restricted, Name: "Restricted"}))
			require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{
				ID: uuid.New().String(), ContractID: cid, GroupID: u.groupID,
				Functions: []rbac.FunctionRule{{Selector: getSel}},
			}))

			run := func(inner, input string) (*ProcessResult, *ProcessRequest) {
				c.mu.Lock()
				c.txFrom, c.txTo, c.txIn = me, entry, "0x"
				c.callTracerBody = map[string]any{
					"type": "CALL", "from": me, "to": entry, "input": "0x", "output": "0x",
					"calls": []any{map[string]any{"type": "CALL", "from": entry, "to": inner, "input": input, "output": "0x"}},
				}
				c.mu.Unlock()
				params := []any{map[string]any{"from": me, "to": entry}, "latest"}
				if method == "debug_traceTransaction" {
					params = []any{traceHash}
				}
				req := traceReq(u.did, u.orgID, method, params...)
				return proc.Process(ctx, req), req
			}

			allowed, _ := run(restricted, getSel)
			require.Nil(t, allowed.Error, "control: a granted function on the restricted contract is served: %+v", allowed.Error)

			noGrant, noGrantReq := run(ungranted, getSel)
			badFunction, badFunctionReq := run(restricted, setCall)
			require.True(t, denied(noGrant))
			require.True(t, denied(badFunction))
			assert.Equal(t, noGrant.Error.StatusCode, badFunction.Error.StatusCode)
			assert.Equal(t, noGrant.Error.Message, badFunction.Error.Message, "the two causes must be indistinguishable to the caller")
			assert.Equal(t, traceDenyCrossOrg, badFunction.Error.Message)
			assert.Equal(t, wireReason(noGrantReq.denialReason), wireReason(badFunctionReq.denialReason))
			assert.Equal(t, ReasonCrossOrg, noGrantReq.denialReason, "the access log keeps the precise reason")
			assert.Equal(t, ReasonTraceAccessDenied, badFunctionReq.denialReason, "the access log keeps the precise reason")
		})
	}
}

// An EIP-1898 block object is rebuilt from its known keys before forwarding.
func TestRD1304_TraceCall_BlockObjectRebuilt(t *testing.T) {
	c := newTraceCanary(t)
	proc, ts := setupTraceProcessor(t, c)
	ctx := context.Background()
	addr := fixedAddr(0xc6)
	c.topTo = addr
	u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
	addContract(t, ctx, ts, u.orgID, addr, u.groupID)
	// Historical blocks are an org-admin privilege (as for eth_call).
	_, err := ts.db.Conn().ExecContext(ctx, `UPDATE groups SET is_org_admin = true WHERE id = $1`, u.groupID)
	require.NoError(t, err)
	require.NoError(t, ts.rbacAccessCtrl.InvalidateGroup(ctx, u.groupID))

	hash := "0x" + strings.Repeat("12", 32)
	res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr},
		map[string]any{"blockHash": hash, "requireCanonical": true, "extra": "x"}))
	require.Nil(t, res.Error, "an org admin may trace at a block hash: %+v", res.Error)
	c.mu.Lock()
	fwd, _ := c.lastCallBlock.(map[string]any)
	c.mu.Unlock()
	assert.Equal(t, map[string]any{"blockHash": hash, "requireCanonical": true}, fwd,
		"only the known EIP-1898 keys are forwarded")
}

// A malformed tx hash is refused before any upstream or DB lookup.
func TestRD1304_TraceTransaction_MalformedHashRefused(t *testing.T) {
	for _, h := range []string{"0xdeadbeef", "0x" + strings.Repeat("a", 63), strings.Repeat("ab", 32), "0x" + strings.Repeat("zz", 32)} {
		t.Run(h, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, fixedAddr(0x34))

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", h))
			require.True(t, denied(res))
			assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
			assert.Empty(t, c.snapshot(), "nothing may reach the node")
		})
	}
}

// The simulation-option check classifies debug_traceCall only, so override and
// replay-position keys in a debug_traceTransaction config are refused by the
// trace config check: a 400 naming the overrides, before any upstream call.
// The caller is a participant, so without that check the replay would be served.
func TestRD1304_TraceTransaction_OverrideConfigKeysRefused(t *testing.T) {
	cases := map[string]map[string]any{
		"stateOverrides": {"tracer": "callTracer", "stateOverrides": map[string]any{}},
		"blockOverride":  {"blockOverride": map[string]any{"number": "0x1"}},
		"TXINDEX":        {"tracer": "callTracer", "TXINDEX": 1},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			addr := fixedAddr(0xc9)
			me := fixedAddr(0x19)
			c.txFrom, c.txTo, c.topTo = me, addr, addr
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, me) // participant (sender)
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceTransaction", "0x"+strings.Repeat("ab", 32), cfg))
			require.True(t, denied(res), "%s must be refused", name)
			assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
			assert.Equal(t, traceDenyOverrides, res.Error.Message)
			assert.Equal(t, ReasonInvalidRequestShape, res.Error.Reason)
			assert.Empty(t, c.snapshot(), "%s: nothing may reach the node", name)
		})
	}
}

// Config keys are matched case-insensitively (as geth decodes them), and keys
// that collide by case are ambiguous and refused.
func TestRD1304_TraceCall_CaseVariantConfigKeysRefused(t *testing.T) {
	cases := map[string]map[string]any{
		"Tracer prestate":         {"Tracer": "prestateTracer"},
		"StateOverrides":          {"tracer": "callTracer", "StateOverrides": map[string]any{}},
		"TracerConfig WithLog":    {"tracer": "callTracer", "TracerConfig": map[string]any{"WithLog": true}},
		"stateOverride singular":  {"tracer": "callTracer", "stateOverride": map[string]any{}},
		"blockOverride singular":  {"tracer": "callTracer", "blockOverride": map[string]any{}},
		"txIndex":                 {"tracer": "callTracer", "txIndex": 1},
		"tracer collides by case": {"tracer": "callTracer", "TRACER": "prestateTracer"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTraceCanary(t)
			proc, ts := setupTraceProcessor(t, c)
			ctx := context.Background()
			addr := fixedAddr(0xc7)
			c.topTo = addr
			u := newTraceUser(t, ctx, ts, "", nil, traceMethods, "")
			addContract(t, ctx, ts, u.orgID, addr, u.groupID)

			res := proc.Process(ctx, traceReq(u.did, "", "debug_traceCall", map[string]any{"to": addr}, "latest", cfg))
			require.True(t, denied(res), "%s must be refused", name)
			assert.Empty(t, c.snapshot(), "%s: nothing may reach the node", name)
		})
	}
}
