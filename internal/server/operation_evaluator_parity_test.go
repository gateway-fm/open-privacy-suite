package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// Review item 7: live RPC, dry-run and the oracle project one evaluation.
// Outcomes are compared as categories: allow, deny, indeterminate, invalid
// (a 400 caller error) and unavailable (an operational failure).
const (
	parityAllow         = "allow"
	parityDeny          = "deny"
	parityIndeterminate = "indeterminate"
	parityInvalid       = "invalid"
	parityUnavailable   = "unavailable"
)

type parityFixture struct {
	ts          *testServerRBAC
	proc        *JSONRPCProcessor
	canary      *creationCanary
	orgA        string
	ownAddr     string
	foreignAddr string
	grantedDID  string
	ungranted   string
	adminDID    string
	dryRun      *gin.Engine
	oracle      *gin.Engine
}

func setupParityFixture(t *testing.T) *parityFixture {
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
	ts.jsonrpcProcessor = proc
	ts.proxy = proxy.New(canary.srv.URL)

	ctx := context.Background()
	f := &parityFixture{ts: ts, proc: proc, canary: canary, ownAddr: fixedAddr(0xa1), foreignAddr: fixedAddr(0xb2)}
	f.orgA = uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: f.orgA, Slug: "parity-a", Name: "Parity A", Settings: map[string]any{}}))
	ownID := drCreateContract(t, ts.db, f.orgA, f.ownAddr, "ParityOwn")
	orgB := registerForeignOrgContract(t, ctx, ts, f.foreignAddr)

	methods := []string{"eth_call", "eth_estimateGas", "eth_createAccessList"}
	f.grantedDID = seedCreationMember(t, ctx, ts, f.orgA, nil, methods)
	f.ungranted = seedCreationMember(t, ctx, ts, f.orgA, nil, methods)
	granted, err := ts.db.GetUserByExternalID(ctx, f.grantedDID)
	require.NoError(t, err)
	memberships, err := ts.db.ListUserMembershipsWithDetails(ctx, granted.ID)
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: ownID, GroupID: memberships[0].Membership.GroupID,
	}))

	adminGroup := drCreateGroup(t, ts.db, f.orgA, "parity-admins", nil, true)
	f.adminDID = "did:test:parity-admin"
	drCreateUserInGroup(t, ts.db, f.adminDID, adminGroup)

	// Both organizations are inside the oracle scope, so every case below is
	// one the oracle may judge.
	ts.config.CrossOrgAuthorizationOracleMode = "verdict_only"
	ts.config.CrossOrgAuthorizationOracleOrgIDs = []string{f.orgA, orgB}

	f.dryRun = gin.New()
	f.dryRun.POST("/dry-run/:org_id", func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_subject", f.adminDID)
		ts.handleDryRun(c)
	})
	f.oracle = gin.New()
	f.oracle.POST("/oracle", func(c *gin.Context) {
		c.Set("auth_method", "cross_org_authorization_oracle_token")
		ts.handlePolicyCheck(c)
	})
	return f
}

func (f *parityFixture) live(t *testing.T, did, method string, params []any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	res := f.proc.Process(context.Background(), &ProcessRequest{UserID: did, Method: method, Params: params, Body: body})
	switch {
	case res.Error == nil:
		return parityAllow
	case res.Error.StatusCode == http.StatusBadRequest:
		return parityInvalid
	case res.Error.StatusCode >= http.StatusInternalServerError || res.Error.Reason == ReasonTracingUnavailable:
		return parityUnavailable
	default:
		return parityDeny
	}
}

func parityHTTP(t *testing.T, router *gin.Engine, path string, body any) string {
	t.Helper()
	jb, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(jb)))
	switch {
	case w.Code == http.StatusBadRequest:
		return parityInvalid
	case w.Code >= http.StatusInternalServerError || w.Code == http.StatusTooManyRequests:
		return parityUnavailable
	case w.Code != http.StatusOK:
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Decision string `json:"decision"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	return resp.Decision
}

func (f *parityFixture) dryRunOutcome(t *testing.T, did, method string, params []any) string {
	t.Helper()
	return parityHTTP(t, f.dryRun, "/dry-run/"+f.orgA, map[string]any{
		"user_did": did, "rpc": apimodels.DryRunRPCBlock{Method: method, Params: params},
	})
}

func (f *parityFixture) oracleOutcome(t *testing.T, did, method string, params []any) string {
	t.Helper()
	return parityHTTP(t, f.oracle, "/oracle", map[string]any{
		"subject": map[string]any{"did": did}, "operation": map[string]any{"method": method, "params": params},
	})
}

func TestOperationEvaluatorParity(t *testing.T) {
	type outcomes struct{ live, dryRun, oracle string }
	call := func(f *parityFixture, block any) []any {
		return []any{map[string]any{"to": f.ownAddr, "data": "0x"}, block}
	}
	for _, method := range []string{"eth_call", "eth_estimateGas", "eth_createAccessList"} {
		for _, tc := range []struct {
			name   string
			setup  func(f *parityFixture)
			did    func(f *parityFixture) string
			params func(f *parityFixture) []any
			want   outcomes
		}{
			{
				name:   "allowed",
				params: func(f *parityFixture) []any { return call(f, "latest") },
				want:   outcomes{parityAllow, parityAllow, parityAllow},
			},
			{
				name:   "RBAC deny",
				did:    func(f *parityFixture) string { return f.ungranted },
				params: func(f *parityFixture) []any { return call(f, "latest") },
				want:   outcomes{parityDeny, parityDeny, parityDeny},
			},
			{
				// The foreign org is inside the oracle scope, so the oracle judges
				// it like live; org-local dry-run cannot look there.
				name: "nested foreign",
				setup: func(f *parityFixture) {
					f.canary.setFrame(traceFrame{Type: "CALL", From: fixedAddr(0x01), To: f.ownAddr,
						Calls: []traceFrame{{Type: "STATICCALL", From: f.ownAddr, To: f.foreignAddr}}})
				},
				params: func(f *parityFixture) []any { return call(f, "latest") },
				want:   outcomes{parityDeny, parityIndeterminate, parityDeny},
			},
			{
				name:   "malformed params",
				params: func(*parityFixture) []any { return []any{"not-an-object"} },
				want:   outcomes{parityDeny, parityDeny, parityDeny},
			},
			{
				name:   "invalid block parameter",
				params: func(f *parityFixture) []any { return call(f, "LATEST!") },
				want:   outcomes{parityDeny, parityDeny, parityDeny},
			},
			{
				name:   "upstream failure",
				setup:  func(f *parityFixture) { f.canary.traceErr = true },
				params: func(f *parityFixture) []any { return call(f, "latest") },
				want:   outcomes{parityUnavailable, parityUnavailable, parityUnavailable},
			},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				f := setupParityFixture(t)
				f.canary.setFrame(traceFrame{Type: "CALL", From: fixedAddr(0x01), To: f.ownAddr})
				if tc.setup != nil {
					tc.setup(f)
				}
				did := f.grantedDID
				if tc.did != nil {
					did = tc.did(f)
				}
				params := tc.params(f)
				want := tc.want
				switch {
				case method == "eth_createAccessList" && tc.name != "RBAC deny" && tc.name != "malformed params":
					// A targeted access list keeps its entry-point gate only, on
					// every path that serves it.
					want.live, want.oracle = parityAllow, parityAllow
				case method == "eth_estimateGas" && tc.name == "invalid block parameter":
					// CheckAccess classifies an eth_call block tag; for
					// eth_estimateGas the trace helper rejects it as a caller error.
					want.live, want.oracle = parityInvalid, parityInvalid
				}

				assert.Equal(t, want.live, f.live(t, did, method, params), "live")
				assert.Equal(t, want.oracle, f.oracleOutcome(t, did, method, params), "oracle")
				if method == "eth_call" {
					assert.Equal(t, want.dryRun, f.dryRunOutcome(t, did, method, params), "dry-run")
				}
			})
		}
	}
}
