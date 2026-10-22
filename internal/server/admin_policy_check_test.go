package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// policyCheckTestServer mirrors dryRunTestServer (admin_dry_run_test.go):
// a tiny test-mode middleware injects the auth context fields the production
// adminAuthMiddleware would set, so tests drive handlePolicyCheck's OWN gates
// without re-testing gin auth itself (covered in admin_auth_test.go).
//
// Header set by tests:
//   - X-Test-Auth-Method: "jwt_admin" | "cross_org_authorization_oracle_token" | "operator_token" | ""
type policyCheckTestServer struct {
	*testServerRBAC
}

type policyCheckDenyingRateLimiter struct{}

func (policyCheckDenyingRateLimiter) CheckAndIncrement(string, *int, *int) (bool, string) {
	return false, "rate limit exceeded"
}

func (policyCheckDenyingRateLimiter) Stop() {}

func setupPolicyCheckTestServer(t *testing.T) *policyCheckTestServer {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	ts.config.CrossOrgAuthorizationOracleMode = "verdict_only"

	router := gin.New()
	api := router.Group("/api")
	api.Use(func(c *gin.Context) {
		method := c.GetHeader("X-Test-Auth-Method")
		if method != "" {
			c.Set("auth_method", method)
		}
		c.Next()
	})
	api.POST("/policy-check", ts.crossOrgAuthorizationOracleLimitMiddleware(), ts.handlePolicyCheck)

	ts.router = router
	node := newPolicyTraceNode(t, "")
	ts.proxy = proxy.New(node.URL)
	return &policyCheckTestServer{testServerRBAC: ts}
}

func newPolicyTraceNode(t *testing.T, nestedTarget string) *httptest.Server {
	t.Helper()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Params) == 0 {
			http.Error(w, "invalid trace request", http.StatusBadRequest)
			return
		}
		var tx map[string]any
		if err := json.Unmarshal(req.Params[0], &tx); err != nil {
			http.Error(w, "invalid transaction object", http.StatusBadRequest)
			return
		}
		from, _ := tx["from"].(string)
		to, _ := tx["to"].(string)
		if from == "" {
			from = "0x0000000000000000000000000000000000000000"
		}
		frame := map[string]any{"type": "CALL", "from": from, "to": to}
		if to == "" {
			frame["type"] = "CREATE"
			delete(frame, "to")
		}
		if nestedTarget != "" {
			frame["calls"] = []map[string]any{{"type": "STATICCALL", "from": to, "to": nestedTarget}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  frame,
		})
	}))
	t.Cleanup(node.Close)
	return node
}

func policyCheckPost(t *testing.T, srv *policyCheckTestServer, authMethod string, body any) *httptest.ResponseRecorder {
	t.Helper()
	jb, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader(jb))
	req.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// pcFixture is a two-org fixture:
//
//	orgA: participant group (grant on acContractAddr: balanceOf(self) via a
//	      function-level param rule, the exact shape RD-435 regressed on),
//	      one user in it with a linked address, one address linked to TWO
//	      DIDs (collision), one address linked to none (via a revoked-only
//	      link, indistinguishable from never having been linked).
//	orgB: a second org the participant user is ALSO a member of, and a
//	      second, unrelated org+contract for cross-org isolation checks.
//	orgC: a third org with one user and no grant.
type pcFixture struct {
	srv              *policyCheckTestServer
	db               *db.DB
	orgA             string
	orgB             string
	orgC             string
	group            string // orgA participant group, granted on contractAddr
	userDID          string
	userAddr         string // linked to userDID
	collisionAddr    string // linked to userDID AND otherDID
	otherDID         string
	unlinkedAddr     string // never linked
	revokedOnlyAddr  string // linked once, then revoked
	contractAddr     string
	orgBContractAddr string
	bankCUserDID     string
}

const (
	pcBalanceOfABI      = `[{"name":"balanceOf","type":"function","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`
	pcBalanceOfSelector = "0x70a08231"
)

func setupPCFixture(t *testing.T) *pcFixture {
	t.Helper()
	srv := setupPolicyCheckTestServer(t)
	ctx := context.Background()
	database := srv.db

	orgA := uuid.New().String()
	orgB := uuid.New().String()
	orgC := uuid.New().String()
	srv.config.CrossOrgAuthorizationOracleOrgIDs = []string{orgA, orgB, orgC}
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgA, Slug: "pc-a", Name: "PC A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgB, Slug: "pc-b", Name: "PC B", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgC, Slug: "pc-c", Name: "PC C", Settings: map[string]any{}}))

	group := drCreateGroup(t, database, orgA, "pc-participant", nil, false)
	userDID := "did:pc:user"
	userID := drCreateUserInGroup(t, database, userDID, group)

	contractAddr := "0xAC000000000000000000000000000000000000a1"
	contractID := drCreateContract(t, database, orgA, contractAddr, "ACContract")
	require.NoError(t, database.UpdateContractABI(ctx, contractID, pcBalanceOfABI))
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: group,
		Functions: []rbac.FunctionRule{{
			Selector:   pcBalanceOfSelector,
			ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
		}},
	}))

	userAddr := "0x000000000000000000000000000000000000ac01"
	require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, userAddr))

	otherDID := "did:pc:other"
	otherGroup := drCreateGroup(t, database, orgB, "pc-other", nil, false)
	drCreateUserInGroup(t, database, otherDID, otherGroup)

	collisionAddr := "0x000000000000000000000000000000000000ac02"
	require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, collisionAddr))
	require.NoError(t, database.SystemLinkEthAddress(ctx, otherDID, collisionAddr))

	revokedOnlyAddr := "0x000000000000000000000000000000000000ac03"
	require.NoError(t, database.SystemLinkEthAddress(ctx, userDID, revokedOnlyAddr))
	require.NoError(t, database.RevokeEthAddressLink(ctx, userDID, revokedOnlyAddr))

	// orgB contract, so orgA's user (once added to orgB below where needed)
	// can hit a genuinely different org's contract for cross-org checks.
	orgBContractAddr := "0xAC000000000000000000000000000000000000b1"
	drCreateContract(t, database, orgB, orgBContractAddr, "ACOrgBContract")

	bankCGroup := drCreateGroup(t, database, orgC, "pc-bankc", nil, false)
	bankCUserDID := "did:pc:bankc"
	drCreateUserInGroup(t, database, bankCUserDID, bankCGroup)

	_ = userID

	return &pcFixture{
		srv:              srv,
		db:               srv.db,
		orgA:             orgA,
		orgB:             orgB,
		orgC:             orgC,
		group:            group,
		userDID:          userDID,
		userAddr:         userAddr,
		collisionAddr:    collisionAddr,
		otherDID:         otherDID,
		unlinkedAddr:     "0x000000000000000000000000000000000000ac99",
		revokedOnlyAddr:  revokedOnlyAddr,
		contractAddr:     contractAddr,
		orgBContractAddr: orgBContractAddr,
		bankCUserDID:     bankCUserDID,
	}
}

func pcBalanceOfCallOp(contract, argAddr string) map[string]any {
	return map[string]any{
		"method": "eth_call",
		"params": []any{
			map[string]any{
				"to":   contract,
				"data": pcBalanceOfSelector + "000000000000000000000000" + strings.TrimPrefix(argAddr, "0x"),
			},
			"latest",
		},
	}
}

func decodePolicyCheckResponse(t *testing.T, w *httptest.ResponseRecorder) policyCheckWireResponse {
	t.Helper()
	var resp policyCheckWireResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), "body: %s", w.Body.String())
	return resp
}

// ---------------------------------------------------------------- auth -----

func TestPolicyCheck_RejectsUnauthenticated(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "" /* no credential */, body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPolicyCheck_RejectsJWTAdmin(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "jwt_admin", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "oracle authentication")
}

func TestPolicyCheck_AcceptsOracleToken(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, w).Decision)
}

func TestPolicyCheck_MalformedSenderBadRequest(t *testing.T) {
	f := setupPCFixture(t)
	op := pcBalanceOfCallOp(f.contractAddr, f.userAddr)
	op["params"].([]any)[0].(map[string]any)["from"] = "not-an-address"
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject": map[string]any{"did": f.userDID}, "operation": op,
	})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid operation")
}

func TestPolicyCheck_RejectsUnlinkedSender(t *testing.T) {
	f := setupPCFixture(t)
	op := pcBalanceOfCallOp(f.contractAddr, f.userAddr)
	op["params"].([]any)[0].(map[string]any)["from"] = f.unlinkedAddr
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject": map[string]any{"did": f.userDID}, "operation": op,
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.Equal(t, oracleDecisionDeny, resp.Decision)
	assert.Equal(t, "denied", resp.Reason)
}

func policyCheckPostFrom(t *testing.T, srv *policyCheckTestServer, remoteIP, forwardedFor string, body any) *httptest.ResponseRecorder {
	t.Helper()
	jb, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader(jb))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "cross_org_authorization_oracle_token")
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	req.RemoteAddr = remoteIP + ":1234"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// One global concurrency key: neither the client IP nor X-Forwarded-For opens
// a fresh slot.
func TestPolicyCheck_ConcurrencyCapIsGlobal(t *testing.T) {
	f := setupPCFixture(t)
	limiter := middleware.NewConcurrencyLimiter(1, 1)
	require.True(t, limiter.TryAcquire(crossOrgOracleLimitKey))
	defer limiter.Release(crossOrgOracleLimitKey)
	f.srv.jsonrpcProcessor = &JSONRPCProcessor{concurrencyLimiter: limiter}

	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	for _, tc := range []struct{ ip, xff string }{
		{"203.0.113.7", ""},
		{"198.51.100.9", ""},
		{"203.0.113.7", "192.0.2.44"},
		{"203.0.113.7", "192.0.2.45"},
	} {
		w := policyCheckPostFrom(t, f.srv, tc.ip, tc.xff, body)
		// Concurrency exhaustion is operational unavailability, not a policy deny.
		require.Equal(t, http.StatusTooManyRequests, w.Code, "ip=%s xff=%s body: %s", tc.ip, tc.xff, w.Body.String())
	}
}

// No request quota: more than the former 100/day budget passes, and the
// processor's rate limiter is never consulted.
func TestPolicyCheck_NoRequestQuota(t *testing.T) {
	f := setupPCFixture(t)
	f.srv.jsonrpcProcessor = &JSONRPCProcessor{
		concurrencyLimiter: middleware.NewConcurrencyLimiter(1, 1),
		rateLimiter:        policyCheckDenyingRateLimiter{},
	}
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	for i := 0; i < 101; i++ {
		w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
		require.Equal(t, http.StatusOK, w.Code, "request %d: %s", i, w.Body.String())
	}
}

func TestPolicyCheck_UpstreamRateLimitReturns429WithRetryAfter(t *testing.T) {
	f := setupPCFixture(t)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusTooManyRequests, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "7", w.Header().Get("Retry-After"))
}

func TestPolicyCheck_TraceTimeoutReturns503(t *testing.T) {
	f := setupPCFixture(t)
	prev := policyCheckTraceTimeout
	policyCheckTraceTimeout = 50 * time.Millisecond
	t.Cleanup(func() { policyCheckTraceTimeout = prev })
	release := make(chan struct{})
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); node.Close() })
	f.srv.proxy = proxy.New(node.URL)

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
}

// policyCheckPostRaw posts a raw body, for cases a marshalled struct cannot
// express (e.g. trailing content after the JSON object).
func policyCheckPostRaw(t *testing.T, srv *policyCheckTestServer, authMethod, raw string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader([]byte(raw)))
	req.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

func TestPolicyCheck_RejectsTrailingJSON(t *testing.T) {
	f := setupPCFixture(t)
	valid := `{"subject":{"did":"` + f.userDID + `"},"operation":{"method":"eth_call","params":[{"to":"` + f.contractAddr + `","data":"0x70a08231"},"latest"]}}`
	w := policyCheckPostRaw(t, f.srv, "cross_org_authorization_oracle_token", valid+`{"unexpected":true}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, "trailing JSON must be rejected; body: %s", w.Body.String())
}

func TestPolicyCheck_MalformedCallParamsDenyLikeLive(t *testing.T) {
	f := setupPCFixture(t)
	// eth_call with a non-object first param is refused by CheckAccess, as on
	// live RPC: a policy answer, never a 500.
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": map[string]any{"method": "eth_call", "params": []any{"not-an-object"}},
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var resp policyCheckWireResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, oracleDecisionDeny, resp.Decision)
}

func TestPolicyCheck_RejectsOperatorToken(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "operator_token", body)
	require.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "oracle authentication")
}

func TestPolicyCheck_RejectsDebugTraceMethods(t *testing.T) {
	f := setupPCFixture(t)
	for _, method := range []string{"debug_traceCall", "debug_traceTransaction"} {
		w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
			"subject": map[string]any{"did": f.userDID},
			"operation": map[string]any{
				"method": method,
				"params": []any{map[string]any{"to": f.contractAddr}},
			},
		})
		require.Equal(t, http.StatusBadRequest, w.Code, "%s: %s", method, w.Body.String())
		assert.Contains(t, w.Body.String(), "operation not supported")
	}
}

// ------------------------------------------------------------- body ----

func TestPolicyCheck_RejectsInvalidJSON(t *testing.T) {
	f := setupPCFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "cross_org_authorization_oracle_token")
	w := httptest.NewRecorder()
	f.srv.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyCheck_RejectsMissingOperationMethod(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": map[string]any{"params": []any{}},
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyCheck_RejectsSubjectWithBothFields(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID, "address": f.userAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "exactly one of did or address")
}

func TestPolicyCheck_RejectsSubjectWithNeitherField(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "exactly one of did or address")
}

func TestPolicyCheck_RejectsMalformedAddressSubject(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": "not-an-ethereum-address"},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "valid Ethereum address")

	assert.Empty(t, oracleAuditRows(t, f), "an early 400 writes no audit row")
}

// -------------------------------------------------------------- subject ---

func assertOracleAnswer(t *testing.T, w *httptest.ResponseRecorder, decision, reason string) {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.Equal(t, decision, resp.Decision, "body: %s", w.Body.String())
	assert.Equal(t, reason, resp.Reason, "body: %s", w.Body.String())
}

// oracleAuditRows returns the payloads of the oracle's RBAC audit rows, oldest
// first, and asserts every row is operator-only (org_id NULL).
func oracleAuditRows(t *testing.T, f *pcFixture) []map[string]any {
	t.Helper()
	rows, err := f.db.Conn().QueryContext(context.Background(), `
		SELECT org_id IS NULL, new_value FROM rbac_audit_log
		 WHERE action = 'cross_org_oracle.query' ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var orgNull bool
		var raw []byte
		require.NoError(t, rows.Scan(&orgNull, &raw))
		assert.True(t, orgNull, "oracle audit rows must be operator-only")
		var payload map[string]any
		require.NoError(t, json.Unmarshal(raw, &payload))
		out = append(out, payload)
	}
	require.NoError(t, rows.Err())
	return out
}

func lastOracleAudit(t *testing.T, f *pcFixture) map[string]any {
	t.Helper()
	rows := oracleAuditRows(t, f)
	require.NotEmpty(t, rows, "expected an oracle audit row")
	return rows[len(rows)-1]
}

// pcUnallowlistedOrg creates an organization outside the oracle allowlist with
// one registered contract.
func pcUnallowlistedOrg(t *testing.T, f *pcFixture, slug, contract string) (orgID, groupID string) {
	t.Helper()
	orgID = uuid.New().String()
	require.NoError(t, f.srv.db.CreateOrganization(context.Background(), &rbac.Organization{
		ID: orgID, Slug: slug, Name: slug, Settings: map[string]any{},
	}))
	groupID = drCreateGroup(t, f.srv.db, orgID, slug, nil, false)
	if contract != "" {
		drCreateContract(t, f.srv.db, orgID, contract, slug)
	}
	return orgID, groupID
}

func pcAddMembership(t *testing.T, f *pcFixture, did, groupID string) {
	t.Helper()
	require.NoError(t, f.srv.db.CreateMembership(context.Background(), &rbac.UserMembership{
		ID: uuid.New().String(), UserID: mustUserIDByDID(t, f.srv.db, did), GroupID: groupID,
		Source: rbac.MembershipSourceAdmin,
	}))
}

func TestPolicyCheck_UnknownDIDOutsideScope(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": "did:pc:nobody"},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
}

// TestPolicyCheck_AddressSubjectResolvesAndMatchesDID verifies that an address
// subject gets the same decision as its linked DID. The self-referencing rule
// also verifies that the database supplies the identity link.
func TestPolicyCheck_AddressSubjectResolvesAndMatchesDID(t *testing.T) {
	f := setupPCFixture(t)

	byDID := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	byAddr := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": f.userAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, byDID.Code)
	require.Equal(t, http.StatusOK, byAddr.Code, "body: %s", byAddr.Body.String())
	assert.Equal(t, decodePolicyCheckResponse(t, byDID), decodePolicyCheckResponse(t, byAddr))
	assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, byAddr).Decision)
}

func TestPolicyCheck_AddressSubjectCaseInsensitive(t *testing.T) {
	f := setupPCFixture(t)
	mixedCase := "0x" + strings.ToUpper(strings.TrimPrefix(f.userAddr, "0x"))
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": mixedCase},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, w).Decision)
}

func TestPolicyCheck_UnlinkedAddressOutsideScope(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": f.unlinkedAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.unlinkedAddr),
	})
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
}

// An unlinked address and a member of a non-allowlisted organization must be
// indistinguishable on the wire.
func TestPolicyCheck_UnlinkedAndUnallowlistedMemberIdentical(t *testing.T) {
	f := setupPCFixture(t)
	_, groupD := pcUnallowlistedOrg(t, f, "pc-d-only", "")
	memberDID := "did:pc:d-only"
	drCreateUserInGroup(t, f.srv.db, memberDID, groupD)
	memberAddr := "0x000000000000000000000000000000000000ad01"
	require.NoError(t, f.srv.db.SystemLinkEthAddress(context.Background(), memberDID, memberAddr))

	unlinked := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": f.unlinkedAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	member := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": memberAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, unlinked.Code, member.Code)
	assert.Equal(t, unlinked.Body.String(), member.Body.String())
	assertOracleAnswer(t, member, oracleDecisionIndeterminate, oracleReasonOutsideScope)
}

// TestPolicyCheck_RevokedLinkOnlyOutsideScope: a link that was revoked must behave
// identically to never having been linked. GetDIDsByEthAddress already
// filters revoked=false, so this pins that the ENDPOINT doesn't accidentally
// bypass that filter (e.g. via a different, unfiltered lookup path).
func TestPolicyCheck_RevokedLinkOnlyOutsideScope(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": f.revokedOnlyAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.revokedOnlyAddr),
	})
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
}

// TestPolicyCheck_CollisionAddressRefusesToChoose is the central subject-
// resolution guard: an address claimed by two DIDs must be refused, never
// resolved to either one by tie-break order. GetDIDByEthAddress (singular,
// used elsewhere for UI convenience lookups) explicitly picks a winner via
// ORDER BY ... LIMIT 1; this endpoint uses the plural GetDIDsByEthAddress and
// must never collapse to that behaviour.
func TestPolicyCheck_CollisionAddressRefusesToChoose(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": f.collisionAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.collisionAddr),
	})
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)

	// Neither colliding DID appears in the audit row: resolution never got far
	// enough to pick one.
	row := lastOracleAudit(t, f)
	assert.Equal(t, strings.ToLower(f.collisionAddr), row["subject_address"])
	assert.Empty(t, row["subject_did"])
}

// ------------------------------------------------------------------ org ---

func TestPolicyCheck_OrgOmittedDerivedFromRegisteredTarget(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
		// org_id omitted entirely.
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, w).Decision)
}

func TestPolicyCheck_ExplicitUnallowlistedOrgOutsideScope(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	forbiddenOrg, _ := pcUnallowlistedOrg(t, f, "pc-forbidden", "")
	body := map[string]any{
		"subject": map[string]any{"did": f.userDID},
		"org_id":  forbiddenOrg,
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": f.contractAddr, "data": "0x"}, "latest"},
		},
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)

	row := lastOracleAudit(t, f)
	assert.Equal(t, "requested_org_outside_allowlist", row["internal_reason"])
	assert.Equal(t, forbiddenOrg, row["requested_org_id"])
	assert.Equal(t, map[string]any{"org_id": forbiddenOrg}, row["scope_detail"])

	// The probe never appears in that organization's tenant audit view.
	scoped, err := f.srv.db.ListAuditLogsScoped(ctx, "", nil, []string{forbiddenOrg}, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, scoped)
}

func TestPolicyCheck_OrgOmittedMultiOrgSubjectDenied(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	// Make the fixture's user ALSO a member of orgB, via a second group.
	secondGroup := drCreateGroup(t, f.srv.db, f.orgB, "pc-second", nil, false)
	require.NoError(t, f.srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: mustUserIDByDID(t, f.srv.db, f.userDID), GroupID: secondGroup,
		Source: rbac.MembershipSourceAdmin,
	}))

	body := map[string]any{
		"subject": map[string]any{"did": f.userDID},
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": "0x0000000000000000000000000000000000feed01", "data": "0x"}, "latest"},
		},
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	// Both orgs are allowlisted and the live path also refuses to pick one.
	assertOracleAnswer(t, w, oracleDecisionDeny, oracleReasonDenied)

	// The audit row keeps the informative reason: it is operator-only.
	assert.Equal(t, "ambiguous_organization", lastOracleAudit(t, f)["internal_reason"])
}

// A target owned outside the allowlist is outside the oracle scope, whether or
// not the subject is a member of its owner (which is never looked up).
func TestPolicyCheck_UnallowlistedTargetOutsideScope(t *testing.T) {
	for _, member := range []bool{true, false} {
		t.Run(fmt.Sprintf("member=%v", member), func(t *testing.T) {
			f := setupPCFixture(t)
			target := "0x0000000000000000000000000000000000feed04"
			_, groupD := pcUnallowlistedOrg(t, f, "pc-unallowlisted", target)
			if member {
				pcAddMembership(t, f, f.userDID, groupD)
			}
			w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
				"subject": map[string]any{"did": f.userDID},
				"operation": map[string]any{
					"method": "eth_call",
					"params": []any{map[string]any{"to": target, "data": "0x"}, "latest"},
				},
			})
			assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
		})
	}
}

// A subject whose only memberships are outside the allowlist is outside the
// oracle scope, even for an allowlisted target.
func TestPolicyCheck_NoAllowlistedMembershipOutsideScope(t *testing.T) {
	f := setupPCFixture(t)
	_, groupD := pcUnallowlistedOrg(t, f, "pc-d-member", "")
	did := "did:pc:d-member"
	drCreateUserInGroup(t, f.srv.db, did, groupD)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": did},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
}

func TestPolicyCheck_ExplicitOrgIDCrossOrgTargetDenied(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	// As on live RPC, a registered target is evaluated in its owner org
	// (orgB), where this member holds no grant on the contract.
	secondGroup := drCreateGroup(t, f.srv.db, f.orgB, "pc-second-b", nil, false)
	require.NoError(t, f.srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: mustUserIDByDID(t, f.srv.db, f.userDID), GroupID: secondGroup,
		Source: rbac.MembershipSourceAdmin,
	}))

	body := map[string]any{
		"subject": map[string]any{"did": f.userDID},
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": f.orgBContractAddr, "data": "0x"}, "latest"},
		},
		"org_id": f.orgA,
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, oracleDecisionDeny, decodePolicyCheckResponse(t, w).Decision)
}

func TestPolicyCheck_ExplicitOrgIDSubjectNotMemberDenied(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject": map[string]any{"did": f.userDID}, // only a member of orgA
		"operation": map[string]any{
			"method": "eth_call",
			"params": []any{map[string]any{"to": f.orgBContractAddr, "data": "0x"}, "latest"},
		},
		"org_id": f.orgB,
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	// The target org is allowlisted, so this is evaluated in scope.
	assertOracleAnswer(t, w, oracleDecisionDeny, oracleReasonDenied)
}

func TestPolicyCheck_ExplicitOrgIDOutsideAllowlistOutsideScope(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
		"org_id":    uuid.New().String(), // does not exist
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
}

func TestPolicyCheck_ThirdPartyNoGrantAnywhereDenied(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.bankCUserDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	// The target org is allowlisted, so this is evaluated in scope.
	assertOracleAnswer(t, w, oracleDecisionDeny, oracleReasonDenied)
}

// ------------------------------------------------------------ operation ---

// TestPolicyCheck_FunctionLevelRulesMatchEnforcement is the RD-435 regression,
// ported to this endpoint. It exists here (not just in admin_dry_run_test.go)
// because handlePolicyCheck has its own handler-level path: if a future change
// stopped it calling dryRunAccessRequest, this catches the same class of bug.
func TestPolicyCheck_FunctionLevelRulesMatchEnforcement(t *testing.T) {
	f := setupPCFixture(t)
	otherAddr := "0x000000000000000000000000000000000000ac77"

	tests := []struct {
		name      string
		argAddr   string
		wantAllow bool
	}{
		{"own balance", f.userAddr, true},
		{"another address", otherAddr, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
				"subject":   map[string]any{"did": f.userDID},
				"operation": pcBalanceOfCallOp(f.contractAddr, tc.argAddr),
			})
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			resp := decodePolicyCheckResponse(t, w)
			assert.Equal(t, tc.wantAllow, resp.Decision == oracleDecisionAllow)
			if !tc.wantAllow {
				assert.NotEmpty(t, resp.Reason)
				assert.NotContains(t, resp.Reason, "function selector required",
					"pre-#435 symptom: a param-rule deny must not be reported as a missing selector")
			}
		})
	}
}

func TestPolicyCheck_ChecksummedTargetNormalized(t *testing.T) {
	f := setupPCFixture(t)
	checksummed := "0x" + strings.ToUpper(strings.TrimPrefix(f.contractAddr, "0x")[:1]) + strings.TrimPrefix(f.contractAddr, "0x")[1:]
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(checksummed, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, w).Decision)
}

func TestPolicyCheck_ReadTraceDeniesNestedForeignCall(t *testing.T) {
	f := setupPCFixture(t)
	node := newPolicyTraceNode(t, f.orgBContractAddr)
	f.srv.proxy = proxy.New(node.URL)

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.Equal(t, oracleDecisionDeny, resp.Decision)
	assert.Equal(t, "denied", resp.Reason)
}

// The A/C example: a contract in allowlisted org A calls into a contract owned
// by non-allowlisted org C. Live RPC allows a member of C; the oracle may not
// look at C, so it answers indeterminate whether or not the subject is a member.
func TestPolicyCheck_NestedCallOutsideAllowlistIndeterminate(t *testing.T) {
	for _, member := range []bool{true, false} {
		t.Run(fmt.Sprintf("member=%v", member), func(t *testing.T) {
			f := setupPCFixture(t)
			f.srv.metrics = metrics.NewNoop()
			nested := "0x0000000000000000000000000000000000feed0c"
			orgC, groupC := pcUnallowlistedOrg(t, f, "pc-org-c", nested)
			if member {
				pcAddMembership(t, f, f.userDID, groupC)
			}
			f.srv.proxy = proxy.New(newPolicyTraceNode(t, nested).URL)

			w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
				"subject":   map[string]any{"did": f.userDID},
				"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
			})
			assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
			assert.NotContains(t, w.Body.String(), orgC)
			assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(nested, "0x"))

			// The specific frame and its owner go to the audit record only.
			var detail map[string]string
			var raw []byte
			require.NoError(t, f.db.Conn().QueryRowContext(context.Background(), `
				SELECT (new_value::jsonb)->'scope_detail' FROM rbac_audit_log
				 WHERE action = 'cross_org_oracle.query' ORDER BY id DESC LIMIT 1`).Scan(&raw))
			require.NoError(t, json.Unmarshal(raw, &detail))
			assert.Equal(t, orgC, detail["org_id"])
			assert.Equal(t, nested, detail["contract"])
			assert.Equal(t, 1.0, oracleIndeterminateCount(t, f.srv.metrics, oracleReasonOutsideScope))
		})
	}
}

func oracleIndeterminateCount(t *testing.T, m *metrics.Metrics, reason string) float64 {
	t.Helper()
	var out dto.Metric
	require.NoError(t, m.CrossOrgOracleIndeterminateTotal.WithLabelValues(reason).Write(&out))
	return out.GetCounter().GetValue()
}

// A method that may execute EVM code but is not simulated by the oracle cannot
// be judged; a catalog read without EVM execution keeps the RBAC verdict.
func TestPolicyCheck_UntracedMethods(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	require.NoError(t, rbac.RegisterExtraNamespaces(map[string][]string{"linea": {"linea_estimateGas"}}, nil, []string{"linea_estimateGas"}))
	f := setupPCFixture(t)
	f.srv.metrics = metrics.NewNoop()
	ctx := context.Background()
	groupID := uuid.New().String()
	require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "pc-untraced", Name: "pc-untraced", Depth: 0, Path: "pc-untraced",
	}))
	require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"linea_estimateGas", "eth_chainId"},
	}))
	pcAddMembership(t, f, f.userDID, groupID)

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": map[string]any{"method": "linea_estimateGas", "params": []any{map[string]any{}, "latest"}},
	})
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonNotSimulated)
	assert.Equal(t, 1.0, oracleIndeterminateCount(t, f.srv.metrics, oracleReasonNotSimulated))

	w = policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": map[string]any{"method": "eth_chainId", "params": []any{}},
	})
	assertOracleAnswer(t, w, oracleDecisionAllow, "")
}

func TestPolicyCheck_WriteTraceDeniesNestedForeignCall(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	groupID := uuid.New().String()
	require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "pc-writer", Name: "pc-writer", Depth: 0, Path: "pc-writer",
	}))
	require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	writerDID := "did:pc:writer"
	drCreateUserInGroup(t, f.db, writerDID, groupID)
	writerAddr := "0x000000000000000000000000000000000000ac52"
	require.NoError(t, f.db.SystemLinkEthAddress(ctx, writerDID, writerAddr))
	target := "0x000000000000000000000000000000000000ac51"
	drCreateGrant(t, f.db, drCreateContract(t, f.db, f.orgA, target, "PCWriterTarget"), groupID)

	node := newPolicyTraceNode(t, f.orgBContractAddr)
	f.srv.proxy = proxy.New(node.URL)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject": map[string]any{"did": writerDID},
		"org_id":  f.orgA,
		"operation": map[string]any{
			"method": "eth_sendTransaction",
			"params": []any{map[string]any{
				"from": writerAddr,
				"to":   target, "data": "0x12345678", "value": "0x0",
			}},
		},
	})

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.Equal(t, oracleDecisionDeny, resp.Decision)
	assert.Equal(t, "denied", resp.Reason)
}

func TestPolicyCheck_WriteRunsCompliancePreview(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	groupID := uuid.New().String()
	require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "pc-compliance", Name: "pc-compliance", Depth: 0, Path: "pc-compliance",
	}))
	require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	did := "did:pc:compliance"
	drCreateUserInGroup(t, f.db, did, groupID)
	from := "0x000000000000000000000000000000000000ac61"
	to := "0x000000000000000000000000000000000000ac62"
	require.NoError(t, f.db.SystemLinkEthAddress(ctx, did, from))
	drCreateGrant(t, f.db, drCreateContract(t, f.db, f.orgA, to, "PCComplianceTarget"), groupID)
	require.NoError(t, f.db.UpsertComplianceConfig(ctx, &compliance.ComplianceConfig{
		ID: uuid.New().String(), OrgID: f.orgA, Enabled: true, ThresholdFiat: 1000,
	}))
	require.NoError(t, f.db.UpsertTokenPrice(ctx, &compliance.TokenPrice{
		ID: uuid.New().String(), OrgID: f.orgA, TokenAddress: "native", Symbol: "ETH",
		Decimals: 18, PriceFiat: 1000, PricesByCurrency: map[string]float64{"usd": 1000},
	}, "usd"))
	f.srv.complianceChecker = compliance.NewChecker(f.db, 24*time.Hour, 15*time.Minute)

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject": map[string]any{"did": did},
		"org_id":  f.orgA,
		"operation": map[string]any{
			"method": "eth_sendTransaction",
			"params": []any{map[string]any{"from": from, "to": to, "value": "0x1bc16d674ec80000"}},
		},
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	resp := decodePolicyCheckResponse(t, w)
	assert.Equal(t, oracleDecisionDeny, resp.Decision)
	assert.Equal(t, "denied", resp.Reason)

	var logs int
	require.NoError(t, f.db.Conn().QueryRowContext(ctx, `SELECT COUNT(*) FROM compliance_logs WHERE org_id = $1`, f.orgA).Scan(&logs))
	assert.Zero(t, logs)
}

func TestPolicyCheck_TraceUnavailableFailsClosed(t *testing.T) {
	f := setupPCFixture(t)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error":   map[string]any{"code": -32601, "message": "method not found"},
		})
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})

	// An upstream trace failure is operational unavailability: 503, never a deny.
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
}

func TestPolicyCheck_TraceUsesResolvedUpstreamCredential(t *testing.T) {
	f := setupPCFixture(t)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "policy-check-key", r.Header.Get("X-RPC-Key"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"type": "CALL", "from": f.userAddr, "to": f.contractAddr},
		})
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)
	f.srv.jsonrpcProcessor = &JSONRPCProcessor{
		defaultRPCAPIKey:       "policy-check-key",
		defaultRPCAPIKeyHeader: "X-RPC-Key",
	}

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, w).Decision)
}

func TestPolicyCheck_ResponseProjectionFollowsConfiguredMode(t *testing.T) {
	f := setupPCFixture(t)
	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}

	f.srv.config.CrossOrgAuthorizationOracleMode = "verdict_only"
	verdict := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	require.Equal(t, http.StatusOK, verdict.Code, "body: %s", verdict.Body.String())
	assert.Nil(t, decodePolicyCheckResponse(t, verdict).Artifacts)

	f.srv.config.CrossOrgAuthorizationOracleMode = "full_simulation"
	full := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	require.Equal(t, http.StatusOK, full.Code, "body: %s", full.Body.String())
	response := decodePolicyCheckResponse(t, full)
	require.NotNil(t, response.Artifacts)
	assert.NotEmpty(t, response.Artifacts.Trace)
}

func TestPolicyCheck_CreateAccessListTracesNestedCalls(t *testing.T) {
	f := setupPCFixture(t)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, "debug_traceCall", request.Method)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"type": "CALL", "from": f.userAddr, "to": f.contractAddr},
		})
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)

	result, err := f.srv.forwardDryRunTraceWithAPIKey(context.Background(), apimodels.DryRunRPCBlock{
		Method: "eth_createAccessList",
		Params: []any{map[string]any{"from": f.userAddr, "to": f.contractAddr}, "latest"},
	}, "", proxy.DefaultAPIKeyHeader)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Parsed)
	require.NotEmpty(t, result.Parsed.CallTargets)
	assert.Equal(t, strings.ToLower(f.contractAddr), strings.ToLower(result.Parsed.CallTargets[0].To))
}

func TestValidatePolicyCheckVisibleTo(t *testing.T) {
	validContractCall := apimodels.DryRunRPCBlock{
		Method: "eth_sendTransaction",
		Params: []any{map[string]any{
			"to": "0x000000000000000000000000000000000000ac51", "data": "0x12345678",
		}},
	}

	t.Run("rejects more than 32 recipients", func(t *testing.T) {
		op := validContractCall
		entries := make([]any, visibleToMaxSize+1)
		for i := range entries {
			entries[i] = fmt.Sprintf("did:example:recipient-%d", i)
		}
		op.Params[0].(map[string]any)["visibleTo"] = entries
		reason, err := validatePolicyCheckVisibleTo(op)
		require.NoError(t, err)
		assert.Equal(t, ReasonInvalidRequestShape, reason)
	})

	t.Run("rejects plain value transfers", func(t *testing.T) {
		op := apimodels.DryRunRPCBlock{Method: "eth_sendTransaction", Params: []any{map[string]any{
			"to": "0x000000000000000000000000000000000000ac51", "value": "0x1", "visibleTo": []any{"did:example:recipient"},
		}}}
		reason, err := validatePolicyCheckVisibleTo(op)
		require.NoError(t, err)
		assert.Equal(t, ReasonInvalidRequestShape, reason)
	})

	t.Run("deduplicates valid recipients before the cap", func(t *testing.T) {
		op := validContractCall
		entries := make([]any, visibleToMaxSize+1)
		for i := range entries {
			entries[i] = "did:example:recipient"
		}
		op.Params[0].(map[string]any)["visibleTo"] = entries
		reason, err := validatePolicyCheckVisibleTo(op)
		require.NoError(t, err)
		assert.Empty(t, reason)
	})
}

// A nested CREATE needs the evaluated org's deploy claim, as on live RPC. A
// claim elsewhere, allowlisted or not, grants nothing.
func TestPolicyCheck_NestedCreateDeployClaimScope(t *testing.T) {
	created := "0x0000000000000000000000000000000000c0ffee"
	for _, tc := range []struct {
		name     string
		claimOrg string // "", "allowlisted" or "unallowlisted"
		decision string
		reason   string
	}{
		{name: "claim only in non-allowlisted org", claimOrg: "unallowlisted", decision: oracleDecisionDeny, reason: oracleReasonDenied},
		{name: "claim in the evaluated org", claimOrg: "allowlisted", decision: oracleDecisionAllow},
		{name: "no claim anywhere", decision: oracleDecisionDeny, reason: oracleReasonDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupPCFixture(t)
			ctx := context.Background()
			orgD, groupD := pcUnallowlistedOrg(t, f, "pc-deploy-d", "")
			pcAddMembership(t, f, f.userDID, groupD)
			if tc.claimOrg != "" {
				orgID := f.orgA
				if tc.claimOrg == "unallowlisted" {
					orgID = orgD
				}
				claimGroup := uuid.New().String()
				require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
					ID: claimGroup, OrgID: orgID, Slug: "pc-claim", Name: "pc-claim", Depth: 0, Path: "pc-claim",
				}))
				require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
					ID: uuid.New().String(), GroupID: claimGroup, AllowedMethods: []string{"eth_call"}, Claims: []rbac.Claim{rbac.ClaimDeploy},
				}))
				pcAddMembership(t, f, f.userDID, claimGroup)
			}
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
					"type": "CALL", "from": f.userAddr, "to": f.contractAddr,
					"calls": []map[string]any{{"type": "CREATE", "from": f.contractAddr, "to": created}},
				}})
			}))
			t.Cleanup(node.Close)
			f.srv.proxy = proxy.New(node.URL)

			w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
				"subject":   map[string]any{"did": f.userDID},
				"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
			})
			assertOracleAnswer(t, w, tc.decision, tc.reason)
		})
	}
}

// TestPolicyCheck_DeploymentRequiresClaim: a tx with no `to` is a deployment,
// gated on the deploy claim regardless of method allowlist.
func TestPolicyCheck_DeploymentRequiresClaim(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	// Not drCreateGroup: it creates its own GroupAccess row, and group_access
	// has UNIQUE(group_id), so a second CreateGroupAccess is a duplicate-key
	// error rather than an update. Build the group directly instead.
	deployGroup := uuid.New().String()
	require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{
		ID: deployGroup, OrgID: f.orgA, Slug: "pc-deployer", Name: "pc-deployer", Depth: 0, Path: "pc-deployer",
	}))
	require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: deployGroup, AllowedMethods: []string{"eth_sendTransaction"}, Claims: []rbac.Claim{rbac.ClaimDeploy},
	}))
	deployerDID := "did:pc:deployer"
	drCreateUserInGroup(t, f.srv.db, deployerDID, deployGroup)

	deployOp := map[string]any{
		"method": "eth_sendTransaction",
		"params": []any{map[string]any{"data": "0x600a600055"}},
	}

	t.Run("no deploy claim, denied", func(t *testing.T) {
		w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
			"subject":   map[string]any{"did": f.userDID}, // orgA participant, no deploy claim
			"operation": deployOp,
		})
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.Equal(t, oracleDecisionDeny, decodePolicyCheckResponse(t, w).Decision)
	})

	t.Run("deploy claim, allowed", func(t *testing.T) {
		w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
			"subject":   map[string]any{"did": deployerDID},
			"operation": deployOp,
		})
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.Equal(t, oracleDecisionAllow, decodePolicyCheckResponse(t, w).Decision)
	})
}

// TestPolicyCheck_RawSendTransactionMatchesEnforcement verifies that
// eth_sendRawTransaction uses the decoded target for access control.
func TestPolicyCheck_RawSendTransactionMatchesEnforcement(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()

	// Not drCreateGroup; see TestPolicyCheck_DeploymentRequiresClaim.
	senderGroup := uuid.New().String()
	require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{
		ID: senderGroup, OrgID: f.orgA, Slug: "pc-sender", Name: "pc-sender", Depth: 0, Path: "pc-sender",
	}))
	require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: senderGroup, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	senderDID := "did:pc:sender"
	drCreateUserInGroup(t, f.srv.db, senderDID, senderGroup)

	grantedAddr := "0x000000000000000000000000000000000000ac41"
	ungrantedAddr := "0x000000000000000000000000000000000000ac42"
	drCreateGrant(t, f.srv.db, drCreateContract(t, f.srv.db, f.orgA, grantedAddr, "ACGranted"), senderGroup)
	drCreateContract(t, f.srv.db, f.orgA, ungrantedAddr, "ACUngranted")

	tests := []struct {
		name      string
		to        string
		wantAllow bool
	}{
		{"granted contract", grantedAddr, true},
		{"contract the group has no grant on", ungrantedAddr, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			to := common.HexToAddress(tc.to)
			rawTx, sender := pcSignedRawTx(t, &to, []byte{0xab, 0xcd, 0xab, 0xcd})
			require.NoError(t, f.srv.db.SystemLinkEthAddress(ctx, senderDID, sender))
			w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
				"subject": map[string]any{"did": senderDID},
				"operation": map[string]any{
					"method": "eth_sendRawTransaction",
					"params": []any{rawTx},
				},
			})
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, tc.wantAllow, decodePolicyCheckResponse(t, w).Decision == oracleDecisionAllow)
		})
	}
}

func TestPolicyCheck_MalformedRawTransactionBadRequestAndAudited(t *testing.T) {
	f := setupPCFixture(t)
	op := map[string]any{
		"method": "eth_sendRawTransaction",
		"params": []any{"0xnotrealhex"},
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": op,
	})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid operation")

	row := lastOracleAudit(t, f)
	assert.Equal(t, "eth_sendRawTransaction", row["method"])
	assert.Equal(t, "error", row["decision"])
	assert.Equal(t, "decode_error", row["internal_reason"])
}

// TestPolicyCheck_AuditWriteFailureIsFailClosed mirrors
// TestDryRun_RawSendTransactionMalformedAudit's "audit write failure is fail
// closed" case, adapted to this table's allowed BOOLEAN column: a temporary
// CHECK constraint rejects any deny-decision insert, forcing the audit write
// to fail on a genuine deny, and the handler must answer 500 with NO verdict
// rather than let the deny leak through despite the broken audit trail.
func TestPolicyCheck_AuditWriteFailureIsFailClosed(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	conn := f.srv.db.Conn()

	_, err := conn.ExecContext(ctx, `
		ALTER TABLE rbac_audit_log
		ADD CONSTRAINT rbac_audit_log_reject_oracle_test
		CHECK (action <> 'cross_org_oracle.query') NOT VALID`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, dropErr := conn.ExecContext(context.Background(), `
			ALTER TABLE rbac_audit_log
			DROP CONSTRAINT IF EXISTS rbac_audit_log_reject_oracle_test`)
		assert.NoError(t, dropErr)
	})

	otherAddr := "0x000000000000000000000000000000000000ac88"
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": pcBalanceOfCallOp(f.contractAddr, otherAddr), // denied by the param rule
	})
	require.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
	assert.JSONEq(t, `{"error":"internal error"}`, w.Body.String())
	assert.Empty(t, oracleAuditRows(t, f))
}

func TestPolicyCheck_NoAuditStoreIsFailClosed(t *testing.T) {
	f := setupPCFixture(t)
	srv := &Server{config: f.srv.config}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("auth_method", "cross_org_authorization_oracle_token")
	jb, err := json.Marshal(map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    uuid.New().String(),
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.NoError(t, err)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/policy-check", bytes.NewReader(jb))
	srv.handlePolicyCheck(c)
	require.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "decision")
}

// One evaluated request leaves exactly one operator-only row, including a 503
// after a trace started, and the hash chain still verifies afterwards.
func TestPolicyCheck_OneChainedAuditRowPerEvaluation(t *testing.T) {
	f := setupPCFixture(t)
	ctx := context.Background()
	f.srv.db.SetRBACAuditChain(audit.NewHashChain(""))

	body := map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"org_id":    f.orgA,
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	}
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	assertOracleAnswer(t, w, oracleDecisionAllow, "")
	rows := oracleAuditRows(t, f)
	require.Len(t, rows, 1)
	assert.Equal(t, f.userDID, rows[0]["subject_did"])
	assert.Equal(t, f.orgA, rows[0]["requested_org_id"])
	assert.Equal(t, f.orgA, rows[0]["evaluated_org_id"])
	assert.Equal(t, "eth_call", rows[0]["method"])
	assert.Equal(t, oracleDecisionAllow, rows[0]["decision"])
	assert.Len(t, rows[0]["params_hash"], 64)

	// The request named orgA, yet orgA's tenant view does not show it.
	scoped, err := f.srv.db.ListAuditLogsScoped(ctx, "", nil, []string{f.orgA}, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, scoped)

	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "node down", http.StatusBadGateway)
	}))
	t.Cleanup(node.Close)
	f.srv.proxy = proxy.New(node.URL)
	w = policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
	rows = oracleAuditRows(t, f)
	require.Len(t, rows, 2)
	assert.Equal(t, "unavailable", rows[1]["decision"])

	res, err := audit.NewVerifier(f.srv.db.Conn(), f.srv.db).Verify(ctx, audit.ChainRBACAuditLog)
	require.NoError(t, err)
	assert.True(t, res.OK, "chain must verify after oracle queries: %s", res.FirstMismatchReason)
}

func TestPolicyCheck_OverLongMethodRejected(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"did": f.userDID},
		"operation": map[string]any{"method": "eth_" + strings.Repeat("x", oracleMaxMethodLength), "params": []any{}},
	})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Empty(t, oracleAuditRows(t, f))
}

// ---------------------------------------------------------------- audit ---

func TestPolicyCheck_AuditRowRecordsSubjectAddressForAddressPath(t *testing.T) {
	f := setupPCFixture(t)
	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject":   map[string]any{"address": f.userAddr},
		"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr),
	})
	require.Equal(t, http.StatusOK, w.Code)

	row := lastOracleAudit(t, f)
	assert.Equal(t, f.userDID, row["subject_did"], "address resolved to the right DID before the row was written")
	assert.Equal(t, strings.ToLower(f.userAddr), row["subject_address"])
}

// ------------------------------------------------------ reason sanitizer ---
// mustUserIDByDID looks up a user's internal UUID by DID for tests that need
// to attach a SECOND membership to an already-created fixture user.
func mustUserIDByDID(t *testing.T, database interface {
	GetUserByExternalID(ctx context.Context, externalID string) (*rbac.User, error)
}, did string) string {
	t.Helper()
	u, err := database.GetUserByExternalID(context.Background(), did)
	require.NoError(t, err)
	require.NotNil(t, u)
	return u.ID
}

// pcSignedRawTx mirrors drSignedRawTx (admin_dry_run_test.go): a signed legacy
// tx as hex, so tests reach the production RLP decode and sender recovery.
func pcSignedRawTx(t *testing.T, to *common.Address, data []byte) (string, string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	tx := types.NewTx(&types.LegacyTx{
		Nonce: 0, GasPrice: big.NewInt(1_000_000_000), Gas: 100_000,
		To: to, Value: big.NewInt(0), Data: data,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1)), key)
	require.NoError(t, err)
	raw, err := signed.MarshalBinary()
	require.NoError(t, err)
	return "0x" + hex.EncodeToString(raw), crypto.PubkeyToAddress(key.PublicKey).Hex()
}

// Live keeps a targeted eth_createAccessList on its entry-point gate, so the
// oracle never evaluates nested scope and must not answer allow.
func TestPolicyCheck_TargetedCreateAccessListNotSimulated(t *testing.T) {
	f := setupPCFixture(t)
	f.srv.metrics = metrics.NewNoop()
	ctx := context.Background()
	groupID := uuid.New().String()
	require.NoError(t, f.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgA, Slug: "pc-access-list", Name: "pc-access-list", Depth: 0, Path: "pc-access-list",
	}))
	require.NoError(t, f.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"eth_createAccessList"},
	}))
	pcAddMembership(t, f, f.userDID, groupID)
	op := pcBalanceOfCallOp(f.contractAddr, f.userAddr)
	op["method"] = "eth_createAccessList"

	w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", map[string]any{
		"subject": map[string]any{"did": f.userDID}, "operation": op,
	})
	assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonNotSimulated)
	assert.Equal(t, 1.0, oracleIndeterminateCount(t, f.srv.metrics, oracleReasonNotSimulated))
}

// Every emitted indeterminate answer is counted once, early returns included.
func TestPolicyCheck_IndeterminateCountedOnEveryPath(t *testing.T) {
	for name, body := range map[string]func(f *pcFixture) map[string]any{
		"requested org outside allowlist": func(f *pcFixture) map[string]any {
			return map[string]any{"subject": map[string]any{"did": f.userDID}, "org_id": uuid.New().String(),
				"operation": pcBalanceOfCallOp(f.contractAddr, f.userAddr)}
		},
		"unlinked address": func(f *pcFixture) map[string]any {
			return map[string]any{"subject": map[string]any{"address": f.unlinkedAddr},
				"operation": pcBalanceOfCallOp(f.contractAddr, f.unlinkedAddr)}
		},
		"address linked to several identities": func(f *pcFixture) map[string]any {
			return map[string]any{"subject": map[string]any{"address": f.collisionAddr},
				"operation": pcBalanceOfCallOp(f.contractAddr, f.collisionAddr)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := setupPCFixture(t)
			f.srv.metrics = metrics.NewNoop()
			w := policyCheckPost(t, f.srv, "cross_org_authorization_oracle_token", body(f))
			assertOracleAnswer(t, w, oracleDecisionIndeterminate, oracleReasonOutsideScope)
			assert.Equal(t, 1.0, oracleIndeterminateCount(t, f.srv.metrics, oracleReasonOutsideScope))
		})
	}
}

// The oracle answers from OPS's own rules; with node policy execution it stays
// unreachable even if configuration validation was skipped.
func TestPolicyCheck_DisabledUnderNodePolicyExecution(t *testing.T) {
	for _, mode := range []string{"verdict_only", "full_simulation"} {
		s := &Server{config: &config.Config{CrossOrgAuthorizationOracleMode: mode}}
		require.True(t, s.crossOrgAuthorizationOracleEnabled(), mode)
		s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth"}
		require.False(t, s.crossOrgAuthorizationOracleEnabled(), mode)
	}
}
