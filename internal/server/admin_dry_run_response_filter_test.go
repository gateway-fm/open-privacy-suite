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
	"testing"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/viewscope"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1308 parity coverage for admin dry-run and the View-as RPC mirror:
// read admission, event filtering, address rendering and organization scope.

const (
	drfMemberDID  = "did:drf:member"
	drfAdminDID   = "did:drf:admin"
	drfMemberEOA  = "0x1308000000000000000000000000000000000a01"
	drfForeignEOA = "0x1308000000000000000000000000000000000f01"
	drfOtherEOA   = "0x1308000000000000000000000000000000000f02"
	drfContractO  = "0x13080000000000000000000000000000000000c1" // org O, member has a Transfer-allowlist grant (ERC-20 ABI)
	drfAdminCO    = "0x13080000000000000000000000000000000000c2" // org O, member is tier-3 admin (ERC-20 ABI)
	drfContractP  = "0x13080000000000000000000000000000000000d1" // org P, member is tier-2 admin of P (multi-org)
	drfCalldata   = "0xa9059cbb0000000000000000000000001308000000000000000000000000000000000f0200000000000000000000000000000000000000000000000000000000000003e8"
	drfTransferT0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

type drfFixture struct {
	ts       *testServerRBAC
	proc     *JSONRPCProcessor
	router   *gin.Engine
	orgO     string
	orgP     string
	memberID string
	// memberGroup is M's plain group in O; contractIDs maps address → contract row id.
	memberGroup string
	contractIDs map[string]string

	mu       sync.Mutex
	upstream map[string][]byte         // JSON-RPC method → full response body
	txByHash map[string]map[string]any // for the RD-1162 batched sender lookup
	seen     []string                  // JSON-RPC methods that reached the node
}

func (f *drfFixture) reached(method string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.seen {
		if m == method {
			return true
		}
	}
	return false
}

func (f *drfFixture) serve(method string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upstream[method] = body
}

// setupDRFFixture: org O with tier-2 admin A (the caller) and member M. M's
// group in O allows the read methods and eth_sendTransaction, holds a
// Transfer-allowlist grant on drfContractO and a tier-3 admin grant on
// drfAdminCO. M is ALSO a tier-2 admin of org P, which owns drfContractP —
// the multi-org case the path-org pin exists for.
func setupDRFFixture(t *testing.T) *drfFixture {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	f := &drfFixture{ts: ts, upstream: map[string][]byte{}, txByHash: map[string]map[string]any{}, contractIDs: map[string]string{}}

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		f.mu.Lock()
		defer f.mu.Unlock()
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
			var batch []struct {
				ID     int   `json:"id"`
				Params []any `json:"params"`
			}
			_ = json.Unmarshal(raw, &batch)
			out := make([]map[string]any, 0, len(batch))
			for _, b := range batch {
				var res any
				if len(b.Params) > 0 {
					if h, ok := b.Params[0].(string); ok {
						if tx, ok := f.txByHash[strings.ToLower(h)]; ok {
							res = tx
						}
					}
				}
				out = append(out, map[string]any{"jsonrpc": "2.0", "id": b.ID, "result": res})
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(raw, &req)
		f.seen = append(f.seen, req.Method)
		if body, ok := f.upstream[req.Method]; ok {
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
	}))
	t.Cleanup(stub.Close)

	up := proxy.New(stub.URL)
	ts.proxy = up
	f.proc = NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:            ts.rbacAccessCtrl,
		RateLimiter:               &noopRateLimiter{},
		Proxy:                     up,
		AccessLogger:              ts.db,
		CircuitBreaker:            middleware.NewCircuitBreaker(),
		ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
		TxVisibilityStore:         ts.db,
		AddressVisibilityResolver: ts.db,
	})
	ts.jsonrpcProcessor = f.proc

	f.orgO = uuid.New().String()
	f.orgP = uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: f.orgO, Slug: "drf-o-" + f.orgO[:6], Name: "DRF O", Settings: map[string]any{}}))
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: f.orgP, Slug: "drf-p-" + f.orgP[:6], Name: "DRF P", Settings: map[string]any{}}))

	adminGroup := drCreateGroup(t, ts.db, f.orgO, "drf-o-admins", nil, true)
	drCreateUserInGroup(t, ts.db, drfAdminDID, adminGroup)

	readMethods := []string{
		rbac.MethodGetTransactionByHash, rbac.MethodGetTransactionReceipt, rbac.MethodGetLogs,
		"eth_call", "eth_sendTransaction", rbac.MethodGetCode, rbac.MethodGetBalance,
		// Outside the View-as method set: granted here so that only the
		// mirror's own allowlist can be what refuses them.
		"eth_sendRawTransaction", "eth_getBlockReceipts", "eth_getBlockByNumber", "debug_traceTransaction",
	}
	memberGroup := uuid.New().String()
	require.NoError(t, ts.db.CreateGroup(ctx, &rbac.Group{ID: memberGroup, OrgID: f.orgO, Slug: "drf-o-members", Name: "drf-o-members", Path: "drf-o-members"}))
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: memberGroup, AllowedMethods: readMethods}))
	adminClaimGroup := uuid.New().String()
	require.NoError(t, ts.db.CreateGroup(ctx, &rbac.Group{ID: adminClaimGroup, OrgID: f.orgO, Slug: "drf-o-c2-admins", Name: "drf-o-c2-admins", Path: "drf-o-c2-admins"}))
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{ID: uuid.New().String(), GroupID: adminClaimGroup, AllowedMethods: readMethods, Claims: []rbac.Claim{rbac.ClaimAdmin}}))

	f.memberGroup = memberGroup
	f.memberID = drCreateUserInGroup(t, ts.db, drfMemberDID, memberGroup)
	impAddUserToGroup(t, ts.db, f.memberID, adminClaimGroup)
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, drfMemberDID, drfMemberEOA))

	cO := wiringCreateContractWithABI(t, ts.db, f.orgO, drfContractO, "DRF-O", erc20ABI)
	wiringCreateGrant(t, ts.db, cO, memberGroup, &rbac.EventRulesField{Rules: []rbac.EventRule{{Topic0: drfTransferT0, Name: "Transfer"}}})
	cO2 := wiringCreateContractWithABI(t, ts.db, f.orgO, drfAdminCO, "DRF-O-admin", erc20ABI)
	drCreateGrant(t, ts.db, cO2, adminClaimGroup)
	f.contractIDs[drfContractO], f.contractIDs[drfAdminCO] = cO, cO2

	// Multi-org: M is a tier-2 admin of P.
	pAdmins := drCreateGroup(t, ts.db, f.orgP, "drf-p-admins", nil, true)
	impAddUserToGroup(t, ts.db, f.memberID, pAdmins)
	f.contractIDs[drfContractP] = wiringCreateContractWithABI(t, ts.db, f.orgP, drfContractP, "DRF-P", erc20ABI)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		if c.GetHeader("X-Test-Auth-Method") == "jwt_admin" {
			c.Set("auth_method", "jwt_admin")
			c.Set("admin_subject", drfAdminDID)
			c.Set("admin_org_ids", []string{f.orgO})
		}
		c.Next()
	})
	api.POST("/admin/orgs/:org_id/dry-run", ts.handleDryRun)
	ts.registerImpersonationRoutes(api.Group("/admin"))
	f.router = router
	return f
}

func drfTx(from, to, hash string) map[string]any {
	return map[string]any{
		"hash": hash, "from": from, "to": to,
		"blockHash": "0x" + strings.Repeat("0", 63) + "1", "blockNumber": "0x1", "transactionIndex": "0x0",
		"value": "0x2a", "gas": "0x5208", "gasPrice": "0x1", "input": drfCalldata, "nonce": "0x7",
		"v": "0x0", "r": "0x0", "s": "0x0",
	}
}

func drfEnvelope(t *testing.T, result any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	require.NoError(t, err)
	return b
}

func drfTransferLog(contract, from, to, txHash, logIndex string) map[string]any {
	return map[string]any{
		"address":         contract,
		"topics":          []string{drfTransferT0, zeroPadAddrToTopic(from), zeroPadAddrToTopic(to)},
		"data":            "0x00000000000000000000000000000000000000000000000000000000000003e8",
		"blockNumber":     "0x1",
		"transactionHash": txHash,
		"logIndex":        logIndex,
	}
}

// dryRunRaw posts a dry-run as the member in org O and returns the recorder.
func (f *drfFixture) dryRunRaw(t *testing.T, method string, params []any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"user_did": drfMemberDID,
		"rpc":      apimodels.DryRunRPCBlock{Method: method, Params: params},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+f.orgO+"/dry-run", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "jwt_admin")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// dryRun posts a dry-run as the member in org O and returns the decoded reply.
func (f *drfFixture) dryRun(t *testing.T, method string, params []any) (dryRunResponse, string) {
	t.Helper()
	w := f.dryRunRaw(t, method, params)
	require.Equal(t, http.StatusOK, w.Code, "dry-run body: %s", w.Body.String())
	var resp dryRunResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp, w.Body.String()
}

// mirrorRaw calls the View-as RPC mirror as the member in org O and returns
// the recorder.
func (f *drfFixture) mirrorRaw(t *testing.T, method string, params []any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, impersonatePath(drfMemberDID, f.orgO, "/rpc"), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Auth-Method", "jwt_admin")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// mirror calls the View-as RPC mirror as the member in org O.
func (f *drfFixture) mirror(t *testing.T, method string, params []any) string {
	t.Helper()
	w := f.mirrorRaw(t, method, params)
	require.Equal(t, http.StatusOK, w.Code, "mirror body: %s", w.Body.String())
	return w.Body.String()
}

// resetReached forgets which methods have reached the node so far.
func (f *drfFixture) resetReached() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = nil
}

// dryRunAuditRows returns the decision and reason of every impersonation_log
// row the dry-run wrote for this fixture's org.
func (f *drfFixture) dryRunAuditRows(t *testing.T) [][2]string {
	t.Helper()
	rows, err := f.ts.db.Conn().QueryContext(context.Background(), `
		SELECT decision, COALESCE(reason, '')
		  FROM impersonation_log
		 WHERE actor_did = $1 AND impersonated_did = $2 AND org_id = $3
		 ORDER BY created_at`,
		drfAdminDID, drfMemberDID, f.orgO)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out [][2]string
	for rows.Next() {
		var r [2]string
		require.NoError(t, rows.Scan(&r[0], &r[1]))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// production runs the response filter exactly as the member's OWN RPC call
// would (no impersonation scope): the reference the dry-run must reproduce
// for a single-org answer, and the control that shows what the path-org pin
// removes for the multi-org one.
func (f *drfFixture) production(t *testing.T, method string, params []any, body []byte) []byte {
	t.Helper()
	res := &rbac.AccessCheckResult{Allowed: true, UserID: f.memberID, OrgID: f.orgO}
	return f.proc.applyResponseFilter(context.Background(),
		&ProcessRequest{Method: method, Params: params, UserID: drfMemberDID, Body: body}, res, body)
}

func drfResult(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &env), "not a JSON-RPC envelope: %s", raw)
	return env.Result
}

func bare(addr string) string { return strings.TrimPrefix(strings.ToLower(addr), "0x") }

func TestDryRun_TxByHash_NonParticipantGetsNull_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const h = "0x1308000000000000000000000000000000000000000000000000000000000001"
	f.serve(rbac.MethodGetTransactionByHash, drfEnvelope(t, drfTx(drfForeignEOA, drfOtherEOA, h)))

	resp, raw := f.dryRun(t, rbac.MethodGetTransactionByHash, []any{h})
	assert.Equal(t, "allow", resp.Decision)
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "a non-participant member gets null in production; dry-run must too: %s", raw)
	lower := strings.ToLower(raw)
	assert.NotContains(t, lower, bare(drfForeignEOA), "foreign sender must be absent")
	assert.NotContains(t, lower, bare(drfCalldata)[:40], "calldata must be absent")
	assert.Equal(t, "null", string(drfResult(t, []byte(f.mirror(t, rbac.MethodGetTransactionByHash, []any{h})))))
}

func TestDryRun_TxByHash_ParticipantSeesOwnTx_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const h = "0x1308000000000000000000000000000000000000000000000000000000000002"
	f.serve(rbac.MethodGetTransactionByHash, drfEnvelope(t, drfTx(drfMemberEOA, drfOtherEOA, h)))

	resp, raw := f.dryRun(t, rbac.MethodGetTransactionByHash, []any{h})
	var tx struct {
		From, Input, Nonce, Value string
	}
	require.NoError(t, json.Unmarshal(drfResult(t, resp.Response), &tx), raw)
	assert.Equal(t, drfMemberEOA, strings.ToLower(tx.From))
	assert.Equal(t, drfCalldata, tx.Input)
	assert.Equal(t, "0x7", tx.Nonce)
	assert.Equal(t, "0x2a", tx.Value)
}

func TestDryRunAndViewAsRPC_DeployerAccessUsesNamedOrg_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	ctx := context.Background()
	_, err := f.ts.db.Conn().ExecContext(ctx,
		`UPDATE contracts SET deployed_by_user_id = $1 WHERE id = $2`, f.memberID, f.contractIDs[drfContractP])
	require.NoError(t, err)

	for _, method := range []string{rbac.MethodCall, rbac.MethodGetCode, rbac.MethodGetBalance} {
		t.Run(method, func(t *testing.T) {
			params := []any{drfContractP, "latest"}
			if method == rbac.MethodCall {
				params = []any{map[string]any{"to": drfContractP, "data": "0x"}, "latest"}
			}
			direct, err := f.ts.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
				UserExternalID: drfMemberDID, OrgID: f.orgO, Method: method, Params: params, TargetAddress: drfContractP,
			})
			require.NoError(t, err)
			require.True(t, direct.Allowed, "the user's direct session retains its multi-org deployer access")

			f.serve(method, drfEnvelope(t, "0x1234"))
			resp, raw := f.dryRun(t, method, params)
			assert.Equal(t, "deny", resp.Decision, raw)
			assert.Empty(t, resp.Response)

			body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, impersonatePath(drfMemberDID, f.orgO, "/rpc"), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-Auth-Method", "jwt_admin")
			w := httptest.NewRecorder()
			f.router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
			assert.False(t, f.reached(method), "a read outside the named org is decided before upstream forwarding")
		})
	}
}

// Dry-run resolves the user's permissions fresh, as the View-as RPC mirror
// does: a grant revoked after the user's own last call no longer allows the
// read, although the user's cached permissions still hold it.
func TestDryRunAndViewAsRPC_ResolvePermissionsFresh_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	ctx := context.Background()
	const target = "0x13080000000000000000000000000000000000c3"
	contractID := wiringCreateContractWithABI(t, f.ts.db, f.orgO, target, "DRF-O-revoked", erc20ABI)
	grantID := uuid.New().String()
	require.NoError(t, f.ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: grantID, ContractID: contractID, GroupID: f.memberGroup}))
	params := []any{target, "latest"}

	own, err := f.ts.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: drfMemberDID, OrgID: f.orgO, Method: rbac.MethodGetBalance, Params: params, TargetAddress: target,
	})
	require.NoError(t, err)
	require.True(t, own.Allowed, "the user's own call is allowed and caches their permissions: %s", own.Reason)

	require.NoError(t, f.ts.db.DeleteContractGrantAndInvalidate(ctx, grantID, f.memberGroup))

	f.serve(rbac.MethodGetBalance, drfEnvelope(t, "0x1234"))
	resp, raw := f.dryRun(t, rbac.MethodGetBalance, params)
	assert.Equal(t, "deny", resp.Decision, "dry-run must not answer from permissions cached before the revocation: %s", raw)
	w := f.mirrorRaw(t, rbac.MethodGetBalance, params)
	assert.Equal(t, http.StatusNotFound, w.Code, "the View-as mirror gives the same answer: %s", w.Body.String())
	assert.False(t, f.reached(rbac.MethodGetBalance), "a revoked read is decided before upstream forwarding")
}

func TestDryRun_TxByHash_AdminExemptionPinnedToPathOrg_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const inO = "0x1308000000000000000000000000000000000000000000000000000000000003"
	const inP = "0x1308000000000000000000000000000000000000000000000000000000000004"

	// Admin on an org-O contract: production shows the tx, dry-run in O too.
	bodyO := drfEnvelope(t, drfTx(drfForeignEOA, drfAdminCO, inO))
	f.serve(rbac.MethodGetTransactionByHash, bodyO)
	resp, raw := f.dryRun(t, rbac.MethodGetTransactionByHash, []any{inO})
	assert.Contains(t, strings.ToLower(string(resp.Response)), bare(drfForeignEOA), "admin exemption in the path org must hold: %s", raw)
	assert.Contains(t, strings.ToLower(f.mirror(t, rbac.MethodGetTransactionByHash, []any{inO})), bare(drfForeignEOA))

	// Admin only in org P: the member's own call shows it, but neither
	// impersonation surface anchored to O may.
	bodyP := drfEnvelope(t, drfTx(drfForeignEOA, drfContractP, inP))
	f.serve(rbac.MethodGetTransactionByHash, bodyP)
	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetTransactionByHash, []any{inP}, bodyP))), bare(drfForeignEOA),
		"control: the member's own call sees the tx through their org-P admin claim")
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionByHash, []any{inP})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "org-P admin claim appeared in an org-O dry-run: %s", raw)
	mirror := f.mirror(t, rbac.MethodGetTransactionByHash, []any{inP})
	assert.Equal(t, "null", string(drfResult(t, []byte(mirror))), "org-P admin claim appeared in the org-O View-as mirror: %s", mirror)
}

func TestDryRun_TxByHash_VisibleToSharePinnedToSenderOrg_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	ctx := context.Background()
	const sharedInO = "0x1308000000000000000000000000000000000000000000000000000000000005"
	const sharedInP = "0x1308000000000000000000000000000000000000000000000000000000000006"
	require.NoError(t, f.ts.db.SaveTxVisibility(ctx, sharedInO, []string{drfMemberDID}, "did:drf:sender-o", f.orgO))
	require.NoError(t, f.ts.db.SaveTxVisibility(ctx, sharedInP, []string{drfMemberDID}, "did:drf:sender-p", f.orgP))

	bodyO := drfEnvelope(t, drfTx(drfForeignEOA, drfOtherEOA, sharedInO))
	f.serve(rbac.MethodGetTransactionByHash, bodyO)
	resp, raw := f.dryRun(t, rbac.MethodGetTransactionByHash, []any{sharedInO})
	assert.Contains(t, strings.ToLower(string(resp.Response)), bare(drfForeignEOA), "a share made in the path org is part of the member's view there: %s", raw)

	bodyP := drfEnvelope(t, drfTx(drfForeignEOA, drfOtherEOA, sharedInP))
	f.serve(rbac.MethodGetTransactionByHash, bodyP)
	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetTransactionByHash, []any{sharedInP}, bodyP))), bare(drfForeignEOA),
		"control: the member's own call sees the org-P share")
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionByHash, []any{sharedInP})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "an org-P share appeared in an org-O dry-run: %s", raw)
	mirror := f.mirror(t, rbac.MethodGetTransactionByHash, []any{sharedInP})
	assert.Equal(t, "null", string(drfResult(t, []byte(mirror))), "an org-P share appeared in the org-O View-as mirror: %s", mirror)
}

// For logs of org-O contracts the dry-run output is the production filter's
// output, byte for byte, on eth_getLogs and on receipts: the admin exemption (a
// log the member sees only through their tier-3 admin claim) and the RD-1214
// embedded-address zeroing included. The org-P log the member's own call
// would also see (they administer P) is removed by the path-org pin and
// nothing else changes.
func TestDryRun_LogsAndReceipt_MatchProductionFilter_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const h = "0x1308000000000000000000000000000000000000000000000000000000000007"
	sameOrg := []any{
		drfTransferLog(drfContractO, drfMemberEOA, drfForeignEOA, h, "0x0"), // names the member; foreign EOA must be zeroed
		drfTransferLog(drfAdminCO, drfForeignEOA, drfOtherEOA, h, "0x1"),    // admin exemption only
	}
	otherOrg := drfTransferLog(drfContractP, drfForeignEOA, drfOtherEOA, h, "0x2") // org P: the member is a P admin
	all := append(append([]any{}, sameOrg...), otherOrg)
	f.txByHash[h] = drfTx(drfForeignEOA, drfContractO, h)

	// The upstream answer deliberately carries more than the address filter
	// asks for: the response filter, not the node, is what is under test.
	params := []any{map[string]any{"address": drfContractO, "fromBlock": "0x1", "toBlock": "0x1"}}
	allBody := drfEnvelope(t, all)
	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetLogs, params, allBody))), bare(drfContractP),
		"control: the member's own call sees the org-P log")
	want := drfResult(t, f.production(t, rbac.MethodGetLogs, params, drfEnvelope(t, sameOrg)))

	f.serve(rbac.MethodGetLogs, allBody)
	resp, raw := f.dryRun(t, rbac.MethodGetLogs, params)
	assert.JSONEq(t, string(want), string(drfResult(t, resp.Response)), "dry-run eth_getLogs diverges from production: %s", raw)

	var got []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
	}
	require.NoError(t, json.Unmarshal(drfResult(t, resp.Response), &got))
	addrs := map[string][]string{}
	for _, l := range got {
		addrs[strings.ToLower(l.Address)] = l.Topics
	}
	require.Contains(t, addrs, drfContractO)
	require.Contains(t, addrs, drfAdminCO, "the tier-3 admin exemption log is part of the member's view")
	assert.NotContains(t, addrs, drfContractP, "an org-P log must never surface in an org-O dry-run")
	assert.NotContains(t, strings.ToLower(strings.Join(addrs[drfContractO], ",")), bare(drfForeignEOA), "embedded foreign EOA must be zeroed")
	assert.Contains(t, strings.ToLower(strings.Join(addrs[drfContractO], ",")), bare(drfMemberEOA), "the member's own address stays")

	receipt := func(logs []any) []byte {
		return drfEnvelope(t, map[string]any{
			"transactionHash": h, "from": drfForeignEOA, "to": drfContractO, "status": "0x1",
			"gasUsed": "0x5208", "cumulativeGasUsed": "0x5208", "effectiveGasPrice": "0x1", "contractAddress": nil,
			"logsBloom": "0x" + strings.Repeat("0", 512), "logs": logs,
		})
	}
	wantReceipt := drfResult(t, f.production(t, rbac.MethodGetTransactionReceipt, []any{h}, receipt(sameOrg)))
	f.serve(rbac.MethodGetTransactionReceipt, receipt(all))
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionReceipt, []any{h})
	assert.JSONEq(t, string(wantReceipt), string(drfResult(t, resp.Response)), "dry-run receipt diverges from production: %s", raw)
	assert.Equal(t, drfResult(t, []byte(f.mirror(t, rbac.MethodGetTransactionReceipt, []any{h}))), drfResult(t, resp.Response),
		"dry-run and the View-as mirror give the same answer")
}

// The write-method trace's logs_visible_to_user is what the member would see
// in the receipt of that tx: admin exemption applies, embedded addresses are
// field-redacted, a no-grant emitter is dropped.
func TestDryRun_TraceLogsVisibleToUser_UseReceiptPipeline_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	traceLog := func(contract, from, to string) map[string]any {
		return map[string]any{
			"address": contract,
			"topics":  []string{drfTransferT0, zeroPadAddrToTopic(from), zeroPadAddrToTopic(to)},
			"data":    "0x00000000000000000000000000000000000000000000000000000000000003e8",
		}
	}
	f.serve("debug_traceCall", drfEnvelope(t, map[string]any{
		"type": "CALL", "from": drfMemberEOA, "to": drfContractO, "gas": "0x0", "gasUsed": "0x0", "input": "0x", "value": "0x0",
		"logs": []any{
			traceLog(drfContractO, drfMemberEOA, drfForeignEOA),
			traceLog(drfAdminCO, drfForeignEOA, drfOtherEOA),
		},
	}))

	resp, raw := f.dryRun(t, "eth_sendTransaction", []any{map[string]any{"from": drfMemberEOA, "to": drfContractO, "data": "0x"}})
	require.Equal(t, "allow", resp.Decision, raw)
	require.Len(t, resp.LogsEmitted, 2)

	visible := map[string]string{}
	for _, l := range resp.LogsVisibleToUser {
		var entry struct {
			Address         string   `json:"address"`
			Topics          []string `json:"topics"`
			TransactionHash *string  `json:"transactionHash"`
		}
		require.NoError(t, json.Unmarshal(l, &entry))
		assert.Nil(t, entry.TransactionHash, "the pipeline's placeholder hash must not surface: %s", l)
		visible[strings.ToLower(entry.Address)] = strings.ToLower(strings.Join(entry.Topics, ","))
	}
	require.Contains(t, visible, drfContractO, raw)
	require.Contains(t, visible, drfAdminCO, "the admin-exemption log is part of the member's receipt view: %s", raw)
	assert.NotContains(t, visible[drfContractO], bare(drfForeignEOA), "embedded foreign EOA must be zeroed as in the real receipt: %s", raw)
	assert.Contains(t, visible[drfContractO], bare(drfMemberEOA), "the member's own address stays")
}

// Without the production response filter the dry-run cannot produce the
// user's view. Nothing from the node is returned, and the audit row records
// the real outcome (an error), not an "allow" for an answer never served.
func TestDryRun_WithoutResponseFilter_FailsClosedAndAuditsError_RD1308(t *testing.T) {
	const h = "0x1308000000000000000000000000000000000000000000000000000000000008"
	cases := []struct {
		name   string
		method string
		params []any
		node   func(t *testing.T, f *drfFixture)
	}{
		{
			name:   "read",
			method: rbac.MethodGetTransactionByHash,
			params: []any{h},
			node: func(t *testing.T, f *drfFixture) {
				f.serve(rbac.MethodGetTransactionByHash, drfEnvelope(t, drfTx(drfForeignEOA, drfOtherEOA, h)))
			},
		},
		{
			name:   "trace",
			method: "eth_sendTransaction",
			params: []any{map[string]any{"from": drfMemberEOA, "to": drfContractO, "data": "0x"}},
			node: func(t *testing.T, f *drfFixture) {
				f.serve("debug_traceCall", drfEnvelope(t, map[string]any{
					"type": "CALL", "from": drfMemberEOA, "to": drfContractO, "input": "0x", "value": "0x0",
					"logs": []any{map[string]any{
						"address": drfContractO,
						"topics":  []string{drfTransferT0, zeroPadAddrToTopic(drfMemberEOA), zeroPadAddrToTopic(drfForeignEOA)},
						"data":    "0x00000000000000000000000000000000000000000000000000000000000003e8",
					}},
				}))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setupDRFFixture(t)
			tc.node(t, f)
			f.ts.jsonrpcProcessor = nil

			w := f.dryRunRaw(t, tc.method, tc.params)
			require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			assert.JSONEq(t, `{"error":"internal error"}`, w.Body.String())
			assert.NotContains(t, strings.ToLower(w.Body.String()), bare(drfForeignEOA), "no node data may be returned")
			assert.Equal(t, [][2]string{{"error", "response_filter_unavailable"}}, f.dryRunAuditRows(t))
		})
	}
}

// The View-as RPC mirror pins the RD-915 nested-call gate to the scope org, as
// the dry-run already does: a wrapper call in org O that STATICCALLs into org
// P is allowed for the member's own call (they belong to both) but denied
// under an org-O impersonation scope.
func TestEthCallTracing_ViewerOrgScopePinsNestedCalls_RD1308(t *testing.T) {
	wrapperO := fixedAddr(0x31)
	foreignP := fixedAddr(0x32)
	frame := traceFrame{Type: "CALL", From: fixedAddr(0x33), To: wrapperO,
		Calls: []traceFrame{{Type: "STATICCALL", From: wrapperO, To: foreignP}}}
	scripted := newScriptedTracer(t, frame, frame, frame)
	proc, ts := setupProcessorWithMockTracer(t, scripted)
	ctx := context.Background()

	orgO := registerForeignOrgContract(t, ctx, ts, wrapperO)
	orgP := registerForeignOrgContract(t, ctx, ts, foreignP)
	did := "did:drf:multi-" + uuid.New().String()
	uid := drCreateUserInGroup(t, ts.db, did, drCreateGroup(t, ts.db, orgO, "drf-o-"+orgO[:6], nil, false))
	impAddUserToGroup(t, ts.db, uid, drCreateGroup(t, ts.db, orgP, "drf-p-"+orgP[:6], nil, false))

	require.Nil(t, proc.validateEthCallWithTracing(ctx, ethCallReq(did, wrapperO), wrapperO),
		"control: the member's own call may reach org P, they are a member")
	denied := proc.validateEthCallWithTracing(withViewerOrgScope(ctx, orgO), ethCallReq(did, wrapperO), wrapperO)
	require.NotNil(t, denied, "an org-O impersonation scope must not reach org P through a wrapper")
	assert.Equal(t, http.StatusForbidden, denied.StatusCode)
	require.NotNil(t, proc.validateEthCallWithTracing(withViewerOrgScope(ctx, ""), ethCallReq(did, wrapperO), wrapperO),
		"an empty scope denies instead of widening to every org")
}

// The participant rule admits the member's own transactions whatever they
// touch. Under the path-org pin, a transaction (or receipt) addressed to a
// contract of another org stays out even though the member sent it.
func TestDryRun_OwnTxWithOtherOrgContract_IsNull_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const toP = "0x1308000000000000000000000000000000000000000000000000000000000011"
	const toO = "0x1308000000000000000000000000000000000000000000000000000000000012"

	bodyP := drfEnvelope(t, drfTx(drfMemberEOA, drfContractP, toP))
	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetTransactionByHash, []any{toP}, bodyP))), bare(drfCalldata)[:40],
		"control: the member's own call sees their org-P transaction")
	f.serve(rbac.MethodGetTransactionByHash, bodyP)
	resp, raw := f.dryRun(t, rbac.MethodGetTransactionByHash, []any{toP})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "the member's org-P tx appeared in an org-O dry-run: %s", raw)
	assert.Equal(t, "null", string(drfResult(t, []byte(f.mirror(t, rbac.MethodGetTransactionByHash, []any{toP})))))

	receiptP := drfEnvelope(t, map[string]any{
		"transactionHash": toP, "from": drfMemberEOA, "to": drfContractP, "status": "0x1", "logs": []any{},
		"logsBloom": "0x" + strings.Repeat("0", 512), "contractAddress": nil,
	})
	f.serve(rbac.MethodGetTransactionReceipt, receiptP)
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionReceipt, []any{toP})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "the member's org-P receipt was returned: %s", raw)

	// A deployment receipt whose created contract belongs to P is P's too.
	deployP := drfEnvelope(t, map[string]any{
		"transactionHash": toP, "from": drfMemberEOA, "to": nil, "status": "0x1", "logs": []any{},
		"logsBloom": "0x" + strings.Repeat("0", 512), "contractAddress": drfContractP,
	})
	f.serve(rbac.MethodGetTransactionReceipt, deployP)
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionReceipt, []any{toP})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "the member's org-P deployment receipt was returned: %s", raw)

	// Positive control: the member's own tx with an org-O contract.
	f.serve(rbac.MethodGetTransactionByHash, drfEnvelope(t, drfTx(drfMemberEOA, drfContractO, toO)))
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionByHash, []any{toO})
	assert.Contains(t, strings.ToLower(string(resp.Response)), bare(drfCalldata)[:40], "own org-O tx must stay visible: %s", raw)
}

// The View-as RPC mirror serves only the methods whose read path is pinned:
// writes, traces and block-level reads are refused before they reach the node.
func TestImpersonationRPC_RefusesMethodsOutsideTheReadSet_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	for _, method := range []string{
		"eth_sendTransaction", "eth_sendRawTransaction", "debug_traceTransaction",
		"eth_getBlockReceipts", "eth_getBlockByNumber", "ETH_GETTRANSACTIONBYHASH",
	} {
		t.Run(method, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": []any{"0x1"}})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodGet, impersonatePath(drfMemberDID, f.orgO, "/rpc"), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Test-Auth-Method", "jwt_admin")
			w := httptest.NewRecorder()
			f.router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.False(t, f.reached(method), "%s reached the node through the read-only mirror", method)
		})
	}
	// The read set still works.
	f.serve("eth_chainId", []byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	assert.Equal(t, `"0x1"`, string(drfResult(t, []byte(f.mirror(t, "eth_chainId", []any{})))))
}

// visibleTo unlock and the ordinary param-rule fallback both follow the pin:
// only a share whose send was authorised under the path org counts, and only
// the path org's contracts unlock.
func TestDryRun_VisibleToUnlockAndFallback_PinnedToPathOrg_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	ctx := context.Background()
	const (
		cUnlock = "0x13080000000000000000000000000000000000f1" // org O, deny-all grant, unlock flag on
		cSelf   = "0x13080000000000000000000000000000000000f2" // org O, Transfer only when `to` is the member
		hO      = "0x1308000000000000000000000000000000000000000000000000000000000021"
		hP      = "0x1308000000000000000000000000000000000000000000000000000000000022"
	)
	unlockID := wiringCreateContractWithABI(t, f.ts.db, f.orgO, cUnlock, "unlock", erc20ABI)
	wiringCreateGrant(t, f.ts.db, unlockID, f.memberGroup, &rbac.EventRulesField{})
	require.NoError(t, f.ts.db.UpdateContractAllowVisibleToUnlock(ctx, unlockID, true))
	require.NoError(t, f.ts.db.UpdateContractAllowVisibleToUnlock(ctx, f.contractIDs[drfContractP], true))
	selfID := wiringCreateContractWithABI(t, f.ts.db, f.orgO, cSelf, "self", erc20ABI)
	wiringCreateGrant(t, f.ts.db, selfID, f.memberGroup,
		&rbac.EventRulesField{Rules: []rbac.EventRule{{Topic0: drfTransferT0, Name: "Transfer", ParamRules: []rbac.ParamRule{{Index: 1, MustBe: "self"}}}}})

	require.NoError(t, f.ts.db.SaveTxVisibility(ctx, hO, []string{drfMemberDID}, "did:drf:sender-o", f.orgO))
	require.NoError(t, f.ts.db.SaveTxVisibility(ctx, hP, []string{drfMemberDID}, "did:drf:sender-p", f.orgP))
	f.txByHash[hO] = drfTx(drfForeignEOA, cUnlock, hO)
	f.txByHash[hP] = drfTx(drfForeignEOA, cUnlock, hP)

	type logKey struct{ contract, tx string }
	logs := []any{
		drfTransferLog(cUnlock, drfForeignEOA, drfOtherEOA, hO, "0x0"),      // O share, O contract: unlocked
		drfTransferLog(cUnlock, drfForeignEOA, drfOtherEOA, hP, "0x1"),      // P share: no unlock in O
		drfTransferLog(drfContractP, drfForeignEOA, drfOtherEOA, hP, "0x2"), // P contract, P share: never in O
		drfTransferLog(cSelf, drfForeignEOA, drfOtherEOA, hO, "0x3"),        // param rule fails; O share: fallback admits
		drfTransferLog(cSelf, drfForeignEOA, drfOtherEOA, hP, "0x4"),        // param rule fails; P share: dropped
	}
	want := map[logKey]bool{{cUnlock, hO}: true, {cSelf, hO}: true}
	params := []any{map[string]any{"address": cUnlock, "fromBlock": "0x1", "toBlock": "0x1"}}
	body := drfEnvelope(t, logs)

	collect := func(raw json.RawMessage) map[logKey]bool {
		var got []struct {
			Address         string `json:"address"`
			TransactionHash string `json:"transactionHash"`
		}
		require.NoError(t, json.Unmarshal(raw, &got), string(raw))
		out := map[logKey]bool{}
		for _, l := range got {
			out[logKey{strings.ToLower(l.Address), strings.ToLower(l.TransactionHash)}] = true
		}
		return out
	}

	own := collect(drfResult(t, f.production(t, rbac.MethodGetLogs, params, body)))
	require.True(t, own[logKey{cUnlock, hP}], "control: the member's own call unlocks with the org-P share")
	require.True(t, own[logKey{cSelf, hP}], "control: the member's own call takes the fallback with the org-P share")

	f.serve(rbac.MethodGetLogs, body)
	resp, raw := f.dryRun(t, rbac.MethodGetLogs, params)
	assert.Equal(t, want, collect(drfResult(t, resp.Response)), "dry-run: %s", raw)
	assert.Equal(t, want, collect(drfResult(t, []byte(f.mirror(t, rbac.MethodGetLogs, params)))), "mirror")
}

// Embedded-address field redaction resolves visibility in the path org: an
// org-O log naming an org-P contract the member sees through their P role is
// zeroed in the org-O dry-run, while the member's own call shows it.
func TestDryRun_FieldRedactionPinnedToPathOrg_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const h = "0x1308000000000000000000000000000000000000000000000000000000000031"
	logs := []any{drfTransferLog(drfContractO, drfMemberEOA, drfContractP, h, "0x0")}
	params := []any{map[string]any{"address": drfContractO, "fromBlock": "0x1", "toBlock": "0x1"}}
	body := drfEnvelope(t, logs)

	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetLogs, params, body))), bare(drfContractP),
		"control: the member's own call shows the org-P contract it can see through its P role")
	f.serve(rbac.MethodGetLogs, body)
	resp, raw := f.dryRun(t, rbac.MethodGetLogs, params)
	lower := strings.ToLower(string(resp.Response))
	assert.Contains(t, lower, bare(drfMemberEOA), "the log stays admitted: %s", raw)
	assert.NotContains(t, lower, bare(drfContractP), "an org-P address must be zeroed in an org-O dry-run: %s", raw)
	assert.NotContains(t, strings.ToLower(f.mirror(t, rbac.MethodGetLogs, params)), bare(drfContractP), "mirror")
}

// The visibility resolver pins group-derived Full to the scope org and fails
// closed on an empty scope.
func TestGetBatchVisibility_ViewerOrgScope_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	ctx := context.Background()
	addrs := []string{drfContractO, drfContractP}

	level := func(ctx context.Context, addr string) explorer.VisibilityLevel {
		detailed, err := f.ts.db.GetBatchVisibilityDetailed(ctx, drfMemberDID, addrs)
		require.NoError(t, err)
		plain, err := f.ts.db.GetBatchVisibility(ctx, drfMemberDID, addrs)
		require.NoError(t, err)
		require.Equal(t, plain[addr], detailed[addr].Level, "plain and detailed agree for %s", addr)
		return plain[addr]
	}
	assert.Equal(t, explorer.VisibilityFull, level(ctx, drfContractP), "unscoped: P admin sees the P contract")
	assert.Equal(t, explorer.VisibilityFull, level(ctx, drfContractO))

	inO := withViewerOrgScope(ctx, f.orgO)
	assert.Equal(t, explorer.VisibilityRedacted, level(inO, drfContractP), "scoped to O: no Full through the P role")
	assert.Equal(t, explorer.VisibilityFull, level(inO, drfContractO), "scoped to O: O grant still counts")

	empty := withViewerOrgScope(ctx, "")
	assert.Equal(t, explorer.VisibilityRedacted, level(empty, drfContractO), "an empty scope grants nothing")
}

// Fail-closed edges of the scope helpers.
func TestViewerOrgScope_FailsClosed_RD1308(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, []string{"a", "b"}, restrictToViewerOrgScope(ctx, []string{"a", "b"}), "no scope: unchanged")
	assert.Equal(t, []string{"b"}, restrictToViewerOrgScope(withViewerOrgScope(ctx, "b"), []string{"a", "b"}))
	assert.Empty(t, restrictToViewerOrgScope(withViewerOrgScope(ctx, "c"), []string{"a", "b"}), "not a member of the scope org")
	assert.Empty(t, restrictToViewerOrgScope(withViewerOrgScope(ctx, ""), []string{"a", ""}), "empty scope matches nothing")

	// A visibility store that cannot answer per org contributes no shares.
	p := &JSONRPCProcessor{txVisibilityStore: shareEverythingStore{}}
	all, err := p.txVisibilityForViewer(ctx, []string{"0x1"})
	require.NoError(t, err)
	require.NotEmpty(t, all, "control: unscoped lookup returns the share")
	scoped, err := p.txVisibilityForViewer(withViewerOrgScope(ctx, "org"), []string{"0x1"})
	require.NoError(t, err)
	assert.Empty(t, scoped, "a store without the per-org lookup must not fall back to every share")

	// Membership outside the scope org resolves no permissions.
	f := setupDRFFixture(t)
	res := &rbac.AccessCheckResult{Allowed: true, UserID: f.memberID, OrgID: f.orgO}
	require.NotNil(t, f.proc.resolvePermsForFilter(withViewerOrgScope(ctx, f.orgO), res))
	assert.Nil(t, f.proc.resolvePermsForFilter(withViewerOrgScope(ctx, uuid.New().String()), res))
	assert.Nil(t, f.proc.resolvePermsForFilter(withViewerOrgScope(ctx, ""), res))
	assert.Empty(t, f.proc.viewerAdminContracts(withViewerOrgScope(ctx, f.orgO), f.memberID, []string{drfContractP}),
		"no admin exemption on another org's contract under an org-O scope")
	assert.True(t, f.proc.viewerAdminContracts(ctx, f.memberID, []string{drfContractP})[drfContractP], "control: unscoped")
}

type shareEverythingStore struct{}

func (shareEverythingStore) GetBatchTxVisibility(_ context.Context, hashes []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, h := range hashes {
		out[h] = []string{drfMemberDID}
	}
	return out, nil
}

// logs_visible_to_user across the grant states, through the real trace path.
// Every visible log is one the member would see in that transaction's
// receipt, a subset of logs_emitted.
func TestDryRun_TraceLogsVisibleToUser_GrantMatrix_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const (
		cWild = "0x13080000000000000000000000000000000000e1" // wildcard event rules
		cDeny = "0x13080000000000000000000000000000000000e2" // deny-all event rules
		cSelf = "0x13080000000000000000000000000000000000e3" // Transfer only when `to` is the member
		cNone = "0x13080000000000000000000000000000000000e4" // org-O contract, no grant
		other = "0x9999999999999999999999999999999999999999999999999999999999999999"
		zero  = "0x0000000000000000000000000000000000000000"
	)
	wiringCreateGrant(t, f.ts.db, wiringCreateContractWithABI(t, f.ts.db, f.orgO, cWild, "wild", erc20ABI), f.memberGroup,
		&rbac.EventRulesField{Wildcard: true})
	wiringCreateGrant(t, f.ts.db, wiringCreateContractWithABI(t, f.ts.db, f.orgO, cDeny, "deny", erc20ABI), f.memberGroup,
		&rbac.EventRulesField{})
	wiringCreateGrant(t, f.ts.db, wiringCreateContractWithABI(t, f.ts.db, f.orgO, cSelf, "self", erc20ABI), f.memberGroup,
		&rbac.EventRulesField{Rules: []rbac.EventRule{{Topic0: drfTransferT0, Name: "Transfer", ParamRules: []rbac.ParamRule{{Index: 1, MustBe: "self"}}}}})
	wiringCreateContractWithABI(t, f.ts.db, f.orgO, cNone, "none", erc20ABI)

	type emitted struct {
		name, contract, topic0, from, to string
		visible                          bool
		visibleAsParticipant             bool
	}
	cases := []emitted{
		{"wildcard grant admits any event", cWild, other, drfForeignEOA, drfOtherEOA, true, true},
		{"deny-all grant drops", cDeny, drfTransferT0, drfForeignEOA, drfOtherEOA, false, true},
		{"param rule self matches the member's linked address", cSelf, drfTransferT0, drfForeignEOA, drfMemberEOA, true, true},
		{"param rule self fails for someone else", cSelf, drfTransferT0, drfForeignEOA, drfOtherEOA, false, true},
		{"allowlist drops an unlisted topic", drfContractO, other, drfForeignEOA, drfOtherEOA, false, true},
		{"no grant drops", cNone, drfTransferT0, drfForeignEOA, drfOtherEOA, false, false},
		{"other-org contract drops", drfContractP, drfTransferT0, drfForeignEOA, drfOtherEOA, false, false},
	}
	logs := make([]any, 0, len(cases))
	for _, c := range cases {
		logs = append(logs, map[string]any{
			"address": c.contract,
			"topics":  []string{c.topic0, zeroPadAddrToTopic(c.from), zeroPadAddrToTopic(c.to)},
			"data":    "0x00000000000000000000000000000000000000000000000000000000000003e8",
		})
	}

	for _, sender := range []string{drfOtherEOA, drfMemberEOA} {
		asParticipant := sender == drfMemberEOA
		t.Run("sender="+sender, func(t *testing.T) {
			f.serve("debug_traceCall", drfEnvelope(t, map[string]any{
				"type": "CALL", "from": sender, "to": cWild, "input": "0x", "value": "0x0", "logs": logs,
			}))
			resp, raw := f.dryRun(t, "eth_sendTransaction", []any{map[string]any{"to": cWild, "data": "0x"}})
			require.Equal(t, "allow", resp.Decision, raw)
			require.Len(t, resp.LogsEmitted, len(cases))

			type key struct{ contract, topic0, to string }
			got := map[key]bool{}
			for _, l := range resp.LogsVisibleToUser {
				var e struct {
					Address         string   `json:"address"`
					Topics          []string `json:"topics"`
					TransactionHash *string  `json:"transactionHash"`
				}
				require.NoError(t, json.Unmarshal(l, &e))
				require.Nil(t, e.TransactionHash, "the synthesized receipt hash must not surface")
				require.Len(t, e.Topics, 3)
				got[key{strings.ToLower(e.Address), strings.ToLower(e.Topics[0]), strings.ToLower(e.Topics[2])}] = true
			}
			for _, c := range cases {
				want := c.visible
				if asParticipant {
					// RD-1162: the sender sees their own transaction's logs on
					// every contract they hold a grant to.
					want = c.visibleAsParticipant
				}
				to := c.to
				if to != drfMemberEOA {
					to = zero // admitted, but a non-member address is field-redacted
				}
				k := key{c.contract, strings.ToLower(c.topic0), strings.ToLower(zeroPadAddrToTopic(to))}
				assert.Equalf(t, want, got[k], "%s", c.name)
			}
		})
	}
}

// Explorer View-as organization scope is tracked separately in RD-1315.
// This test preserves the current explorer behavior while RD-1308 changes
// the dry-run and RPC surfaces.
func TestExplorerViewAs_ExistingVisibilityScope_RD1315(t *testing.T) {
	f := setupDRFFixture(t)
	var gotScoped bool
	var gotLevel explorer.VisibilityLevel
	router := gin.New()
	probe := router.Group("/probe/:target_did/in/:org_id")
	probe.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_subject", drfAdminDID)
		c.Set("admin_org_ids", []string{f.orgO})
		c.Next()
	}, f.ts.impersonationGateMiddleware())
	probe.GET("/explorer-handler", func(c *gin.Context) {
		ctx := c.Request.Context()
		_, gotScoped = viewscope.Org(ctx)
		gotLevel = f.ts.calculateAddressVisibilityWithDID(ctx, f.ts.getViewerDIDFromRequest(c), drfContractP).Level
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/probe/"+drfMemberDID+"/in/"+f.orgO+"/explorer-handler", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	assert.False(t, gotScoped, "the explorer mirror retains its current context")
	assert.Equal(t, explorer.VisibilityFull, gotLevel, "the explorer visibility resolver retains its current membership scope")
}

// filterDryRunLogs is a test-only wrapper that pins the rbac.FilterEventLogs
// grant states (wildcard / deny / allowlist) without a Server, passing no
// linked addresses, ABI provider, visibleTo context or admin map. Dry-run
// itself does NOT use it: logs_visible_to_user comes from the production
// receipt filter (dryRunTraceLogsVisibleToUser, RD-1308).
func filterDryRunLogs(logs []json.RawMessage, perms *rbac.EffectivePermissions, user *rbac.User, viewerDID string) []json.RawMessage {
	if len(logs) == 0 || perms == nil {
		return nil
	}
	_ = user
	_ = viewerDID
	return rbac.FilterEventLogs(logs, perms, []string{}, nil, nil, nil)
}

// A deployment transaction has no `to`: the envelope pin judges it by the
// contract it creates (CREATE from sender + nonce).
func TestDryRun_OwnDeploymentOfOtherOrgContract_IsNull_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	const h = "0x1308000000000000000000000000000000000000000000000000000000000041"
	deploy := func(nonce uint64) []byte {
		tx := drfTx(drfMemberEOA, "", h)
		tx["to"] = nil
		tx["nonce"] = hexutil.EncodeUint64(nonce)
		return drfEnvelope(t, tx)
	}
	created := func(nonce uint64) string {
		return strings.ToLower(gethcrypto.CreateAddress(gethcommon.HexToAddress(drfMemberEOA), nonce).Hex())
	}
	wiringCreateContractWithABI(t, f.ts.db, f.orgP, created(11), "deployed-in-P", erc20ABI)
	wiringCreateContractWithABI(t, f.ts.db, f.orgO, created(12), "deployed-in-O", erc20ABI)

	bodyP := deploy(11)
	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetTransactionByHash, []any{h}, bodyP))), bare(drfCalldata)[:40],
		"control: the member's own call sees their org-P deployment")
	f.serve(rbac.MethodGetTransactionByHash, bodyP)
	resp, raw := f.dryRun(t, rbac.MethodGetTransactionByHash, []any{h})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "an org-P deployment appeared in an org-O dry-run: %s", raw)
	assert.Equal(t, "null", string(drfResult(t, []byte(f.mirror(t, rbac.MethodGetTransactionByHash, []any{h})))))

	f.serve(rbac.MethodGetTransactionByHash, deploy(12))
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionByHash, []any{h})
	assert.Contains(t, strings.ToLower(string(resp.Response)), bare(drfCalldata)[:40], "own org-O deployment stays visible: %s", raw)

	// No nonce on a deployment object: cannot tell which contract it creates.
	tx := drfTx(drfMemberEOA, "", h)
	tx["to"] = nil
	delete(tx, "nonce")
	f.serve(rbac.MethodGetTransactionByHash, drfEnvelope(t, tx))
	resp, raw = f.dryRun(t, rbac.MethodGetTransactionByHash, []any{h})
	assert.Equal(t, "null", string(drfResult(t, resp.Response)), "fail closed: %s", raw)
}

// Embedded-address redaction counts only disclosure grants requested in the
// path org: a Full grant the member holds through org P does not unzero the
// disclosed subject in an org-O dry-run.
func TestDryRun_DisclosureGrantFromOtherOrg_NotApplied_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	ctx := context.Background()
	const subjectDID = "did:drf:subject"
	const subjectEOA = "0x1308000000000000000000000000000000000d05"
	subjectID := drCreateUserInGroup(t, f.ts.db, subjectDID, drCreateGroup(t, f.ts.db, f.orgP, "drf-p-subjects", nil, false))
	require.NoError(t, f.ts.db.SystemLinkEthAddress(ctx, subjectDID, subjectEOA))
	reqID := uuid.New().String()
	scope := `{"disclosure_level":"full"}`
	_, err := f.ts.db.Conn().ExecContext(ctx, `
		INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'rd1308', 'approved', NOW())`, reqID, drfMemberDID, subjectID, f.orgP, scope)
	require.NoError(t, err)
	_, err = f.ts.db.Conn().ExecContext(ctx, `
		INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, 'rd1308hash', $3::jsonb, NOW(), NOW() + interval '1 day')`, uuid.New().String(), reqID, scope)
	require.NoError(t, err)

	const h = "0x1308000000000000000000000000000000000000000000000000000000000042"
	params := []any{map[string]any{"address": drfContractO, "fromBlock": "0x1", "toBlock": "0x1"}}
	body := drfEnvelope(t, []any{drfTransferLog(drfContractO, drfMemberEOA, subjectEOA, h, "0x0")})
	require.Contains(t, strings.ToLower(string(f.production(t, rbac.MethodGetLogs, params, body))), bare(subjectEOA),
		"control: the member's own call shows the subject it holds a grant on")
	f.serve(rbac.MethodGetLogs, body)
	resp, raw := f.dryRun(t, rbac.MethodGetLogs, params)
	assert.Contains(t, strings.ToLower(string(resp.Response)), bare(drfMemberEOA), "the log stays admitted: %s", raw)
	assert.NotContains(t, strings.ToLower(string(resp.Response)), bare(subjectEOA), "an org-P disclosure grant applied in an org-O dry-run: %s", raw)
}

// A trace that reverts yields no visible logs: its receipt would carry none.
func TestDryRun_RevertedTrace_NoVisibleLogs_RD1308(t *testing.T) {
	f := setupDRFFixture(t)
	f.serve("debug_traceCall", drfEnvelope(t, map[string]any{
		"type": "CALL", "from": drfMemberEOA, "to": drfContractO, "input": "0x", "value": "0x0", "error": "execution reverted",
		"logs": []any{map[string]any{
			"address": drfContractO,
			"topics":  []string{drfTransferT0, zeroPadAddrToTopic(drfMemberEOA), zeroPadAddrToTopic(drfOtherEOA)},
			"data":    "0x",
		}},
	}))
	resp, raw := f.dryRun(t, "eth_sendTransaction", []any{map[string]any{"from": drfMemberEOA, "to": drfContractO, "data": "0x"}})
	require.Equal(t, "allow", resp.Decision, raw)
	assert.Empty(t, resp.LogsVisibleToUser, raw)
}

// The View-as RPC mirror's method set is reviewed explicitly; a method added
// to dry-run does not silently open on the mirror.
func TestImpersonationRPCMethods_ExactSet_RD1308(t *testing.T) {
	want := []string{
		"eth_call", "eth_getLogs", "eth_getTransactionReceipt", "eth_getTransactionByHash",
		"eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_blockNumber", "eth_chainId",
		"eth_gasPrice", "net_version", "net_listening", "web3_clientVersion",
	}
	got := make([]string, 0, len(impersonationRPCMethods))
	for m, ok := range impersonationRPCMethods {
		if ok {
			got = append(got, m)
		}
	}
	assert.ElementsMatch(t, want, got)
}
