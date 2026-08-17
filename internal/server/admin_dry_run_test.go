package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dryRunTestServer wraps testServerRBAC and exposes a router whose
// dry-run route is preceded by a tiny test-mode middleware that
// injects the auth context fields the production middleware would set
// (auth_method, admin_subject). The point is not to test gin auth
// itself — that's covered elsewhere — but to drive the dry-run
// handler's own gates from a test fixture.
//
// Header set by tests:
//   - X-Test-Auth-Method: "jwt_admin" | "admin_token" | ""  (empty = unauth)
//   - X-Test-Admin-Subject: <admin DID>  (only honoured for jwt_admin)
type dryRunTestServer struct {
	*testServerRBAC
}

func setupDryRunTestServer(t *testing.T) *dryRunTestServer {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	// Inject a minimal middleware that mirrors what
	// adminAuthMiddleware sets in production. Real auth is exercised
	// elsewhere (admin_auth_test.go); here we just need the context
	// values present so the handler's own gates run.
	router := gin.New()
	api := router.Group("/api")
	api.Use(func(c *gin.Context) {
		method := c.GetHeader("X-Test-Auth-Method")
		if method == "" {
			c.Next()
			return
		}
		c.Set("auth_method", method)
		if method == "jwt_admin" {
			c.Set("admin_subject", c.GetHeader("X-Test-Admin-Subject"))
		}
		c.Next()
	})
	api.POST("/orgs/:org_id/dry-run", ts.handleDryRun)

	ts.router = router
	return &dryRunTestServer{testServerRBAC: ts}
}

func dryRunPost(t *testing.T, srv *dryRunTestServer, orgID, authMethod, adminDID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	jb, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/dry-run", bytes.NewReader(jb))
	req.Header.Set("Content-Type", "application/json")
	if authMethod != "" {
		req.Header.Set("X-Test-Auth-Method", authMethod)
	}
	if adminDID != "" {
		req.Header.Set("X-Test-Admin-Subject", adminDID)
	}
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// Fixture: one org, one tier-2 admin, one ordinary user (granted on a
// contract), and a fake "user not in this org" account.
type dryRunFixture struct {
	srv             *dryRunTestServer
	orgID           string
	otherOrgID      string
	adminDID        string
	userDID         string
	otherOrgUserDID string
	userGroupID     string
	contractAddr    string
}

func setupDryRunFixture(t *testing.T) *dryRunFixture {
	t.Helper()
	srv := setupDryRunTestServer(t)
	ctx := context.Background()
	database := srv.db

	// Two orgs — admin's org + a different one to test cross-org isolation.
	orgID := uuid.New().String()
	otherOrgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "dr-a", Name: "DR A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: otherOrgID, Slug: "dr-b", Name: "DR B", Settings: map[string]any{}}))

	// Tier-2 admin group + member.
	adminGroupID := drCreateGroup(t, database, orgID, "dr-a-admin", nil, true /* is_org_admin */)
	adminDID := "did:dr:admin"
	drCreateUserInGroup(t, database, adminDID, adminGroupID)

	// Ordinary user with access to one contract.
	userGroupID := drCreateGroup(t, database, orgID, "dr-a-user", nil, false)
	userDID := "did:dr:user"
	drCreateUserInGroup(t, database, userDID, userGroupID)
	contractAddr := "0x1111111111111111111111111111111111111111"
	contractID := drCreateContract(t, database, orgID, contractAddr, "DRContract")
	drCreateGrant(t, database, contractID, userGroupID)

	// User in the other org, no membership in admin's org.
	otherOrgGroupID := drCreateGroup(t, database, otherOrgID, "dr-b-only", nil, false)
	otherOrgUserDID := "did:dr:cross-org-user"
	drCreateUserInGroup(t, database, otherOrgUserDID, otherOrgGroupID)

	return &dryRunFixture{
		srv:             srv,
		orgID:           orgID,
		otherOrgID:      otherOrgID,
		adminDID:        adminDID,
		userDID:         userDID,
		otherOrgUserDID: otherOrgUserDID,
		userGroupID:     userGroupID,
		contractAddr:    contractAddr,
	}
}

func TestDryRun_RejectsSuperAdminToken(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "admin_token", "" /* DID irrelevant */, body)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "X-Admin-Token credentials are not authorised")
}

// TestDryRun_RejectsOperatorToken (RD-1132, RD-1159 Phase 2) is the explicit
// operator-token companion to TestDryRun_RejectsSuperAdminToken. The gate at
// admin_dry_run.go:110 rejects `auth_method == "admin_token" || auth_method == "operator_token"`,
// but the pre-existing test only drove the FULL admin_token. RD-1132 split the
// single X-Admin-Token principal into admin_token (full) + operator_token
// (restricted platform onboarder); impersonating a user reads tenant data as
// that user, which NEITHER token may do. This pins the restricted operator
// principal → 403 on the same surface, so a future refactor that forgets the
// operator arm of the OR is caught.
func TestDryRun_RejectsOperatorToken(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "operator_token", "" /* DID irrelevant */, body)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "X-Admin-Token credentials are not authorised")
}

func TestDryRun_RejectsUnauthenticated(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "" /* no auth */, "", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDryRun_RejectsSelfDryRun(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.adminDID, // admin trying to dry-run themselves
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "cannot dry-run as yourself")
}

func TestDryRun_RejectsUnsupportedMethod(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc":      map[string]any{"method": "eth_subscribe", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "method not supported")
}

func TestDryRun_CrossOrgUserReturns404(t *testing.T) {
	f := setupDryRunFixture(t)
	// Admin in Org A, target user only in Org B → identical generic
	// 404 to the "user does not exist at all" case.
	body := map[string]any{
		"user_did": f.otherOrgUserDID,
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "user not found")
}

func TestDryRun_NonExistentUserReturns404(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": "did:dr:nobody",
		"rpc":      map[string]any{"method": "eth_call", "params": []any{}},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDryRun_DenyDecisionLoggedAndReturned exercises the full flow for
// a denial case: the impersonated user has no access to a target
// contract, RBAC says deny, and the handler returns
// `{"decision":"deny","reason":...}` while writing an impersonation_log
// row.
func TestDryRun_DenyDecisionLoggedAndReturned(t *testing.T) {
	f := setupDryRunFixture(t)
	// User is granted on f.contractAddr; we point the call at a
	// different unregistered address to force RBAC deny.
	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_call",
			"params": []any{
				map[string]any{"to": "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead", "data": "0x"},
				"latest",
			},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp dryRunResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "deny", resp.Decision, "expected deny on unregistered target")
	assert.NotEmpty(t, resp.Reason)

	// Audit row written.
	var count int
	require.NoError(t,
		f.srv.db.Conn().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM impersonation_log
			 WHERE actor_did = $1 AND impersonated_did = $2 AND decision = 'deny'`,
			f.adminDID, f.userDID).Scan(&count),
	)
	assert.Equal(t, 1, count, "expected exactly one deny row in impersonation_log")
}

const (
	dryRunBalanceOfABI      = `[{"name":"balanceOf","type":"function","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`
	dryRunBalanceOfSelector = "0x70a08231"
)

// TestDryRun_FunctionLevelRules pins dry-run's verdict to the enforcement
// path's on a contract whose grant carries function-level rules. Pre-fix the
// handler left FunctionSelector unset, so validateFunctionSelector denied
// every such contract with "function selector required" — a call the user may
// make and one blocked by a param rule were indistinguishable.
func TestDryRun_FunctionLevelRules(t *testing.T) {
	f := setupDryRunFixture(t)
	ctx := context.Background()

	// Grant the user balanceOf(self) on a contract of its own, and give the
	// param rule what it needs: an ABI to decode the argument with, and a
	// linked address to compare it against.
	selfAddr := "0x00000000000000000000000000000000000000a1"
	otherAddr := "0x00000000000000000000000000000000000000b2"
	contractAddr := "0x2222222222222222222222222222222222222222"
	contractID := drCreateContract(t, f.srv.db, f.orgID, contractAddr, "DRFunctionRules")
	require.NoError(t, f.srv.db.UpdateContractABI(ctx, contractID, dryRunBalanceOfABI))
	require.NoError(t, f.srv.db.SystemLinkEthAddress(ctx, f.userDID, selfAddr))
	require.NoError(t, f.srv.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: f.userGroupID,
		Functions: []rbac.FunctionRule{{
			Selector:   dryRunBalanceOfSelector,
			ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
		}},
	}))

	// The allow case forwards upstream, so the fixture needs a node to answer.
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	t.Cleanup(stub.Close)
	f.srv.proxy = proxy.New(stub.URL)

	tests := []struct {
		name       string
		argAddr    string
		want       string
		wantReason string
	}{
		{"own balance", selfAddr, "allow", ""},
		{"another address", otherAddr, "deny", "parameter constraint violation"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rpc := dryRunRPCBlock{
				Method: "eth_call",
				Params: []any{
					map[string]any{
						"to":   contractAddr,
						"data": dryRunBalanceOfSelector + "000000000000000000000000" + strings.TrimPrefix(tc.argAddr, "0x"),
					},
					"latest",
				},
			}
			w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, map[string]any{
				"user_did": f.userDID,
				"rpc":      rpc,
			})
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

			var resp dryRunResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tc.want, resp.Decision)
			assert.Contains(t, resp.Reason, tc.wantReason)
			assert.NotContains(t, resp.Reason, "function selector required")
		})
	}
}

// TestDryRunAccessRequest_MatchesEnforcementDerivation pins the fields the
// builder derives to the values JSONRPCProcessor derives for the same call,
// computed here from the params the way the enforcement path does rather than
// through the builder itself.
func TestDryRunAccessRequest_MatchesEnforcementDerivation(t *testing.T) {
	// Checksummed on the wire: grants are keyed lowercase, so a target that
	// keeps its mixed case matches no contract and denies a call the live
	// path allows.
	t.Run("eth_call with a checksummed target", func(t *testing.T) {
		params := []any{map[string]any{
			"to":   "0xAbC0000000000000000000000000000000000001",
			"data": "0x70a08231ff",
		}, "latest"}
		got, err := dryRunAccessRequest("did:x", "org", dryRunRPCBlock{Method: "eth_call", Params: params})
		require.NoError(t, err)
		assert.Equal(t, rbac.ResolveMethodAlias("eth_call"), got.AccessMethod)
		assert.Equal(t, rbac.GetTargetAddress("eth_call", params), got.TargetAddress)
		assert.Equal(t, "0xabc0000000000000000000000000000000000001", got.TargetAddress)
		assert.Equal(t, rbac.GetFunctionSelector("eth_call", params), got.FunctionSelector)
	})

	t.Run("eth_sendRawTransaction", func(t *testing.T) {
		to := common.HexToAddress("0x3333333333333333333333333333333333333333")
		rawHex := drSignedRawTx(t, &to, []byte{0x70, 0xa0, 0x82, 0x31})
		got, err := dryRunAccessRequest("did:x", "org", dryRunRPCBlock{
			Method: "eth_sendRawTransaction", Params: []any{rawHex},
		})
		require.NoError(t, err)

		// processRawTransaction(): decode, then check as eth_sendTransaction
		// against the decoded target and calldata selector.
		from, wantTo, data, value, _, err := decodeRawTransaction(rawHex)
		require.NoError(t, err)
		assert.Equal(t, "eth_sendTransaction", got.Method)
		assert.Equal(t, wantTo, got.TargetAddress)
		assert.Equal(t, extractSelector(data), got.FunctionSelector)
		assert.Equal(t, buildTxParams(from, wantTo, data, value), got.Params)
	})

	t.Run("undecodable raw tx is an error, not an empty target", func(t *testing.T) {
		_, err := dryRunAccessRequest("did:x", "org", dryRunRPCBlock{
			Method: "eth_sendRawTransaction", Params: []any{"0xnotrealhex"},
		})
		require.Error(t, err)
	})
}

// TestDryRun_RawTransactionChecksDecodedTarget covers the raw-tx contract gate
// end to end. eth_sendRawTransaction hides its target in the signed blob, so a
// check built from the undecoded params has no target address and skips
// validateContractAccess entirely — every raw tx reached the tracer whatever
// contract it pointed at, and its emitted logs came back in logs_emitted.
func TestDryRun_RawTransactionChecksDecodedTarget(t *testing.T) {
	f := setupDryRunFixture(t)
	ctx := context.Background()

	// A group allowed to send transactions, granted on one contract only.
	groupID := uuid.New().String()
	require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: f.orgID, Slug: "dr-sender", Name: "dr-sender", Depth: 0, Path: "dr-sender",
	}))
	require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	senderDID := "did:dr:sender"
	drCreateUserInGroup(t, f.srv.db, senderDID, groupID)

	grantedAddr := "0x4444444444444444444444444444444444444444"
	ungrantedAddr := "0x5555555555555555555555555555555555555555"
	drCreateGrant(t, f.srv.db, drCreateContract(t, f.srv.db, f.orgID, grantedAddr, "DRGranted"), groupID)
	drCreateContract(t, f.srv.db, f.orgID, ungrantedAddr, "DRUngranted")

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(stub.Close)
	f.srv.proxy = proxy.New(stub.URL)

	tests := []struct {
		name string
		to   string
		want string
	}{
		{"granted contract", grantedAddr, "allow"},
		{"contract the group has no grant on", ungrantedAddr, "deny"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			to := common.HexToAddress(tc.to)
			w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, map[string]any{
				"user_did": senderDID,
				"rpc": dryRunRPCBlock{
					Method: "eth_sendRawTransaction",
					Params: []any{drSignedRawTx(t, &to, []byte{0xab, 0xcd, 0xab, 0xcd})},
				},
			})
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			var resp dryRunResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tc.want, resp.Decision, "reason: %s", resp.Reason)
		})
	}
}

// drSignedRawTx returns a signed legacy tx as 0x-prefixed hex, so tests reach
// the production RLP decode + sender-recovery path.
func drSignedRawTx(t *testing.T, to *common.Address, data []byte) string {
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
	return "0x" + hex.EncodeToString(raw)
}

// TestDryRun_ParamsHashStable pins the params-hash invariant: same
// method + params produce the same hash, different params don't. The
// audit log uses this hash so reviewers can correlate without us ever
// persisting raw params.
func TestDryRun_ParamsHashStable(t *testing.T) {
	h1 := dryRunParamsHash("eth_call", []any{map[string]any{"to": "0xaa"}, "latest"})
	h2 := dryRunParamsHash("eth_call", []any{map[string]any{"to": "0xaa"}, "latest"})
	h3 := dryRunParamsHash("eth_call", []any{map[string]any{"to": "0xbb"}, "latest"})
	assert.Equal(t, h1, h2, "same input must hash identically")
	assert.NotEqual(t, h1, h3, "different params must produce different hashes")
	assert.Equal(t, 64, len(h1), "sha256 hex length")
}

// TestDryRun_TraceMethodWithoutProxyReturnsClearError covers the
// debug_traceCall path when no upstream proxy is wired (testServerRBAC
// runs without one). The handler should pass RBAC, then surface a
// clear "proxy not configured" / "node does not support" error rather
// than 500-with-stack-trace.
func TestDryRun_TraceMethodWithoutProxyReturnsClearError(t *testing.T) {
	f := setupDryRunFixture(t)
	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_sendTransaction",
			"params": []any{
				map[string]any{
					"from": "0xaa",
					"to":   f.contractAddr,
					"data": "0xabcd",
				},
			},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)
	// RBAC may deny first (no method allowlist) or allow with trace
	// failure; either way the user gets a clean structured response.
	if w.Code == http.StatusOK {
		var resp dryRunResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		// allow + no trace because our test fixture has no upstream
		// proxy, OR deny because eth_sendTransaction needs a writable
		// claim. Either is structurally fine.
		assert.True(t, resp.Decision == "allow" || resp.Decision == "deny",
			"unexpected decision: %s", resp.Decision)
	} else {
		// 502 from the trace-forward branch is also acceptable.
		assert.Equal(t, http.StatusBadGateway, w.Code)
	}
}

// TestDryRun_RawSendTransactionDecodes verifies that a signed raw tx
// passes through the production decoder and reaches the trace branch
// (rather than being rejected as unsupported). The test fixture has
// no upstream node, so the trace step itself fails with a 502 — the
// point is that the failure is "couldn't reach upstream" not
// "couldn't decode."
func TestDryRun_RawSendTransactionDecodes(t *testing.T) {
	f := setupDryRunFixture(t)

	// Build a real signed legacy tx so decodeRawTransaction runs the
	// full RLP + signer-recovery path (same code as production
	// processRawTransaction). 32-byte arbitrary key; chain ID 1.
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	chainID := big.NewInt(1)
	toAddr := common.HexToAddress(f.contractAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      100_000,
		To:       &toAddr,
		Value:    big.NewInt(0),
		Data:     []byte{0xab, 0xcd},
	})
	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, key)
	require.NoError(t, err)
	rawBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)
	rawHex := "0x" + hex.EncodeToString(rawBytes)

	body := map[string]any{
		"user_did": f.userDID,
		"rpc": map[string]any{
			"method": "eth_sendRawTransaction",
			"params": []any{rawHex},
		},
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body)

	// One of three outcomes is acceptable; all confirm we got past
	// decode without the old "not supported" stub:
	//
	//   200 + decision=deny — RBAC denied based on the recovered
	//     sender's lack of access to f.contractAddr (most likely
	//     since the random key is not linked to f.userDID).
	//   200 + decision=allow — RBAC let it through; trace branch
	//     responded.
	//   502 — RBAC allowed, trace branch failed reaching upstream
	//     (no proxy in test fixture). The body should NOT contain
	//     "decode" / "not supported".
	switch w.Code {
	case http.StatusOK:
		var resp dryRunResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Contains(t, []string{"allow", "deny"}, resp.Decision)
	case http.StatusBadGateway:
		bodyText := strings.ToLower(w.Body.String())
		require.NotContains(t, bodyText, "not supported",
			"raw tx must reach trace branch — got 'not supported' which means the old stub fired")
		require.NotContains(t, bodyText, "decode pending",
			"raw tx must reach trace branch — got 'decode pending' which means the old stub fired")
	default:
		t.Fatalf("unexpected status code: %d, body: %s", w.Code, w.Body.String())
	}
}

// TestDryRun_RawSendTransactionMalformedAudit confirms that malformed raw
// transactions are recorded before the handler returns a client error, and
// that an audit-write failure withholds that response.
func TestDryRun_RawSendTransactionMalformedAudit(t *testing.T) {
	const rawHex = "0xnotrealhex"

	t.Run("records decode error before returning bad request", func(t *testing.T) {
		f := setupDryRunFixture(t)
		rpc := dryRunRPCBlock{
			Method: "eth_sendRawTransaction",
			Params: []any{rawHex},
		}
		w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, map[string]any{
			"user_did": f.userDID,
			"rpc":      rpc,
		})

		require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "invalid raw transaction")

		var method, paramsHash, decision, reason string
		require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(), `
			SELECT method, params_hash, decision, reason
			  FROM impersonation_log
			 WHERE actor_did = $1 AND impersonated_did = $2 AND org_id = $3`,
			f.adminDID, f.userDID, f.orgID,
		).Scan(&method, &paramsHash, &decision, &reason))
		assert.Equal(t, rpc.Method, method)
		assert.Equal(t, dryRunParamsHash(rpc.Method, rpc.Params), paramsHash)
		assert.Equal(t, "error", decision)
		assert.Equal(t, "decode_error", reason)
	})

	t.Run("audit write failure is fail closed", func(t *testing.T) {
		f := setupDryRunFixture(t)
		ctx := context.Background()
		conn := f.srv.db.Conn()

		// NOT VALID avoids scanning existing audit rows but still enforces the
		// constraint for this test's new insert.
		_, err := conn.ExecContext(ctx, `
			ALTER TABLE impersonation_log
			ADD CONSTRAINT impersonation_log_reject_error_test
			CHECK (decision <> 'error') NOT VALID`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, dropErr := conn.ExecContext(context.Background(), `
				ALTER TABLE impersonation_log
				DROP CONSTRAINT IF EXISTS impersonation_log_reject_error_test`)
			assert.NoError(t, dropErr)
		})

		rpc := dryRunRPCBlock{
			Method: "eth_sendRawTransaction",
			Params: []any{rawHex},
		}
		w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, map[string]any{
			"user_did": f.userDID,
			"rpc":      rpc,
		})

		require.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
		assert.JSONEq(t, `{"error":"internal error"}`, w.Body.String())

		var count int
		require.NoError(t, conn.QueryRowContext(ctx, `
			SELECT COUNT(*)
			  FROM impersonation_log
			 WHERE actor_did = $1 AND impersonated_did = $2 AND org_id = $3
			   AND params_hash = $4`,
			f.adminDID, f.userDID, f.orgID, dryRunParamsHash(rpc.Method, rpc.Params),
		).Scan(&count))
		assert.Zero(t, count)
	})
}

// ---- fixture helpers -------------------------------------------------

func drCreateGroup(t *testing.T, database interface {
	CreateGroup(ctx context.Context, g *rbac.Group) error
	CreateGroupAccess(ctx context.Context, ga *rbac.GroupAccess) error
}, orgID, slug string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: gid, OrgID: orgID, Slug: slug, Name: slug, Depth: 0, Path: slug, IsOrgAdmin: isOrgAdmin,
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_call", "eth_getLogs"}, Claims: claims,
	}))
	return gid
}

func drCreateUserInGroup(t *testing.T, database interface {
	CreateUser(ctx context.Context, u *rbac.User) error
	CreateMembership(ctx context.Context, m *rbac.UserMembership) error
}, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: uid, ExternalID: did, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: uid, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return uid
}

func drCreateContract(t *testing.T, database interface {
	CreateContract(ctx context.Context, c *rbac.Contract) error
}, orgID, address, name string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: address, Name: name, Metadata: map[string]any{},
	}))
	return cid
}

func drCreateGrant(t *testing.T, database interface {
	CreateContractGrant(ctx context.Context, g *rbac.ContractGrant) error
}, contractID, groupID string) {
	t.Helper()
	require.NoError(t, database.CreateContractGrant(context.Background(), &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, Functions: nil,
	}))
}
