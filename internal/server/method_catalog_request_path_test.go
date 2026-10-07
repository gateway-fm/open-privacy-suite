package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Request-path regression tests for the RPC method catalog (RD-1311).
//
// A method the proxy has no model for has no target address (so no
// per-contract / cross-org gate), no response filter and no send-side
// tracing. It must therefore never reach the node, however a group's
// allowed_methods was populated: a literal "*" (the batch-move new_group
// path used to store one), a free-text name saved through the admin API, or
// the anonymous group's row. A canary upstream records every method it
// receives, so each test proves the node never saw the request rather than
// inferring it from the proxy's verdict.

// canaryNode is an httptest upstream that records the JSON-RPC method of
// every request it receives and answers with a trivial result.
type canaryNode struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
}

func newCanaryNode(t *testing.T) *canaryNode {
	t.Helper()
	c := &canaryNode{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &env)
		c.mu.Lock()
		c.methods = append(c.methods, env.Method)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *canaryNode) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.methods...)
}

// newCanaryProcessor wires a processor to the test server's real RBAC stack
// and forwards to the canary node.
func newCanaryProcessor(t *testing.T, ts *testServerRBAC, canary *canaryNode) *JSONRPCProcessor {
	t.Helper()
	return NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		AccessLogger:       ts.db,
		Proxy:              proxy.New(canary.srv.URL),
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})
}

// rpcBody builds the verbatim request body the proxy forwards upstream.
func rpcBody(t *testing.T, method string, params []any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	return b
}

func processRPC(t *testing.T, p *JSONRPCProcessor, userDID, method string, params []any) *ProcessResult {
	t.Helper()
	return p.Process(context.Background(), &ProcessRequest{
		UserID: userDID,
		Method: method,
		Params: params,
		Body:   rpcBody(t, method, params),
	})
}

const (
	catalogTestTxHash = "0x1311000000000000000000000000000000000000000000000000000000000001"
	catalogTestAddr   = "0x1311131113111311131113111311131113111311"
)

// unmodelledMethods are real upstream methods (geth, erigon, reth, otterscan,
// parity/openethereum, EIP-7966) that the proxy has no gate or response filter
// for. Each one returns data a private network must not expose unfiltered —
// raw sender/value/calldata/nonce, full traces, account state — or, for
// eth_sendRawTransactionSync, submits a transaction around the send-side
// decode, sender-link, trace and compliance checks.
var unmodelledMethods = []struct {
	method string
	params []any
}{
	{"eth_getRawTransactionByHash", []any{catalogTestTxHash}},
	{"eth_getRawTransactionByBlockHashAndIndex", []any{catalogTestTxHash, "0x0"}},
	{"eth_getRawTransactionByBlockNumberAndIndex", []any{"latest", "0x0"}},
	{"eth_getTransactionBySenderAndNonce", []any{catalogTestAddr, "0x0"}},
	{"eth_getAccount", []any{catalogTestAddr, "latest"}},
	{"eth_simulateV1", []any{map[string]any{"blockStateCalls": []any{}}, "latest"}},
	{"eth_callMany", []any{[]any{}, map[string]any{}}},
	{"eth_sendRawTransactionSync", []any{"0x02f8"}},
	{"trace_transaction", []any{catalogTestTxHash}},
	{"trace_replayTransaction", []any{catalogTestTxHash, []any{"trace"}}},
	{"trace_block", []any{"latest"}},
	{"trace_filter", []any{map[string]any{}}},
	{"trace_call", []any{map[string]any{"to": catalogTestAddr}, []any{"trace"}, "latest"}},
	{"ots_getTransactionBySenderAndNonce", []any{catalogTestAddr, "0x0"}},
	{"ots_searchTransactionsBefore", []any{catalogTestAddr, "0x0", 10}},
	{"erigon_getLogs", []any{map[string]any{}}},
	{"parity_listStorageKeys", []any{catalogTestAddr, 10, nil, "latest"}},
}

func unmodelledMethodNames() []string {
	out := make([]string, 0, len(unmodelledMethods))
	for _, m := range unmodelledMethods {
		out = append(out, m.method)
	}
	return out
}

// assertNeverForwarded sends every unmodelled method as userDID and asserts
// each is refused with the opaque "method not found" and never reaches the
// canary.
func assertNeverForwarded(t *testing.T, p *JSONRPCProcessor, canary *canaryNode, userDID string) {
	t.Helper()
	for _, tc := range unmodelledMethods {
		res := processRPC(t, p, userDID, tc.method, tc.params)
		if assert.NotNilf(t, res.Error, "%s must be refused", tc.method) {
			assert.Equalf(t, http.StatusNotFound, res.Error.StatusCode, "%s: denial must stay masked", tc.method)
			assert.Equalf(t, "method not found", res.Error.Message, "%s: denial must stay opaque", tc.method)
		}
	}
	assert.Empty(t, canary.seen(), "the node must never receive a method the proxy has no gate or response filter for")
}

// A group whose stored allowed_methods is the literal "*" — the shape the
// batch-move new_group path and the dev admin bootstrap wrote — reaches the
// catalog, never methods outside it.
func TestMethodCatalog_LiteralStarGroup_UnmodelledMethodsNeverReachNode(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	did := createKYCMember(t, ctx, ts, []rbac.Claim{rbac.ClaimDeploy}, "*")

	assertNeverForwarded(t, p, canary, did)

	// Control: the same user still reaches a catalog method through the full
	// check (eth_feeHistory is not an org-free shortcut), so the refusals
	// above are the catalog gate, not broken wiring.
	res := processRPC(t, p, did, "eth_feeHistory", []any{"0x1", "latest", []any{}})
	require.Nil(t, res.Error, "catalog method must still be forwarded for a '*' group")
	assert.Equal(t, []string{"eth_feeHistory"}, canary.seen())
}

// A group row that names unmodelled methods explicitly (setGroupAccess stored
// any string verbatim) still cannot reach them.
func TestMethodCatalog_ExplicitUnknownNames_NeverReachNode(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	did := createKYCMember(t, ctx, ts, nil, unmodelledMethodNames()...)

	assertNeverForwarded(t, p, canary, did)
}

// The anonymous group's row is super-admin editable. Even if it lists
// unmodelled methods, an unauthenticated caller never reaches them.
func TestMethodCatalog_AnonymousGroupListingUnknownNames_NeverReachNode(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	seedAnonymousGroupAccess(t, ctx, ts, append(unmodelledMethodNames(), "eth_chainId"))

	assertNeverForwarded(t, p, canary, "")

	res := processRPC(t, p, "", "eth_chainId", []any{})
	require.Nil(t, res.Error, "anonymous allowlisted catalog method must still be forwarded")
	assert.Equal(t, []string{"eth_chainId"}, canary.seen())
}

// An operator alias whose target is not a catalog method inherits no gate
// from it, so the alias is not forwardable either.
func TestMethodCatalog_AliasToUnmodelledTarget_NeverReachesNode(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	registerTestNamespaces(t, map[string][]string{"Custom": {"custom_getRaw"}},
		map[string]string{"custom_getRaw": "eth_getRawTransactionByHash"})

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	did := createKYCMember(t, ctx, ts, nil, "custom_getRaw")
	res := processRPC(t, p, did, "custom_getRaw", []any{catalogTestTxHash})
	require.NotNil(t, res.Error)
	assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)
	assert.Empty(t, canary.seen())
}

// Control for RD-841: an operator alias to a catalog method keeps working and
// is forwarded under the target's gate (here the eth_estimateGas EOA
// value-transfer carve-out).
func TestMethodCatalog_AliasToCatalogMethod_StillForwarded(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	registerTestNamespaces(t, map[string][]string{"Linea": {"linea_estimateGas"}},
		map[string]string{"linea_estimateGas": "eth_estimateGas"})

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	did := createKYCMember(t, ctx, ts, nil, "linea_estimateGas")
	res := processRPC(t, p, did, "linea_estimateGas", []any{map[string]any{"to": catalogTestAddr, "value": "0x1"}})
	require.Nil(t, res.Error)
	assert.Equal(t, []string{"linea_estimateGas"}, canary.seen())
}

// seedAnonymousGroupAccess recreates the RD-870 anonymous org/group (the test
// harness wipes RBAC tables) with the given allowlist.
func seedAnonymousGroupAccess(t *testing.T, ctx context.Context, ts *testServerRBAC, methods []string) {
	t.Helper()
	conn := ts.db.Conn()
	_, err := conn.ExecContext(ctx,
		`INSERT INTO organizations (id, slug, name, settings, is_system)
		 VALUES ($1, 'anonymous', 'Anonymous', '{}'::jsonb, true) ON CONFLICT DO NOTHING`, rbac.AnonymousOrgID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, depth, is_system)
		 VALUES ($1, $2, 'anonymous', 'Anonymous', 'anonymous', 0, true) ON CONFLICT DO NOTHING`,
		rbac.AnonymousGroupID, rbac.AnonymousOrgID)
	require.NoError(t, err)
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        rbac.AnonymousGroupID,
		AllowedMethods: methods,
		Claims:         []rbac.Claim{},
	}))
	ts.rbacAccessCtrl.InvalidateAnonymousAccess()
}

// registerTestNamespaces installs operator namespace entries directly into
// the rbac registries (the package's tests may already have armed them via
// server construction, so the startup-only registration call is not usable
// here). Callers must defer rbac.SnapshotMethodRegistriesForTest()().
func registerTestNamespaces(t *testing.T, names map[string][]string, aliases map[string]string) {
	t.Helper()
	if rbac.ExtraNamespaces == nil {
		rbac.ExtraNamespaces = map[string][]string{}
	}
	for ns, methods := range names {
		rbac.ExtraNamespaces[ns] = methods
		for _, m := range methods {
			rbac.ExtraMethods[m] = true
		}
	}
	for m, target := range aliases {
		rbac.MethodAliases[m] = target
	}
}

// createKYCMember creates an org, group and KYC-verified member with the
// requested stored permissions. It returns the member's DID.
func createKYCMember(t *testing.T, ctx context.Context, ts *testServerRBAC, claims []rbac.Claim, allowedMethods ...string) string {
	t.Helper()
	orgID := uuid.New().String()
	groupID := uuid.New().String()
	userID := uuid.New().String()
	did := "did:privado:catalog-" + uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "catalog-" + orgID[:8], Name: "Catalog Org",
	}))
	insertGroupRawSQL(t, ctx, ts.db, groupID, orgID, "catalog-"+groupID[:8], "Catalog Group", "catalog-"+groupID[:8])
	if claims == nil {
		claims = []rbac.Claim{}
	}
	if allowedMethods == nil {
		allowedMethods = []string{}
	}
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: claims, AllowedMethods: allowedMethods,
	}))
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return did
}

// An operator passthrough method is forwarded only to a group that lists it by
// exact name: never through "*", never anonymously.
func TestMethodCatalog_PassthroughMethod_OnlyForExplicitAuthenticatedGrant(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	registerTestNamespaces(t, map[string][]string{"Tracing": {"trace_block"}}, nil)
	rbac.PassthroughMethods["trace_block"] = true

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	starDID := createKYCMember(t, ctx, ts, []rbac.Claim{rbac.ClaimDeploy}, "*")
	res := processRPC(t, p, starDID, "trace_block", []any{"latest"})
	require.NotNil(t, res.Error, "'*' must not grant a passthrough method")
	assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)

	seedAnonymousGroupAccess(t, ctx, ts, []string{"trace_block"})
	res = processRPC(t, p, "", "trace_block", []any{"latest"})
	require.NotNil(t, res.Error, "passthrough must never be anonymous")
	assert.Empty(t, canary.seen())

	explicitDID := createKYCMember(t, ctx, ts, nil, "trace_block")
	res = processRPC(t, p, explicitDID, "trace_block", []any{"latest"})
	require.Nil(t, res.Error, "an explicit grant reaches the passthrough method")
	assert.Equal(t, []string{"trace_block"}, canary.seen())
}

// An alias to a method whose protection runs in a dedicated request path
// (raw-tx decode + trace, send-side trace + travel rule, trace validation) is
// dispatched by its own name and would skip that path, so it is refused — even
// if it reached the registry, and even for a "*" group.
func TestMethodCatalog_AliasToSpecialDispatchMethod_NeverReachesNode(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	aliases := map[string]string{
		"linea_sendRawTransaction": "eth_sendRawTransaction",
		"linea_sendTransaction":    "eth_sendTransaction",
		"linea_traceCall":          "debug_traceCall",
		"linea_traceTransaction":   "debug_traceTransaction",
	}
	names := make([]string, 0, len(aliases))
	for m := range aliases {
		names = append(names, m)
	}
	registerTestNamespaces(t, map[string][]string{"Linea": names}, aliases)

	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	canary := newCanaryNode(t)
	p := newCanaryProcessor(t, ts, canary)

	explicitDID := createKYCMember(t, ctx, ts, []rbac.Claim{rbac.ClaimDeploy}, names...)
	starDID := createKYCMember(t, ctx, ts, []rbac.Claim{rbac.ClaimDeploy}, "*")
	params := map[string][]any{
		"linea_sendRawTransaction": {"0x02f8"},
		"linea_sendTransaction":    {map[string]any{"from": catalogTestAddr, "to": catalogTestAddr, "value": "0x1"}},
		"linea_traceCall":          {map[string]any{"to": catalogTestAddr}, "latest", map[string]any{}},
		"linea_traceTransaction":   {catalogTestTxHash, map[string]any{}},
	}
	for _, did := range []string{explicitDID, starDID} {
		for m, ps := range params {
			res := processRPC(t, p, did, m, ps)
			if assert.NotNilf(t, res.Error, "%s must be refused", m) {
				assert.Equal(t, http.StatusNotFound, res.Error.StatusCode)
			}
		}
	}
	assert.Empty(t, canary.seen())
}
