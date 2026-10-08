package server

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The proxy authorises a JSON-RPC request on its own parse of the body and
// forwards a body to the node. These tests pin that the two can never
// disagree: an ambiguous envelope (duplicate or case-variant member names)
// never reaches the node, and an accepted request reaches it as exactly the
// members the proxy authorised. The canary upstream records every body the
// proxy forwards, so "nothing forwarded" is observed, not inferred.

// envelopeCanaryNode is a fake upstream node that records every request body.
type envelopeCanaryNode struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
}

func newEnvelopeCanaryNode(t *testing.T) *envelopeCanaryNode {
	t.Helper()
	c := &envelopeCanaryNode{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *envelopeCanaryNode) received() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.bodies))
	copy(out, c.bodies)
	return out
}

func (c *envelopeCanaryNode) receivedStrings() []string {
	var out []string
	for _, b := range c.received() {
		out = append(out, string(b))
	}
	return out
}

func (c *envelopeCanaryNode) reset() {
	c.mu.Lock()
	c.bodies = nil
	c.mu.Unlock()
}

type envelopeHarness struct {
	ts     *testServerRBAC
	node   *envelopeCanaryNode
	router *gin.Engine
}

// setupEnvelopeHarness wires the production JSON-RPC handler (same routes and
// optional-JWT middleware as setupRouter) to a real processor with DB-backed
// RBAC, forwarding to a canary node.
func setupEnvelopeHarness(t *testing.T) *envelopeHarness {
	t.Helper()
	ts := setupTestServerForRBAC(t)
	node := newEnvelopeCanaryNode(t)
	seedAnonymousGroup(t, ts.db)
	ts.jsonrpcProcessor = newEnvelopeCanaryProcessor(ts, node)

	router := gin.New()
	jwtMW := auth.OptionalJWTAuthMiddleware(ts.jwtService, ts.db)
	router.POST("/", jwtMW, ts.handleJSONRPC)
	router.POST("/rpc", jwtMW, ts.handleJSONRPC)
	router.POST("/rpc/:org_id", jwtMW, ts.handleJSONRPC)
	return &envelopeHarness{ts: ts, node: node, router: router}
}

// newEnvelopeCanaryProcessor is a real processor with DB-backed RBAC that forwards to
// the canary node.
func newEnvelopeCanaryProcessor(ts *testServerRBAC, node *envelopeCanaryNode) *JSONRPCProcessor {
	return NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              proxy.New(node.srv.URL),
		AccessLogger:       ts.db,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})
}

// seedAnonymousGroup restores the migration-seeded anonymous org/group/access
// row that setupTestServerForRBAC wipes, so the anonymous path is live.
func seedAnonymousGroup(t *testing.T, database *db.DB) {
	t.Helper()
	ctx := context.Background()
	conn := database.Conn()
	_, err := conn.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, settings, is_system)
		VALUES ($1, 'anonymous', 'Anonymous', '{}'::jsonb, true) ON CONFLICT DO NOTHING`, rbac.AnonymousOrgID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `INSERT INTO groups (id, org_id, slug, name, depth, path, is_system)
		VALUES ($1, $2, 'anonymous', 'Anonymous', 0, 'anonymous', true) ON CONFLICT DO NOTHING`, rbac.AnonymousGroupID, rbac.AnonymousOrgID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `INSERT INTO group_access (id, group_id, allowed_methods, claims)
		VALUES ($1, $1, ARRAY['eth_blockNumber','eth_chainId','eth_gasPrice','net_version','net_listening','web3_clientVersion'], ARRAY[]::TEXT[])
		ON CONFLICT DO NOTHING`, rbac.AnonymousGroupID)
	require.NoError(t, err)
}

// envelopeMember creates an org, a group allowed exactly `methods`, and a
// KYC'd member of it. Returns the member's access token and the org ID.
func (h *envelopeHarness) envelopeMember(t *testing.T, methods ...string) (token, orgID string) {
	t.Helper()
	ctx := context.Background()
	orgID = uuid.New().String()
	require.NoError(t, h.ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "env-org-" + orgID[:8], Name: "Envelope Org",
	}))
	groupID := uuid.New().String()
	insertGroupRawSQL(t, ctx, h.ts.db, groupID, orgID, "env-grp-"+groupID[:8], "Envelope Group", "env-grp-"+groupID[:8])
	require.NoError(t, h.ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{}, AllowedMethods: methods,
	}))
	userID := uuid.New().String()
	did := "did:privado:envelope-" + uuid.New().String()
	require.NoError(t, h.ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	require.NoError(t, h.ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	token, err := h.ts.jwtService.IssueAccessToken(did, true)
	require.NoError(t, err)
	return token, orgID
}

func (h *envelopeHarness) post(t *testing.T, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

// assertRejectedUnforwarded asserts an opaque 400 and that the node saw nothing.
func (h *envelopeHarness) assertRejectedUnforwarded(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, w.Code, "ambiguous envelope must be refused before any access decision; body=%s", w.Body.String())
	assert.JSONEq(t, `{"error":"invalid JSON-RPC request"}`, w.Body.String(), "rejection must be opaque")
	assert.Empty(t, h.node.receivedStrings(), "an ambiguous envelope must never reach the node")
}

const (
	envAddrA = "0x000000000000000000000000000000000000000a"
	envAddrB = "0x000000000000000000000000000000000000000b"
)

func TestJSONRPCEnvelope_Anonymous_AmbiguousNeverForwarded(t *testing.T) {
	h := setupEnvelopeHarness(t)
	cases := map[string]string{
		// Duplicate and case-variant members are rejected before forwarding.
		"method then Method": `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","Method":"eth_blockNumber","params":["` + envAddrA + `","latest"]}`,
		"duplicate method":   `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","method":"eth_blockNumber","params":["` + envAddrA + `","latest"]}`,
		"lone Method":        `{"jsonrpc":"2.0","id":1,"Method":"eth_blockNumber","params":[]}`,
		"params then Params": `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":["` + envAddrA + `"],"Params":[]}`,
	}
	for name, body := range cases {
		for _, path := range []string{"/", "/rpc"} {
			t.Run(name+" "+path, func(t *testing.T) {
				h.node.reset()
				h.assertRejectedUnforwarded(t, h.post(t, path, "", body))
			})
		}
	}
}

func TestJSONRPCEnvelope_Authenticated_AmbiguousNeverForwarded(t *testing.T) {
	h := setupEnvelopeHarness(t)
	token, orgID := h.envelopeMember(t, "eth_getBalance")
	cases := map[string]string{
		// eth_getStorageAt is not in the member's allowlist; eth_blockNumber
		// is org-free metadata and always allowed to a member.
		"method then Method": `{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","Method":"eth_blockNumber","params":["` + envAddrA + `","0x0","latest"]}`,
		"Method then method": `{"jsonrpc":"2.0","id":1,"Method":"eth_getStorageAt","method":"eth_blockNumber","params":["` + envAddrA + `","0x0","latest"]}`,
		// Case-variant parameter members are rejected before forwarding.
		"params then Params": `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["` + envAddrA + `","latest"],"Params":["` + envAddrB + `","latest"]}`,
		"duplicate params":   `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["` + envAddrA + `","latest"],"params":["` + envAddrB + `","latest"]}`,
		"nested case pair":   `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["` + envAddrA + `",{"blockHash":"0x01","BlockHash":"0x02"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h.node.reset()
			h.assertRejectedUnforwarded(t, h.post(t, "/rpc/"+orgID, token, body))
		})
	}
}

// TestJSONRPCEnvelope_SpecialPaths covers the methods with their own
// processing branch (raw transactions, traces, rewritten block queries) and a
// case-variant field inside a call object, which is refused because the
// proxy reads request fields by exact name only.
func TestJSONRPCEnvelope_SpecialPaths(t *testing.T) {
	h := setupEnvelopeHarness(t)
	token, orgID := h.envelopeMember(t, "eth_call", "eth_sendRawTransaction", "debug_traceCall", "eth_getBlockByNumber")
	path := "/rpc/" + orgID

	rejected := map[string]string{
		"raw tx params then Params": `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"],"Params":["0x02"]}`,
		"trace Method":              `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","Method":"eth_blockNumber","params":[{"to":"` + envAddrA + `"},"latest"]}`,
		"call with To":              `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"To":"` + envAddrB + `","data":"0x01"},"latest"]}`,
		"call with to and Data":     `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + envAddrA + `","data":"0x01","Data":"0x02"},"latest"]}`,
	}
	for name, body := range rejected {
		t.Run(name, func(t *testing.T) {
			h.node.reset()
			h.assertRejectedUnforwarded(t, h.post(t, path, token, body))
		})
	}

	t.Run("block query rewrite starts from the canonical envelope", func(t *testing.T) {
		h.node.reset()
		h.post(t, path, token, `{"id":3,"method":"eth_getBlockByNumber","params":["latest",false],"jsonrpc":"2.0","extra":1}`)
		got := h.node.receivedStrings()
		require.Len(t, got, 1)
		assert.JSONEq(t, `{"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":["latest",true]}`, got[0])
		assert.NotContains(t, got[0], "extra")
	})
}

// TestJSONRPCEnvelope_ImpersonationMirror pins that the view-as-user RPC mirror
// (a GET carrying a JSON-RPC body) goes through the same envelope parse.
func TestJSONRPCEnvelope_ImpersonationMirror(t *testing.T) {
	f := setupImpersonationFixture(t)
	node := newEnvelopeCanaryNode(t)
	f.srv.jsonrpcProcessor = newEnvelopeCanaryProcessor(f.srv.testServerRBAC, node)

	get := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, impersonatePath(f.userDID, f.orgID, "/rpc"), bytes.NewReader([]byte(body)))
		req.Header.Set("X-Test-Auth-Method", "jwt_admin")
		req.Header.Set("X-Test-Admin-Subject", f.adminDID)
		req.Header.Set("X-Test-Admin-Org-IDs", f.orgID)
		w := httptest.NewRecorder()
		f.srv.router.ServeHTTP(w, req)
		return w
	}

	w := get(`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","Method":"eth_blockNumber","params":["` + envAddrA + `","latest"]}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, "body=%s", w.Body.String())
	assert.JSONEq(t, `{"error":"invalid JSON-RPC request"}`, w.Body.String())
	assert.Empty(t, node.receivedStrings(), "an ambiguous envelope must never reach the node")

	node.reset()
	w = get(`{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[],"foo":1}`)
	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	assert.Equal(t, []string{`{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}`}, node.receivedStrings())
}

func TestJSONRPCEnvelope_Alias_AmbiguousNeverForwarded(t *testing.T) {
	withMethodAlias(t, "linea_getBalance", "eth_getBalance")
	h := setupEnvelopeHarness(t)
	token, orgID := h.envelopeMember(t, "linea_getBalance")

	h.node.reset()
	body := `{"jsonrpc":"2.0","id":1,"method":"linea_getBalance","METHOD":"eth_blockNumber","params":["` + envAddrA + `","latest"]}`
	h.assertRejectedUnforwarded(t, h.post(t, "/rpc/"+orgID, token, body))
}

// TestJSONRPCEnvelope_ForwardsExactlyWhatWasAuthorised pins the forwarded
// bytes: only the members the proxy read (exact case, once each), the id and
// params byte-for-byte (number precision intact), unknown members dropped.
func TestJSONRPCEnvelope_ForwardsExactlyWhatWasAuthorised(t *testing.T) {
	withMethodAlias(t, "linea_getBalance", "eth_getBalance")
	h := setupEnvelopeHarness(t)
	token, orgID := h.envelopeMember(t, "eth_getBalance", "linea_getBalance")

	cases := []struct {
		name, path, token, body, want string
	}{
		{
			name: "anonymous, extra member dropped", path: "/",
			body: `{"jsonrpc":"2.0","id":7,"method":"eth_blockNumber","params":[],"foo":{"method":"eth_getBalance"}}`,
			want: `{"jsonrpc":"2.0","id":7,"method":"eth_blockNumber","params":[]}`,
		},
		{
			name: "anonymous, string id, no params", path: "/rpc",
			body: `{"id":"abc","method":"eth_chainId","jsonrpc":"2.0"}`,
			want: `{"jsonrpc":"2.0","id":"abc","method":"eth_chainId"}`,
		},
		{
			name: "anonymous, big-number id keeps precision", path: "/rpc",
			body: `{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"eth_chainId","params":[]}`,
			want: `{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"eth_chainId","params":[]}`,
		},
		{
			name: "anonymous, null id", path: "/rpc",
			body: `{"jsonrpc":"2.0","id":null,"method":"eth_chainId","params":[]}`,
			want: `{"jsonrpc":"2.0","id":null,"method":"eth_chainId","params":[]}`,
		},
		{
			name: "authenticated, escaped method decoded", path: "/rpc/" + orgID, token: token,
			body: `{"jsonrpc":"2.0","id":1,"method":"eth_get` + string(rune(92)) + `u0042alance","params":["` + envAddrA + `", "latest"]}`,
			want: `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["` + envAddrA + `", "latest"]}`,
		},
		{
			name: "anonymous, catalog method forwarded in its built-in spelling", path: "/rpc",
			body: `{"jsonrpc":"2.0","id":4,"method":"ETH_CHAINID","params":[]}`,
			want: `{"jsonrpc":"2.0","id":4,"method":"eth_chainId","params":[]}`,
		},
		{
			name: "authenticated, catalog method forwarded in its built-in spelling", path: "/rpc/" + orgID, token: token,
			body: `{"jsonrpc":"2.0","id":5,"method":"Eth_GetBalance","params":["` + envAddrA + `","latest"]}`,
			want: `{"jsonrpc":"2.0","id":5,"method":"eth_getBalance","params":["` + envAddrA + `","latest"]}`,
		},
		{
			name: "alias forwarded under its own name", path: "/rpc/" + orgID, token: token,
			body: `{"jsonrpc":"2.0","id":2,"method":"linea_getBalance","params":["` + envAddrA + `","latest"]}`,
			want: `{"jsonrpc":"2.0","id":2,"method":"linea_getBalance","params":["` + envAddrA + `","latest"]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.node.reset()
			w := h.post(t, tc.path, tc.token, tc.body)
			require.Equal(t, http.StatusOK, w.Code, "legitimate request must be served; body=%s", w.Body.String())
			got := h.node.received()
			require.Len(t, got, 1, "exactly one upstream request")
			assert.Equal(t, tc.want, string(got[0]), "node must receive exactly the authorised members")
			var probe map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(got[0], &probe), "forwarded body must be valid JSON")
		})
	}
}

// TestParseAndValidateBody_ProxyMetadataOnlyOnSends: visibleTo/privateFor
// stay in the body only for the two send methods, whose paths read and strip
// them; for any other method the node never receives them.
func TestParseAndValidateBody_ProxyMetadataOnlyOnSends(t *testing.T) {
	const meta = `,"visibleTo":["did:a:b"],"privateFor":["did:c:d"]}`
	for _, method := range []string{"eth_sendTransaction", "eth_sendRawTransaction", "ETH_SENDRAWTRANSACTION"} {
		_, _, body, perr := ParseAndValidateBody([]byte(`{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":[]` + meta))
		require.Nil(t, perr)
		assert.Contains(t, string(body), `"visibleTo":["did:a:b"]`, method)
		assert.Contains(t, string(body), `"privateFor":["did:c:d"]`, method)
	}
	for _, method := range []string{"eth_call", "eth_getBalance", "linea_sendRawTransaction"} {
		_, _, body, perr := ParseAndValidateBody([]byte(`{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":[]` + meta))
		require.Nil(t, perr)
		assert.Equal(t, `{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":[]}`, string(body), method)
	}
}

// TestParseAndValidateBody_ForwardsCanonicalMethodName: access is decided on
// the built-in spelling of a catalog method, so that spelling is what the
// forwarded body carries, never the caller's letter case. Operator methods
// are matched by exact name and keep theirs.
func TestParseAndValidateBody_ForwardsCanonicalMethodName(t *testing.T) {
	t.Cleanup(rbac.SnapshotMethodRegistriesForTest())
	rbac.MethodAliases["linea_GetBalance"] = "eth_getBalance"
	rbac.PassthroughMethods["lotus_Send"] = true

	for _, tc := range []struct{ sent, want string }{
		{"ETH_CHAINID", "eth_chainId"},
		{"eth_chaİnId", "eth_chainId"}, // U+0130 folds to "i"
		{"Eth_GetBalance", "eth_getBalance"},
		{"eth_getBalance", "eth_getBalance"},
		{"linea_GetBalance", "linea_GetBalance"},
		{"lotus_Send", "lotus_Send"},
		{"unknown_Method", "unknown_Method"},
	} {
		t.Run(tc.sent, func(t *testing.T) {
			method, _, body, perr := ParseAndValidateBody([]byte(`{"jsonrpc":"2.0","id":1,"method":"` + tc.sent + `","params":[]}`))
			require.Nil(t, perr)
			assert.Equal(t, tc.want, method, "method handed to the processor")
			assert.Equal(t, `{"jsonrpc":"2.0","id":1,"method":"`+tc.want+`","params":[]}`, string(body), "forwarded body")
		})
	}

	t.Run("send keeps its metadata", func(t *testing.T) {
		_, _, body, perr := ParseAndValidateBody([]byte(`{"jsonrpc":"2.0","id":1,"method":"ETH_SENDRAWTRANSACTION","params":["0x01"],"visibleTo":["did:a:b"]}`))
		require.Nil(t, perr)
		assert.Equal(t, `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"],"visibleTo":["did:a:b"]}`, string(body))
	})
}

// TestProcessCalledOnlyFromHandleJSONRPC pins the single choke point: the
// processor forwards ProcessRequest.Body, so the only production code that
// reaches Process must be handleJSONRPC, which fills Body from
// ParseAndValidateBody. A new caller has to go through the same parse
// (RD-1303). It is a syntactic gate over every non-test file of the package:
// any reference to a selector named Process (a call, a method value, a
// method expression; any receiver) counts, and the Body handed to the
// processor must be the third result of a ParseAndValidateBody call in the
// same function. Process is only referenced in this package (repo-wide grep at
// the time of writing).
func TestProcessCalledOnlyFromHandleJSONRPC(t *testing.T) {
	fset := token.NewFileSet()
	pkgFiles, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var references []string
	bodyFromParse := false
	for _, path := range pkgFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err, path)
		for _, decl := range file.Decls {
			owner := "<package level>"
			var root ast.Node = decl
			if fn, ok := decl.(*ast.FuncDecl); ok {
				if fn.Body == nil {
					continue
				}
				owner, root = fn.Name.Name, fn.Body
			}
			parsedInto := map[string]bool{} // identifiers assigned from ParseAndValidateBody's body result
			ast.Inspect(root, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					if call, ok := n.Rhs[0].(*ast.CallExpr); ok && len(n.Rhs) == 1 && len(n.Lhs) == 4 {
						if fnID, ok := call.Fun.(*ast.Ident); ok && fnID.Name == "ParseAndValidateBody" {
							if id, ok := n.Lhs[2].(*ast.Ident); ok {
								parsedInto[id.Name] = true
							}
						}
					}
				case *ast.SelectorExpr:
					if n.Sel.Name == "Process" {
						references = append(references, owner)
					}
				case *ast.CompositeLit:
					if id, ok := n.Type.(*ast.Ident); ok && id.Name == "ProcessRequest" {
						for _, elt := range n.Elts {
							kv, ok := elt.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Body" {
								require.Equal(t, "handleJSONRPC", owner, "ProcessRequest.Body set outside handleJSONRPC (%s)", path)
								val, _ := kv.Value.(*ast.Ident)
								require.NotNil(t, val, "ProcessRequest.Body must be the canonical body from ParseAndValidateBody")
								bodyFromParse = parsedInto[val.Name]
							}
						}
					}
				}
				return true
			})
		}
	}
	assert.Equal(t, []string{"handleJSONRPC"}, references, "references to a Process selector in production code")
	assert.True(t, bodyFromParse, "handleJSONRPC must pass the body returned by ParseAndValidateBody")
}

// TestDryRun_RefusesCaseVariantRequestField: the admin dry-run forwards its rpc
// block re-encoded. Both diagnostics follow the request-field validation policy.
func TestDryRun_RefusesCaseVariantRequestField(t *testing.T) {
	f := setupDryRunFixture(t)
	node := newEnvelopeCanaryNode(t)
	f.srv.proxy = proxy.New(node.srv.URL)

	body := func(toKey string) map[string]any {
		return map[string]any{
			"user_did": f.userDID,
			"rpc": map[string]any{
				"method": "eth_call",
				"params": []any{map[string]any{toKey: f.contractAddr, "data": "0x"}, "latest"},
			},
		}
	}
	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body("To"))
	assert.Equal(t, http.StatusBadRequest, w.Code, "body=%s", w.Body.String())
	assert.JSONEq(t, `{"error":"invalid request body"}`, w.Body.String())
	assert.Empty(t, node.receivedStrings(), "the refused rpc block must not reach the node")

	// Control: the exact-case field passes the parse (whatever the decision).
	w = dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, body("to"))
	assert.NotContains(t, w.Body.String(), "invalid request body")
}

// TestTestRequest_RefusesCaseVariantRequestField: same for the admin
// test-request preview, which forwards its own decode of method and params.
func TestTestRequest_RefusesCaseVariantRequestField(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	node := newEnvelopeCanaryNode(t)
	ts.proxy = proxy.New(node.srv.URL)
	router := gin.New()
	router.POST("/test-request", ts.handleTestRequest)

	post := func(toKey string) *httptest.ResponseRecorder {
		b := `{"method":"eth_call","params":[{"` + toKey + `":"` + envAddrB + `","data":"0x"},"latest"]}`
		req := httptest.NewRequest(http.MethodPost, "/test-request", bytes.NewReader([]byte(b)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	w := post("To")
	assert.Equal(t, http.StatusBadRequest, w.Code, "body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid request body")
	assert.Empty(t, node.receivedStrings(), "the refused request must not reach the node")

	w = post("to")
	assert.NotContains(t, w.Body.String(), "invalid request body")
}

// TestParseAndValidateBody_ParamsRulesScopedToReadMethods: the request-field
// and data/input rules refuse params the proxy's checks read, and leave alone
// only the payloads of named passthrough methods, which it never inspects.
// Typed-data signing is globally blocked and gets no exemption.
func TestParseAndValidateBody_ParamsRulesScopedToReadMethods(t *testing.T) {
	t.Cleanup(rbac.SnapshotMethodRegistriesForTest())
	rbac.MethodAliases["linea_call"] = "eth_call"
	rbac.PassthroughMethods["lotus_send"] = true

	refused := map[string]string{
		"eth_call To":            `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"To":"` + envAddrB + `","data":"0x01"},"latest"]}`,
		"aliased call To":        `{"jsonrpc":"2.0","id":1,"method":"linea_call","params":[{"To":"` + envAddrB + `","data":"0x01"},"latest"]}`,
		"getLogs Address":        `{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"Address":"` + envAddrB + `"}]}`,
		"data and input differ":  `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + envAddrA + `","data":"0xa9059cbb","input":"0x095ea7b3"},"latest"]}`,
		"estimateGas BlockHash":  `{"jsonrpc":"2.0","id":1,"method":"eth_estimateGas","params":[{"to":"` + envAddrA + `"},{"BlockHash":"0x01"}]}`,
		"sendRawTransaction opt": `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01",{"VisibleTo":["did:a:b"]}]}`,
		"typed data To":          `{"jsonrpc":"2.0","id":1,"method":"eth_signTypedData_v4","params":["` + envAddrA + `",{"types":{"EIP712Domain":[],"Data":[{"name":"To","type":"address"}]},"primaryType":"Data","message":{"To":"` + envAddrB + `","Value":1}}]}`,
	}
	for name, body := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			_, _, _, perr := ParseAndValidateBody([]byte(body))
			require.NotNil(t, perr)
			assert.Equal(t, http.StatusBadRequest, perr.StatusCode)
			assert.Equal(t, "invalid JSON-RPC request", perr.Message)
		})
	}
	accepted := map[string]string{
		"named passthrough PascalCase schema":    `{"jsonrpc":"2.0","id":1,"method":"lotus_send","params":[{"To":"f01","From":"f02","Value":"1","Nonce":1}]}`,
		"data and input equal ignoring hex case": `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + envAddrA + `","data":"0xA9059CBB","input":"0xa9059cbb"},"latest"]}`,
	}
	for name, body := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			_, _, _, perr := ParseAndValidateBody([]byte(body))
			assert.Nil(t, perr)
		})
	}
}
