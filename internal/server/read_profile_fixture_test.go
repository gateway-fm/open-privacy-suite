package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Shared fixture for the RD-1299 read-profile tests: ONE database drives both
// the JSON-RPC filters and the proxy-mode explorer, so every viewer is judged on
// identical facts by both layers.
//
// Org O owns contract C (ERC-20 ABI). User U (EOA rpE) sends tx rpTx1 E -> C with
// calldata, value and nonce, listing V in visibleTo. The tx emits:
//
//	L0 Transfer(E, P, 1000)  — indexed-self for U and P
//	L1 Transfer(Q, R, 5)     — names none of the viewers
//	L2 Transfer(AA, R, 1)    — indexed-self for the org admin A
//
// A second tx rpTx2 (Q -> C) sits in the same block and involves no viewer.
const (
	rpC    = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0" // org O contract (ERC-20 ABI)
	rpC2   = "0xd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0" // other org contract
	rpE    = "0xa11ce00000000000000000000000000000000001" // U, the sender
	rpP    = "0xb0b0000000000000000000000000000000000002" // P, the payee
	rpAA   = "0xad00000000000000000000000000000000000003" // A, org admin
	rpT3   = "0x7e30000000000000000000000000000000000004" // T, contract admin (tier 3)
	rpV    = "0x7150000000000000000000000000000000000005" // V, visibleTo recipient
	rpM    = "0x3e30000000000000000000000000000000000006" // M, ordinary member, wildcard rules
	rpX    = "0x0e70000000000000000000000000000000000007" // X, other-org viewer
	rpQ    = "0x9990000000000000000000000000000000000008" // third party
	rpR    = "0x8880000000000000000000000000000000000009" // third party
	rpTx1  = "0x1299000000000000000000000000000000000000000000000000000000000a01"
	rpTx2  = "0x1299000000000000000000000000000000000000000000000000000000000a02"
	rpData = "0xa9059cbb000000000000000000000000b0b000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000003e8"
	rpT0   = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" // Transfer(address,address,uint256)
)

type rpViewer struct {
	name string
	did  string
	uuid string
	org  string
	addr string
}

type rpFixture struct {
	srv     *Server
	db      *db.DB
	conn    *sql.DB
	orgID   string
	otherID string
	viewers map[string]rpViewer
	block   int64
}

// viewer names, in matrix order
var rpViewerNames = []string{"participant", "payee", "ordinary", "contract_admin", "org_admin", "visibleto", "other_org"}

func setupRPFixture(t *testing.T) *rpFixture {
	t.Helper()
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	_, err := conn.ExecContext(context.Background(), explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})
	ctx := context.Background()
	f := &rpFixture{srv: srv, db: database, conn: conn, viewers: map[string]rpViewer{}}

	f.orgID = uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: f.orgID, Slug: "rp-o-" + f.orgID[:8], Name: "RP O", Settings: map[string]any{}}))
	f.otherID = uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: f.otherID, Slug: "rp-x-" + f.otherID[:8], Name: "RP X", Settings: map[string]any{}}))

	cID := wiringCreateContractWithABI(t, database, f.orgID, rpC, "RPToken", erc20ABI)
	c2ID := wiringCreateContractWithABI(t, database, f.otherID, rpC2, "RPOther", erc20ABI)

	selfEither := &rbac.EventRulesField{Rules: []rbac.EventRule{{
		Topic0: rpT0, Name: "Transfer",
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}, {Index: 1, MustBe: "self"}},
	}}}
	gUser := wiringCreateGroup(t, database, f.orgID, "rp-users", nil, false)
	wiringCreateGrant(t, database, cID, gUser, selfEither)
	gWild := wiringCreateGroup(t, database, f.orgID, "rp-wild", nil, false)
	wiringCreateGrant(t, database, cID, gWild, &rbac.EventRulesField{Wildcard: true})
	gAdmin := wiringCreateGroup(t, database, f.orgID, "rp-admins", nil, true)
	gT3 := wiringCreateGroup(t, database, f.orgID, "rp-t3", []rbac.Claim{rbac.ClaimAdmin}, false)
	wiringCreateGrant(t, database, cID, gT3, nil)
	gX := wiringCreateGroup(t, database, f.otherID, "rp-x", nil, false)
	wiringCreateGrant(t, database, c2ID, gX, &rbac.EventRulesField{Wildcard: true})

	add := func(name, group, org, addr string) {
		did := "did:test:rp:" + name
		uid := wiringCreateUserInGroup(t, database, did, group)
		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))
		f.viewers[name] = rpViewer{name: name, did: did, uuid: uid, org: org, addr: addr}
	}
	add("participant", gUser, f.orgID, rpE)
	add("payee", gUser, f.orgID, rpP)
	add("visibleto", gUser, f.orgID, rpV)
	add("ordinary", gWild, f.orgID, rpM)
	add("org_admin", gAdmin, f.orgID, rpAA)
	add("contract_admin", gT3, f.orgID, rpT3)
	add("other_org", gX, f.otherID, rpX)
	// Q and R are real users too (linked, so their addresses are private EOAs).
	for _, a := range []struct{ did, addr string }{{"did:test:rp:q", rpQ}, {"did:test:rp:r", rpR}} {
		wiringCreateUserInGroup(t, database, a.did, gUser)
		require.NoError(t, database.SystemLinkEthAddress(ctx, a.did, a.addr))
	}

	// visibleTo: U listed V on rpTx1.
	require.NoError(t, database.SaveTxVisibility(ctx, rpTx1, []string{f.viewers["visibleto"].did}, f.viewers["participant"].did, f.orgID))

	// Explorer chain data for the same two transactions.
	f.block = seedExplorerBlock(t, conn)
	for _, tx := range []struct{ hash, from, input string }{{rpTx1, rpE, rpData}, {rpTx2, rpQ, "0x"}} {
		_, err := conn.ExecContext(ctx,
			`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, nonce, status, input_data)
			 VALUES ($1, $2, 0, $3, $4, 42, 21000, 1000000000, 7, 1, $5)`, tx.hash, f.block, tx.from, rpC, tx.input)
		require.NoError(t, err)
	}
	for i, l := range rpLogs() {
		_, err := conn.ExecContext(ctx, `INSERT INTO logs (tx_hash, log_index, address, topic0, topic1, topic2, data, block_number)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, rpTx1, i, rpC, l.topics[0], l.topics[1], l.topics[2], l.data, f.block)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, rpTx1, i, rpC, l.from, l.to, l.value, f.block)
		require.NoError(t, err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		VALUES ($1, $2, '0', $3, $4, 50, 'CALL')`, rpTx1, f.block, rpC, rpP)
	require.NoError(t, err)
	return f
}

type rpLog struct {
	topics   [3]string
	data     string
	from, to string
	value    int
}

func rpValueWord(v int) string { return fmt.Sprintf("0x%064x", v) }

func rpLogs() []rpLog {
	mk := func(from, to string, v int) rpLog {
		return rpLog{topics: [3]string{rpT0, zeroPadAddrToTopic(from), zeroPadAddrToTopic(to)}, data: rpValueWord(v), from: from, to: to, value: v}
	}
	return []rpLog{mk(rpE, rpP, 1000), mk(rpQ, rpR, 5), mk(rpAA, rpR, 1)}
}

// rpProcessor builds a processor wired like production (visibleTo store and the
// address-visibility resolver for log field redaction) with the given profile.
func (f *rpFixture) rpProcessor(profile rbac.ReadProfile) *JSONRPCProcessor {
	return NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:            f.srv.rbacAccessCtrl,
		RateLimiter:               &noopRateLimiter{},
		AccessLogger:              f.db,
		CircuitBreaker:            middleware.NewCircuitBreaker(),
		ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
		TxVisibilityStore:         f.db,
		AddressVisibilityResolver: f.db,
		ReadProfile:               profile,
	})
}

func (f *rpFixture) result(v rpViewer) *rbac.AccessCheckResult {
	return &rbac.AccessCheckResult{Allowed: true, UserID: v.uuid, OrgID: v.org}
}

func (f *rpFixture) call(t *testing.T, p *JSONRPCProcessor, v rpViewer, method string, params []any, body []byte) []byte {
	t.Helper()
	return p.applyResponseFilter(context.Background(), &ProcessRequest{Method: method, UserID: v.did, Params: params, Body: body}, f.result(v), body)
}

func rpJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func rpTxObject(hash, from, input string) map[string]any {
	return map[string]any{
		"hash": hash, "from": from, "to": rpC, "input": input, "value": "0x2a", "nonce": "0x7",
		"blockHash": "0x" + strings.Repeat("0", 63) + "b", "blockNumber": "0x1", "transactionIndex": "0x0",
		"gas": "0x5208", "gasPrice": "0x1", "v": "0x0", "r": "0x0", "s": "0x0",
	}
}

func rpRawLogs(txHash string) []map[string]any {
	out := []map[string]any{}
	for i, l := range rpLogs() {
		out = append(out, map[string]any{
			"address": rpC, "topics": []string{l.topics[0], l.topics[1], l.topics[2]}, "data": l.data,
			"blockNumber": "0x1", "transactionHash": txHash, "logIndex": fmt.Sprintf("0x%x", i), "removed": false,
		})
	}
	return out
}

func rpReceiptObject(hash, from string, logs []map[string]any) map[string]any {
	if logs == nil {
		logs = []map[string]any{}
	}
	return map[string]any{
		"transactionHash": hash, "from": from, "to": rpC, "status": "0x1", "gasUsed": "0x5208",
		"cumulativeGasUsed": "0x5208", "effectiveGasPrice": "0x1", "contractAddress": nil,
		"blockNumber": "0x1", "transactionIndex": "0x0", "logsBloom": "0x" + strings.Repeat("f", 512), "logs": logs,
	}
}

func rpEnvelope(t *testing.T, result any) []byte {
	return rpJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
}

func rpResult(t *testing.T, body []byte) json.RawMessage {
	t.Helper()
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoErrorf(t, json.Unmarshal(body, &resp), "invalid JSON-RPC body: %s", body)
	return resp.Result
}

// rpHasAddr reports whether addr appears anywhere in body (case-insensitive,
// with or without the 0x prefix, including inside zero-padded topics).
func rpHasAddr(body []byte, addr string) bool {
	return strings.Contains(strings.ToLower(string(body)), strings.TrimPrefix(strings.ToLower(addr), "0x"))
}

// wireExplorer installs an explorer redaction engine wired like production
// (wireExplorerRedactor) with the given profile, and sets the server's profile,
// so explorer handlers and the RPC processor run the same policy.
func (f *rpFixture) wireExplorer(profile rbac.ReadProfile) {
	engine := explorer.NewRedactionEngine(f.srv.explorerStore, f.db, profile)
	wireExplorerRedactor(engine, f.db, f.srv.rbacAccessCtrl, f.srv.explorerStore, nil)
	f.srv.explorerRedactor = engine
	f.srv.config.ReadProfile = profile
}

// explorerRouter mounts every explorer endpoint (production binding) behind
// the optional-JWT middleware.
func (f *rpFixture) explorerRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	g := router.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(f.srv.jwtService, f.srv.db))
	f.srv.bindExplorerEndpoints(g)
	return router
}

func (f *rpFixture) explorerGet(t *testing.T, router *gin.Engine, v rpViewer, path string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+issueTestJWT(t, f.srv, v.did))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes()
}
