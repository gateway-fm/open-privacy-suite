package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1353: disclosure grants apply only through the grant API, so the grant
// API is hardened as the single source of disclosed data — requester
// eligibility, the scope (date range, address list, methods, level), no real
// address at the pseudonymous level, a transaction detail endpoint for Full
// grants, and an audit row for every read.

const (
	rd1353Counterparty = "0x3333333333333333333333333333333333333333"
	rd1353Other        = "0x4444444444444444444444444444444444444444"
)

func setupRD1353GrantRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	g := router.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	g.GET("/viewable-addresses", srv.getViewableAddresses)
	g.GET("/grant/:grant_id/resolve/:address_id", srv.resolveAddressID)
	g.GET("/grant/:grant_id/activity", srv.getGrantActivityLogs)
	g.GET("/grant/:grant_id/:address_id/transactions", srv.getGrantTransactions)
	g.GET("/grant/:grant_id/:address_id/transactions/:tx_hash", srv.getGrantTransaction)
	return router
}

var rd1353TxCounter int64

// rd1353SeedBlockAt inserts a block with the given timestamp.
func rd1353SeedBlockAt(t *testing.T, conn *sql.DB, ts int64) int64 {
	t.Helper()
	num := atomic.AddInt64(&explorerBlockCounter, 1)
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count,
		 size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES ($1, $2, $3, $4, 21000, 30000000, 1, 0, '0', '0', '0x0', '', '', '', '', '')`,
		num, fmt.Sprintf("0xblock%d", num), fmt.Sprintf("0xparent%d", num-1), ts)
	require.NoError(t, err)
	return num
}

// rd1353SeedTx inserts a transaction with a real-looking 32-byte hash and
// calldata embedding the recipient, and returns the hash.
func rd1353SeedTx(t *testing.T, conn *sql.DB, block int64, txIndex int, from, to string) string {
	t.Helper()
	n := atomic.AddInt64(&rd1353TxCounter, 1)
	hash := fmt.Sprintf("0x%064x", 0xd15c000000+n)
	input := "0xa9059cbb000000000000000000000000" + strings.TrimPrefix(to, "0x")
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, nonce, status, input_data)
		 VALUES ($1, $2, $3, $4, $5, 1234, 21000, 1000000000, 7, 1, $6)`,
		hash, block, txIndex, from, to, input)
	require.NoError(t, err)
	return hash
}

func rd1353Get(t *testing.T, router *gin.Engine, srv *Server, did, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if did != "" {
		addBearerToken(t, req, srv, did)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

type rd1353Fixture struct {
	srv          *Server
	database     *db.DB
	conn         *sql.DB
	router       *gin.Engine
	targetUserID string
}

func newRD1353Fixture(t *testing.T) *rd1353Fixture {
	t.Helper()
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	f := &rd1353Fixture{srv: srv, database: database, conn: conn, router: setupRD1353GrantRouter(srv)}
	createTestUserForExplorer(t, database, testViewerDID)
	linkEthAddressToUser(t, database, testViewerDID, testViewerWallet)
	f.targetUserID = createTestUserForExplorer(t, database, testTargetDID)
	linkEthAddressToUser(t, database, testTargetDID, testTargetAddress)
	return f
}

func (f *rd1353Fixture) grant(t *testing.T, scopeJSON string) (grantID, addressID string) {
	t.Helper()
	grantID = createDisclosureGrantWithScopeJSON(t, f.database, testViewerDID, f.targetUserID, scopeJSON, time.Now().Add(24*time.Hour))
	return grantID, explorer.GenerateAddressID(testTargetAddress, grantID)
}

func (f *rd1353Fixture) txs(t *testing.T, grantID, addressID string) (int, apimodels.GrantTransactionsResponse) {
	t.Helper()
	w := rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions?limit=100")
	var resp apimodels.GrantTransactionsResponse
	if w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	}
	return w.Code, resp
}

func (f *rd1353Fixture) detail(t *testing.T, did, grantID, addressID, hash string) *httptest.ResponseRecorder {
	t.Helper()
	return rd1353Get(t, f.router, f.srv, did, "/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions/"+hash)
}

// The requester must still be a current member of the organization the
// request was made in; a former member (or one whose membership expired) is
// treated like any non-holder: the uniform 404, and no disclosed address in
// the viewable list.
func TestGrantAPI_RequesterMustStayOrgMember_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	grantID, addressID := f.grant(t, `{"disclosure_level":"full","methods":["full_disclosure"]}`)
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	hash := rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)

	code, resp := f.txs(t, grantID, addressID)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, resp.Transactions, 1)
	require.Equal(t, http.StatusOK, f.detail(t, testViewerDID, grantID, addressID, hash).Code)

	_, err := f.conn.ExecContext(context.Background(),
		`UPDATE user_memberships SET expires_at = NOW() - interval '1 minute'
		 WHERE user_id = (SELECT id FROM users WHERE external_id = $1)`, testViewerDID)
	require.NoError(t, err)

	for name, path := range map[string]string{
		"transactions": "/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions",
		"detail":       "/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions/" + hash,
		"resolve":      "/api/v1/explorer/grant/" + grantID + "/resolve/" + addressID,
		"activity":     "/api/v1/explorer/grant/" + grantID + "/activity",
	} {
		w := rd1353Get(t, f.router, f.srv, testViewerDID, path)
		assert.Equal(t, http.StatusNotFound, w.Code, "%s: a requester who left the org must get the uniform 404", name)
		assert.NotContains(t, strings.ToLower(w.Body.String()), strings.TrimPrefix(testTargetAddress, "0x"), name)
	}

	w := rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/viewable-addresses")
	require.Equal(t, http.StatusOK, w.Code)
	var va apimodels.ViewableAddressesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &va))
	assert.Empty(t, va.DisclosedAddresses, "a former member's grants are not listed")
}

// A grant made in an organization the requester never belonged to does not
// apply either.
func TestGrantAPI_GrantInForeignOrg_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	grantID, addressID := f.grant(t, `{"disclosure_level":"full"}`)
	otherOrg := uuid.New().String()
	_, err := f.conn.ExecContext(context.Background(),
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, 'Other', '{}')", otherOrg, "other-"+otherOrg[:8])
	require.NoError(t, err)
	_, err = f.conn.ExecContext(context.Background(),
		`UPDATE disclosure_requests SET org_id = $1 WHERE id = (SELECT request_id FROM disclosure_grants WHERE id = $2)`, otherOrg, grantID)
	require.NoError(t, err)

	code, _ := f.txs(t, grantID, addressID)
	assert.Equal(t, http.StatusNotFound, code)
}

// An empty disclosure_level renders as redacted on every grant route, never
// as full.
func TestGrantAPI_EmptyLevelIsRedacted_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	grantID, addressID := f.grant(t, `{}`)
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)

	w := rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/viewable-addresses")
	require.Equal(t, http.StatusOK, w.Code)
	var va apimodels.ViewableAddressesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &va))
	require.Len(t, va.DisclosedAddresses, 1)
	assert.Equal(t, "redacted", va.DisclosedAddresses[0].DisclosureLevel)
	assert.Equal(t, "[PRIVATE]", va.DisclosedAddresses[0].Address)

	w = rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/grant/"+grantID+"/resolve/"+addressID)
	require.Equal(t, http.StatusOK, w.Code)
	var rr apimodels.ResolveAddressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rr))
	assert.Equal(t, "redacted", rr.DisclosureLevel)
	assert.Nil(t, rr.RealAddress)
	assert.Empty(t, rr.Pseudonym)

	code, resp := f.txs(t, grantID, addressID)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "redacted", resp.DisclosureLevel)
	require.Len(t, resp.Transactions, 1)
	tx := resp.Transactions[0]
	assert.Nil(t, tx.TxHash)
	assert.Equal(t, "[PRIVATE]", tx.From)
	assert.Equal(t, "[PRIVATE]", tx.To)
	assert.Equal(t, "hidden", tx.Value)
}

// The transaction feed and detail require transaction_history or
// full_disclosure (or no method restriction); an activity-logs-only grant
// does not disclose transactions.
func TestGrantAPI_MethodsGateTransactions_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	hash := rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)

	for _, c := range []struct {
		scope string
		want  int
	}{
		{`{"disclosure_level":"full","methods":["activity_logs"]}`, http.StatusForbidden},
		{`{"disclosure_level":"full","methods":["transaction_history"]}`, http.StatusOK},
		{`{"disclosure_level":"full","methods":["full_disclosure"]}`, http.StatusOK},
		{`{"disclosure_level":"full"}`, http.StatusOK},
	} {
		grantID, addressID := f.grant(t, c.scope)
		code, _ := f.txs(t, grantID, addressID)
		assert.Equal(t, c.want, code, "feed, scope %s", c.scope)
		assert.Equal(t, c.want, f.detail(t, testViewerDID, grantID, addressID, hash).Code, "detail, scope %s", c.scope)
	}
}

// The date range (inclusive, on the block time) and the address list bound
// the feed and the detail alike.
func TestGrantAPI_ScopeBoundsFeedAndDetail_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC).Unix()

	hashAt := map[string]string{}
	for name, ts := range map[string]int64{"before": start - 1, "start": start, "mid": start + 86400, "end": end, "after": end + 1} {
		b := rd1353SeedBlockAt(t, f.conn, ts)
		hashAt[name] = rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)
	}
	grantID, addressID := f.grant(t, `{"disclosure_level":"full","date_range":{"start":"2026-01-01T00:00:00Z","end":"2026-01-31T23:59:59Z"}}`)

	code, resp := f.txs(t, grantID, addressID)
	require.Equal(t, http.StatusOK, code)
	var got []string
	for _, tx := range resp.Transactions {
		require.NotNil(t, tx.TxHash)
		got = append(got, *tx.TxHash)
	}
	assert.ElementsMatch(t, []string{hashAt["start"], hashAt["mid"], hashAt["end"]}, got)
	for name, hash := range hashAt {
		want := http.StatusOK
		if name == "before" || name == "after" {
			want = http.StatusNotFound
		}
		assert.Equal(t, want, f.detail(t, testViewerDID, grantID, addressID, hash).Code, "detail %s", name)
	}

	// Address list: only the subject's transactions with a listed party.
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	withListed := rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)
	withOther := rd1353SeedTx(t, f.conn, b, 1, rd1353Other, testTargetAddress)
	grantID, addressID = f.grant(t, `{"disclosure_level":"full","addresses":["`+rd1353Counterparty+`"]}`)
	code, resp = f.txs(t, grantID, addressID)
	require.Equal(t, http.StatusOK, code)
	got = nil
	for _, tx := range resp.Transactions {
		got = append(got, *tx.TxHash)
	}
	assert.Contains(t, got, withListed)
	assert.NotContains(t, got, withOther)
	assert.Equal(t, http.StatusOK, f.detail(t, testViewerDID, grantID, addressID, withListed).Code)
	assert.Equal(t, http.StatusNotFound, f.detail(t, testViewerDID, grantID, addressID, withOther).Code)
}

// The detail endpoint serves a Full grant's in-scope transaction of the
// subject, and the uniform 404 for anything else — including every
// pseudonymous or redacted grant, for which a hash lookup would confirm that
// a hash belongs to the subject.
func TestGrantAPI_TransactionDetail_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	hash := rd1353SeedTx(t, f.conn, b, 3, testTargetAddress, rd1353Counterparty)
	notSubjects := rd1353SeedTx(t, f.conn, b, 4, rd1353Other, rd1353Counterparty)
	grantID, addressID := f.grant(t, `{"disclosure_level":"full"}`)

	w := f.detail(t, testViewerDID, grantID, addressID, hash)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var d apimodels.GrantTransactionDetail
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &d))
	assert.Equal(t, hash, d.TxHash)
	assert.Equal(t, uint64(b), d.BlockNumber)
	assert.Equal(t, 3, d.TxIndex)
	assert.Equal(t, testTargetAddress, d.From)
	assert.Equal(t, rd1353Counterparty, d.To)
	assert.Equal(t, "1234", d.Value)
	assert.Equal(t, "out", d.Direction)
	assert.NotEmpty(t, d.InputData)
	assert.NotZero(t, d.BlockTimestamp)

	assert.Equal(t, http.StatusNotFound, f.detail(t, testViewerDID, grantID, addressID, notSubjects).Code, "not the subject's transaction")
	assert.Equal(t, http.StatusNotFound, f.detail(t, testViewerDID, grantID, addressID, "0x"+strings.Repeat("ab", 32)).Code, "unknown hash")
	assert.Equal(t, http.StatusBadRequest, f.detail(t, testViewerDID, grantID, addressID, "0x1234").Code, "malformed hash")
	assert.Equal(t, http.StatusUnauthorized, f.detail(t, "", grantID, addressID, hash).Code, "anonymous")
	assert.Equal(t, http.StatusNotFound, f.detail(t, "did:privado:someone_else", grantID, addressID, hash).Code, "not the grantee")

	for _, level := range []string{"pseudonymous", "redacted"} {
		g, a := f.grant(t, `{"disclosure_level":"`+level+`"}`)
		w := f.detail(t, testViewerDID, g, a, hash)
		assert.Equal(t, http.StatusNotFound, w.Code, level)
		assert.NotContains(t, w.Body.String(), strings.TrimPrefix(hash, "0x"), level)
	}

	_, err := f.conn.ExecContext(context.Background(), `UPDATE disclosure_grants SET revoked_at = NOW() WHERE id = $1`, grantID)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, f.detail(t, testViewerDID, grantID, addressID, hash).Code, "revoked")
}

var (
	rd1353HexAddr = regexp.MustCompile(`(?i)0x[0-9a-f]{40}`)
	rd1353HexHash = regexp.MustCompile(`(?i)0x[0-9a-f]{64}`)
)

// At the pseudonymous level no real address (and no transaction hash) appears
// in any grant response: not the subject's, not a counterparty's.
func TestGrantAPI_PseudonymousResponsesCarryNoRealHex_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	hash := rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)
	rd1353SeedTx(t, f.conn, b, 1, rd1353Other, testTargetAddress)
	rd1353SeedTx(t, f.conn, b, 2, testTargetAddress, "")
	grantID, addressID := f.grant(t, `{"disclosure_level":"pseudonymous","methods":["full_disclosure"]}`)

	for _, path := range []string{
		"/api/v1/explorer/grant/" + grantID + "/resolve/" + addressID,
		"/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions",
		"/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions/" + hash,
		"/api/v1/explorer/grant/" + grantID + "/activity",
	} {
		w := rd1353Get(t, f.router, f.srv, testViewerDID, path)
		assert.Empty(t, rd1353HexAddr.FindAllString(w.Body.String(), -1), "%s leaked an address: %s", path, w.Body.String())
		assert.Empty(t, rd1353HexHash.FindAllString(w.Body.String(), -1), "%s leaked a hash", path)
	}

	// The viewable list carries the viewer's own addresses, never the subject's.
	w := rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/viewable-addresses")
	body := strings.ToLower(w.Body.String())
	for _, a := range []string{testTargetAddress, rd1353Counterparty, rd1353Other} {
		assert.NotContains(t, body, strings.ToLower(a))
	}

	// Rows carry their position so a client can order and de-duplicate them.
	code, resp := f.txs(t, grantID, addressID)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, resp.Transactions, 3)
	idx := map[int]bool{}
	for _, tx := range resp.Transactions {
		assert.Equal(t, uint64(b), tx.BlockNumber)
		idx[tx.TxIndex] = true
	}
	assert.Equal(t, map[int]bool{0: true, 1: true, 2: true}, idx)
}

// Every grant read leaves a disclosure event naming the grant and the viewer;
// the event carries counts, never a transaction hash.
func TestGrantAPI_ReadsAreAudited_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	b := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	hash := rd1353SeedTx(t, f.conn, b, 0, testTargetAddress, rd1353Counterparty)
	grantID, addressID := f.grant(t, `{"disclosure_level":"full","methods":["full_disclosure"]}`)

	for _, path := range []string{
		"/api/v1/explorer/viewable-addresses",
		"/api/v1/explorer/grant/" + grantID + "/resolve/" + addressID,
		"/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions",
		"/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions/" + hash,
		"/api/v1/explorer/grant/" + grantID + "/activity",
	} {
		require.Equal(t, http.StatusOK, rd1353Get(t, f.router, f.srv, testViewerDID, path).Code, path)
	}

	rows, err := f.conn.QueryContext(context.Background(),
		`SELECT e.action, e.resource_type, COALESCE(e.data_summary::text, ''), u.external_id
		 FROM disclosure_events e LEFT JOIN users u ON u.id = e.viewer_user_id
		 WHERE e.grant_id = $1`, grantID)
	require.NoError(t, err)
	defer rows.Close()
	actions := map[string]bool{}
	for rows.Next() {
		var action, resource, summary string
		var viewer sql.NullString
		require.NoError(t, rows.Scan(&action, &resource, &summary, &viewer))
		actions[action] = true
		assert.Equal(t, testViewerDID, viewer.String, "event %s names the viewer", action)
		assert.NotContains(t, summary, strings.TrimPrefix(hash, "0x"), "event %s carries no tx hash", action)
	}
	require.NoError(t, rows.Err())
	for _, a := range []string{"list_addresses", "resolve_address", "view_transactions", "view_transaction", "view_logs"} {
		assert.True(t, actions[a], "missing %s event; got %v", a, actions)
	}
}

func TestGrantAPI_OrgPinAndInvalidScope_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	grantID, addressID := f.grant(t, `{"disclosure_level":"full"}`)
	for _, path := range []string{
		"/api/v1/explorer/viewable-addresses",
		"/api/v1/explorer/grant/" + grantID + "/resolve/" + addressID,
		"/api/v1/explorer/grant/" + grantID + "/" + addressID + "/transactions",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		addBearerToken(t, req, f.srv, testViewerDID)
		req = req.WithContext(withViewerOrgScope(req.Context(), uuid.NewString()))
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, req)
		if strings.HasSuffix(path, "viewable-addresses") {
			var response apimodels.ViewableAddressesResponse
			require.Equal(t, http.StatusOK, w.Code)
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Empty(t, response.DisclosedAddresses)
		} else {
			assert.Equal(t, http.StatusNotFound, w.Code)
		}
	}
	for _, scope := range []string{
		`{"methods":["eth_call"],"disclosure_level":"full"}`,
		`{"addresses":["not-an-address"],"disclosure_level":"full"}`,
		`{"date_range":{"start":"2026-01-01T00:00:00Z"},"disclosure_level":"full"}`,
	} {
		_, err := f.conn.ExecContext(context.Background(), "UPDATE disclosure_grants SET scope=$1 WHERE id=$2", scope, grantID)
		require.NoError(t, err)
		code, _ := f.txs(t, grantID, addressID)
		assert.Equal(t, http.StatusNotFound, code, scope)
		w := rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/viewable-addresses")
		var response apimodels.ViewableAddressesResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Empty(t, response.DisclosedAddresses, scope)
	}
}

func TestGrantAPI_KeyedIdentifiersAndPrivateOwnerDID_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	if f.srv.config == nil {
		f.srv.config = &config.Config{}
	}
	f.srv.config.ExplorerPseudonymKey = []byte("rd1353-regression-key")
	grantID, oldID := f.grant(t, `{"disclosure_level":"pseudonymous"}`)
	w := rd1353Get(t, f.router, f.srv, testViewerDID, "/api/v1/explorer/viewable-addresses")
	var response apimodels.ViewableAddressesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Len(t, response.DisclosedAddresses, 1)
	disclosed := response.DisclosedAddresses[0]
	assert.Empty(t, disclosed.OwnerDID, "non-Full lists must not reveal an address-bearing owner DID")
	assert.NotEqual(t, oldID, disclosed.AddressID, "candidate addresses cannot reproduce keyed routing identifiers")
	base := "/api/v1/explorer/grant/" + grantID + "/resolve/"
	assert.Equal(t, http.StatusOK, rd1353Get(t, f.router, f.srv, testViewerDID, base+disclosed.AddressID).Code)
	assert.Equal(t, http.StatusNotFound, rd1353Get(t, f.router, f.srv, testViewerDID, base+oldID).Code)
	assert.NotEqual(t, generateExternalPseudonym(rd1353Counterparty, grantID), f.srv.externalPseudonym(rd1353Counterparty, grantID))
}
