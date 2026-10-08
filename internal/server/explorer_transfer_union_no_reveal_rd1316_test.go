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
	"time"

	"privacy-proxy/internal/explorer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1316 exercises explorer parent-row inclusion, ordinary field rendering
// and genuine shares through the HTTP routes for admins and grant holders.
const (
	rd1316Vault    = "0xcccccccccccccccccccccccccccccccccccc1316"
	rd1316Token    = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1316"
	rd1316EOA      = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1316"
	rd1316Callee   = "0xdddddddddddddddddddddddddddddddddddd1316"
	rd1316Calldata = "0xa9059cbb000000000000000000000000cccccccccccccccccccccccccccccccccccc131600000000000000000000000000000000000000000000000000000000000003e8"
	rd1316AdminDID = "did:privado:rd1316_admin"
	rd1316GrantDID = "did:privado:rd1316_grant_holder"
	rd1316Shared   = "did:privado:rd1316_shared_with"
)

type rd1316Fixture struct {
	srv    *Server
	conn   *sql.DB
	router http.Handler
	hash   string
}

func setupRD1316Fixture(t *testing.T) *rd1316Fixture {
	t.Helper()
	srv, _, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()
	_, err := conn.ExecContext(ctx, explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})
	exec := func(q string, args ...any) {
		t.Helper()
		_, err := conn.ExecContext(ctx, q, args...)
		require.NoError(t, err)
	}

	// Org U: tier-2 admin, a plain member with a grant on the vault, the vault.
	orgU := uuid.New().String()
	exec("INSERT INTO organizations (id, slug, name, settings) VALUES ($1, 'rd1316-u', 'U', '{}')", orgU)
	vaultID := uuid.New().String()
	exec("INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Vault')", vaultID, orgU, rd1316Vault)
	adminGroup := uuid.New().String()
	exec("INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)", adminGroup, orgU)
	grantGroup := uuid.New().String()
	exec("INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'vault-readers', 'Vault readers', 0, 'vault-readers')", grantGroup, orgU)
	exec("INSERT INTO contract_grants (id, contract_id, group_id) VALUES ($1, $2, $3)", uuid.New().String(), vaultID, grantGroup)
	for did, group := range map[string]string{rd1316AdminDID: adminGroup, rd1316GrantDID: grantGroup, rd1316Shared: grantGroup} {
		uid := uuid.New().String()
		exec("INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')", uid, did)
		exec("INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')", uuid.New().String(), uid, group)
	}

	// Org O: the token, an internally called contract, and a user whose EOA sends.
	orgO := uuid.New().String()
	exec("INSERT INTO organizations (id, slug, name, settings) VALUES ($1, 'rd1316-o', 'O', '{}')", orgO)
	exec("INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Token')", uuid.New().String(), orgO, rd1316Token)
	exec("INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Callee')", uuid.New().String(), orgO, rd1316Callee)
	exec("INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, 'did:privado:rd1316_sender', false, false, '{}')", uuid.New().String())
	exec("INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ('did:privado:rd1316_sender', $1, 'user')", rd1316EOA)

	block := seedExplorerBlock(t, conn)
	hash := "0x1316" + strings.Repeat("0", 60)
	exec(`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, nonce, status, input_data)
		VALUES ($1, $2, 0, $3, $4, 42, 21000, 1000000000, 7, 1, $5)`, hash, block, rd1316EOA, rd1316Token, rd1316Calldata)
	exec(`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ($1, 0, $2, $3, $4, 1000, $5)`, hash, rd1316Token, rd1316EOA, rd1316Vault, block)
	exec(`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		VALUES ($1, $2, '0', $3, $4, 0, 'CALL'), ($1, $2, '0,0', $4, $5, 0, 'STATICCALL'), ($1, $2, '0,1', $4, $6, 0, 'CALL')`,
		hash, block, rd1316EOA, rd1316Token, rd1316Callee, rd1316Vault)

	return &rd1316Fixture{srv: srv, conn: conn, router: setupCoherenceRouter(srv), hash: hash}
}

func (f *rd1316Fixture) get(t *testing.T, did, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer"+path, nil)
	req.Header.Set("Authorization", "Bearer "+issueTestJWT(t, f.srv, did))
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// requireNoForeignIdentity checks the private addresses (default: the foreign
// EOA, token and callee) and the calldata appear nowhere in body.
func requireNoForeignIdentity(t *testing.T, body, surface string, private ...string) {
	t.Helper()
	lower := strings.ToLower(body)
	if len(private) == 0 {
		private = []string{rd1316EOA, rd1316Token, rd1316Callee}
	}
	for _, addr := range private {
		assert.NotContainsf(t, lower, strings.TrimPrefix(addr, "0x"), "%s returned %s (field or addressMetadata key): %s", surface, addr, body)
	}
	assert.NotContainsf(t, lower, strings.TrimPrefix(rd1316Calldata, "0x")[:40], "%s returned the calldata: %s", surface, body)
}

func TestExplorer_TransferUnion_KeepsRowsWithoutRevealing_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)

	// Org admin: the rows survive (RD-1009 coherence), the identities do not.
	rr := f.get(t, rd1316AdminDID, "/transactions/"+f.hash)
	require.Equal(t, http.StatusOK, rr.Code, "RD-1009: the parent of a visible transfer must not 404: %s", rr.Body.String())
	var tx explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tx))
	assert.Equal(t, "[PRIVATE]", tx.From)
	require.NotNil(t, tx.To)
	assert.Equal(t, "[PRIVATE]", *tx.To)
	assert.Nil(t, tx.Nonce, "nonce revealed")
	assert.Empty(t, tx.InputData, "calldata revealed")
	assert.Empty(t, string(tx.Value), "value revealed")
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions/:hash")

	rr = f.get(t, rd1316AdminDID, "/transactions?limit=25")
	require.Equal(t, http.StatusOK, rr.Code)
	var list []explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	row := findTx(list, f.hash)
	require.NotNil(t, row, "the list keeps the row: %s", rr.Body.String())
	assert.Equal(t, "[PRIVATE]", row.From)
	assert.Nil(t, row.Nonce, "list: nonce revealed")
	assert.Empty(t, row.InputData, "list: calldata revealed")
	assert.Empty(t, string(row.Value), "list: value revealed")
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions")

	rr = f.get(t, rd1316AdminDID, "/transactions/"+f.hash+"/transfers")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, strings.ToLower(rr.Body.String()), strings.TrimPrefix(rd1316Vault, "0x"), "the admin's own contract stays visible")
	// tokenAddress is public infrastructure on a transfer row (§3.3).
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions/:hash/transfers", rd1316EOA)

	// The union keeps the parent only: its frames follow the ordinary frame
	// rules. The frame into the admin's vault survives with the token
	// [PRIVATE]; the two frames with both sides private (the wallet's call,
	// the token's call into another org's contract) are dropped.
	rr = f.get(t, rd1316AdminDID, "/transactions/"+f.hash+"/internal")
	require.Equal(t, http.StatusOK, rr.Code)
	var frames []explorer.InternalTransaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &frames))
	require.Len(t, frames, 1, "only the frame with a side the admin sees: %s", rr.Body.String())
	assert.Equal(t, "[PRIVATE]", frames[0].From)
	require.NotNil(t, frames[0].To)
	assert.Equal(t, rd1316Vault, strings.ToLower(*frames[0].To))
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions/:hash/internal")

	// A plain grant holder of the vault is not an admin: G10 drops another
	// user's one-side-hidden tx, and the union does not keep it for them.
	// (/internal is pinned separately: GAP G28.)
	rr = f.get(t, rd1316GrantDID, "/transactions/"+f.hash)
	assert.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	for _, path := range []string{"/transactions?limit=25", "/transactions/" + f.hash + "/transfers"} {
		rr = f.get(t, rd1316GrantDID, path)
		require.Equal(t, http.StatusOK, rr.Code, path)
		assert.NotContains(t, rr.Body.String(), f.hash[:20], "%s kept a row for a non-admin: %s", path, rr.Body.String())
		requireNoForeignIdentity(t, rr.Body.String(), path)
	}
}

func findTx(txs []explorer.Transaction, hash string) *explorer.Transaction {
	for i := range txs {
		if strings.EqualFold(txs[i].Hash, hash) {
			return &txs[i]
		}
	}
	return nil
}

// addWalletUser creates a user whose linked wallet is addr.
func (f *rd1316Fixture) addWalletUser(t *testing.T, did, addr string) string {
	t.Helper()
	uid := uuid.New().String()
	_, err := f.conn.Exec("INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')", uid, did)
	require.NoError(t, err)
	_, err = f.conn.Exec("INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ($1, $2, 'user')", did, addr)
	require.NoError(t, err)
	return uid
}

// addTransfer adds a token transfer to the fixture's parent tx.
func (f *rd1316Fixture) addTransfer(t *testing.T, logIndex int, token, from, to string, value int) {
	t.Helper()
	_, err := f.conn.Exec(`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		SELECT $1, $2, $3, $4, $5, $6, block_number FROM transactions WHERE hash = $1`, f.hash, logIndex, token, from, to, value)
	require.NoError(t, err)
}

const rd1316TransferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

func rd1316Topic(addr string) string {
	return "0x000000000000000000000000" + strings.TrimPrefix(strings.ToLower(addr), "0x")
}

// A token receiver learns the sender as a participant of the parent tx, through
// the Transfer log (RD-939 log-participant detection), not through the union.
// Without that log signal the union still keeps the row for the receiver, but
// the sender stays [PRIVATE].
func TestExplorer_TransferReceiverSeesSenderAsParticipant_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)
	f.srv.explorerRedactor.SetLogParticipantStore(f.srv.explorerStore)
	const receiverDID = "did:privado:rd1316_receiver"
	const receiverWallet = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1316"
	f.addWalletUser(t, receiverDID, receiverWallet)
	f.addTransfer(t, 1, rd1316Token, rd1316EOA, receiverWallet, 7)

	// No Transfer log indexed yet: the row is kept for the receiver by the
	// union (their own wallet is a transfer party), with nothing revealed.
	rr := f.get(t, receiverDID, "/transactions/"+f.hash)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var tx explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tx))
	assert.Equal(t, "[PRIVATE]", tx.From, "without a participant signal the union reveals nothing")
	requireNoForeignIdentity(t, rr.Body.String(), "receiver, no log")

	// With the Transfer log, the receiver is a participant of the tx and sees
	// the sender, labelled as their counterparty.
	_, err := f.conn.Exec(`INSERT INTO logs (tx_hash, log_index, address, topic0, topic1, topic2, data, block_number)
		SELECT $1, 1, $2, $3, $4, $5, '0x07', block_number FROM transactions WHERE hash = $1`,
		f.hash, rd1316Token, rd1316TransferTopic, rd1316Topic(rd1316EOA), rd1316Topic(receiverWallet))
	require.NoError(t, err)
	for _, path := range []string{"/transactions/" + f.hash, "/transactions?limit=25"} {
		rr = f.get(t, receiverDID, path)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var got *explorer.Transaction
		if strings.Contains(path, "?") {
			var list []explorer.Transaction
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
			got = findTx(list, f.hash)
		} else {
			got = &explorer.Transaction{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), got))
		}
		require.NotNil(t, got, "%s: the receiver keeps the row: %s", path, rr.Body.String())
		assert.Equal(t, rd1316EOA, strings.ToLower(got.From), "%s: a participant sees the sender", path)
		assert.Equal(t, explorer.ReasonParticipantOverride, got.AddressMetadata[rd1316EOA], "%s: labelled as the counterparty", path)
		assert.Nil(t, got.Nonce, "%s: the private sender's nonce stays stripped for a participant", path)
	}
}

// A Full disclosure grant on a transfer recipient keeps the parent tx (the
// grant subject drives the union), with the tx-level parties at the viewer's
// own level. The counterparty is revealed on the transfer row by the Full-grant
// lens (its GrantFullReveals count is pinned by the redactor tests).
func TestExplorer_FullDisclosureGrantOnRecipient_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)
	ctx := context.Background()
	const eveDID = "did:privado:rd1316_eve"
	const eveWallet = "0x9999999999999999999999999999999999991316"
	const auditorDID = "did:privado:rd1316_auditor"
	eveUserID := f.addWalletUser(t, eveDID, eveWallet)
	f.addTransfer(t, 1, rd1316Token, rd1316EOA, eveWallet, 7)

	// The auditor: a member of the token's org with event access on the token
	// (so the transfer row is not stripped), and a Full disclosure grant on Eve.
	var orgO, tokenID string
	require.NoError(t, f.conn.QueryRow("SELECT org_id, id FROM contracts WHERE address = $1", rd1316Token).Scan(&orgO, &tokenID))
	gid := uuid.New().String()
	_, err := f.conn.Exec("INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, 'auditors', 'Auditors', 0, 'auditors')", gid, orgO)
	require.NoError(t, err)
	_, err = f.conn.Exec(`INSERT INTO contract_grants (id, contract_id, group_id, event_rules) VALUES ($1, $2, $3, '"*"'::jsonb)`, uuid.New().String(), tokenID, gid)
	require.NoError(t, err)
	auditorID := uuid.New().String()
	_, err = f.conn.Exec("INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')", auditorID, auditorDID)
	require.NoError(t, err)
	_, err = f.conn.Exec("INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')", uuid.New().String(), auditorID, gid)
	require.NoError(t, err)
	const scope = `{"disclosure_level":"full"}`
	requestID := uuid.New().String()
	_, err = f.conn.Exec(`INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'rd1316 test', 'approved', NOW())`, requestID, auditorDID, eveUserID, orgO, scope)
	require.NoError(t, err)
	_, err = f.conn.Exec(`INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, 'rd1316hash_full', $3::jsonb, NOW(), $4)`, uuid.New().String(), requestID, scope, time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.False(t, f.srv.isViewerAdmin(ctx, auditorDID), "precondition: the auditor is not an admin")

	rr := f.get(t, auditorDID, "/transactions/"+f.hash)
	require.Equal(t, http.StatusOK, rr.Code, "the grant subject's transfer keeps its parent tx: %s", rr.Body.String())
	var tx explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tx))
	assert.Equal(t, "[PRIVATE]", tx.From, "the tx sender is not the grant subject: it stays at the viewer's own level")
	assert.Nil(t, tx.Nonce)
	assert.Empty(t, tx.InputData)
	assert.Empty(t, string(tx.Value))
	requireNoForeignIdentity(t, rr.Body.String(), "auditor tx", rd1316EOA, rd1316Callee)

	rr = f.get(t, auditorDID, "/transactions/"+f.hash+"/transfers")
	require.Equal(t, http.StatusOK, rr.Code)
	var transfers []explorer.TokenTransfer
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &transfers))
	require.Len(t, transfers, 1, "only the grant subject's transfer: %s", rr.Body.String())
	assert.Equal(t, eveWallet, strings.ToLower(transfers[0].To))
	assert.Equal(t, rd1316EOA, strings.ToLower(transfers[0].From), "the Full lens reveals the counterparty on the transfer row")
	assert.Equal(t, explorer.ReasonNoAccess, transfers[0].AddressMetadata[rd1316EOA], "the lens reveal keeps the counterparty's own reason")
}

// addMember creates a non-admin user holding a grant on each contract (via a
// new group in the contract's org). grants maps contract -> wildcard event
// rules; event access keeps a token's transfer rows from being stripped.
func (f *rd1316Fixture) addMember(t *testing.T, did string, grants map[string]bool) {
	t.Helper()
	uid := uuid.New().String()
	_, err := f.conn.Exec("INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')", uid, did)
	require.NoError(t, err)
	for c, withEvents := range grants {
		var orgID, cid string
		require.NoError(t, f.conn.QueryRow("SELECT org_id, id FROM contracts WHERE address = $1", c).Scan(&orgID, &cid))
		gid := uuid.New().String()
		slug := "m-" + uuid.New().String()[:8]
		_, err = f.conn.Exec("INSERT INTO groups (id, org_id, slug, name, depth, path) VALUES ($1, $2, $3, $4, 0, $5)", gid, orgID, slug, slug, slug)
		require.NoError(t, err)
		rules := "NULL"
		if withEvents {
			rules = `'"*"'::jsonb`
		}
		_, err = f.conn.Exec("INSERT INTO contract_grants (id, contract_id, group_id, event_rules) VALUES ($1, $2, $3, "+rules+")", uuid.New().String(), cid, gid)
		require.NoError(t, err)
		_, err = f.conn.Exec("INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')", uuid.New().String(), uid, gid)
		require.NoError(t, err)
	}
}

const rd1316Zero = "0x0000000000000000000000000000000000000000"

// F1: a non-admin who sees both sides of a transfer (a Full contract, or the
// zero address of a mint/burn) and has event access on the token sees that
// transfer row. Its parent tx — another user's wallet calling the token — must
// survive too, rendered at the viewer's own level: kept as [PRIVATE], not 404.
func TestExplorer_BothSidesVisibleTransferKeepsParent_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)
	ctx := context.Background()
	f.addTransfer(t, 1, rd1316Token, rd1316Zero, rd1316Vault, 500) // mint into the vault
	const member = "did:privado:rd1316_token_member"
	f.addMember(t, member, map[string]bool{rd1316Token: true, rd1316Vault: true})
	require.False(t, f.srv.isViewerAdmin(ctx, member), "precondition: not an admin")

	rr := f.get(t, member, "/transactions/"+f.hash+"/transfers")
	require.Equal(t, http.StatusOK, rr.Code)
	var transfers []explorer.TokenTransfer
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &transfers))
	require.Len(t, transfers, 1, "only the mint survives; the wallet's transfer is G10-dropped: %s", rr.Body.String())
	assert.Equal(t, rd1316Zero, transfers[0].From)
	assert.Equal(t, rd1316Vault, strings.ToLower(transfers[0].To))
	assert.Equal(t, "500", string(transfers[0].Value))

	rr = f.get(t, member, "/transactions/"+f.hash)
	require.Equal(t, http.StatusOK, rr.Code, "the parent of a visible transfer must not 404 (§6): %s", rr.Body.String())
	var tx explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tx))
	assert.Equal(t, "[PRIVATE]", tx.From, "the other user's wallet stays private")
	require.NotNil(t, tx.To)
	assert.Equal(t, rd1316Token, strings.ToLower(*tx.To), "the token renders at the viewer's own (Full) level")
	assert.Nil(t, tx.Nonce, "nonce revealed")
	assert.Empty(t, tx.InputData, "calldata revealed")
	assert.Empty(t, string(tx.Value), "value revealed")
	requireNoForeignIdentity(t, rr.Body.String(), "member by-hash", rd1316EOA, rd1316Callee)

	rr = f.get(t, member, "/transactions?limit=25")
	require.Equal(t, http.StatusOK, rr.Code)
	var list []explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	row := findTx(list, f.hash)
	require.NotNil(t, row, "the list keeps the row: %s", rr.Body.String())
	assert.Equal(t, "[PRIVATE]", row.From)
	assert.Empty(t, string(row.Value))
	requireNoForeignIdentity(t, rr.Body.String(), "member list", rd1316EOA, rd1316Callee)

	// Without event access on the token the member sees no transfer row, so
	// nothing keeps the parent: G10 drops it as before.
	const noEvents = "did:privado:rd1316_token_member_no_events"
	f.addMember(t, noEvents, map[string]bool{rd1316Token: false, rd1316Vault: false})
	rr = f.get(t, noEvents, "/transactions/"+f.hash+"/transfers")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), f.hash[:20], "no event access, no transfer row")
	rr = f.get(t, noEvents, "/transactions/"+f.hash)
	assert.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
}

// The third driver class at the filter level: a transfer whose two sides are
// both Full or public (the zero address, a precompile) on a token with event
// access drives it; a transfer with a hidden side, or on a token without event
// access, does not.
func TestBuildVisibilityFilter_BothSidesVisibleTransfers_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)
	ctx := context.Background()
	const vault2 = "0xcccccccccccccccccccccccccccccccccccc2316"
	const otherToken = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2316"
	const ecrecover = "0x0000000000000000000000000000000000000001"
	var orgU string
	require.NoError(t, f.conn.QueryRow("SELECT org_id FROM contracts WHERE address = $1", rd1316Vault).Scan(&orgU))
	for _, c := range []string{vault2, otherToken} {
		_, err := f.conn.Exec("INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'C')", uuid.New().String(), orgU, c)
		require.NoError(t, err)
	}
	block := seedExplorerBlock(t, f.conn)
	tx := func(n int, token, from, to string) string {
		h := fmt.Sprintf("0x2316%060d", n)
		seedExplorerTransaction(t, f.conn, block, h, rd1316EOA, token)
		_, err := f.conn.Exec(`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
			VALUES ($1, 0, $2, $3, $4, 1, $5)`, h, token, from, to, block)
		require.NoError(t, err)
		return h
	}
	mint := tx(1, rd1316Token, rd1316Zero, rd1316Vault)
	burn := tx(2, rd1316Token, rd1316Vault, rd1316Zero)
	between := tx(3, rd1316Token, rd1316Vault, vault2)
	toPrecompile := tx(4, rd1316Token, rd1316Vault, ecrecover)
	zeroToZero := tx(5, rd1316Token, rd1316Zero, rd1316Zero)
	hiddenSide := tx(6, rd1316Token, rd1316Vault, rd1316EOA)
	noAccess := tx(7, otherToken, rd1316Zero, rd1316Vault)

	const member = "did:privado:rd1316_filter_member"
	// otherToken: a grant without event rules (Full, but no event access).
	f.addMember(t, member, map[string]bool{rd1316Token: true, rd1316Vault: true, vault2: true, otherToken: false})

	filter := f.srv.buildVisibilityFilter(ctx, member, f.srv.isViewerAdmin(ctx, member))
	for _, h := range []string{mint, burn, between, toPrecompile, zeroToZero} {
		assert.Contains(t, filter.VisibleTxHashes, h, "both transfer sides Full or public: the parent row is kept")
	}
	for _, h := range []string{hiddenSide, noAccess, f.hash} {
		assert.NotContains(t, filter.VisibleTxHashes, h, "a hidden side or no event access: not kept")
	}
	assert.Empty(t, filter.ListedTxHashes, "the union never becomes a listing")
}

// GAP G28: a derived row can survive while its parent tx does not. Case (2)
// predates RD-1316; case (1) predates it for txs with no visible transfer party,
// and RD-1316's narrower non-admin union extends it to this transfer-linked tx.
// These tests pin the current behaviour so the fix cannot land (or the gap
// widen) silently.
func TestExplorer_DerivedRowWithoutParent_GAP_G28(t *testing.T) {
	f := setupRD1316Fixture(t)

	// GAP G28 (1): internal frames have no G10 drop. The vault grant holder's
	// GET /transactions/:hash is 404 (G10), yet /internal returns the frame
	// into the vault, with the token [PRIVATE]. Desired: no frame without the
	// parent (apply G10 to frames for non-admins) — fix before release.
	rr := f.get(t, rd1316GrantDID, "/transactions/"+f.hash)
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	rr = f.get(t, rd1316GrantDID, "/transactions/"+f.hash+"/internal")
	require.Equal(t, http.StatusOK, rr.Code)
	var frames []explorer.InternalTransaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &frames))
	require.Len(t, frames, 1, "GAP G28: the frame into the vault surfaces without its parent: %s", rr.Body.String())
	assert.Equal(t, "[PRIVATE]", frames[0].From)
	requireNoForeignIdentity(t, rr.Body.String(), "grant holder /internal")

	// GAP G28 (2): an admin's /transfers keeps a mint to a private wallet on
	// another org's token (the zero address is public; admins skip G10 and the
	// event-access strip — G13), but the zero address does not drive the admin
	// union, so the parent (a private wallet calling another org's token) is
	// dropped. Desired: the mint row and its parent agree — fix before release.
	const otherWallet = "0x7777777777777777777777777777777777771316"
	f.addWalletUser(t, "did:privado:rd1316_mint_recipient", otherWallet)
	block := seedExplorerBlock(t, f.conn)
	mintHash := "0x1316" + strings.Repeat("7", 60)
	seedExplorerTransaction(t, f.conn, block, mintHash, rd1316EOA, rd1316Token)
	_, err := f.conn.Exec(`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ($1, 0, $2, $3, $4, 9, $5)`, mintHash, rd1316Token, rd1316Zero, otherWallet, block)
	require.NoError(t, err)
	rr = f.get(t, rd1316AdminDID, "/transactions/"+mintHash+"/transfers")
	require.Equal(t, http.StatusOK, rr.Code)
	var transfers []explorer.TokenTransfer
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &transfers))
	require.Len(t, transfers, 1, "GAP G28: the admin sees the mint: %s", rr.Body.String())
	assert.Equal(t, "[PRIVATE]", transfers[0].To)
	rr = f.get(t, rd1316AdminDID, "/transactions/"+mintHash)
	assert.Equal(t, http.StatusNotFound, rr.Code, "GAP G28: the mint's parent is dropped for the admin: %s", rr.Body.String())
}

// Positive control: a genuine visibleTo share of the same tx still reveals the
// sender to the listed viewer.
func TestExplorer_GenuineShareStillReveals_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)
	require.NoError(t, f.srv.db.SaveTxVisibility(context.Background(), f.hash, []string{rd1316Shared}, "did:privado:rd1316_sender", "org-o"))

	rr := f.get(t, rd1316Shared, "/transactions/"+f.hash)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var tx explorer.Transaction
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tx))
	assert.Equal(t, rd1316EOA, strings.ToLower(tx.From), "the sender shared this tx with the viewer")
	assert.Equal(t, explorer.ReasonVisibleToGrant, tx.AddressMetadata[rd1316EOA])

	// The grant holder who is NOT listed still gets nothing: the share
	// reveals to the listed viewer only.
	rr = f.get(t, rd1316GrantDID, "/transactions/"+f.hash)
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	requireNoForeignIdentity(t, rr.Body.String(), "unlisted viewer")
}

// buildVisibilityFilter keeps the genuine listings apart from the union, and
// drives the union from every Full address only for a viewer exempt from G10.
func TestBuildVisibilityFilter_ListedTxHashesExcludeUnion_RD1316(t *testing.T) {
	f := setupRD1316Fixture(t)
	ctx := context.Background()
	shared := "0x1316" + strings.Repeat("1", 60)
	require.NoError(t, f.srv.db.SaveTxVisibility(ctx, shared, []string{rd1316AdminDID}, "did:privado:rd1316_sender", "org-o"))

	filter := f.srv.buildVisibilityFilter(ctx, rd1316AdminDID, f.srv.isViewerAdmin(ctx, rd1316AdminDID))
	require.Contains(t, filter.VisibleTxHashes, f.hash, "the union keeps the vault transfer's parent for the admin")
	require.Contains(t, filter.VisibleTxHashes, shared)
	assert.Equal(t, []string{shared}, filter.ListedTxHashes, "only the genuine share is a listing")

	opts := redactOptsFromFilter(filter)
	assert.True(t, opts.VisibleTxHashes[f.hash])
	assert.False(t, opts.ListedTxHashes[f.hash], "a union hash must never reach the redactor as a listing")
	assert.True(t, opts.ListedTxHashes[shared])

	nonAdmin := f.srv.buildVisibilityFilter(ctx, rd1316GrantDID, f.srv.isViewerAdmin(ctx, rd1316GrantDID))
	assert.NotContains(t, nonAdmin.VisibleTxHashes, f.hash, "a contract grant alone does not drive the union for a non-admin")

	// A non-admin's own wallet still drives the union: a user who received
	// tokens in the tx keeps the parent row, but it is not a listing.
	const receiverDID = "did:privado:rd1316_receiver"
	const receiverWallet = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1316"
	_, err := f.conn.ExecContext(ctx, "INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')", uuid.New().String(), receiverDID)
	require.NoError(t, err)
	_, err = f.conn.ExecContext(ctx, "INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ($1, $2, 'user')", receiverDID, receiverWallet)
	require.NoError(t, err)
	_, err = f.conn.ExecContext(ctx, `INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		SELECT $1, 1, $2, $3, $4, 7, block_number FROM transactions WHERE hash = $1`, f.hash, rd1316Token, rd1316EOA, receiverWallet)
	require.NoError(t, err)
	receiver := f.srv.buildVisibilityFilter(ctx, receiverDID, f.srv.isViewerAdmin(ctx, receiverDID))
	assert.Contains(t, receiver.VisibleTxHashes, f.hash, "the receiver's own wallet drives the union")
	assert.NotContains(t, receiver.ListedTxHashes, f.hash, "the union never becomes a listing")
}
