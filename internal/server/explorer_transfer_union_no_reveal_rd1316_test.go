package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		VALUES ($1, $2, '0', $3, $4, 0, 'CALL'), ($1, $2, '0,0', $4, $5, 0, 'STATICCALL')`, hash, block, rd1316EOA, rd1316Token, rd1316Callee)

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
	assert.Contains(t, rr.Body.String(), f.hash, "the list keeps the row")
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions")

	rr = f.get(t, rd1316AdminDID, "/transactions/"+f.hash+"/transfers")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, strings.ToLower(rr.Body.String()), strings.TrimPrefix(rd1316Vault, "0x"), "the admin's own contract stays visible")
	// tokenAddress is public infrastructure on a transfer row (§3.3).
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions/:hash/transfers", rd1316EOA)

	rr = f.get(t, rd1316AdminDID, "/transactions/"+f.hash+"/internal")
	require.Equal(t, http.StatusOK, rr.Code)
	var frames []json.RawMessage
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &frames))
	assert.Len(t, frames, 2, "the kept parent's frames survive: %s", rr.Body.String())
	requireNoForeignIdentity(t, rr.Body.String(), "GET /transactions/:hash/internal")

	// A plain grant holder of the vault is not an admin: G10 drops another
	// user's one-side-hidden tx, and the union does not keep it for them.
	rr = f.get(t, rd1316GrantDID, "/transactions/"+f.hash)
	assert.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	for _, path := range []string{"/transactions?limit=25", "/transactions/" + f.hash + "/transfers", "/transactions/" + f.hash + "/internal"} {
		rr = f.get(t, rd1316GrantDID, path)
		require.Equal(t, http.StatusOK, rr.Code, path)
		assert.NotContains(t, rr.Body.String(), f.hash[:20], "%s kept a row for a non-admin: %s", path, rr.Body.String())
		requireNoForeignIdentity(t, rr.Body.String(), path)
	}
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
