package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCountSurfaceRouter wires the address stats badge endpoint alongside the
// three list endpoints whose row counts the badges must match.
func setupCountSurfaceRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	g.GET("/addresses/:address/stats", srv.getExplorerAddressStats)
	g.GET("/addresses/:address/transactions", srv.getExplorerAddressTransactions)
	g.GET("/addresses/:address/transfers", srv.getExplorerAddressTransfers)
	g.GET("/addresses/:address/internal", srv.getExplorerAddressInternal)
	return r
}

// TestExplorerAddressStats_AllCountsVisibilityFiltered_RD1154 is the parity
// guard for the count-surface leak: every address-stats badge (Transactions /
// Token transfers / Internal txns) must equal the number of rows the viewer can
// actually load on the matching list surface — never the raw address_stats
// aggregate. Before RD-1154 only TxCount was filtered; TokenTransferCount and
// InternalTxCount were returned RAW, so a restricted viewer's badge revealed how
// many rows exist that they cannot see.
//
// The invariant asserted for EVERY viewer, on EVERY surface:
//
//	stats.<Count> == len(fully-visible list rows for that viewer)   AND   != raw aggregate (99)
//
// This holds regardless of why a given viewer sees more or fewer rows (admin,
// grant lens, participant, G10 drops) — it pins badge↔list agreement directly.
//
// MUTATION CHECK: revert the TokenTransferCount/InternalTxCount filtering in
// getExplorerAddressStats and the badges fall back to the raw 99, breaking both
// the parity assertion and the "!= 99" assertion.
func TestExplorerAddressStats_AllCountsVisibilityFiltered_RD1154(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	// --- Subject contract, org-owned (visible to org members via the grant). ---
	subject := "0xc0ffee0000000000000000000000000000000001"
	groupID := registerOrgContract(t, database, subject)

	// Admin: is_org_admin of the subject's org + a member of the grant group
	// (is_org_admin alone does not confer contract visibility — see
	// address_stats_visibility_test.go).
	aliceDID := "did:test:alice_counts"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-counts', 'Admins', 0, 'admins-counts', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)
	addUserToGroup(t, database, aliceUserID, groupID)

	// Restricted viewer: sees `subject` via the grant group, but is NOT an admin
	// and is NOT a participant of any of its activity.
	eveDID := "did:test:eve_counts"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID)

	// Hidden foreign counterparties (unregistered ⇒ private by default).
	hiddenA := "0xdead000000000000000000000000000000000001"
	hiddenB := "0xdead000000000000000000000000000000000002"
	hiddenToken := "0xdead000000000000000000000000000000000003"

	blockNum := seedExplorerBlock(t, conn)

	// 3 transactions: subject <-> hidden.
	txHashes := []string{"0xcnt_tx_0", "0xcnt_tx_1", "0xcnt_tx_2"}
	for i, h := range txHashes {
		_, err = conn.ExecContext(ctx,
			`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
			 VALUES ($1, $2, $3, $4, $5, 0, 21000, 1000, 1, '0x')`,
			h, blockNum, i, subject, hiddenA)
		require.NoError(t, err)
	}

	// 2 token transfers where `subject` is a party (parent txs reused, FK-safe).
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, txHashes[0], hiddenToken, subject, hiddenA, blockNum)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 2000, $5)`, txHashes[1], hiddenToken, subject, hiddenB, blockNum)
	require.NoError(t, err)

	// 2 internal txs where `subject` is a party.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 5, 'CALL')`, txHashes[0], blockNum, subject, hiddenA)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 5, 'CALL')`, txHashes[1], blockNum, subject, hiddenB)
	require.NoError(t, err)

	// Inflated RAW aggregate — the value the buggy handler would leak.
	const rawAggregate = 99
	_, err = conn.ExecContext(ctx,
		`INSERT INTO address_stats (address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract)
		 VALUES ($1, $2, $2, $2, 1, 1, true)`, subject, rawAggregate)
	require.NoError(t, err)

	router := setupCountSurfaceRouter(srv)

	getStats := func(t *testing.T, did string) explorer.AddressStats {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+subject+"/stats", nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "stats should be 200 for a viewer who can see the subject")
		var stats explorer.AddressStats
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stats))
		return stats
	}
	// listLen returns the visible row count for a surface. Every list surface
	// returns an envelope; the array lives under a surface-specific key —
	// transactions/transfers on the address feeds (RD-1149 token-only
	// pagination), data on the internal feed.
	listLen := func(t *testing.T, did, suffix string) int {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+subject+suffix, nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "list %s should be 200", suffix)
		var env struct {
			Transactions []json.RawMessage `json:"transactions"`
			Transfers    []json.RawMessage `json:"transfers"`
			Data         []json.RawMessage `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		switch suffix {
		case "/transactions":
			return len(env.Transactions)
		case "/transfers":
			return len(env.Transfers)
		default:
			return len(env.Data)
		}
	}

	assertParity := func(t *testing.T, did string) explorer.AddressStats {
		t.Helper()
		stats := getStats(t, did)
		assert.Equal(t, listLen(t, did, "/transactions"), stats.TxCount,
			"Transactions badge must equal the visible tx-list length")
		assert.Equal(t, listLen(t, did, "/transfers"), stats.TokenTransferCount,
			"Token transfers badge must equal the visible transfer-list length")
		assert.Equal(t, listLen(t, did, "/internal"), stats.InternalTxCount,
			"Internal txns badge must equal the visible internal-list length")
		// None of the badges may be the raw aggregate.
		assert.NotEqual(t, rawAggregate, stats.TxCount, "TxCount must not be the raw aggregate")
		assert.NotEqual(t, rawAggregate, stats.TokenTransferCount, "TokenTransferCount must not be the raw aggregate")
		assert.NotEqual(t, rawAggregate, stats.InternalTxCount, "InternalTxCount must not be the raw aggregate")
		return stats
	}

	var adminStats, eveStats explorer.AddressStats
	t.Run("admin badges match admin's visible rows (never raw)", func(t *testing.T) {
		adminStats = assertParity(t, aliceDID)
	})
	t.Run("restricted viewer badges match viewer's visible rows (never raw)", func(t *testing.T) {
		eveStats = assertParity(t, eveDID)
	})
	t.Run("filtering actually diverges per viewer", func(t *testing.T) {
		// The restricted viewer must see strictly fewer token transfers than the
		// admin — proving the transfer badge is filtered per viewer, not shared.
		assert.Less(t, eveStats.TokenTransferCount, adminStats.TokenTransferCount,
			"restricted viewer should see fewer transfers than admin")
	})
}

// TestExplorerToken_CountsVisibilityFiltered_RD1154 is the token-page companion
// to the address-stats parity guard above — the surface RD-1154 cites as the
// motivating leak ("Transfers 7 / 3 rows visible" on the token page). The token
// page's "Transfers" and "Holders" badges must equal the rows the viewer can
// actually load on the matching token list surfaces, never the raw
// tokens.transfer_count / holder_count aggregate. Before RD-1154 both were RAW.
//
// Invariant, asserted per viewer:
//
//	getExplorerToken.<Count> == len(visible list rows for that viewer)  AND  != raw
//
// MUTATION CHECK: revert the countVisibleTokenTransfers / countVisibleTokenHolders
// recompute in getExplorerToken (fall back to GetToken's raw counts) and the
// badges become 50/10, breaking both the parity and the "!= raw" assertions.
func TestExplorerToken_CountsVisibilityFiltered_RD1154(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, tokenSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS token_transfers; DROP TABLE IF EXISTS token_balances; DROP TABLE IF EXISTS tokens")
	})
	_, err = conn.ExecContext(ctx, "TRUNCATE tokens, token_balances, token_transfers CASCADE")
	require.NoError(t, err)

	// Org-owned token contract: group members see it at Full, so getExplorerToken
	// runs the visibility recompute (not the pseudonymous zero-out path).
	token := "0xc0ffee0000000000000000000000000000000abc"
	groupID := registerOrgContract(t, database, token)

	aliceDID := "did:test:alice_tokcnt"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-tokcnt', 'Admins', 0, 'admins-tokcnt', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)
	addUserToGroup(t, database, aliceUserID, groupID)

	eveDID := "did:test:eve_tokcnt"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID)

	hiddenA := "0xdead000000000000000000000000000000000a01"
	hiddenB := "0xdead000000000000000000000000000000000a02"
	blockNum := seedExplorerBlock(t, conn)

	// Raw aggregates the pre-RD-1154 handler leaked (seedToken: 50 transfers / 10 holders).
	seedToken(t, conn, token, "TKN", "Test Token", "ERC-20")
	const rawTransfers, rawHolders = 50, 10

	// A handful of real transfers/holders (≪ the raw 50/10), so the recomputed
	// survivor count can never coincide with the raw aggregate.
	txHashes := []string{"0xtokcnt_0", "0xtokcnt_1", "0xtokcnt_2"}
	parties := [][2]string{{hiddenA, hiddenB}, {hiddenB, hiddenA}, {hiddenA, hiddenB}}
	for i, h := range txHashes {
		seedExplorerTransaction(t, conn, blockNum, h, parties[i][0], parties[i][1])
		_, err = conn.ExecContext(ctx,
			`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
			 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, h, token, parties[i][0], parties[i][1], blockNum)
		require.NoError(t, err)
	}
	for _, holder := range []string{hiddenA, hiddenB} {
		_, err = conn.ExecContext(ctx,
			`INSERT INTO token_balances (address, token_address, block_number, balance) VALUES ($1, $2, $3, 1000)`,
			holder, token, blockNum)
		require.NoError(t, err)
	}

	router := setupTokenRouter(srv)

	getToken := func(t *testing.T, did string) explorer.Token {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+token, nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "token page should be 200 for a viewer who can see the token")
		var tok explorer.Token
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tok))
		return tok
	}
	// listLen returns the viewer's visible row count on a token list surface,
	// which returns a {"data":[...]} envelope.
	listLen := func(t *testing.T, did, suffix string) int {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+token+suffix, nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "token list %s should be 200", suffix)
		var env struct {
			Data []json.RawMessage `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		return len(env.Data)
	}

	assertParity := func(t *testing.T, did string) explorer.Token {
		t.Helper()
		tok := getToken(t, did)
		assert.Equal(t, listLen(t, did, "/transfers"), tok.TransferCount,
			"Transfers badge must equal the viewer's visible transfer-list length")
		assert.Equal(t, listLen(t, did, "/holders"), tok.HolderCount,
			"Holders badge must equal the viewer's visible holder-list length")
		assert.NotEqual(t, rawTransfers, tok.TransferCount, "TransferCount must not be the raw aggregate")
		assert.NotEqual(t, rawHolders, tok.HolderCount, "HolderCount must not be the raw aggregate")
		return tok
	}

	var aliceTok, eveTok explorer.Token
	t.Run("admin badges match admin's visible rows (never raw)", func(t *testing.T) {
		aliceTok = assertParity(t, aliceDID)
	})
	t.Run("restricted viewer badges match viewer's visible rows (never raw)", func(t *testing.T) {
		eveTok = assertParity(t, eveDID)
	})
	t.Run("restricted viewer never sees more than the admin", func(t *testing.T) {
		assert.LessOrEqual(t, eveTok.TransferCount, aliceTok.TransferCount)
		assert.LessOrEqual(t, eveTok.HolderCount, aliceTok.HolderCount)
	})
}

// TestExplorerInternalTx_TransferUnionRevealsNothing_RD1316 replaces the RD-1155
// label pin. The RD-1009 transfer-participant union used to reveal every frame
// of the parent tx (RD-1155 then only fixed the label). Since RD-1316 the
// union keeps rows and reveals nothing, and a non-admin is not given union
// rows through a plain contract grant at all (G10; the RPC returns null):
//
// Fixture (RD-1009 coherence shape, non-admin viewer):
//   - eve's org owns a "vault" contract eve sees at Full (eve is NOT admin and
//     NOT the internal frame's from/to).
//   - a foreign private wallet calls a foreign private token contract.
//   - the token's Transfer credits eve's vault.
//   - the internal call is between the two foreign (Hidden) addresses.
//
// Expected: eve gets no frame and no foreign address, in any field or as an
// addressMetadata key.
func TestExplorerInternalTx_TransferUnionRevealsNothing_RD1316(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})

	// eve's org-owned vault contract (the transfer recipient eve sees at Full).
	vault := "0xec00000000000000000000000000000000000001"
	groupID := registerOrgContract(t, database, vault)
	eveDID := "did:test:eve_rd1155"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID) // non-admin member ⇒ sees vault at Full

	// Foreign, Hidden-to-eve parties.
	foreignEOA := "0xdead000000000000000000000000000000000021"
	foreignToken := "0xdead000000000000000000000000000000000022"

	blockNum := seedExplorerBlock(t, conn)
	txHash := "0xrd1155_participant_reveal"
	seedExplorerTransaction(t, conn, blockNum, txHash, foreignEOA, foreignToken)

	// Transfer: foreignToken emits Transfer(from=foreignEOA, to=vault) ⇒ eve is a
	// transfer participant of txHash (RD-1009 union adds it to eve's visible set).
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, txHash, foreignToken, foreignEOA, vault, blockNum)
	require.NoError(t, err)

	// Internal call between the two foreign (Hidden) addresses — the nested frame
	// the viewer is NOT a direct participant of.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 50, 'CALL')`, txHash, blockNum, foreignEOA, foreignToken)
	require.NoError(t, err)

	router := setupCoherenceRouter(srv)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/explorer/transactions/"+txHash+"/internal", nil)
	addBearerToken(t, req, srv, eveDID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "internal-tx surface answers 200 with the viewer's rows")

	lower := strings.ToLower(w.Body.String())
	for _, addr := range []string{foreignEOA, foreignToken} {
		assert.NotContainsf(t, lower, strings.TrimPrefix(addr, "0x"),
			"a foreign address reached a non-admin through the transfer union: %s", w.Body.String())
	}
	var itxs []json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &itxs))
	assert.Empty(t, itxs, "a non-admin is not kept another user's frames by a plain contract grant (G10)")
}
