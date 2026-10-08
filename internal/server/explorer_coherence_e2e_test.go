package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// explorerCoherenceExtraSchema layers the token_transfers / internal_transactions
// / logs tables on top of the base explorerSchema. The coherence E2E exercises
// all four explorer surfaces (transactions, transfers, internal txs, logs) for
// the same parent tx; they each query a different table.
//
// Kept inline rather than introducing a shared schema constant so the existing
// per-test TRUNCATE flows in setupTestServerForExplorerTransactions stay
// unchanged. The drop tables in t.Cleanup are explicit because these tables
// don't appear in db.ResetTestDatabase's TRUNCATE set.
const explorerCoherenceExtraSchema = `
CREATE TABLE IF NOT EXISTS token_transfers (
    id SERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
    log_index INT NOT NULL,
    token_address TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    value NUMERIC(78, 0) NOT NULL,
    block_number BIGINT NOT NULL,
    timestamp BIGINT,
    transfer_type TEXT DEFAULT 'transfer',
    token_type TEXT DEFAULT 'ERC20',
    token_id NUMERIC(78, 0),
    is_internal BOOLEAN DEFAULT false,
    UNIQUE(tx_hash, log_index)
);

CREATE TABLE IF NOT EXISTS internal_transactions (
    id SERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
    block_number BIGINT NOT NULL,
    trace_address TEXT NOT NULL DEFAULT '',
    from_address TEXT NOT NULL,
    to_address TEXT,
    value NUMERIC(78, 0) NOT NULL DEFAULT 0,
    gas BIGINT,
    gas_used BIGINT,
    input TEXT,
    output TEXT,
    call_type TEXT NOT NULL DEFAULT 'CALL',
    error TEXT,
    timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL,
    log_index INT NOT NULL,
    address TEXT NOT NULL,
    topic0 TEXT,
    topic1 TEXT,
    topic2 TEXT,
    topic3 TEXT,
    data TEXT,
    block_number BIGINT NOT NULL DEFAULT 0,
    timestamp BIGINT,
    removed BOOLEAN DEFAULT false,
    UNIQUE(tx_hash, log_index)
);
`

// setupCoherenceRouter wires the five explorer surfaces this test drives:
// list (`/transactions`), by-hash (`/transactions/:hash`), per-tx transfers
// (`/transactions/:hash/transfers`), per-tx internal txs
// (`/transactions/:hash/internal`), and per-tx logs
// (`/transactions/:hash/logs`). Mirrors RegisterExplorerRoutes' shape for
// these endpoints; we don't pull in the full registrar because we don't need
// the unrelated routes and their auth middleware variations.
func setupCoherenceRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	g := router.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	g.GET("/transactions", srv.getExplorerTransactions)
	g.GET("/transactions/:hash", srv.getExplorerTransaction)
	g.GET("/transactions/:hash/transfers", srv.getExplorerTransactionTransfers)
	g.GET("/transactions/:hash/internal", srv.getExplorerTransactionInternal)
	g.GET("/transactions/:hash/logs", srv.getExplorerTransactionLogs)
	return router
}

// TestExplorerCoherence_RD1009_AllSurfacesAgree is the end-to-end follow-up
// to PR #285 (RD-1009): pin the cross-surface row-survival invariant across
// every explorer surface that renders something derivable from a parent tx.
// The RD-1009 fix pinned `/transactions` and `/transfers` agreement at the
// SQL allowlist + by-hash opts level; the follow-up fixes
// RedactInternalTransactions to honour the same VisibleTxHashes allowlist.
// This test drives all five surfaces as the same admin viewer against the
// same reproducer fixture and asserts they agree on which rows survive.
//
// Reproducer fixture (same shape as the unit-level RD-1009 tests):
//   - admin viewer is an org-admin of the test org (contract-owning org)
//   - the org owns a "vault" contract — admin-visible (the surviving side)
//   - a wholly-foreign private wallet (linked to a different org's user)
//     calls a foreign private token contract
//   - the token's Transfer event credits the admin's vault contract
//
// To the admin, tx.from (foreign EOA) and tx.to (foreign token contract)
// are both Hidden. Without the cross-surface fix, /transactions and
// /transactions/:hash/internal would drop the row while /transfers would
// surface it — incoherent UX and an audit-trail gap.
//
// SURFACES COVERED (5):
//   - /transactions (list)             — RedactTransactions w/ buildVisibilityFilter
//   - /transactions/:hash (by-hash)    — RedactTransactions w/ buildRedactOptsForViewer
//   - /transactions/:hash/transfers    — RedactTransfers w/ buildRedactOptsForViewer
//   - /transactions/:hash/internal     — RedactInternalTransactions w/ buildRedactOptsForViewer
//   - /transactions/:hash/logs         — RedactLogs w/ buildRedactOptsForViewer
//     (logs already inherit VisibleTxHashes; covered for completeness so the
//     coherence invariant has the full surface set pinned in one test, not
//     just the redactors that needed the fix.)
//
// COHERENCE INVARIANT (the assertion):
//   if /transfers returns a row with tx_hash=X, then
//     - /transactions list contains X, AND
//     - /transactions/:hash=X returns 200 (not 404), AND
//     - /transactions/:hash=X/internal returns the frames that have a side the
//       viewer can see — and only those (RD-1316: the union keeps the parent
//       row, not the parent's private frames), AND
//     - /transactions/:hash=X/logs returns the Transfer log
//
// MUTATION CHECK: reverting PR #285's `FindTransferParticipantTxs` union in
// buildVisibilityFilter fails steps 2-3; letting the union keep frames again
// fails step 4's both-private-frame assertion.
func TestExplorerCoherence_RD1009_AllSurfacesAgree(t *testing.T) {
	srv, _, conn := setupTestServerForExplorerTransactions(t)

	_, err := conn.ExecContext(context.Background(), explorerCoherenceExtraSchema)
	require.NoError(t, err, "create extended explorer schema")
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})

	ctx := context.Background()
	router := setupCoherenceRouter(srv)

	// ---- Admin org + admin user (org-admin via is_org_admin group).
	orgID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "coherence-org", "Coherence Test Org")
	require.NoError(t, err)

	adminUserID := uuid.New().String()
	const adminDID = "did:privado:coherence_admin"
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		adminUserID, adminDID)
	require.NoError(t, err)

	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
		adminGroupID, orgID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')",
		uuid.New().String(), adminUserID, adminGroupID)
	require.NoError(t, err)

	// The admin-visible "vault" contract (the surviving-side counterparty).
	const orgVaultContract = "0xcccccccccccccccccccccccccccccccccccccccc"
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), orgID, orgVaultContract, "Org Vault")
	require.NoError(t, err)

	// Foreign org owning the private token contract — Hidden to admin.
	const privateTokenContract = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherOrgID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		otherOrgID, "coherence-other-org", "Other Org")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), otherOrgID, privateTokenContract, "Private Token")
	require.NoError(t, err)

	// Foreign user's EOA — Hidden to admin.
	const privateWalletEOA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherUserID := uuid.New().String()
	const otherDID = "did:privado:coherence_other"
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		otherUserID, otherDID)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ($1, $2, 'user')`,
		otherDID, privateWalletEOA)
	require.NoError(t, err)

	// ---- Seed chain data: one reproducer tx with the four derived surfaces.
	blockNum := seedExplorerBlock(t, conn)
	const reproducerTxHash = "0xrd1009_coherence_reproducer"
	seedExplorerTransaction(t, conn, blockNum, reproducerTxHash, privateWalletEOA, privateTokenContract)

	// Token transfer: privateTokenContract emits Transfer(from=privateWalletEOA, to=orgVaultContract)
	_, err = conn.ExecContext(ctx, `
		INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ($1, 0, $2, $3, $4, 1000, $5)`,
		reproducerTxHash, privateTokenContract, privateWalletEOA, orgVaultContract, blockNum)
	require.NoError(t, err)

	// Internal txs: the wallet's call into the token (both sides private to
	// the admin) and the token's call into the admin's vault (one side the
	// admin sees, e.g. a settlement hop).
	_, err = conn.ExecContext(ctx, `
		INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		VALUES ($1, $2, '0', $3, $4, 50, 'CALL'), ($1, $2, '0,0', $4, $5, 0, 'CALL')`,
		reproducerTxHash, blockNum, privateWalletEOA, privateTokenContract, orgVaultContract)
	require.NoError(t, err)

	// Transfer event log: emitter = privateTokenContract (Hidden).
	// Topic0 = keccak("Transfer(address,address,uint256)"), topics 1/2 hold the
	// 32-byte-padded addresses. Our admin-vault recipient appears in topic2,
	// so the log is admin-relevant on the surviving-side argument.
	const transferTopic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	from32 := "0x000000000000000000000000" + privateWalletEOA[2:]
	to32 := "0x000000000000000000000000" + orgVaultContract[2:]
	// Data is the non-indexed value (uint256 = 1000) as a 32-byte hex slot.
	const transferValueData = "0x00000000000000000000000000000000000000000000000000000000000003e8"
	_, err = conn.ExecContext(ctx, `
		INSERT INTO logs (tx_hash, log_index, address, topic0, topic1, topic2, data, block_number)
		VALUES ($1, 0, $2, $3, $4, $5, $6, $7)`,
		reproducerTxHash, privateTokenContract, transferTopic0, from32, to32, transferValueData, blockNum)
	require.NoError(t, err)

	// ---- Drive the surfaces as admin.
	adminToken := issueTestJWT(t, srv, adminDID)
	authHeader := func(req *http.Request) { req.Header.Set("Authorization", "Bearer "+adminToken) }

	// 1. /transfers — the surface that defines the truth-set. If a transfer
	// row surfaces with tx_hash=X, every other surface must agree X exists.
	type transferRow struct {
		TxHash string `json:"txHash"`
	}
	var transferRows []transferRow
	{
		req, _ := http.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/explorer/transactions/%s/transfers", reproducerTxHash), nil)
		authHeader(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, "/transfers must return 200 for the admin viewer")
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &transferRows))
	}
	require.NotEmptyf(t, transferRows,
		"PRE-CONDITION FAIL: /transfers must surface the reproducer row for the admin viewer (admin-visible recipient %q). "+
			"If this fails the fixture setup is broken before the coherence assertions can be meaningful.",
		orgVaultContract)
	transferTxHash := transferRows[0].TxHash
	require.Equal(t, reproducerTxHash, transferTxHash,
		"unexpected tx hash in transfer row: %q", transferTxHash)

	// 2. /transactions list — must contain the same tx_hash.
	// This is the original RD-1009 list-path assertion (PR #285 commit 1).
	type txListResp struct {
		Hash string `json:"hash"`
	}
	{
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/explorer/transactions?limit=50", nil)
		authHeader(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, "/transactions must return 200")
		// The /transactions endpoint returns []Transaction directly (see
		// getExplorerTransactions).
		var rows []txListResp
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
		hashes := make([]string, 0, len(rows))
		hasIt := false
		for _, r := range rows {
			hashes = append(hashes, r.Hash)
			if r.Hash == transferTxHash {
				hasIt = true
			}
		}
		require.Truef(t, hasIt,
			"COHERENCE VIOLATION (/transfers vs /transactions list): /transfers exposed tx %q but /transactions list does not contain it. "+
				"Saw hashes: %v. This is the RD-1009 list-path invariant — buildVisibilityFilter must union in transfer-participant tx hashes.",
			transferTxHash, hashes)
	}

	// 3. /transactions/:hash by-hash — must return 200 (not 404).
	// This is the by-hash invariant pinned by PR #285 commit 2.
	{
		req, _ := http.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/explorer/transactions/%s", transferTxHash), nil)
		authHeader(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equalf(t, http.StatusOK, rr.Code,
			"COHERENCE VIOLATION (/transfers vs /transactions/:hash): /transfers exposed tx %q but by-hash dereference returned %d. "+
				"This is the RD-1009 by-hash invariant — buildRedactOptsForViewer must delegate to buildVisibilityFilter so VisibleTxHashes is populated identically on single-item handlers.",
			transferTxHash, rr.Code)
	}

	// 4. /transactions/:hash/internal — surfaces the frame into the admin's
	// vault and drops the frame with both sides private (RD-1316).
	type internalTxRow struct {
		ID           int64  `json:"id"`
		TxHash       string `json:"txHash"`
		TraceAddress string `json:"traceAddress"`
	}
	{
		req, _ := http.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/explorer/transactions/%s/internal", transferTxHash), nil)
		authHeader(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, "/internal must return 200")
		var rows []internalTxRow
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
		require.NotEmptyf(t, rows,
			"COHERENCE VIOLATION (/transfers vs /transactions/:hash/internal): /transfers exposed tx %q, "+
				"but /internal returned no rows although the fixture has a frame into the admin's vault (a side the admin sees).",
			transferTxHash)
		require.Equal(t, transferTxHash, rows[0].TxHash,
			"internal-tx row points at the wrong parent tx hash: got %q want %q", rows[0].TxHash, transferTxHash)
		require.Lenf(t, rows, 1, "RD-1316: the frame with both sides private must not surface: %s", rr.Body.String())
		require.Equal(t, "0,0", rows[0].TraceAddress, "the surviving frame is the call into the admin's vault")
	}

	// 5. /transactions/:hash/logs — the raw event log is emitted by a
	// FOREIGN-org contract (privateTokenContract), Hidden to this admin and on
	// which they hold no grant. Both layers gate the raw event payload on an
	// emitter grant: the RPC drops it (rbac.DecideLogEmitterAccess: no grant),
	// so the explorer MUST drop it too — symmetry (RD-1208/RD-1214). Ordinary
	// visibleTo / tx-participation does NOT rescue a no-grant emitter's log.
	//
	// This does not contradict steps 1–4: those expose the tx *summary*
	// surfaces (the transfer's from/to/value touch the admin's own vault), which
	// stay coherent. The foreign contract's raw event payload is a distinct,
	// more-sensitive surface, gated identically on both layers. Pre-RD-1208 the
	// explorer upgraded Hidden→Full via a visibleTo override and surfaced this
	// log — an asymmetry the RPC never had; this assertion now guards against
	// its return. Cross-layer parity for this exact case is proven directly by
	// TestRPCExplorerLogParity_RD1214.
	{
		req, _ := http.NewRequest(http.MethodGet,
			fmt.Sprintf("/api/v1/explorer/transactions/%s/logs", transferTxHash), nil)
		authHeader(req)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, "/logs must return 200 (empty array, not 404)")
		var rows []explorer.Log
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
		require.Emptyf(t, rows,
			"SYMMETRY (RD-1208/RD-1214): /logs must DROP tx %q's raw log — its emitter is a foreign-org "+
				"contract the admin has no grant on, and the RPC drops it identically. The tx summary stays "+
				"visible via /transfers, but the raw event payload is emitter-grant-gated on both layers.",
			transferTxHash)
	}
}
