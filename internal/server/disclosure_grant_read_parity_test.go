package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A disclosure grant is an input of the shared read decisions: a viewer holding
// an approved Full grant over a user reads that user's transactions, receipts,
// events and token transfers identically on JSON-RPC and on the explorer, in
// both read profiles. Only Full grants admit; pseudonymous and redacted grants
// keep their explorer-only lens; an expired or revoked grant admits nothing.
//
// Fixture: setupRPFixture. The grant subject is U (rpE), the sender of rpTx1.
// rpTx1 emits L0 Transfer(E, P), L1 Transfer(Q, R), L2 Transfer(AA, R) on C.

// grantViewerAddrs gives every grant viewer its own linked address.
var grantViewerAddrs = map[string]string{
	"auditor":          "0xa0d1000000000000000000000000000000000001",
	"auditor_noevents": "0xa0d1000000000000000000000000000000000002",
	"auditor_pseudo":   "0xa0d1000000000000000000000000000000000003",
	"auditor_redacted": "0xa0d1000000000000000000000000000000000004",
	"auditor_expired":  "0xa0d1000000000000000000000000000000000005",
	"auditor_revoked":  "0xa0d1000000000000000000000000000000000006",
}

// addGrantViewer creates a viewer in org O, in the group with the given slug
// (created without contract grants when it does not exist), holding a
// disclosure grant of the given level on U.
func (f *rpFixture) addGrantViewer(t *testing.T, name, groupSlug, level string, expires time.Time, revoked bool) rpViewer {
	t.Helper()
	ctx := context.Background()
	var groupID string
	err := f.conn.QueryRowContext(ctx, `SELECT id FROM groups WHERE org_id = $1 AND slug = $2`, f.orgID, groupSlug).Scan(&groupID)
	if err != nil {
		groupID = wiringCreateGroup(t, f.db, f.orgID, groupSlug, nil, false)
	}
	did := "did:test:rp:" + name
	uid := wiringCreateUserInGroup(t, f.db, did, groupID)
	require.NoError(t, f.db.SystemLinkEthAddress(ctx, did, grantViewerAddrs[name]))
	v := rpViewer{name: name, did: did, uuid: uid, org: f.orgID, addr: grantViewerAddrs[name]}
	f.viewers[name] = v

	scope := fmt.Sprintf(`{"disclosure_level":%q}`, level)
	requestID := uuid.New().String()
	_, err = f.conn.ExecContext(ctx, `
		INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'grant read parity', 'approved', NOW())`,
		requestID, did, f.viewers["participant"].uuid, f.orgID, scope)
	require.NoError(t, err)
	var revokedAt any
	if revoked {
		revokedAt = time.Now().Add(-time.Minute)
	}
	_, err = f.conn.ExecContext(ctx, `
		INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4::jsonb, NOW() - INTERVAL '1 hour', $5, $6)`,
		uuid.New().String(), requestID, "parity-"+name, scope, expires, revokedAt)
	require.NoError(t, err)
	return v
}

// rpLogIndexes returns the logIndex of each JSON-RPC log, in order.
func rpLogIndexes(t *testing.T, logs []json.RawMessage) []int {
	t.Helper()
	out := []int{}
	for _, l := range logs {
		var m struct {
			LogIndex string `json:"logIndex"`
		}
		require.NoError(t, json.Unmarshal(l, &m))
		n, ok := new(big.Int).SetString(strings.TrimPrefix(m.LogIndex, "0x"), 16)
		require.True(t, ok, "logIndex %q", m.LogIndex)
		out = append(out, int(n.Int64()))
	}
	return out
}

// rpLogTopics returns topics[1..] of a JSON-RPC log, lower-case.
func rpLogTopics(t *testing.T, l json.RawMessage) []string {
	t.Helper()
	var m struct {
		Topics []string `json:"topics"`
	}
	require.NoError(t, json.Unmarshal(l, &m))
	out := []string{}
	for _, tp := range m.Topics[1:] {
		out = append(out, strings.ToLower(tp))
	}
	return out
}

func explorerLogTopics(l explorer.Log) []string {
	out := []string{}
	for _, tp := range []*string{l.Topic1, l.Topic2, l.Topic3} {
		if tp != nil {
			out = append(out, strings.ToLower(*tp))
		}
	}
	return out
}

// TestDisclosureGrant_RPCExplorerParity: the Full-grant viewer receives the
// subject's transaction, receipt, block entries, events and token transfers on
// both surfaces, with the same fields and the same embedded addresses, in both
// profiles. A Full-grant viewer without event access to the token receives the
// transaction and receipt but no event and no transfer, on both surfaces.
func TestDisclosureGrant_RPCExplorerParity(t *testing.T) {
	f := setupRPFixture(t)
	day := time.Now().Add(24 * time.Hour)
	// auditor: a member of the [Transfer, from|to = self] group on C.
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", day, false)
	// auditor_noevents: no contract grant at all.
	noEvents := f.addGrantViewer(t, "auditor_noevents", "rp-auditors-noevents", "full", day, false)
	router := f.explorerRouter()

	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	tx2Body := rpEnvelope(t, rpTxObject(rpTx2, rpQ, "0x"))
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))
	logsBody := rpEnvelope(t, rpRawLogs(rpTx1))
	blockBody := rpEnvelope(t, map[string]any{
		"number": "0x1", "logsBloom": "0x" + strings.Repeat("f", 512), "gasUsed": "0x10",
		"transactions": []any{rpTxObject(rpTx1, rpE, rpData), rpTxObject(rpTx2, rpQ, "0x")},
	})
	blockReceiptsBody := rpEnvelope(t, []any{
		rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)),
		rpReceiptObject(rpTx2, rpQ, nil),
	})

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		f.wireExplorer(profile)
		p := f.rpProcessor(profile)
		for _, tc := range []struct {
			v         rpViewer
			wantLogs  []int // log indexes of rpTx1 returned to the viewer
			wantPayee bool  // the subject's counterparty P is revealed in L0
		}{
			{auditor, []int{0}, true},
			{noEvents, []int{}, false},
		} {
			v := tc.v
			t.Run(profile.String()+"/"+v.name, func(t *testing.T) {
				// --- Transaction object: RPC (3 methods) vs explorer by hash.
				for _, m := range []string{rbac.MethodGetTransactionByHash, rbac.MethodGetTransactionByBlockHashAndIndex, rbac.MethodGetTransactionByBlockNumberAndIndex} {
					var tx map[string]any
					out := f.call(t, p, v, m, []any{rpTx1}, txBody)
					require.NoError(t, json.Unmarshal(rpResult(t, out), &tx), "%s: %s", m, out)
					require.NotNil(t, tx, "%s must return the grant subject's tx: %s", m, out)
					assert.Equal(t, rpE, tx["from"], m)
					assert.Equal(t, rpC, tx["to"], m)
					assert.Equal(t, rpData, tx["input"], m)
					assert.Equal(t, "0x2a", tx["value"], m)
					assert.Equal(t, "0x7", tx["nonce"], m)
				}
				code, body := f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1)
				require.Equal(t, http.StatusOK, code, string(body))
				var etx explorer.Transaction
				require.NoError(t, json.Unmarshal(body, &etx))
				assert.Equal(t, rpE, strings.ToLower(etx.From))
				require.NotNil(t, etx.To)
				assert.Equal(t, rpC, strings.ToLower(*etx.To))
				assert.Equal(t, rpData, etx.InputData)
				assert.Equal(t, "42", string(etx.Value))
				require.NotNil(t, etx.Nonce)
				assert.Equal(t, uint64(7), *etx.Nonce)

				// A transaction of a user the grant does not cover: refused on both.
				assert.Equal(t, "null", string(rpResult(t, f.call(t, p, v, rbac.MethodGetTransactionByHash, []any{rpTx2}, tx2Body))))
				code, _ = f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx2)
				assert.Equal(t, http.StatusNotFound, code)

				// --- Receipt: admitted, logs as the shared event decision says.
				var rc struct {
					From string            `json:"from"`
					Logs []json.RawMessage `json:"logs"`
				}
				out := f.call(t, p, v, rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody)
				require.NoError(t, json.Unmarshal(rpResult(t, out), &rc), "receipt: %s", out)
				assert.Equal(t, rpE, rc.From, "receipt: %s", out)
				assert.Equal(t, tc.wantLogs, rpLogIndexes(t, rc.Logs), "receipt logs")

				// --- eth_getLogs: the same logs, rendered the same.
				var logs []json.RawMessage
				out = f.call(t, p, v, rbac.MethodGetLogs, []any{map[string]any{"address": rpC}}, logsBody)
				require.NoError(t, json.Unmarshal(rpResult(t, out), &logs), "logs: %s", out)
				assert.Equal(t, tc.wantLogs, rpLogIndexes(t, logs), "eth_getLogs")
				for i := range logs {
					assert.JSONEq(t, string(rc.Logs[i]), string(logs[i]), "receipt and eth_getLogs render log %d identically", i)
				}

				// --- Explorer transaction logs: the same set, the same topics.
				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1+"/logs")
				require.Equal(t, http.StatusOK, code, string(body))
				var elogs []explorer.Log
				require.NoError(t, json.Unmarshal(body, &elogs))
				eIdx := []int{}
				for _, l := range elogs {
					eIdx = append(eIdx, l.LogIndex)
				}
				assert.Equal(t, tc.wantLogs, eIdx, "explorer logs")
				for i := range elogs {
					if i < len(logs) {
						assert.Equal(t, rpLogTopics(t, logs[i]), explorerLogTopics(elogs[i]), "log %d topics differ between RPC and explorer", elogs[i].LogIndex)
					}
				}
				if tc.wantPayee {
					assert.True(t, rpHasAddr(rc.Logs[0], rpP), "the Full grant reveals the subject's counterparty in the event: %s", rc.Logs[0])
				}
				for _, other := range []string{rpQ, rpR, rpAA} {
					assert.False(t, rpHasAddr(out, other), "eth_getLogs leaked %s: %s", other, out)
				}

				// --- Explorer token transfers: one row per admitted Transfer log,
				// with the addresses the log carries.
				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1+"/transfers")
				require.Equal(t, http.StatusOK, code, string(body))
				var transfers []explorer.TokenTransfer
				require.NoError(t, json.Unmarshal(body, &transfers))
				tIdx := []int{}
				for _, tr := range transfers {
					tIdx = append(tIdx, tr.LogIndex)
				}
				assert.Equal(t, tc.wantLogs, tIdx, "explorer transfers follow the admitted Transfer logs")
				for _, tr := range transfers {
					assert.Equal(t, rpE, strings.ToLower(tr.From))
					assert.Equal(t, rpP, strings.ToLower(tr.To), "the transfer row reveals the counterparty, as the event does")
					assert.Equal(t, "1000", string(tr.Value))
				}

				// --- Block listing, block count and block receipts: the subject's
				// transaction only.
				var block struct {
					Transactions []map[string]any `json:"transactions"`
				}
				require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetBlockByNumber, []any{"0x1", true}, blockBody)), &block))
				require.Len(t, block.Transactions, 1)
				assert.Equal(t, rpTx1, block.Transactions[0]["hash"])
				var hashes []string
				require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetBlockByNumber, []any{"0x1", false}, blockBody)), &struct {
					Transactions *[]string `json:"transactions"`
				}{&hashes}))
				assert.Equal(t, []string{rpTx1}, hashes)
				assert.Equal(t, `"0x1"`, string(rpResult(t, f.call(t, p, v, "eth_getBlockTransactionCountByNumber", []any{"0x1"}, blockBody))))
				var brs []struct {
					TransactionHash string            `json:"transactionHash"`
					Logs            []json.RawMessage `json:"logs"`
				}
				require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetBlockReceipts, []any{"0x1"}, blockReceiptsBody)), &brs))
				require.Len(t, brs, 1)
				assert.Equal(t, rpTx1, brs[0].TransactionHash)
				assert.Equal(t, tc.wantLogs, rpLogIndexes(t, brs[0].Logs))
				code, body = f.explorerGet(t, router, v, fmt.Sprintf("/api/v1/explorer/blocks/%d/transactions", f.block))
				require.Equal(t, http.StatusOK, code, string(body))
				var blockTxs []explorer.Transaction
				require.NoError(t, json.Unmarshal(body, &blockTxs))
				require.Len(t, blockTxs, 1, "explorer block listing: %s", body)
				assert.Equal(t, rpTx1, strings.ToLower(blockTxs[0].Hash))
				assert.False(t, rpHasAddr(body, rpQ), "explorer block listing included another user: %s", body)
			})
		}
	}
}

// TestDisclosureGrant_OnlyActiveFullGrantsAdmitOverRPC: a pseudonymous or
// redacted grant keeps its explorer lens and never opens a JSON-RPC read; an
// expired or revoked Full grant opens nothing on either surface.
func TestDisclosureGrant_OnlyActiveFullGrantsAdmitOverRPC(t *testing.T) {
	f := setupRPFixture(t)
	day := time.Now().Add(24 * time.Hour)
	viewers := []rpViewer{
		f.addGrantViewer(t, "auditor_pseudo", "rp-users", "pseudonymous", day, false),
		f.addGrantViewer(t, "auditor_redacted", "rp-users", "redacted", day, false),
		f.addGrantViewer(t, "auditor_expired", "rp-users", "full", time.Now().Add(-time.Minute), false),
		f.addGrantViewer(t, "auditor_revoked", "rp-users", "full", day, true),
	}
	router := f.explorerRouter()
	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))
	logsBody := rpEnvelope(t, rpRawLogs(rpTx1))
	blockBody := rpEnvelope(t, map[string]any{"number": "0x1", "transactions": []any{rpTxObject(rpTx1, rpE, rpData)}})

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		f.wireExplorer(profile)
		p := f.rpProcessor(profile)
		for _, v := range viewers {
			t.Run(profile.String()+"/"+v.name, func(t *testing.T) {
				out := f.call(t, p, v, rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody)
				assert.Equal(t, "null", string(rpResult(t, out)), "tx: %s", out)
				out = f.call(t, p, v, rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody)
				assert.Equal(t, "null", string(rpResult(t, out)), "receipt: %s", out)
				out = f.call(t, p, v, rbac.MethodGetLogs, []any{map[string]any{"address": rpC}}, logsBody)
				assert.False(t, rpHasAddr(out, rpE), "eth_getLogs revealed the subject: %s", out)
				var block struct {
					Transactions []any `json:"transactions"`
				}
				require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetBlockByNumber, []any{"0x1", true}, blockBody)), &block))
				assert.Empty(t, block.Transactions)

				code, body := f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1)
				switch v.name {
				case "auditor_expired", "auditor_revoked":
					assert.Equal(t, http.StatusNotFound, code, "an inactive grant opens nothing: %s", body)
				default:
					// The explorer keeps its lens: the row renders the subject
					// as a pseudonym or [PRIVATE], never the real address.
					require.Equal(t, http.StatusOK, code, string(body))
					var etx explorer.Transaction
					require.NoError(t, json.Unmarshal(body, &etx))
					assert.NotEqual(t, rpE, strings.ToLower(etx.From), "a %s grant rendered the subject's real address: %s", v.name, body)
				}
			})
		}
	}
}

// TestDisclosureGrant_RPCRevealIsAudited: a JSON-RPC read revealed through a
// Full grant writes one disclosure-grant audit entry, attributed to the
// grantee, with the transaction hash in the entry payload (never in the UUID
// resource id). A read the viewer is entitled to without the grant writes none.
func TestDisclosureGrant_RPCRevealIsAudited(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))
	ctx := context.Background()
	count := func(actor string) int {
		var n int
		require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rbac_audit_log
			WHERE action = 'access' AND resource_type = 'disclosure_grant' AND actor_external_id = $1`, actor).Scan(&n))
		return n
	}

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			_, err := f.conn.ExecContext(ctx, `DELETE FROM rbac_audit_log WHERE resource_type = 'disclosure_grant'`)
			require.NoError(t, err)
			p := f.rpProcessor(profile)

			out := f.call(t, p, auditor, rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody)
			require.NotEqual(t, "null", string(rpResult(t, out)))
			require.Equal(t, 1, count(auditor.did), "one audit entry per revealing response")
			var target, method, class string
			var objects int
			var resourceID *string
			require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT new_value::jsonb->>'target', new_value::jsonb->>'endpoint',
				new_value::jsonb->>'reveal_class', (new_value::jsonb->>'objects_revealed')::int, resource_id::text
				FROM rbac_audit_log WHERE resource_type = 'disclosure_grant' AND actor_external_id = $1`, auditor.did).
				Scan(&target, &method, &class, &objects, &resourceID))
			assert.Equal(t, rpTx1, target)
			assert.Equal(t, rbac.MethodGetTransactionByHash, method)
			assert.Equal(t, "disclosure_grant_full_rpc", class)
			assert.Equal(t, 1, objects)
			assert.Nil(t, resourceID, "the resource id is a UUID column: a tx hash never goes there")
			var grantIDs string
			require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT new_value::jsonb->>'grant_ids' FROM rbac_audit_log
				WHERE resource_type = 'disclosure_grant' AND actor_external_id = $1`, auditor.did).Scan(&grantIDs))
			var wantID string
			require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT id::text FROM disclosure_grants WHERE grant_token_hash = 'parity-auditor'`).Scan(&wantID))
			assert.JSONEq(t, `["`+wantID+`"]`, grantIDs, "the entry names the grant the reveal was made through")

			// The receipt reveals the envelope and the subject's Transfer event.
			f.call(t, p, auditor, rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody)
			require.Equal(t, 2, count(auditor.did))

			// The participant's own reads are not grant reveals.
			f.call(t, p, f.viewers["participant"], rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody)
			f.call(t, p, f.viewers["participant"], rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody)
			assert.Zero(t, count(f.viewers["participant"].did))
			assert.Equal(t, 2, count(auditor.did))
		})
	}
}

// failingGrantResolver is a disclosure-grant lookup that always fails.
type failingGrantResolver struct{}

func (failingGrantResolver) FullDisclosureGrantAddresses(context.Context, string) (map[string][]string, error) {
	return nil, errors.New("grant lookup unavailable")
}

// countingGrantResolver counts disclosure-grant lookups.
type countingGrantResolver struct {
	inner rbac.FullDisclosureGrantResolver
	calls int
}

func (c *countingGrantResolver) FullDisclosureGrantAddresses(ctx context.Context, did string) (map[string][]string, error) {
	c.calls++
	return c.inner.FullDisclosureGrantAddresses(ctx, did)
}

func (f *rpFixture) rpProcessorWithGrants(profile rbac.ReadProfile, grants rbac.FullDisclosureGrantResolver) *JSONRPCProcessor {
	return NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:            f.srv.rbacAccessCtrl,
		RateLimiter:               &noopRateLimiter{},
		AccessLogger:              f.db,
		CircuitBreaker:            middleware.NewCircuitBreaker(),
		ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
		TxVisibilityStore:         f.db,
		AddressVisibilityResolver: f.db,
		DisclosureGrantResolver:   grants,
		ReadProfile:               profile,
	})
}

// TestDisclosureGrant_RPCFailsClosed: a failed grant lookup grants nothing —
// the grantee is refused — while a participant's own read is unaffected.
func TestDisclosureGrant_RPCFailsClosed(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	logsBody := rpEnvelope(t, rpRawLogs(rpTx1))
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			p := f.rpProcessorWithGrants(profile, failingGrantResolver{})
			assert.Equal(t, "null", string(rpResult(t, f.call(t, p, auditor, rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody))))
			out := f.call(t, p, auditor, rbac.MethodGetLogs, []any{map[string]any{"address": rpC}}, logsBody)
			assert.False(t, rpHasAddr(out, rpE), "a failed lookup must not reveal the subject: %s", out)
			assert.NotEqual(t, "null", string(rpResult(t, f.call(t, p, f.viewers["participant"], rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody))))
		})
	}
}

// TestDisclosureGrant_OneLookupPerResponse: the grant set is resolved once per
// response, however many receipts, logs or block entries it carries.
func TestDisclosureGrant_OneLookupPerResponse(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	many := func(n int, mk func(i int) any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = mk(i)
		}
		return out
	}
	hash := func(i int) string { return fmt.Sprintf("0x%064x", 0x1353000+i) }
	logs := []any{}
	for i := 0; i < 20; i++ {
		for _, l := range rpRawLogs(hash(i)) {
			logs = append(logs, l)
		}
	}
	bodies := map[string]struct {
		params []any
		body   []byte
	}{
		rbac.MethodGetBlockReceipts: {[]any{"0x1"}, rpEnvelope(t, many(20, func(i int) any { return rpReceiptObject(hash(i), rpE, rpRawLogs(hash(i))) }))},
		rbac.MethodGetBlockByNumber: {[]any{"0x1", true}, rpEnvelope(t, map[string]any{"number": "0x1", "transactions": many(20, func(i int) any { return rpTxObject(hash(i), rpE, rpData) })})},
		rbac.MethodGetLogs:          {[]any{map[string]any{"address": rpC}}, rpEnvelope(t, logs)},
	}
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for m, b := range bodies {
			t.Run(profile.String()+"/"+m, func(t *testing.T) {
				counter := &countingGrantResolver{inner: f.db}
				p := f.rpProcessorWithGrants(profile, counter)
				out := f.call(t, p, auditor, m, b.params, b.body)
				assert.True(t, rpHasAddr(out, rpE), "the grant admits the subject's entries: %s", out)
				assert.Equal(t, 1, counter.calls, "one grant lookup per response")
			})
		}
	}
}

// A transaction someone else sent (a relayer, an operator) that moves tokens to
// the grant subject: the grant reveals the subject's Transfer event, but not
// the transaction — its sender and recipient are not the subject. The receipt
// stays null (a grant-admitted event never admits a receipt through log
// entitlement), and the response records no transaction reveal.
func TestDisclosureGrant_RelayedTransferRevealsTheEventNotTheTransaction(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	const relayed = "0x1353000000000000000000000000000000000000000000000000000000000b01"
	transfer := map[string]any{
		"address": rpC, "topics": []string{rpT0, zeroPadAddrToTopic(rpQ), zeroPadAddrToTopic(rpE)}, "data": rpValueWord(9),
		"blockNumber": "0x1", "transactionHash": relayed, "logIndex": "0x0", "removed": false,
	}
	receiptBody := rpEnvelope(t, rpReceiptObject(relayed, rpQ, []map[string]any{transfer}))
	logsBody := rpEnvelope(t, []any{transfer})
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			p := f.rpProcessor(profile)
			out := f.call(t, p, auditor, rbac.MethodGetTransactionReceipt, []any{relayed}, receiptBody)
			assert.Equal(t, "null", string(rpResult(t, out)), "the relayer's receipt is not the subject's transaction: %s", out)
			out = f.call(t, p, auditor, rbac.MethodGetLogs, []any{map[string]any{"address": rpC}}, logsBody)
			var logs []json.RawMessage
			require.NoError(t, json.Unmarshal(rpResult(t, out), &logs))
			require.Len(t, logs, 1, "the subject's Transfer is revealed: %s", out)
			assert.True(t, rpHasAddr(logs[0], rpQ) && rpHasAddr(logs[0], rpE), "the grant lens shows both parties of the event: %s", logs[0])
		})
	}
}

// A deployment by the grant subject: the receipt — created address included —
// and the block entry are returned, as the explorer shows the deployment.
func TestDisclosureGrant_SubjectDeploymentReceipt(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	const deployTx = "0x1353000000000000000000000000000000000000000000000000000000000c01"
	const created = "0xc4ea7ed000000000000000000000000000000005"
	receipt := rpReceiptObject(deployTx, rpE, nil)
	receipt["to"] = nil
	receipt["contractAddress"] = created
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			p := f.rpProcessor(profile)
			var rc map[string]any
			require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, auditor, rbac.MethodGetTransactionReceipt, []any{deployTx}, rpEnvelope(t, receipt))), &rc))
			require.NotNil(t, rc)
			assert.Equal(t, created, rc["contractAddress"])
			var brs []map[string]any
			require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, auditor, rbac.MethodGetBlockReceipts, []any{"0x1"}, rpEnvelope(t, []any{receipt}))), &brs))
			require.Len(t, brs, 1)
		})
	}
}

// A Full grant whose scope restricts a date range or contract addresses, or
// that the subject approved only for their activity logs, is honoured on its
// grant pages only, where the scope is applied: it opens no regular read on
// either surface — no JSON-RPC result, no explorer row, no explorer count.
func TestDisclosureGrant_ScopedGrantOpensNoRegularRead(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	router := f.explorerRouter()
	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	for _, scope := range []string{
		`{"disclosure_level":"full","date_range":{"start":"2026-01-01T00:00:00Z","end":"2026-02-01T00:00:00Z"}}`,
		`{"disclosure_level":"full","addresses":["` + rpC + `"]}`,
		`{"disclosure_level":"full","methods":["activity_logs"]}`,
	} {
		_, err := f.conn.ExecContext(context.Background(),
			`UPDATE disclosure_grants SET scope = $1::jsonb WHERE grant_token_hash = 'parity-auditor'`, scope)
		require.NoError(t, err)
		for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
			t.Run(profile.String()+"/"+scope, func(t *testing.T) {
				f.wireExplorer(profile)
				p := f.rpProcessor(profile)
				out := f.call(t, p, auditor, rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody)
				assert.Equal(t, "null", string(rpResult(t, out)), "a restricted grant opens no JSON-RPC read: %s", out)
				code, body := f.explorerGet(t, router, auditor, "/api/v1/explorer/transactions/"+rpTx1)
				assert.Equal(t, http.StatusNotFound, code, "a restricted grant opens no explorer row: %s", body)
				assert.False(t, rpHasAddr(body, rpE), "%s", body)
				filter := f.srv.buildVisibilityFilter(context.Background(), auditor.did, false)
				n, err := f.srv.explorerStore.GetBlockTransactionCountFiltered(context.Background(), uint64(f.block), filter)
				require.NoError(t, err)
				if profile.Strict() {
					assert.Zero(t, n, "a restricted grant's subject is not counted")
				}
				for _, a := range filter.VisibleAddresses {
					assert.NotEqual(t, rpE, strings.ToLower(a), "a restricted grant's subject is not on the explorer allowlist")
				}
			})
		}
	}
}

// The grant lens reveals the parties an event names in its ABI-indexed
// address parameters, identically on JSON-RPC and the explorer; an address in
// the event data stays at the viewer's own level.
func TestDisclosureGrant_LensRevealsIndexedPartiesOnBothSurfaces(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	const (
		settled    = "0x5e771ed000000000000000000000000000000007"
		settledABI = `[{"type":"event","name":"Settled","anonymous":false,"inputs":[{"name":"payer","type":"address","indexed":true},{"name":"payee","type":"address","indexed":true},{"name":"agent","type":"address","indexed":false}]}]`
		settledTx  = "0x1353000000000000000000000000000000000000000000000000000000000d01"
	)
	ctx := context.Background()
	var groupID string
	require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT id FROM groups WHERE org_id = $1 AND slug = 'rp-users'`, f.orgID).Scan(&groupID))
	cid := wiringCreateContractWithABI(t, f.db, f.orgID, settled, "Settlement", settledABI)
	wiringCreateGrant(t, f.db, cid, groupID, &rbac.EventRulesField{Wildcard: true})
	t0 := "0x" + topicHex("Settled(address,address,address)")
	agentWord := "0x" + strings.Repeat("0", 24) + strings.TrimPrefix(rpR, "0x")
	_, err := f.conn.ExecContext(ctx, `INSERT INTO logs (tx_hash, log_index, address, topic0, topic1, topic2, data, block_number)
		VALUES ($1, 0, $2, $3, $4, $5, $6, $7)`, settledTx, settled, t0, zeroPadAddrToTopic(rpE), zeroPadAddrToTopic(rpP), agentWord, f.block)
	require.NoError(t, err)
	logsBody := rpEnvelope(t, []any{map[string]any{
		"address": settled, "topics": []string{t0, zeroPadAddrToTopic(rpE), zeroPadAddrToTopic(rpP)}, "data": agentWord,
		"blockNumber": "0x1", "transactionHash": settledTx, "logIndex": "0x0", "removed": false,
	}})
	router := f.explorerRouter()
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			f.wireExplorer(profile)
			p := f.rpProcessor(profile)
			out := f.call(t, p, auditor, rbac.MethodGetLogs, []any{map[string]any{"address": settled}}, logsBody)
			var logs []json.RawMessage
			require.NoError(t, json.Unmarshal(rpResult(t, out), &logs))
			require.Len(t, logs, 1, "%s", out)
			assert.True(t, rpHasAddr(logs[0], rpP), "the indexed counterparty is revealed on JSON-RPC: %s", logs[0])
			assert.False(t, rpHasAddr(logs[0], rpR), "the data address stays masked on JSON-RPC: %s", logs[0])

			code, body := f.explorerGet(t, router, auditor, "/api/v1/explorer/transactions/"+settledTx+"/logs")
			require.Equal(t, http.StatusOK, code, "%s", body)
			var elogs []explorer.Log
			require.NoError(t, json.Unmarshal(body, &elogs))
			require.Len(t, elogs, 1, "%s", body)
			assert.Equal(t, rpLogTopics(t, logs[0]), explorerLogTopics(elogs[0]), "same topics on both surfaces")
			assert.Equal(t, strings.ToLower(rpLogData(t, logs[0])), strings.ToLower(elogs[0].Data), "same data on both surfaces")
			assert.False(t, rpHasAddr(body, rpR), "the data address stays masked on the explorer: %s", body)
		})
	}
}

func rpLogData(t *testing.T, l json.RawMessage) string {
	t.Helper()
	var m struct {
		Data string `json:"data"`
	}
	require.NoError(t, json.Unmarshal(l, &m))
	return m.Data
}

// Under View-as and the admin dry-run the viewer's grants do not apply: the
// subject's transaction is refused, and no grant reveal is audited in the
// grantee's name. The grantee's own call is the control.
func TestDisclosureGrant_RPCSuppressedUnderViewAsAndDryRun(t *testing.T) {
	f := setupRD1318Fixture(t)
	ctx := context.Background()
	database := f.srv.db
	var memberGroup, granteeUID string
	require.NoError(t, database.Conn().QueryRowContext(ctx,
		`SELECT id FROM groups WHERE org_id = $1 AND slug = 'members'`, f.orgID).Scan(&memberGroup))
	require.NoError(t, database.Conn().QueryRowContext(ctx,
		`SELECT id FROM users WHERE external_id = $1`, rd1318GranteeDID).Scan(&granteeUID))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: memberGroup, AllowedMethods: []string{rbac.MethodGetTransactionByHash},
	}))

	txHash := "0x1318" + strings.Repeat("2", 60)
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
		"hash": txHash, "from": rd1318SubjectEOA, "to": rd1318Peer, "input": "0x", "value": "0x5", "nonce": "0x1",
	}})
	require.NoError(t, err)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(stub.Close)
	f.srv.proxy = proxy.New(stub.URL)
	f.srv.jsonrpcProcessor = NewJSONRPCProcessor(JSONRPCProcessorConfig{
		ReadProfile:               rbac.ReadProfileStandard,
		RBACAccessCtrl:            f.srv.rbacAccessCtrl,
		RateLimiter:               &noopRateLimiter{},
		Proxy:                     f.srv.proxy,
		AccessLogger:              database,
		CircuitBreaker:            middleware.NewCircuitBreaker(),
		ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
		TxVisibilityStore:         database,
		AddressVisibilityResolver: database,
		DisclosureGrantResolver:   database,
	})
	subject := strings.TrimPrefix(rd1318SubjectEOA, "0x")
	audits := func() int {
		var n int
		require.NoError(t, database.Conn().QueryRowContext(ctx, `SELECT COUNT(*) FROM rbac_audit_log
			WHERE resource_type = 'disclosure_grant' AND actor_external_id = $1`, rd1318GranteeDID).Scan(&n))
		return n
	}

	own := f.srv.jsonrpcProcessor.applyResponseFilter(ctx,
		&ProcessRequest{Method: rbac.MethodGetTransactionByHash, Params: []any{txHash}, UserID: rd1318GranteeDID},
		&rbac.AccessCheckResult{Allowed: true, UserID: granteeUID, OrgID: f.orgID}, body)
	require.Contains(t, strings.ToLower(string(own)), subject, "control: the grantee's own call returns the subject's tx")
	require.Equal(t, 1, audits(), "control: the grantee's own reveal is audited")

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_subject", rd1318AdminDID)
		c.Next()
	})
	router.POST("/api/orgs/:org_id/dry-run", f.srv.handleDryRun)
	reqBody, err := json.Marshal(map[string]any{"user_did": rd1318GranteeDID, "rpc": map[string]any{"method": rbac.MethodGetTransactionByHash, "params": []any{txHash}}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+f.orgID+"/dry-run", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"allow"`, "the dry-run must be allowed, or the assertion below proves nothing")
	assert.NotContains(t, strings.ToLower(w.Body.String()), subject, "dry-run must not apply the grantee's grant: %s", w.Body.String())

	rpcBody, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": rbac.MethodGetTransactionByHash, "params": []any{txHash}})
	require.NoError(t, err)
	mreq := httptest.NewRequest(http.MethodGet, impersonatePath(rd1318GranteeDID, f.orgID, "/rpc"), strings.NewReader(string(rpcBody)))
	mreq.Header.Set("Content-Type", "application/json")
	mreq.Header.Set("X-Test-Admin", "1")
	mw := httptest.NewRecorder()
	f.router.ServeHTTP(mw, mreq)
	require.Equal(t, http.StatusOK, mw.Code, mw.Body.String())
	assert.Contains(t, mw.Body.String(), `"result":null`, "View-as must not apply the grantee's grant: %s", mw.Body.String())
	assert.NotContains(t, strings.ToLower(mw.Body.String()), subject)

	assert.Equal(t, 1, audits(), "no grant reveal is audited in the grantee's name under View-as or dry-run")
}

// The explorer's log endpoints record a grant-lens reveal in the audit log,
// naming the grant, like its transaction endpoints.
func TestDisclosureGrant_ExplorerLogRevealIsAudited(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	router := f.explorerRouter()
	ctx := context.Background()
	var wantID string
	require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT id::text FROM disclosure_grants WHERE grant_token_hash = 'parity-auditor'`).Scan(&wantID))
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			_, err := f.conn.ExecContext(ctx, `DELETE FROM rbac_audit_log WHERE resource_type = 'disclosure_grant'`)
			require.NoError(t, err)
			f.wireExplorer(profile)
			for _, ep := range []struct{ path, label string }{
				{"/api/v1/explorer/transactions/" + rpTx1 + "/logs", "transaction_logs"},
				{"/api/v1/explorer/addresses/" + rpC + "/logs", "address_logs"},
				{"/api/v1/explorer/logs?address=" + rpC, "logs"},
			} {
				code, body := f.explorerGet(t, router, auditor, ep.path)
				require.Equal(t, http.StatusOK, code, "%s: %s", ep.path, body)
				require.True(t, rpHasAddr(body, rpP), "%s: the lens reveals the subject's counterparty: %s", ep.path, body)
				var n int
				var ids string
				require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(new_value::jsonb->>'grant_ids'), '') FROM rbac_audit_log
					WHERE resource_type = 'disclosure_grant' AND actor_external_id = $1 AND resource_name = $2`, auditor.did, ep.label).Scan(&n, &ids))
				assert.Equal(t, 1, n, "%s: one audit entry", ep.label)
				assert.JSONEq(t, `["`+wantID+`"]`, ids, "%s: the entry names the grant", ep.label)
			}
		})
	}
}

// The JSON-RPC audit entry is written even when the client has gone away by
// the time the response is filtered.
func TestDisclosureGrant_RPCAuditSurvivesCancelledRequest(t *testing.T) {
	f := setupRPFixture(t)
	auditor := f.addGrantViewer(t, "auditor", "rp-users", "full", time.Now().Add(24*time.Hour), false)
	p := f.rpProcessor(rbac.ReadProfileStandard)
	grants := rbac.ResolveDisclosureGrants(context.Background(), f.db, auditor.did)
	require.True(t, grants.Covers(rpE))
	grants.RecordReveal(rpE)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.auditDisclosureGrantReveals(ctx, &ProcessRequest{Method: rbac.MethodGetTransactionByHash, UserID: auditor.did, Params: []any{rpTx1}}, grants)
	var n int
	require.NoError(t, f.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM rbac_audit_log
		WHERE resource_type = 'disclosure_grant' AND actor_external_id = $1`, auditor.did).Scan(&n))
	assert.Equal(t, 1, n)
}
