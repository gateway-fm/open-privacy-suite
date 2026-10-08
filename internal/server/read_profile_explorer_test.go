package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1299 acceptance 1 and 4 on the proxy-mode explorer: under strict, the
// transaction, its receipt fields, token transfers, internal calls, list rows
// and counts reach only a transaction participant (tx from/to), exactly as the
// RPC decides on the same fixture (read_profile_rpc_envelope_test.go). Token
// transfers follow the strict event predicate of the Transfer log they derive
// from. ORG_ADMIN_VIEW_USER_TXS=true changes nothing under strict.
func TestReadProfile_ExplorerTx_Matrix(t *testing.T) {
	f := setupRPFixture(t)
	router := f.explorerRouter()

	for _, flag := range []bool{false, true} {
		f.srv.config.OrgAdminViewUserTxs = flag
		f.wireExplorer(rbac.ReadProfileStrict)
		for _, name := range rpViewerNames {
			v := f.viewers[name]
			participant := name == "participant"
			t.Run(fmt.Sprintf("strict/flag=%v/%s", flag, name), func(t *testing.T) {
				// By hash: the full tx for the participant, 404 for everyone else.
				code, body := f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1)
				if participant {
					require.Equal(t, http.StatusOK, code, string(body))
					var tx explorer.Transaction
					require.NoError(t, json.Unmarshal(body, &tx))
					assert.Equal(t, rpE, strings.ToLower(tx.From))
					assert.Equal(t, rpData, tx.InputData)
					assert.Equal(t, "42", string(tx.Value))
					require.NotNil(t, tx.Nonce)
					assert.Equal(t, uint64(7), *tx.Nonce)
					// Strict transaction rows omit transfer-count summaries.
					assert.Zero(t, tx.TokenTransferCount, "strict: no transfer count on the row")
					assert.NotContains(t, tx.TxCategories, "token_transfer")
				} else {
					assert.Equal(t, http.StatusNotFound, code, string(body))
					assert.False(t, rpHasAddr(body, rpE), "by-hash included the sender: %s", body)
				}

				// Lists: global, paginated, block and contract-address feeds.
				wantHashes := []string{}
				if participant {
					wantHashes = []string{rpTx1}
				}
				assert.ElementsMatch(t, wantHashes, explorerTxHashes(t, f, router, v, "/api/v1/explorer/transactions?limit=50", ""), "/transactions")
				assert.ElementsMatch(t, wantHashes, explorerTxHashes(t, f, router, v, "/api/v1/explorer/transactions/paginated?limit=50", "data"), "/transactions/paginated")
				assert.ElementsMatch(t, wantHashes, explorerTxHashes(t, f, router, v, fmt.Sprintf("/api/v1/explorer/blocks/%d/transactions", f.block), ""), "/blocks/:n/transactions")
				if name != "other_org" && name != "anonymous" {
					assert.ElementsMatch(t, wantHashes, explorerTxHashes(t, f, router, v, "/api/v1/explorer/addresses/"+rpC+"/transactions", "transactions"), "/addresses/:C/transactions")
				}

				// Counts (block transaction count, stats) use the same SQL
				// visibility filter: it admits only the participant's rows.
				filter := f.srv.buildVisibilityFilter(context.Background(), v.did)
				n, err := f.srv.explorerStore.GetBlockTransactionCountFiltered(context.Background(), uint64(f.block), filter)
				require.NoError(t, err)
				assert.Equal(t, len(wantHashes), n, "block transaction count")
				assert.Empty(t, filter.VisibleTxHashes, "strict: no visibleTo/union hash overrides")
				assert.Empty(t, filter.ListedTxHashes, "strict: no visibleTo listings")
				for _, a := range filter.VisibleAddresses {
					assert.Equal(t, v.addr, a, "strict allowlist holds only the viewer's own address")
				}

				// Token transfers: only the Transfer events that name the
				// viewer (L0 for the participant and payee, L2 for the org
				// admin); the counterparty stays private, the amount is kept
				// (it is not an address), as on eth_getLogs.
				wantTransfers := map[string][]int{"participant": {0}, "payee": {0}, "org_admin": {2}}[name]
				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1+"/transfers")
				require.Equal(t, http.StatusOK, code, string(body))
				var transfers []explorer.TokenTransfer
				require.NoError(t, json.Unmarshal(body, &transfers))
				assertStrictTransfers(t, v, body, transfers, wantTransfers)

				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/transfers?limit=50")
				require.Equal(t, http.StatusOK, code, string(body))
				var page struct {
					Data  []explorer.TokenTransfer `json:"data"`
					Total int                      `json:"total"`
				}
				require.NoError(t, json.Unmarshal(body, &page))
				assertStrictTransfers(t, v, body, page.Data, wantTransfers)
				assert.Equal(t, len(wantTransfers), page.Total)

				// Internal calls: the participant only.
				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1+"/internal")
				require.Equal(t, http.StatusOK, code, string(body))
				var internals []explorer.InternalTransaction
				require.NoError(t, json.Unmarshal(body, &internals))
				code, body2 := f.explorerGet(t, router, v, fmt.Sprintf("/api/v1/explorer/blocks/%d/internal", f.block))
				require.Equal(t, http.StatusOK, code, string(body2))
				var blockInternals []explorer.InternalTransaction
				require.NoError(t, json.Unmarshal(body2, &blockInternals))
				if participant {
					require.Len(t, internals, 1)
					assert.Len(t, blockInternals, 1)
					// The frame C -> P: the contract is shown, the payee (another
					// user's private address, not a party of the parent tx) is not;
					// the value is kept.
					assert.Equal(t, rpC, strings.ToLower(internals[0].From))
					assert.Equal(t, "50", string(internals[0].Value))
					assert.False(t, rpHasAddr(body, rpP), "internal call included the payee: %s", body)
					assert.False(t, rpHasAddr(body2, rpP), "block internal calls included the payee: %s", body2)
				} else {
					assert.Empty(t, internals, "internal calls of another user's tx: %s", body)
					assert.Empty(t, blockInternals, "block internal calls of another user's tx: %s", body2)
				}

				// Address stats counters (/addresses/:a/stats) walk the same
				// redactor: they count only rows the viewer may load.
				ctx := context.Background()
				opts := f.srv.buildRedactOptsForViewer(ctx, v.did)
				nTx, err := f.srv.countVisibleAddressTxs(ctx, rpC, v.did, opts)
				require.NoError(t, err)
				assert.Equal(t, len(wantHashes), nTx, "address tx count")
				wantP, wantR := 0, 0
				for _, i := range wantTransfers {
					if i == 0 {
						wantP++
					} else {
						wantR++
					}
				}
				nP, err := f.srv.countVisibleAddressTransfers(ctx, rpP, v.did, opts)
				require.NoError(t, err)
				assert.Equal(t, wantP, nP, "payee address transfer count")
				nR, err := f.srv.countVisibleAddressTransfers(ctx, rpR, v.did, opts)
				require.NoError(t, err)
				assert.Equal(t, wantR, nR, "third-party address transfer count")
				nIn, err := f.srv.countVisibleAddressInternalTxs(ctx, rpP, v.did, opts)
				require.NoError(t, err)
				wantIn := 0
				if participant {
					wantIn = 1
				}
				assert.Equal(t, wantIn, nIn, "payee address internal-call count")

				// Search: a tx hash is suggested only to a viewer who may open it.
				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/search/suggestions?q="+rpTx1[:12])
				require.Equal(t, http.StatusOK, code, string(body))
				var sugg []explorer.SearchSuggestion
				require.NoError(t, json.Unmarshal(body, &sugg))
				got := []string{}
				for _, s := range sugg {
					if s.Type == "transaction" {
						got = append(got, strings.ToLower(s.Value))
					}
				}
				assert.ElementsMatch(t, wantHashes, got, "search suggestions")
			})
		}
	}

	// Standard anchors (the documented default, unchanged): the participant
	// sees the full tx, a destination-contract admin keeps the redacted audit
	// row, an ordinary grant holder sees nothing.
	f.srv.config.OrgAdminViewUserTxs = false
	f.wireExplorer(rbac.ReadProfileStandard)
	code, body := f.explorerGet(t, router, f.viewers["participant"], "/api/v1/explorer/transactions/"+rpTx1)
	require.Equal(t, http.StatusOK, code, string(body))
	code, body = f.explorerGet(t, router, f.viewers["contract_admin"], "/api/v1/explorer/transactions/"+rpTx1)
	require.Equal(t, http.StatusOK, code, string(body))
	var redacted explorer.Transaction
	require.NoError(t, json.Unmarshal(body, &redacted))
	assert.Equal(t, "[PRIVATE]", redacted.From)
	assert.Empty(t, redacted.InputData)
	assert.Nil(t, redacted.Nonce)
	code, body = f.explorerGet(t, router, f.viewers["ordinary"], "/api/v1/explorer/transactions/"+rpTx1)
	assert.Equal(t, http.StatusNotFound, code, string(body))
}

func TestReadProfile_ParticipantFields_RPCExplorerParity(t *testing.T) {
	f := setupRPFixture(t)
	router := f.explorerRouter()
	_, err := f.conn.ExecContext(context.Background(),
		`UPDATE transactions SET from_address=$1, to_address=$2, input_data=$3 WHERE hash=$4`,
		rpE, rpP, rpData, rpTx2)
	require.NoError(t, err)

	txObject := rpTxObject(rpTx2, rpE, rpData)
	txObject["to"] = rpP
	txBody := rpEnvelope(t, txObject)
	receiptObject := rpReceiptObject(rpTx2, rpE, nil)
	receiptObject["to"] = rpP
	receiptBody := rpEnvelope(t, receiptObject)

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		f.wireExplorer(profile)
		p := f.rpProcessor(profile)
		for _, name := range []string{"participant", "payee", "ordinary"} {
			t.Run(profile.String()+"/"+name, func(t *testing.T) {
				v := f.viewers[name]
				out := f.call(t, p, v, rbac.MethodGetTransactionByHash, []any{rpTx2}, txBody)
				receipt := f.call(t, p, v, rbac.MethodGetTransactionReceipt, []any{rpTx2}, receiptBody)
				code, body := f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx2)
				if name == "ordinary" {
					assert.Equal(t, "null", string(rpResult(t, out)))
					assert.Equal(t, "null", string(rpResult(t, receipt)))
					assert.Equal(t, http.StatusNotFound, code, string(body))
					for _, response := range [][]byte{out, receipt, body} {
						for _, protected := range []string{rpTx2, rpE, rpP, rpData} {
							assert.NotContains(t, string(response), protected)
						}
						for _, field := range []string{"value", "nonce"} {
							assert.NotContains(t, string(response), `"`+field+`"`)
						}
					}
					return
				}

				var rpcTx map[string]any
				require.NoError(t, json.Unmarshal(rpResult(t, out), &rpcTx))
				assert.Equal(t, rpTx2, rpcTx["hash"])
				assert.Equal(t, rpE, rpcTx["from"])
				assert.Equal(t, rpP, rpcTx["to"])
				assert.Equal(t, rpData, rpcTx["input"])
				assert.Equal(t, "0x2a", rpcTx["value"])
				assert.Equal(t, "0x7", rpcTx["nonce"])
				var rpcReceipt map[string]any
				require.NoError(t, json.Unmarshal(rpResult(t, receipt), &rpcReceipt))
				assert.Equal(t, rpTx2, rpcReceipt["transactionHash"])
				assert.Equal(t, rpE, rpcReceipt["from"])
				assert.Equal(t, rpP, rpcReceipt["to"])

				require.Equal(t, http.StatusOK, code, string(body))
				var tx explorer.Transaction
				require.NoError(t, json.Unmarshal(body, &tx))
				assert.Equal(t, rpcTx["hash"], tx.Hash)
				assert.Equal(t, rpcTx["from"], tx.From)
				require.NotNil(t, tx.To)
				assert.Equal(t, rpcTx["to"], *tx.To)
				assert.Equal(t, rpcTx["input"], tx.InputData)
				assert.Equal(t, "42", string(tx.Value))
				if profile.Strict() || name == "participant" {
					require.NotNil(t, tx.Nonce)
					assert.Equal(t, uint64(7), *tx.Nonce)
				} else {
					assert.Nil(t, tx.Nonce, "standard recipients retain the sender nonce policy")
				}
			})
		}
	}
}

func explorerTxHashes(t *testing.T, f *rpFixture, router *gin.Engine, v rpViewer, path, field string) []string {
	t.Helper()
	code, body := f.explorerGet(t, router, v, path)
	require.Equal(t, http.StatusOK, code, "%s: %s", path, body)
	var txs []explorer.Transaction
	if field == "" {
		require.NoError(t, json.Unmarshal(body, &txs), "%s: %s", path, body)
	} else {
		var wrap map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &wrap), "%s: %s", path, body)
		require.NoError(t, json.Unmarshal(wrap[field], &txs), "%s: %s", path, body)
	}
	out := []string{}
	for _, tx := range txs {
		out = append(out, strings.ToLower(tx.Hash))
	}
	for _, other := range []string{rpE, rpQ} {
		if !strings.EqualFold(other, v.addr) {
			assert.False(t, rpHasAddr(body, other), "%s included %s: %s", path, other, body)
		}
	}
	return out
}

func assertStrictTransfers(t *testing.T, v rpViewer, body []byte, got []explorer.TokenTransfer, wantIdx []int) {
	t.Helper()
	logs := rpLogs()
	idx := []int{}
	for _, tr := range got {
		idx = append(idx, tr.LogIndex)
		src := logs[tr.LogIndex]
		for _, side := range []struct{ got, src string }{{tr.From, src.from}, {tr.To, src.to}} {
			if strings.EqualFold(side.src, v.addr) {
				assert.Equal(t, v.addr, strings.ToLower(side.got), "own side of transfer %d", tr.LogIndex)
			} else {
				assert.Equal(t, "[PRIVATE]", side.got, "counterparty of transfer %d", tr.LogIndex)
			}
		}
		assert.Equal(t, fmt.Sprint(src.value), string(tr.Value), "amount of transfer %d", tr.LogIndex)
	}
	if wantIdx == nil {
		wantIdx = []int{}
	}
	assert.ElementsMatch(t, wantIdx, idx, "admitted transfers for %s", v.name)
	for _, other := range []string{rpE, rpP, rpQ, rpR, rpAA} {
		if !strings.EqualFold(other, v.addr) {
			assert.False(t, rpHasAddr(body, other), "transfers included %s: %s", other, body)
		}
	}
}

// Under strict an approved disclosure grant is the one surviving exception on
// the explorer: an auditor granted full disclosure of the sender U opens U's
// transaction, and nothing else. JSON-RPC has no grant path: the same viewer
// gets null.
func TestReadProfile_Strict_DisclosureGrantSurvives(t *testing.T) {
	f := setupRPFixture(t)
	router := f.explorerRouter()
	f.wireExplorer(rbac.ReadProfileStrict)
	ctx := context.Background()

	auditor := rpViewer{name: "auditor", did: "did:test:rp:auditor", uuid: uuid.New().String(), org: f.otherID}
	require.NoError(t, f.db.CreateUser(ctx, &rbac.User{ID: auditor.uuid, ExternalID: auditor.did, KYC: true, Metadata: map[string]any{}}))
	// Disclosure grants are scoped to current members of the target org.
	auditorGroup := wiringCreateGroup(t, f.db, f.orgID, "rp-auditors", nil, false)
	require.NoError(t, f.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: auditor.uuid, GroupID: auditorGroup, Source: rbac.MembershipSourceAdmin}))
	scope := `{"disclosure_level":"full"}`
	requestID := uuid.New().String()
	_, err := f.conn.ExecContext(ctx, `
		INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, 'rd1299 strict grant', 'approved', NOW())`,
		requestID, auditor.did, f.viewers["participant"].uuid, f.orgID, scope)
	require.NoError(t, err)
	_, err = f.conn.ExecContext(ctx, `
		INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, $4::jsonb, NOW(), $5)`,
		uuid.New().String(), requestID, "rd1299-strict-grant", scope, time.Now().Add(time.Hour))
	require.NoError(t, err)

	code, body := f.explorerGet(t, router, auditor, "/api/v1/explorer/transactions/"+rpTx1)
	require.Equal(t, http.StatusOK, code, "the granted user's tx: %s", body)
	var revealAudits int
	require.NoError(t, f.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rbac_audit_log WHERE action='access' AND resource_type='disclosure_grant' AND new_value::jsonb->>'target'=$1`, rpTx1).Scan(&revealAudits))
	assert.Positive(t, revealAudits, "a full disclosure reveal is audited")
	code, body = f.explorerGet(t, router, auditor, "/api/v1/explorer/transactions/"+rpTx2)
	assert.Equal(t, http.StatusNotFound, code, "a tx of a user not under the grant: %s", body)
	code, body = f.explorerGet(t, router, auditor, "/api/v1/explorer/transactions?limit=50")
	require.Equal(t, http.StatusOK, code, string(body))
	var granted []explorer.Transaction
	require.NoError(t, json.Unmarshal(body, &granted))
	require.Len(t, granted, 1)
	assert.Equal(t, rpTx1, strings.ToLower(granted[0].Hash))

	p := f.rpProcessor(rbac.ReadProfileStrict)
	raw := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	out := f.call(t, p, auditor, "eth_getTransactionByHash", []any{rpTx1}, raw)
	assert.Equal(t, "null", string(rpResult(t, out)), "RPC has no disclosure-grant path")
}
