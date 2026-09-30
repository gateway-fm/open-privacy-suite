package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1300: the per-contract visibleTo unlock (RD-874, REDACTION_SPEC §3.7.1)
// shares the FULL event payload of the flagged emitter's logs in one listed
// transaction. These tests drive ONE fixture through all three log surfaces —
// eth_getLogs, eth_getTransactionReceipt (both through the production
// applyResponseFilter path) and the explorer's /transactions/:hash/logs
// handler — and assert the rendered topics and data bytes, not just presence.

// paymentCreatedABIRD1300: two indexed parties, one non-indexed third-party
// address (embedded in data) and a dynamic identifier (string → M15 gate).
const paymentCreatedABIRD1300 = `[{"anonymous":false,"type":"event","name":"PaymentCreated","inputs":[
	{"indexed":true,"name":"payer","type":"address"},
	{"indexed":true,"name":"payee","type":"address"},
	{"indexed":false,"name":"intermediary","type":"address"},
	{"indexed":false,"name":"paymentId","type":"string"}]}]`

type vtuLog struct {
	Address string
	Topics  []string
	Data    string
}

func (l vtuLog) norm() vtuLog {
	out := vtuLog{Address: strings.ToLower(l.Address), Data: strings.ToLower(l.Data)}
	for _, t := range l.Topics {
		out.Topics = append(out.Topics, strings.ToLower(t))
	}
	return out
}

type vtuFixture struct {
	t      *testing.T
	srv    *Server
	db     *db.DB
	proc   *JSONRPCProcessor
	router *gin.Engine
	orgID  string

	payment, ledger, audit    string // emitter addresses
	paymentCID                string
	payer, payee, intermedAdr string

	// chain data per tx (upstream = what the node returns)
	txFrom map[string]string
	txTo   map[string]string
	txLogs map[string][]vtuLog

	users map[string]string // DID -> user UUID
}

func vtuPackPaymentData(t *testing.T, intermediary, paymentID string) string {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(paymentCreatedABIRD1300))
	require.NoError(t, err)
	packed, err := parsed.Events["PaymentCreated"].Inputs.NonIndexed().Pack(common.HexToAddress(intermediary), paymentID)
	require.NoError(t, err)
	return "0x" + hex.EncodeToString(packed)
}

func newVTUFixture(t *testing.T) *vtuFixture {
	t.Helper()
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	_, err := conn.ExecContext(context.Background(), explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})
	wireExplorerRedactor(srv.explorerRedactor, database, srv.rbacAccessCtrl, noopLogParticipantStore{}, nil)

	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:            srv.rbacAccessCtrl,
		RateLimiter:               &noopRateLimiter{},
		AccessLogger:              database,
		CircuitBreaker:            middleware.NewCircuitBreaker(),
		ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
		TxVisibilityStore:         database,
		AddressVisibilityResolver: database,
	})

	return &vtuFixture{
		t: t, srv: srv, db: database, proc: proc, router: setupCoherenceRouter(srv),
		payment:     "0x1000000000000000000000000000000000000001",
		ledger:      "0x1000000000000000000000000000000000000002",
		audit:       "0x1000000000000000000000000000000000000003",
		payer:       "0x" + strings.Repeat("a1", 20),
		payee:       "0x" + strings.Repeat("b2", 20),
		intermedAdr: "0x" + strings.Repeat("c3", 20),
		txFrom:      map[string]string{},
		txTo:        map[string]string{},
		txLogs:      map[string][]vtuLog{},
		users:       map[string]string{},
	}
}

func (f *vtuFixture) user(did string, groupID string, linked string) {
	f.t.Helper()
	ctx := context.Background()
	var uid string
	if groupID != "" {
		uid = wiringCreateUserInGroup(f.t, f.db, did, groupID)
	} else {
		uid = uuid.New().String()
		require.NoError(f.t, f.db.CreateUser(ctx, &rbac.User{ID: uid, ExternalID: did, KYC: true, Metadata: map[string]any{}}))
	}
	f.users[did] = uid
	if linked != "" {
		require.NoError(f.t, f.db.SystemLinkEthAddress(ctx, did, linked))
	}
}

// seedTx records a tx both upstream (for the RPC responses) and in the
// explorer's indexed tables (for the explorer handler).
func (f *vtuFixture) seedTx(hash, from, to string, logs []vtuLog) {
	f.t.Helper()
	conn := f.db.Conn()
	block := seedExplorerBlock(f.t, conn)
	seedExplorerTransaction(f.t, conn, block, hash, from, to)
	for i, l := range logs {
		var tp [4]any
		for j := 0; j < 4; j++ {
			if j < len(l.Topics) {
				tp[j] = l.Topics[j]
			}
		}
		_, err := conn.ExecContext(context.Background(),
			`INSERT INTO logs (tx_hash, log_index, address, topic0, topic1, topic2, topic3, data, block_number)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			hash, i, l.Address, tp[0], tp[1], tp[2], tp[3], l.Data, block)
		require.NoError(f.t, err)
	}
	f.txFrom[hash], f.txTo[hash], f.txLogs[hash] = from, to, logs
}

func (f *vtuFixture) upstreamLog(hash string, i int, l vtuLog) map[string]any {
	return map[string]any{
		"address": l.Address, "topics": l.Topics, "data": l.Data,
		"blockNumber": "0x1", "blockHash": "0x" + strings.Repeat("0b", 32),
		"transactionHash": hash, "transactionIndex": "0x0",
		"logIndex": fmt.Sprintf("0x%x", i), "removed": false,
	}
}

func parseRPCLogs(t *testing.T, raw json.RawMessage) []vtuLog {
	t.Helper()
	var arr []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
		Data    string   `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &arr))
	out := make([]vtuLog, 0, len(arr))
	for _, a := range arr {
		out = append(out, vtuLog{Address: a.Address, Topics: a.Topics, Data: a.Data}.norm())
	}
	return out
}

func (f *vtuFixture) accessResult(did string) *rbac.AccessCheckResult {
	uid := f.users[did]
	if uid == "" {
		return nil // anonymous / unknown viewer: no access-check identity
	}
	return &rbac.AccessCheckResult{Allowed: true, UserID: uid, OrgID: f.orgID}
}

// rpcGetLogsMulti sends ONE eth_getLogs response spanning several txs (the
// cross-tx leak class) and returns the rendered logs keyed by their tx hash.
func (f *vtuFixture) rpcGetLogsMulti(t *testing.T, did string, txHashes ...string) map[string][]vtuLog {
	t.Helper()
	var upstream []map[string]any
	for _, h := range txHashes {
		for i, l := range f.txLogs[h] {
			upstream = append(upstream, f.upstreamLog(h, i, l))
		}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": upstream})
	require.NoError(t, err)
	out := f.proc.applyResponseFilter(context.Background(),
		&ProcessRequest{UserID: did, Method: rbac.MethodGetLogs, Body: body}, f.accessResult(did), body)
	var resp struct {
		Result []json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	got := map[string][]vtuLog{}
	for _, raw := range resp.Result {
		var m struct {
			TxHash string `json:"transactionHash"`
		}
		require.NoError(t, json.Unmarshal(raw, &m))
		got[strings.ToLower(m.TxHash)] = append(got[strings.ToLower(m.TxHash)], parseRPCLogs(t, json.RawMessage("["+string(raw)+"]"))...)
	}
	return got
}

// requireReceiptEnvelope asserts whether eth_getTransactionReceipt returns a
// non-null envelope (the envelope rules are independent of the unlock).
func (f *vtuFixture) requireReceiptEnvelope(t *testing.T, did, txHash string, want bool, msg string) {
	t.Helper()
	_, ok := f.rpcReceiptLogs(t, did, txHash)
	assert.Equalf(t, want, ok, "receipt envelope: %s", msg)
}

// rpcGetLogs returns the logs of txHash the viewer receives from eth_getLogs.
func (f *vtuFixture) rpcGetLogs(t *testing.T, did, txHash string) []vtuLog {
	t.Helper()
	var upstream []map[string]any
	for i, l := range f.txLogs[txHash] {
		upstream = append(upstream, f.upstreamLog(txHash, i, l))
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": upstream})
	require.NoError(t, err)
	out := f.proc.applyResponseFilter(context.Background(),
		&ProcessRequest{UserID: did, Method: rbac.MethodGetLogs, Body: body}, f.accessResult(did), body)
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	return parseRPCLogs(t, resp.Result)
}

// rpcReceiptLogs returns (logs, envelopeReturned) from eth_getTransactionReceipt.
func (f *vtuFixture) rpcReceiptLogs(t *testing.T, did, txHash string) ([]vtuLog, bool) {
	t.Helper()
	var upstream []map[string]any
	for i, l := range f.txLogs[txHash] {
		upstream = append(upstream, f.upstreamLog(txHash, i, l))
	}
	receipt := map[string]any{
		"transactionHash": txHash, "from": f.txFrom[txHash], "to": f.txTo[txHash],
		"status": "0x1", "logs": upstream, "logsBloom": "0x" + strings.Repeat("0", 512),
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": receipt})
	require.NoError(t, err)
	out := f.proc.applyResponseFilter(context.Background(),
		&ProcessRequest{UserID: did, Method: rbac.MethodGetTransactionReceipt, Body: body}, f.accessResult(did), body)
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	if len(resp.Result) == 0 || string(resp.Result) == "null" {
		return nil, false
	}
	var r struct {
		Logs json.RawMessage `json:"logs"`
	}
	require.NoError(t, json.Unmarshal(resp.Result, &r))
	return parseRPCLogs(t, r.Logs), true
}

// explorerLogs returns the logs of txHash from GET /transactions/:hash/logs.
func (f *vtuFixture) explorerLogs(t *testing.T, did, txHash string) []vtuLog {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer/transactions/"+txHash+"/logs", nil)
	if did != "" {
		req.Header.Set("Authorization", "Bearer "+issueTestJWT(t, f.srv, did))
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var logs []explorer.Log
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &logs))
	out := make([]vtuLog, 0, len(logs))
	for _, l := range logs {
		v := vtuLog{Address: l.Address, Data: l.Data}
		for _, tp := range []*string{l.Topic0, l.Topic1, l.Topic2, l.Topic3} {
			if tp != nil {
				v.Topics = append(v.Topics, *tp)
			}
		}
		out = append(out, v.norm())
	}
	return out
}

// requireSurfaces asserts that eth_getLogs, the receipt's logs and the explorer
// return EXACTLY want (order-preserving) for (viewer, tx). Each surface is
// checked independently so a divergence reports which layer drifted.
func (f *vtuFixture) requireSurfaces(t *testing.T, did, txHash string, want []vtuLog, msg string) {
	t.Helper()
	normWant := make([]vtuLog, 0, len(want))
	for _, w := range want {
		normWant = append(normWant, w.norm())
	}
	assert.Equalf(t, normWant, f.rpcGetLogs(t, did, txHash), "eth_getLogs: %s", msg)
	rl, ok := f.rpcReceiptLogs(t, did, txHash)
	if ok {
		assert.Equalf(t, normWant, rl, "eth_getTransactionReceipt logs: %s", msg)
	} else {
		assert.Emptyf(t, normWant, "eth_getTransactionReceipt returned null but logs were expected: %s", msg)
	}
	assert.Equalf(t, normWant, f.explorerLogs(t, did, txHash), "explorer /transactions/:hash/logs: %s", msg)
}

func TestVisibleToUnlockFullPayload_CrossLayer_RD1300(t *testing.T) {
	ctx := context.Background()
	f := newVTUFixture(t)

	// ---- Organisation + contracts ------------------------------------
	f.orgID = uuid.New().String()
	require.NoError(t, f.db.CreateOrganization(ctx, &rbac.Organization{ID: f.orgID, Slug: "vtu-owner", Name: "Owner", Settings: map[string]any{}}))
	f.paymentCID = wiringCreateContractWithABI(t, f.db, f.orgID, f.payment, "Payments", paymentCreatedABIRD1300)
	ledgerCID := wiringCreateContractWithABI(t, f.db, f.orgID, f.ledger, "Ledger", erc20ABI)
	auditCID := wiringCreateContractWithABI(t, f.db, f.orgID, f.audit, "Audit", erc20ABI)
	// Dynamic identifier: operator attests the payload so the ORDINARY path can
	// admit (and mask) the event; the M15-drop variant is exercised below.
	require.NoError(t, f.db.UpdateContractEventsAllowDynamicPayload(ctx, f.paymentCID, true))
	require.NoError(t, f.db.UpdateContractAllowVisibleToUnlock(ctx, auditCID, true)) // flagged, but recipient has no grant on it

	paymentCreated := "0x" + topicHex("PaymentCreated(address,address,address,string)")
	transfer := "0x" + topicHex("Transfer(address,address,uint256)")
	approval := "0x" + topicHex("Approval(address,address,uint256)")

	// Settlement recipient's group: PaymentCreated allowlisted only when the
	// viewer is the payer (must_be=self), wildcard on Ledger, nothing on Audit.
	recipientGID := wiringCreateGroup(t, f.db, f.orgID, "settlement", nil, false)
	wiringCreateGrant(t, f.db, f.paymentCID, recipientGID, &rbac.EventRulesField{Rules: []rbac.EventRule{{
		Topic0: paymentCreated, Name: "PaymentCreated", ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
	}}})
	wiringCreateGrant(t, f.db, ledgerCID, recipientGID, &rbac.EventRulesField{Wildcard: true})
	// A second eligible grant holder whose PaymentCreated rules are deny-all.
	denyGID := wiringCreateGroup(t, f.db, f.orgID, "settlement-deny", nil, false)
	wiringCreateGrant(t, f.db, f.paymentCID, denyGID, &rbac.EventRulesField{})

	const (
		recipient  = "did:test:vtu:recipient"
		recipient2 = "did:test:vtu:recipient2"
		bystander  = "did:test:vtu:bystander"
		noGroup    = "did:test:vtu:nogroup"
		crossOrg   = "did:test:vtu:crossorg"
	)
	recipientAddr := "0x" + strings.Repeat("d4", 20)
	recipient2Addr := "0x" + strings.Repeat("e5", 20)
	f.user(recipient, recipientGID, recipientAddr)
	f.user(recipient2, denyGID, recipient2Addr)
	f.user(bystander, recipientGID, "0x"+strings.Repeat("f6", 20))
	f.user(noGroup, "", "")
	f.user("did:test:vtu:payer", "", f.payer)
	f.user("did:test:vtu:payee", "", f.payee)
	f.user("did:test:vtu:intermediary", "", f.intermedAdr)

	otherOrg := uuid.New().String()
	require.NoError(t, f.db.CreateOrganization(ctx, &rbac.Organization{ID: otherOrg, Slug: "vtu-other", Name: "Other", Settings: map[string]any{}}))
	otherGID := wiringCreateGroup(t, f.db, otherOrg, "other", nil, false)
	otherCID := wiringCreateContractWithABI(t, f.db, otherOrg, "0x2000000000000000000000000000000000000001", "OtherPayments", paymentCreatedABIRD1300)
	wiringCreateGrant(t, f.db, otherCID, otherGID, &rbac.EventRulesField{Wildcard: true})
	f.user(crossOrg, otherGID, "")

	// ---- Chain data ---------------------------------------------------
	paymentData := vtuPackPaymentData(t, f.intermedAdr, "PAY-0001")
	paymentLog := vtuLog{Address: f.payment, Topics: []string{paymentCreated, zeroPadAddrToTopic(f.payer), zeroPadAddrToTopic(f.payee)}, Data: paymentData}
	ledgerLog := vtuLog{Address: f.ledger, Topics: []string{transfer, zeroPadAddrToTopic(f.payer), zeroPadAddrToTopic(f.payee)}, Data: "0x" + strings.Repeat("0", 62) + "64"}
	auditLog := vtuLog{Address: f.audit, Topics: []string{approval, zeroPadAddrToTopic(f.payer), zeroPadAddrToTopic(f.payee)}, Data: "0x" + strings.Repeat("0", 62) + "01"}

	maskedPayment := vtuLog{Address: f.payment, Topics: []string{paymentCreated, zeroTopic, zeroTopic}, Data: vtuPackPaymentData(t, "0x0000000000000000000000000000000000000000", "PAY-0001")}
	maskedLedger := vtuLog{Address: f.ledger, Topics: []string{transfer, zeroTopic, zeroTopic}, Data: ledgerLog.Data}

	tx1 := "0x" + strings.Repeat("11", 32) // listed
	tx2 := "0x" + strings.Repeat("22", 32) // later tx, not listed
	tx3 := "0x" + strings.Repeat("33", 32) // later tx, not listed; recipient2 is a token-transfer party
	tx4 := "0x" + strings.Repeat("34", 32) // later tx, not listed; the flagged contract itself is a token-transfer party
	f.seedTx(tx1, f.payer, f.payment, []vtuLog{paymentLog, ledgerLog, auditLog})
	f.seedTx(tx2, f.payer, f.payment, []vtuLog{paymentLog})
	f.seedTx(tx3, f.payer, f.payment, []vtuLog{paymentLog})
	f.seedTx(tx4, f.payer, f.payment, []vtuLog{paymentLog})
	for _, tt := range []struct{ tx, from, to string }{
		{tx3, f.payer, recipient2Addr}, // viewer's own address → Full → RD-1009 union
		{tx4, f.payment, f.payee},      // granted contract → Full for every grant holder → RD-1009 union
	} {
		_, err := f.db.Conn().ExecContext(ctx,
			`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
			 VALUES ($1, 9, $2, $3, $4, 1, 1)`, tt.tx, f.ledger, tt.from, tt.to)
		require.NoError(t, err)
	}
	require.NoError(t, f.db.SaveTxVisibility(ctx, tx1,
		[]string{recipient, recipient2, noGroup, crossOrg}, "did:test:vtu:payer", f.orgID))

	setUnlock := func(t *testing.T, on bool) {
		t.Helper()
		require.NoError(t, f.db.UpdateContractAllowVisibleToUnlock(ctx, f.paymentCID, on))
		f.srv.rbacAccessCtrl.InvalidateOrg(ctx, f.orgID)
	}

	// ---- Flag OFF: ordinary path (unchanged by RD-1300) ---------------
	setUnlock(t, false)
	t.Run("flag off: ordinary visibleTo fallback admits PaymentCreated with every hidden address masked", func(t *testing.T) {
		f.requireSurfaces(t, recipient, tx1, []vtuLog{maskedPayment, maskedLedger},
			"allowlisted topic0 + listed → admitted, payer/payee topics and embedded intermediary zeroed; Audit dropped (no grant)")
	})
	t.Run("flag off: deny-all grant holder sees nothing from Payments", func(t *testing.T) {
		f.requireSurfaces(t, recipient2, tx1, nil, "deny-all rules, no unlock")
	})
	t.Run("flag off: a transfer-party tx is not a listing for the param-rule fallback", func(t *testing.T) {
		f.requireSurfaces(t, recipient, tx4, nil, "the flagged contract is a transfer party in tx4, but no one listed the recipient; must_be=self fails")
	})

	// ---- Flag ON --------------------------------------------------------
	setUnlock(t, true)
	t.Run("flag on: eligible listed recipient gets the exact payload on every surface", func(t *testing.T) {
		f.requireSurfaces(t, recipient, tx1, []vtuLog{paymentLog, maskedLedger},
			"Payments log unlocked → exact payer/payee topics and intermediary bytes; Ledger (not flagged) keeps ordinary masking; Audit (flagged, no grant) dropped")
	})
	t.Run("flag on: deny-all grant holder listed gets the exact payload", func(t *testing.T) {
		f.requireSurfaces(t, recipient2, tx1, []vtuLog{paymentLog}, "unlock bypasses deny-all event rules and masking")
	})
	t.Run("flag on: a later tx without its own visibleTo stays on the ordinary path", func(t *testing.T) {
		f.requireSurfaces(t, recipient, tx2, nil, "tx2 not listed: must_be=self fails, no fallback")
		f.requireSurfaces(t, recipient2, tx2, nil, "tx2 not listed: deny-all")
	})
	t.Run("flag on: a token-transfer party of a later tx is not 'listed' (RD-1009 union must not trigger the unlock)", func(t *testing.T) {
		f.requireSurfaces(t, recipient2, tx3, nil, "tx3 not in tx_visible_to; deny-all rules must stand")
	})
	t.Run("flag on: the flagged contract being a token-transfer party does not unlock unlisted txs", func(t *testing.T) {
		f.requireSurfaces(t, recipient2, tx4, nil, "tx4 not in tx_visible_to; the granted contract is Full for the viewer, which feeds the RD-1009 union")
	})
	t.Run("flag on: the ordinary param-rule fallback also needs a genuine listing", func(t *testing.T) {
		f.requireSurfaces(t, recipient, tx3, nil, "tx3 not listed (recipient2 is the transfer party); must_be=self fails")
		f.requireSurfaces(t, recipient, tx4, nil, "tx4 not listed; the flagged contract being a transfer party is not a listing; must_be=self fails")
	})
	t.Run("flag on: one eth_getLogs response spanning listed and unlisted txs unlocks only the listed tx", func(t *testing.T) {
		got := f.rpcGetLogsMulti(t, recipient2, tx1, tx2, tx3, tx4)
		assert.Equal(t, map[string][]vtuLog{tx1: {paymentLog.norm()}}, got, "deny-all holder: only tx1's Payments log, exact")
		got = f.rpcGetLogsMulti(t, recipient, tx1, tx2, tx3, tx4)
		assert.Equal(t, map[string][]vtuLog{tx1: {paymentLog.norm(), maskedLedger.norm()}}, got, "allowlist holder: tx1 exact Payments + masked Ledger; nothing from unlisted txs")
	})
	t.Run("receipt envelope is independent of the unlock", func(t *testing.T) {
		f.requireReceiptEnvelope(t, recipient2, tx1, true, "listed")
		f.requireReceiptEnvelope(t, noGroup, tx1, true, "listed, no group: envelope shared, logs filtered")
		f.requireReceiptEnvelope(t, crossOrg, tx1, true, "listed, cross-org: envelope shared, logs filtered")
		f.requireReceiptEnvelope(t, recipient2, tx3, false, "not listed, not a participant, no entitled log")
		f.requireReceiptEnvelope(t, "", tx1, false, "anonymous")
	})
	t.Run("flag on: eligible but not listed", func(t *testing.T) {
		f.requireSurfaces(t, bystander, tx1, []vtuLog{maskedLedger},
			"bystander not in visibleTo: must_be=self fails on Payments; the wildcard Ledger grant still admits (masked)")
	})
	t.Run("flag on: listed but ineligible viewers", func(t *testing.T) {
		f.requireSurfaces(t, noGroup, tx1, nil, "no group")
		f.requireSurfaces(t, crossOrg, tx1, nil, "grant only in another org")
		f.requireSurfaces(t, "", tx1, nil, "anonymous")
	})

	// ---- Dynamic identifier without the operator attestation (M15) ------
	require.NoError(t, f.db.UpdateContractEventsAllowDynamicPayload(ctx, f.paymentCID, false))
	f.srv.rbacAccessCtrl.InvalidateOrg(ctx, f.orgID)
	t.Run("M15 gate: unlock bypasses the dynamic-payload drop, flag off drops it", func(t *testing.T) {
		setUnlock(t, true)
		f.requireSurfaces(t, recipient, tx1, []vtuLog{paymentLog, maskedLedger}, "unlock resolves before the M15 gate (RD-874)")
		setUnlock(t, false)
		f.requireSurfaces(t, recipient, tx1, []vtuLog{maskedLedger}, "ordinary path: dynamic non-indexed payload without attestation → dropped")
	})
	require.NoError(t, f.db.UpdateContractEventsAllowDynamicPayload(ctx, f.paymentCID, true))
	setUnlock(t, true)

	// ---- Revocations take effect on the next read -----------------------
	t.Run("flag on: grant revoked → no unlock", func(t *testing.T) {
		g, err := f.db.GetContractGrantByContractAndGroup(ctx, f.paymentCID, denyGID)
		require.NoError(t, err)
		require.NotNil(t, g)
		require.NoError(t, f.db.DeleteContractGrant(ctx, g.ID))
		f.srv.rbacAccessCtrl.InvalidateOrg(ctx, f.orgID)
		f.requireSurfaces(t, recipient2, tx1, nil, "grant on Payments deleted")
	})
	t.Run("flag on: membership revoked → no unlock", func(t *testing.T) {
		ms, err := f.db.ListUserMembershipsWithDetails(ctx, f.users[recipient])
		require.NoError(t, err)
		for _, m := range ms {
			require.NoError(t, f.db.DeleteMembership(ctx, m.Membership.ID))
		}
		f.srv.rbacAccessCtrl.InvalidateOrg(ctx, f.orgID)
		f.requireSurfaces(t, recipient, tx1, nil, "recipient removed from its only group")
	})
}

// TestVisibleToUnlockFullPayload_NoABI_RD1300: the unlock also bypasses the
// deny-when-no-ABI gate (RD-874). Without an ABI the ordinary path would drop
// the log; unlocked, both layers must return it byte-for-byte.
func TestVisibleToUnlockFullPayload_NoABI_RD1300(t *testing.T) {
	ctx := context.Background()
	f := newVTUFixture(t)
	f.orgID = uuid.New().String()
	require.NoError(t, f.db.CreateOrganization(ctx, &rbac.Organization{ID: f.orgID, Slug: "vtu-noabi", Name: "NoABI", Settings: map[string]any{}}))
	cid := wiringCreateContract(t, f.db, f.orgID, f.payment, "NoABI")
	require.NoError(t, f.db.UpdateContractAllowVisibleToUnlock(ctx, cid, true))
	gid := wiringCreateGroup(t, f.db, f.orgID, "grantees", nil, false)
	wiringCreateGrant(t, f.db, cid, gid, &rbac.EventRulesField{})
	const recipient = "did:test:vtu:noabi-recipient"
	f.user(recipient, gid, "0x"+strings.Repeat("d4", 20))
	f.user("did:test:vtu:noabi-payer", "", f.payer)

	sig := "0x" + topicHex("Opaque(address,address)")
	raw := vtuLog{Address: f.payment, Topics: []string{sig, zeroPadAddrToTopic(f.payer), zeroPadAddrToTopic(f.payee)}, Data: "0x" + strings.Repeat("0", 24) + strings.Repeat("c3", 20)}
	tx := "0x" + strings.Repeat("44", 32)
	f.seedTx(tx, f.payer, f.payment, []vtuLog{raw})
	require.NoError(t, f.db.SaveTxVisibility(ctx, tx, []string{recipient}, "did:test:vtu:noabi-payer", f.orgID))

	f.requireSurfaces(t, recipient, tx, []vtuLog{raw}, "unlocked, no ABI: exact topics and data")

	unlisted := "0x" + strings.Repeat("45", 32)
	f.seedTx(unlisted, f.payer, f.payment, []vtuLog{raw})
	f.requireSurfaces(t, recipient, unlisted, nil, "no ABI, not listed: deny-when-no-ABI drops the log")

	require.NoError(t, f.db.UpdateContractAllowVisibleToUnlock(ctx, cid, false))
	f.srv.rbacAccessCtrl.InvalidateOrg(ctx, f.orgID)
	f.requireSurfaces(t, recipient, tx, nil, "no ABI, flag off: deny-when-no-ABI drops the log")
}

// TestVisibleToUnlockEligibility_OrgAdmin_RD1300 characterises the CURRENT
// eligibility of an org admin (effective access to every org contract without
// a contract_grant row). It does NOT assert that this is the intended policy —
// see the RD-1300 report. It asserts that whatever the helper decides, every
// surface renders the same payload.
func TestVisibleToUnlockEligibility_OrgAdmin_RD1300(t *testing.T) {
	ctx := context.Background()
	f := newVTUFixture(t)
	f.orgID = uuid.New().String()
	require.NoError(t, f.db.CreateOrganization(ctx, &rbac.Organization{ID: f.orgID, Slug: "vtu-admin", Name: "Admin", Settings: map[string]any{}}))
	cid := wiringCreateContractWithABI(t, f.db, f.orgID, f.payment, "Payments", paymentCreatedABIRD1300)
	require.NoError(t, f.db.UpdateContractEventsAllowDynamicPayload(ctx, cid, true))
	require.NoError(t, f.db.UpdateContractAllowVisibleToUnlock(ctx, cid, true))
	adminGID := wiringCreateGroup(t, f.db, f.orgID, "admins", nil, true)
	const admin = "did:test:vtu:orgadmin"
	f.user(admin, adminGID, "0x"+strings.Repeat("d4", 20))
	f.user("did:test:vtu:oa-payer", "", f.payer)
	f.user("did:test:vtu:oa-payee", "", f.payee)
	f.user("did:test:vtu:oa-intermediary", "", f.intermedAdr)

	paymentCreated := "0x" + topicHex("PaymentCreated(address,address,address,string)")
	raw := vtuLog{Address: f.payment, Topics: []string{paymentCreated, zeroPadAddrToTopic(f.payer), zeroPadAddrToTopic(f.payee)}, Data: vtuPackPaymentData(t, f.intermedAdr, "PAY-0002")}
	masked := vtuLog{Address: f.payment, Topics: []string{paymentCreated, zeroTopic, zeroTopic}, Data: vtuPackPaymentData(t, "0x0000000000000000000000000000000000000000", "PAY-0002")}
	listed := "0x" + strings.Repeat("55", 32)
	unlisted := "0x" + strings.Repeat("66", 32)
	f.seedTx(listed, f.payer, f.payment, []vtuLog{raw})
	f.seedTx(unlisted, f.payer, f.payment, []vtuLog{raw})
	require.NoError(t, f.db.SaveTxVisibility(ctx, listed, []string{admin}, "did:test:vtu:oa-payer", f.orgID))

	require.True(t, rbac.IsViewerEligibleForVisibleToUnlock(ctx, f.srv.rbacAccessCtrl, admin, f.payment),
		"CURRENT behaviour: org-admin effective access makes the admin unlock-eligible without a contract_grant")
	f.requireSurfaces(t, admin, listed, []vtuLog{raw}, "org admin listed on a flagged contract: unlock applies on every surface")
	f.requireSurfaces(t, admin, unlisted, []vtuLog{masked}, "org admin, not listed: admin bypass admits, ordinary masking of user EOAs")

	// Any org contract is Full for an org admin, so a token transfer touching
	// one feeds the explorer's RD-1009 union. That must not count as a listing.
	unlistedUnion := "0x" + strings.Repeat("67", 32)
	f.seedTx(unlistedUnion, f.payer, f.payment, []vtuLog{raw})
	_, err := f.db.Conn().ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 9, $2, $3, $4, 1, 1)`, unlistedUnion, f.payment, f.payment, f.payee)
	require.NoError(t, err)
	f.requireSurfaces(t, admin, unlistedUnion, []vtuLog{masked},
		"org admin, not listed, org contract is a token-transfer party: user EOAs stay masked")

}
