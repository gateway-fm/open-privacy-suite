package server

import (
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// Full WorkflowCore-shaped fixture: one capture writer, a reader, an event, and a
// tx method — all keyed by the same string record id (msgId, non-indexed in the
// event). No Partior specifics.
const crossABI = `[
  {"type":"function","name":"initiatePayment","stateMutability":"nonpayable",
   "inputs":[{"name":"msgId","type":"string"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"processPayment","stateMutability":"nonpayable",
   "inputs":[{"name":"msgId","type":"string"},{"name":"status","type":"uint8"}],"outputs":[]},
  {"type":"function","name":"getPaymentInfo","stateMutability":"view",
   "inputs":[{"name":"msgId","type":"string"}],"outputs":[{"name":"payer","type":"address"}]},
  {"type":"event","name":"PaymentProcessed",
   "inputs":[{"name":"msgId","type":"string","indexed":false},{"name":"status","type":"uint8","indexed":false}]}
]`

// One policy links the audience captured on initiatePayment to the reader, the
// event, and the tx — the "save parties on the initial call, match on later
// events / getPaymentInfo" model.
const crossPolicy = `{"records":{"payment":{
  "capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
    "remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
  "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
    "allow":[{"callerIn":["audience"]}],"onNoRecord":"deny","else":"deny"}],
  "events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},
    "allow":[{"callerIn":["audience"]}]}],
  "transactions":[{"method":"processPayment(string,uint8)","key":{"source":"param","index":0},
    "allow":[{"callerIn":["audience"]}]}]
}}}`

// TestRecordAudience_OneCaptureGatesEventTxAndReader proves rules 71 + 72 + the
// reader are all driven by a SINGLE captured audience, against a REAL Postgres
// capture store (outbox → promote, the same path the settle-time capture writes).
// A submits initiatePayment(PAY-1) with visibleTo=[alice,bob,carol]; the policy
// then admits exactly those three on the PaymentProcessed(PAY-1) event, the
// processPayment(PAY-1) tx, and getPaymentInfo(PAY-1) — while dave (same coarse
// eligibility, NOT in the audience) is denied all three from the one record.
func TestRecordAudience_OneCaptureGatesEventTxAndReader(t *testing.T) {
	ctx := context.Background()
	dbURL := sharedTestDBURL(t)
	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "cross-test", Name: "CrossTest", Settings: map[string]any{},
	}))
	const addr = "0x6666666666666666666666666666666666666666"
	cid := wiringCreateContractWithABI(t, database, orgID, addr, "WorkflowCore", crossABI)
	require.NoError(t, database.UpdateContractMethodPolicies(ctx, cid, []byte(crossPolicy)))

	// initiatePayment(PAY-1) captured audience = {alice, bob, carol} via the real
	// outbox → promote path (identical storage to the settle-time capture writer).
	writes := []rbac.CapturedWrite{
		{RecordType: "payment", RecordKey: "PAY-1", Field: "audience", Value: "did:test:alice", Merge: "union"},
		{RecordType: "payment", RecordKey: "PAY-1", Field: "audience", Value: "did:test:bob", Merge: "union"},
		{RecordType: "payment", RecordKey: "PAY-1", Field: "audience", Value: "did:test:carol", Merge: "union"},
	}
	require.NoError(t, database.EnqueuePendingRecordCaptures(ctx, "0xseedtx", orgID, addr, "did:test:alice", writes))
	pending, err := database.ListDuePendingRecordCaptures(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, database.PromoteRecordCapture(ctx, pending[0]))

	parsed, err := abi.JSON(strings.NewReader(crossABI))
	require.NoError(t, err)
	doc, err := rbac.ParseMethodPolicyDocument([]byte(crossPolicy))
	require.NoError(t, err)

	// The real DB-backed gate (store + capture capability = *db.DB).
	gateFor := func(did string) *recordAudienceGate { return newRecordAudienceGate(ctx, database, database, did, nil) }

	// Build the governed subjects for PAY-1.
	ev := parsed.Events["PaymentProcessed"]
	evData, err := ev.Inputs.NonIndexed().Pack("PAY-1", uint8(1))
	require.NoError(t, err)
	evTopics := []string{ev.ID.Hex()}
	evDataHex := "0x" + common.Bytes2Hex(evData)

	txCalldataP1, err := parsed.Pack("processPayment", "PAY-1", uint8(1))
	require.NoError(t, err)
	txInputP1 := "0x" + common.Bytes2Hex(txCalldataP1)

	readCalldataP1, err := parsed.Pack("getPaymentInfo", "PAY-1")
	require.NoError(t, err)
	// A different, un-captured record — every subject for PAY-2 must be denied
	// (parameter-bound: PAY-1's audience grants nothing for PAY-2).
	readCalldataP2, err := parsed.Pack("getPaymentInfo", "PAY-2")
	require.NoError(t, err)

	loadCaptures := func(recordType, recordKey string) ([]rbac.CapturedField, error) {
		return database.GetRecordCaptures(ctx, orgID, addr, recordType, recordKey)
	}
	noReturn := func() ([]common.Address, error) { return nil, nil }

	type want struct {
		did          string
		event, tx    bool // rule 71 / rule 72
		readerAllows bool // reader (getPaymentInfo(PAY-1))
	}
	cases := []want{
		{"did:test:alice", true, true, true},   // captured audience
		{"did:test:bob", true, true, true},     // captured audience
		{"did:test:carol", true, true, true},   // captured audience
		{"did:test:dave", false, false, false}, // NOT in PAY-1's audience
		{"did:test:eve", false, false, false},  // unrelated
	}
	for _, c := range cases {
		t.Run(c.did, func(t *testing.T) {
			g := gateFor(c.did)
			if got := g.EventLogAdmits(addr, crossABI, evTopics, evDataHex); got != c.event {
				t.Fatalf("rule 71 (PaymentProcessed PAY-1): EventLogAdmits=%v want %v", got, c.event)
			}
			if got := g.TxInputAdmits(addr, crossABI, txInputP1); got != c.tx {
				t.Fatalf("rule 72 (processPayment PAY-1): TxInputAdmits=%v want %v", got, c.tx)
			}
			// reader gate (rule 70) fed by the SAME capture:
			_, dec, derr := doc.EvaluateReader(readCalldataP1, rbac.NewCallerIdentity(c.did, nil), loadCaptures, noReturn, parsed)
			require.NoError(t, derr)
			if dec.Allow != c.readerAllows {
				t.Fatalf("reader getPaymentInfo(PAY-1): Allow=%v want %v", dec.Allow, c.readerAllows)
			}
		})
	}

	// Parameter-bound: even a PAY-1 audience member is denied PAY-2 on every
	// subject (nothing captured for PAY-2).
	t.Run("parameter-bound: alice denied for a different record (PAY-2)", func(t *testing.T) {
		g := gateFor("did:test:alice")
		evData2, err := ev.Inputs.NonIndexed().Pack("PAY-2", uint8(1))
		require.NoError(t, err)
		if g.EventLogAdmits(addr, crossABI, evTopics, "0x"+common.Bytes2Hex(evData2)) {
			t.Fatal("PAY-1 audience must not see a PAY-2 event")
		}
		_, dec, derr := doc.EvaluateReader(readCalldataP2, rbac.NewCallerIdentity("did:test:alice", nil), loadCaptures, noReturn, parsed)
		require.NoError(t, derr)
		if dec.Allow {
			t.Fatal("PAY-1 audience must not read getPaymentInfo(PAY-2)")
		}
	})
}
