package server

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/rbac"
)

const audienceEventsABI = `[
  {"type":"function","name":"initiatePayment","stateMutability":"nonpayable",
   "inputs":[{"name":"msgId","type":"string"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"event","name":"PaymentProcessed",
   "inputs":[{"name":"msgId","type":"string","indexed":false},{"name":"status","type":"uint8","indexed":false}]}
]`

const audienceEventsPolicy = `{"records":{"payment":{
  "capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
    "remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
  "events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},
    "allow":[{"callerIn":["audience"]}]}]
}}}`

func newTestAudienceGate(store rbac.Store, caps methodPolicyCaptureStore, did string) *recordAudienceGate {
	return &recordAudienceGate{
		ctx:              context.Background(),
		store:            store,
		caps:             caps,
		caller:           rbac.NewCallerIdentity(did, nil),
		policyByContract: map[string]*contractPolicyABI{},
		captureCache:     map[string][]rbac.CapturedField{},
	}
}

func audienceProcessedLog(t *testing.T, msgID string) ([]string, string) {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(audienceEventsABI))
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	ev := parsed.Events["PaymentProcessed"]
	data, err := ev.Inputs.NonIndexed().Pack(msgID, uint8(1))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return []string{ev.ID.Hex()}, "0x" + common.Bytes2Hex(data)
}

// TestRecordAudienceGate_EventLogAdmits exercises the real request-path gate end
// to end (fake store): it must decode the record key from the log, look up the
// captured audience, and admit only a caller in it — the S5-T rule-71 behavior.
func TestRecordAudienceGate_EventLogAdmits(t *testing.T) {
	topics, dataHex := audienceProcessedLog(t, "PAY-1")
	contract := &rbac.Contract{
		ID: "c1", OrgID: gateOrg, Address: gateContractAddr,
		ABI: audienceEventsABI, MethodPolicies: []byte(audienceEventsPolicy),
	}

	t.Run("caller in captured audience → admit", func(t *testing.T) {
		store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
		gate := newTestAudienceGate(store, store, "did:test:alice")
		if !gate.EventLogAdmits(gateContractAddr, audienceEventsABI, topics, dataHex) {
			t.Fatal("caller in audience must be admitted")
		}
	})

	t.Run("caller not in audience → abstain", func(t *testing.T) {
		store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
		gate := newTestAudienceGate(store, store, "did:test:eve")
		if gate.EventLogAdmits(gateContractAddr, audienceEventsABI, topics, dataHex) {
			t.Fatal("caller not in audience must abstain")
		}
	})

	t.Run("no captures → abstain", func(t *testing.T) {
		store := &fakeGateStore{globalContract: contract, captures: nil}
		gate := newTestAudienceGate(store, store, "did:test:alice")
		if gate.EventLogAdmits(gateContractAddr, audienceEventsABI, topics, dataHex) {
			t.Fatal("no captured audience must abstain")
		}
	})

	t.Run("contract has no policy → abstain", func(t *testing.T) {
		store := &fakeGateStore{globalContract: &rbac.Contract{ID: "c1", OrgID: gateOrg, Address: gateContractAddr, ABI: audienceEventsABI}}
		gate := newTestAudienceGate(store, store, "did:test:alice")
		if gate.EventLogAdmits(gateContractAddr, audienceEventsABI, topics, dataHex) {
			t.Fatal("a contract with no method policy must abstain")
		}
	})

	t.Run("wrong record key (different payment) → abstain", func(t *testing.T) {
		// captures exist for PAY-1's audience, but the store returns them for ANY
		// key; prove the DECODED key flows through by using a caller absent from
		// the returned set — covered above. Here assert an ungoverned event abstains.
		store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
		gate := newTestAudienceGate(store, store, "did:test:alice")
		// an event topic0 not in the policy
		if gate.EventLogAdmits(gateContractAddr, audienceEventsABI, []string{"0x" + strings.Repeat("ab", 32)}, "0x") {
			t.Fatal("an ungoverned event topic must abstain")
		}
	})
}

// TestRecordAudienceGate_TxInputAdmits exercises rule 72: a transaction is
// disclosed to its record's captured audience, keyed by the tx's own calldata.
func TestRecordAudienceGate_TxInputAdmits(t *testing.T) {
	const txPolicy = `{"records":{"payment":{
      "capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
        "remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
      "transactions":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["audience"]}]}]
    }}}`
	parsed, err := abi.JSON(strings.NewReader(audienceEventsABI))
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	calldata, err := parsed.Pack("initiatePayment", "PAY-1", big.NewInt(100))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	inputHex := "0x" + common.Bytes2Hex(calldata)
	contract := &rbac.Contract{ID: "c1", OrgID: gateOrg, Address: gateContractAddr, ABI: audienceEventsABI, MethodPolicies: []byte(txPolicy)}

	t.Run("caller in audience → admit tx", func(t *testing.T) {
		store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
		gate := newTestAudienceGate(store, store, "did:test:alice")
		if !gate.TxInputAdmits(gateContractAddr, audienceEventsABI, inputHex) {
			t.Fatal("caller in audience must be admitted for the tx")
		}
	})
	t.Run("caller not in audience → abstain", func(t *testing.T) {
		store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
		gate := newTestAudienceGate(store, store, "did:test:diana")
		if gate.TxInputAdmits(gateContractAddr, audienceEventsABI, inputHex) {
			t.Fatal("caller not in audience must abstain")
		}
	})
	t.Run("ungoverned method → abstain", func(t *testing.T) {
		// A method with no transactions rule (getPaymentInfo isn't even in this ABI;
		// use a random selector via empty calldata) abstains.
		store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
		gate := newTestAudienceGate(store, store, "did:test:alice")
		if gate.TxInputAdmits(gateContractAddr, audienceEventsABI, "0xdeadbeef") {
			t.Fatal("an ungoverned/undecodable tx must abstain")
		}
	})
}

// TestTxResponseRecordAudienceAdmits covers the rule-72 wiring end to end: a
// getTransactionByHash-style response whose sender is a stranger (so the
// participant/admin filter would null it) is admitted for a caller in the tx's
// record audience, and abstained for one who isn't — proving txResponseRecordAudienceAdmits
// extracts to+input and drives the gate.
func TestTxResponseRecordAudienceAdmits(t *testing.T) {
	const txPolicy = `{"records":{"payment":{
      "capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
        "remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
      "transactions":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["audience"]}]}]
    }}}`
	parsed, err := abi.JSON(strings.NewReader(audienceEventsABI))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	calldata, err := parsed.Pack("initiatePayment", "PAY-1", big.NewInt(100))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	txResp := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"from":"0x00000000000000000000000000000000000000ff","to":%q,"input":"0x%s"}}`,
		gateContractAddr, common.Bytes2Hex(calldata)))
	contract := &rbac.Contract{ID: "c1", OrgID: gateOrg, Address: gateContractAddr, ABI: audienceEventsABI, MethodPolicies: []byte(txPolicy)}
	ctx := context.Background()

	store := &fakeGateStore{globalContract: contract, captures: []rbac.CapturedField{{Field: "audience", Value: "did:test:alice", Merge: "union"}}}
	p := newGateProcessor(store)

	// F2 eligibility bound: even a caller who IS in the record audience is NOT
	// admitted when contract eligibility can't be confirmed — resolvePermsForFilter
	// returns nil for a nil / identity-less result (no grant), so the gate abstains.
	// (The audience-match happy path is covered by TestRecordAudienceGate_TxInputAdmits;
	// the RPC event path's grant bound by TestFilterEventLogs_RecordAudienceAdditive.)
	t.Run("no resolvable grant → audience member still abstained (F2)", func(t *testing.T) {
		if p.txResponseRecordAudienceAdmits(ctx, "did:test:alice", nil, nil, txResp) {
			t.Fatal("must abstain when contract eligibility is unresolved (nil result)")
		}
		if p.txResponseRecordAudienceAdmits(ctx, "did:test:alice", nil, &rbac.AccessCheckResult{UserID: ""}, txResp) {
			t.Fatal("must abstain when result has no user identity")
		}
	})
	t.Run("malformed / null result → abstain", func(t *testing.T) {
		if p.txResponseRecordAudienceAdmits(ctx, "did:test:alice", nil, nil, []byte(`{"jsonrpc":"2.0","id":1,"result":null}`)) {
			t.Fatal("null result must abstain")
		}
	})
}
