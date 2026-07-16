package rbac

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// eventsABI is a generic WorkflowCore-shaped fixture (no Partior specifics):
// a writer that captures an audience, a reader, a processed event carrying the
// record key in NON-indexed data, and events exercising indexed static/dynamic.
const eventsABI = `[
  {"type":"function","name":"initiatePayment","stateMutability":"nonpayable",
   "inputs":[{"name":"msgId","type":"string"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"processPayment","stateMutability":"nonpayable",
   "inputs":[{"name":"msgId","type":"string"},{"name":"status","type":"uint8"}],"outputs":[]},
  {"type":"function","name":"getPaymentInfo","stateMutability":"view",
   "inputs":[{"name":"msgId","type":"string"}],"outputs":[{"name":"payer","type":"address"}]},
  {"type":"event","name":"PaymentProcessed",
   "inputs":[{"name":"msgId","type":"string","indexed":false},{"name":"status","type":"uint8","indexed":false}]},
  {"type":"event","name":"PaymentTagged",
   "inputs":[{"name":"account","type":"address","indexed":true},{"name":"msgId","type":"string","indexed":false}]},
  {"type":"event","name":"PaymentByNonce",
   "inputs":[{"name":"nonce","type":"uint256","indexed":true}]},
  {"type":"event","name":"PaymentIndexedId",
   "inputs":[{"name":"msgId","type":"string","indexed":true}]}
]`

// captureOnly + events/transactions referencing the captured "audience".
const eventsPolicyJSON = `{"records":{"payment":{
  "capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},
    "remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
  "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
    "allow":[{"callerIn":["audience"]}],"onNoRecord":"deny","else":"deny"}],
  "events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},
    "allow":[{"callerIn":["audience"]}]}],
  "transactions":[{"method":"processPayment(string,uint8)","key":{"source":"param","index":0},
    "allow":[{"callerIn":["audience"]}]}]
}}}`

func mustParseEventsABI(t *testing.T) abi.ABI {
	t.Helper()
	p, err := abi.JSON(strings.NewReader(eventsABI))
	if err != nil {
		t.Fatalf("parse eventsABI: %v", err)
	}
	return p
}

func mustDoc(t *testing.T, js string) *MethodPolicyDocument {
	t.Helper()
	d, err := ParseMethodPolicyDocument([]byte(js))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return d
}

// processedLog builds the (topics, data) of a PaymentProcessed(msgId,status) log.
func processedLog(t *testing.T, parsed abi.ABI, msgID string, status uint8) ([]string, []byte) {
	t.Helper()
	ev := parsed.Events["PaymentProcessed"]
	data, err := ev.Inputs.NonIndexed().Pack(msgID, status)
	if err != nil {
		t.Fatalf("pack PaymentProcessed: %v", err)
	}
	return []string{ev.ID.Hex()}, data
}

func loadAudience(dids ...string) func(string, string) ([]CapturedField, error) {
	return func(_ /*recordType*/, _ /*recordKey*/ string) ([]CapturedField, error) {
		out := make([]CapturedField, 0, len(dids))
		for _, d := range dids {
			out = append(out, CapturedField{Field: "audience", Value: d, Merge: "union"})
		}
		return out, nil
	}
}

// ---- Validation ----

func TestValidate_EventsTransactions(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string // "" = must validate
	}{
		{name: "valid events+transactions policy", json: eventsPolicyJSON},
		{
			name:    "event not in ABI",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"Ghost(string)","key":{"source":"eventParam","index":0},"allow":[{"callerIn":["audience"]}]}]}}}`,
			wantErr: "event \"Ghost(string)\" not found in ABI",
		},
		{
			name:    "event key index out of range",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":9},"allow":[{"callerIn":["audience"]}]}]}}}`,
			wantErr: "key index 9 out of range",
		},
		{
			name:    "event key type disagrees with capture key",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":1},"allow":[{"callerIn":["audience"]}]}]}}}`,
			wantErr: "event key type",
		},
		{
			name:    "indexed dynamic event key rejected",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentIndexedId(string)","key":{"source":"eventParam","index":0},"allow":[{"callerIn":["audience"]}]}]}}}`,
			wantErr: "indexed+dynamic",
		},
		{
			name:    "event key source not eventParam",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"param","index":0},"allow":[{"callerIn":["audience"]}]}]}}}`,
			wantErr: "key source \"param\" unsupported",
		},
		{
			name:    "event callerIn undeclared field",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},"allow":[{"callerIn":["ghost"]}]}]}}}`,
			wantErr: "neither a captured field",
		},
		{
			name:    "event return-source callerIn rejected",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},"allow":[{"callerIn":{"source":"return","paths":["x"],"kind":"address"}}]}]}}}`,
			wantErr: "return-source callerIn is not supported",
		},
		{
			name:    "transaction method not in ABI",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"transactions":[{"method":"ghostTx(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["audience"]}]}]}}}`,
			wantErr: "transaction method \"ghostTx(string)\" not found in ABI",
		},
		{
			name:    "event has no allow rules",
			json:    `{"records":{"p":{"capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],"events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},"allow":[]}]}}}`,
			wantErr: "no allow rules",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := mustDoc(t, tc.json)
			err := doc.Validate(eventsABI)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// ---- EventAudienceAdmits (rule 71 decision) ----

func TestEventAudienceAdmits(t *testing.T) {
	parsed := mustParseEventsABI(t)
	doc := mustDoc(t, eventsPolicyJSON)
	topics, data := processedLog(t, parsed, "PAY-1", 2)

	tests := []struct {
		name      string
		callerDID string
		load      func(string, string) ([]CapturedField, error)
		want      bool
	}{
		{"caller in audience → admit", "did:test:alice", loadAudience("did:test:alice", "did:test:bob"), true},
		{"caller not in audience → abstain", "did:test:eve", loadAudience("did:test:alice", "did:test:bob"), false},
		{"no captures → abstain", "did:test:alice", loadAudience(), false},
		{"lookup error → abstain", "did:test:alice", func(string, string) ([]CapturedField, error) { return nil, errDecode }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caller := NewCallerIdentity(tc.callerDID, nil)
			got := doc.EventAudienceAdmits(topics, data, caller, parsed, tc.load)
			if got != tc.want {
				t.Fatalf("EventAudienceAdmits = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEventAudienceAdmits_NotGoverned(t *testing.T) {
	parsed := mustParseEventsABI(t)
	doc := mustDoc(t, eventsPolicyJSON)
	// PaymentByNonce is not in the events policy → abstain regardless of audience.
	ev := parsed.Events["PaymentByNonce"]
	topics := []string{ev.ID.Hex(), "0x" + strings.Repeat("0", 63) + "1"}
	caller := NewCallerIdentity("did:test:alice", nil)
	if doc.EventAudienceAdmits(topics, nil, caller, parsed, loadAudience("did:test:alice")) {
		t.Fatal("an ungoverned event must abstain (false), not admit")
	}
}

func TestEventAudienceAdmits_PoisonedAbstains(t *testing.T) {
	parsed := mustParseEventsABI(t)
	doc := mustDoc(t, eventsPolicyJSON)
	topics, data := processedLog(t, parsed, "PAY-1", 2)
	caller := NewCallerIdentity("did:test:alice", nil)
	// A poisoned set-once field must fail closed (abstain), even though a union
	// "audience" row would otherwise admit.
	poison := func(string, string) ([]CapturedField, error) {
		return []CapturedField{
			{Field: "payer", Value: "did:a", Merge: "set_once"},
			{Field: "payer", Value: "did:b", Merge: "set_once"},
			{Field: "audience", Value: "did:test:alice", Merge: "union"},
		}, nil
	}
	if doc.EventAudienceAdmits(topics, data, caller, parsed, poison) {
		t.Fatal("a poisoned record must abstain")
	}
}

func TestEventAudienceAdmits_LiteralPrincipal(t *testing.T) {
	parsed := mustParseEventsABI(t)
	// A literal DID principal admits directly (a standing compliance desk), even
	// with no captured audience.
	js := `{"records":{"payment":{
      "capture":[{"method":"initiatePayment(string,uint256)","key":{"source":"param","index":0},"remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
      "events":[{"event":"PaymentProcessed(string,uint8)","key":{"source":"eventParam","index":0},"allow":[{"callerIn":["did:test:compliance"]}]}]}}}`
	doc := mustDoc(t, js)
	if err := doc.Validate(eventsABI); err != nil {
		t.Fatalf("policy must validate: %v", err)
	}
	topics, data := processedLog(t, parsed, "PAY-1", 2)
	if !doc.EventAudienceAdmits(topics, data, NewCallerIdentity("did:test:compliance", nil), parsed, loadAudience()) {
		t.Fatal("literal DID principal must be admitted")
	}
	if doc.EventAudienceAdmits(topics, data, NewCallerIdentity("did:test:eve", nil), parsed, loadAudience()) {
		t.Fatal("a non-principal caller must abstain")
	}
}

// ---- TxAudienceAdmits (rule 72 decision) ----

func TestTxAudienceAdmits(t *testing.T) {
	parsed := mustParseEventsABI(t)
	doc := mustDoc(t, eventsPolicyJSON)
	calldata, err := parsed.Pack("processPayment", "PAY-1", uint8(1))
	if err != nil {
		t.Fatalf("pack processPayment: %v", err)
	}
	if !doc.TxAudienceAdmits(calldata, NewCallerIdentity("did:test:alice", nil), parsed, loadAudience("did:test:alice")) {
		t.Fatal("caller in audience must be admitted for the tx")
	}
	if doc.TxAudienceAdmits(calldata, NewCallerIdentity("did:test:eve", nil), parsed, loadAudience("did:test:alice")) {
		t.Fatal("caller not in audience must abstain")
	}
	// getPaymentInfo is a reader (access), NOT a governed transaction → abstain.
	rd, _ := parsed.Pack("getPaymentInfo", "PAY-1")
	if doc.TxAudienceAdmits(rd, NewCallerIdentity("did:test:alice", nil), parsed, loadAudience("did:test:alice")) {
		t.Fatal("an ungoverned method must abstain")
	}
}

// ---- decodeEventKeyValue (key extraction) ----

func TestDecodeEventKeyValue(t *testing.T) {
	parsed := mustParseEventsABI(t)

	t.Run("non-indexed string key", func(t *testing.T) {
		ev := parsed.Events["PaymentProcessed"]
		data, _ := ev.Inputs.NonIndexed().Pack("PAY-1", uint8(3))
		v, err := decodeEventKeyValue(ev, 0, []string{ev.ID.Hex()}, data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		got, _ := canonicalizeValue(v)
		if got != "PAY-1" {
			t.Fatalf("got %q want PAY-1", got)
		}
	})

	t.Run("non-indexed key after an indexed param", func(t *testing.T) {
		// PaymentTagged(address indexed account, string msgId) — key at input index 1.
		ev := parsed.Events["PaymentTagged"]
		data, _ := ev.Inputs.NonIndexed().Pack("PAY-9")
		topics := []string{ev.ID.Hex(), "0x" + strings.Repeat("0", 24) + strings.Repeat("a", 40)}
		v, err := decodeEventKeyValue(ev, 1, topics, data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, _ := canonicalizeValue(v); got != "PAY-9" {
			t.Fatalf("got %q want PAY-9", got)
		}
	})

	t.Run("indexed static uint256 key", func(t *testing.T) {
		ev := parsed.Events["PaymentByNonce"]
		topic, _ := abi.Arguments{{Type: ev.Inputs[0].Type}}.Pack(big.NewInt(42))
		v, err := decodeEventKeyValue(ev, 0, []string{ev.ID.Hex(), "0x" + toHex(topic)}, nil)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, _ := canonicalizeValue(v); got != "42" {
			t.Fatalf("got %q want 42", got)
		}
	})

	t.Run("index out of range → error", func(t *testing.T) {
		ev := parsed.Events["PaymentProcessed"]
		if _, err := decodeEventKeyValue(ev, 5, []string{ev.ID.Hex()}, nil); err == nil {
			t.Fatal("want error for out-of-range index")
		}
	})
}

func toHex(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0x0f]
	}
	return string(out)
}
