package rbac

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// PaymentRegistry-shaped ABI used across the method-policy tests.
const testPaymentABI = `[
  {"type":"function","name":"createPayment","stateMutability":"nonpayable",
   "inputs":[{"name":"paymentIdentifier","type":"string"},{"name":"payee","type":"address"},{"name":"amount","type":"uint256"}],
   "outputs":[]},
  {"type":"function","name":"completePayment","stateMutability":"nonpayable",
   "inputs":[{"name":"paymentIdentifier","type":"string"}],"outputs":[]},
  {"type":"function","name":"getPaymentInfo","stateMutability":"view",
   "inputs":[{"name":"paymentIdentifier","type":"string"}],
   "outputs":[{"name":"amount","type":"uint256"},{"name":"timestamp","type":"uint256"},{"name":"payer","type":"address"},{"name":"payee","type":"address"},{"name":"isCompleted","type":"bool"}]},
  {"type":"function","name":"getTradeStatus","stateMutability":"view",
   "inputs":[{"name":"tradeId","type":"string"}],
   "outputs":[{"name":"status","type":"uint8"},{"name":"filled","type":"uint256"}]}
]`

// The canonical policy for the Partior getPaymentInfo case:
// capture payer(=sender)/payee(=param1)/audience(=visibleTo) on createPayment,
// gate getPaymentInfo by those fields OR the decoded return payer/payee.
const testPaymentPolicyJSON = `{
  "records": {
    "payment": {
      "capture": [
        {"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
         "remember":{
           "payer":{"source":"sender","merge":"set_once"},
           "payee":{"source":"param","index":1,"merge":"set_once"},
           "audience":{"source":"visibleTo","merge":"union"}}},
        {"method":"completePayment(string)","key":{"source":"param","index":0},
         "remember":{"audience":{"source":"visibleTo","merge":"union"}}}
      ],
      "access": [
        {"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
         "allow":[
           {"callerIn":["payer","payee","audience"]},
           {"callerIn":{"source":"return","paths":["payer","payee"],"kind":"address"}}
         ],
         "onNoRecord":"deny","else":"deny"}
      ]
    }
  }
}`

func mustParseABI(t *testing.T) abi.ABI {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(testPaymentABI))
	if err != nil {
		t.Fatalf("parse test ABI: %v", err)
	}
	return parsed
}

// encodeCall builds calldata for a method by name using the test ABI.
func encodeCall(t *testing.T, method string, args ...any) []byte {
	t.Helper()
	parsed := mustParseABI(t)
	data, err := parsed.Pack(method, args...)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	return data
}

func addr(h string) common.Address { return common.HexToAddress(h) }

const (
	payerAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	payeeAddr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	otherAddr = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
)

// ---- Validation (test 1) ----

func TestMethodPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string // substring; "" = must validate
	}{
		{name: "valid partior policy", json: testPaymentPolicyJSON},
		{
			name:    "unknown capture method",
			json:    `{"records":{"p":{"capture":[{"method":"noSuchFn(string)","key":{"source":"param","index":0},"remember":{"x":{"source":"sender","merge":"union"}}}],"access":[]}}}`,
			wantErr: "not found in ABI",
		},
		{
			name:    "key param index out of range",
			json:    `{"records":{"p":{"capture":[{"method":"completePayment(string)","key":{"source":"param","index":5},"remember":{"x":{"source":"sender","merge":"union"}}}],"access":[]}}}`,
			wantErr: "out of range",
		},
		{
			name:    "return path not an address output",
			json:    `{"records":{"p":{"capture":[],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":{"source":"return","paths":["amount"],"kind":"address"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "not an address",
		},
		{
			name:    "callerIn field not declared by any capture",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"payer":{"source":"sender","merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["ghost"]}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "not declared",
		},
		{
			name:    "capture and access key types differ",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":1},"remember":{"payer":{"source":"sender","merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["payer"]}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "key type",
		},
		{
			name: "return-only access (no capture) validates",
			json: `{"records":{"p":{"capture":[],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":{"source":"return","paths":["payer","payee"],"kind":"address"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
		},
		{
			name:    "param remember without index",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"payee":{"source":"param","merge":"set_once"}}}],"access":[]}}}`,
			wantErr: "requires an index",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseMethodPolicyDocument([]byte(tc.json))
			if err == nil {
				err = doc.Validate(testPaymentABI)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// ---- Key canonicalization (test M2) ----

func TestMethodPolicy_DecodeRecordKey_Canonical(t *testing.T) {
	parsed := mustParseABI(t)

	// string key
	cd := encodeCall(t, "createPayment", "PAY-123", addr(payeeAddr), bigInt(1001))
	spec := KeySpec{Source: "param", Index: 0}
	key, err := decodeRecordKey(spec, cd, parsed)
	if err != nil {
		t.Fatalf("string key: %v", err)
	}
	if key != "PAY-123" {
		t.Fatalf("string key = %q, want PAY-123", key)
	}

	// A different logical string that superficially looks hex-ish must not collide.
	cd2 := encodeCall(t, "createPayment", "0x01", addr(payeeAddr), bigInt(1))
	key2, _ := decodeRecordKey(spec, cd2, parsed)
	if key2 == key {
		t.Fatalf("distinct keys collided: %q", key2)
	}
	if key2 != "0x01" {
		t.Fatalf("string key not verbatim: %q", key2)
	}
}

// ---- Capture decode (test 2) ----

func TestMethodPolicy_DecodeCaptures(t *testing.T) {
	doc, err := ParseMethodPolicyDocument([]byte(testPaymentPolicyJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}

	cd := encodeCall(t, "createPayment", "PAY-1", addr(payeeAddr), bigInt(1001))
	caps, err := doc.DecodeCaptures(cd, "did:test:alice", []string{"did:test:charlie"}, testPaymentABI)
	if err != nil {
		t.Fatalf("decode captures: %v", err)
	}

	got := map[string][]string{}
	for _, c := range caps {
		if c.RecordType != "payment" || c.RecordKey != "PAY-1" {
			t.Fatalf("unexpected record ident: %+v", c)
		}
		got[c.Field] = append(got[c.Field], c.Value)
	}
	if len(got["payer"]) != 1 || got["payer"][0] != "did:test:alice" {
		t.Fatalf("payer capture = %v, want [did:test:alice]", got["payer"])
	}
	if len(got["payee"]) != 1 || !strings.EqualFold(got["payee"][0], payeeAddr) {
		t.Fatalf("payee capture = %v, want [%s]", got["payee"], payeeAddr)
	}
	if len(got["audience"]) != 1 || got["audience"][0] != "did:test:charlie" {
		t.Fatalf("audience capture = %v, want [did:test:charlie]", got["audience"])
	}

	// A non-matching selector produces no captures (no error).
	cd2 := encodeCall(t, "getPaymentInfo", "PAY-1")
	caps2, err := doc.DecodeCaptures(cd2, "did:test:alice", nil, testPaymentABI)
	if err != nil {
		t.Fatalf("decode non-writer: %v", err)
	}
	if len(caps2) != 0 {
		t.Fatalf("expected no captures for reader method, got %d", len(caps2))
	}
}

// ---- Evaluation matrix (test 5) ----

func rows(pairs ...[2]string) []CapturedField {
	out := make([]CapturedField, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, CapturedField{Field: p[0], Value: p[1], Merge: "union"})
	}
	return out
}

func TestMethodPolicy_Evaluate(t *testing.T) {
	doc, err := ParseMethodPolicyDocument([]byte(testPaymentPolicyJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	getInfo := encodeCall(t, "getPaymentInfo", "PAY-1")

	// return resolver that yields the record's payer/payee
	returnPayerPayee := func() ([]common.Address, error) {
		return []common.Address{addr(payerAddr), addr(payeeAddr)}, nil
	}
	returnErr := func() ([]common.Address, error) { return nil, errDecode }

	captured := rows(
		[2]string{"payer", "did:test:alice"},
		[2]string{"payee", strings.ToLower(payeeAddr)},
		[2]string{"audience", "did:test:charlie"},
	)

	tests := []struct {
		name        string
		callerDID   string
		callerAddr  []string
		captured    []CapturedField
		ret         func() ([]common.Address, error)
		wantAllow   bool
		wantForward bool // whether the return resolver had to be consulted
	}{
		{name: "payer via capture-sender DID", callerDID: "did:test:alice", captured: captured, ret: returnErr, wantAllow: true},
		{name: "payee via capture-param address", callerAddr: []string{payeeAddr}, captured: captured, ret: returnErr, wantAllow: true},
		{name: "settlement via capture-visibleTo DID", callerDID: "did:test:charlie", captured: captured, ret: returnErr, wantAllow: true},
		{name: "unrelated denied", callerDID: "did:test:diana", callerAddr: []string{otherAddr}, captured: captured, ret: returnErr, wantAllow: false},
		{name: "no capture rows, return admits payer", callerAddr: []string{payerAddr}, captured: nil, ret: returnPayerPayee, wantAllow: true, wantForward: true},
		{name: "no capture rows, return admits payee", callerAddr: []string{payeeAddr}, captured: nil, ret: returnPayerPayee, wantAllow: true, wantForward: true},
		{name: "no capture rows, return does not admit unrelated", callerAddr: []string{otherAddr}, captured: nil, ret: returnPayerPayee, wantAllow: false, wantForward: true},
		{name: "no capture rows, return decode error -> deny", callerAddr: []string{payerAddr}, captured: nil, ret: returnErr, wantAllow: false, wantForward: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ident := NewCallerIdentity(tc.callerDID, tc.callerAddr)
			forwarded := false
			ret := func() ([]common.Address, error) { forwarded = true; return tc.ret() }
			dec, err := doc.EvaluateAccess("payment", getInfo, ident, tc.captured, ret, testPaymentABI)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if dec.Allow != tc.wantAllow {
				t.Fatalf("allow = %v, want %v", dec.Allow, tc.wantAllow)
			}
			if tc.wantForward && !forwarded {
				t.Fatalf("expected the return resolver to be consulted")
			}
		})
	}
}

// C2: capture-only policy (no return source) must NEVER consult the resolver.
func TestMethodPolicy_CaptureOnly_NeverForwards(t *testing.T) {
	const captureOnly = `{"records":{"payment":{
      "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
        "remember":{"payer":{"source":"sender","merge":"set_once"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["payer"]}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(captureOnly))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	getInfo := encodeCall(t, "getPaymentInfo", "PAY-1")
	for _, hit := range []bool{true, false} {
		var captured []CapturedField
		if hit {
			captured = rows([2]string{"payer", "did:test:alice"})
		}
		forwarded := false
		ret := func() ([]common.Address, error) { forwarded = true; return nil, nil }
		dec, err := doc.EvaluateAccess("payment", getInfo, NewCallerIdentity("did:test:alice", nil), captured, ret, testPaymentABI)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if forwarded {
			t.Fatalf("capture-only policy must not consult the return resolver (hit=%v)", hit)
		}
		if dec.Allow != hit {
			t.Fatalf("hit=%v: allow=%v", hit, dec.Allow)
		}
	}
}

// L3: zero / empty values never match a caller.
func TestMethodPolicy_ZeroGuard(t *testing.T) {
	doc, _ := ParseMethodPolicyDocument([]byte(testPaymentPolicyJSON))
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	getInfo := encodeCall(t, "getPaymentInfo", "PAY-1")

	// Captured payee is the zero address; a caller who (bugged) presents the
	// zero address must NOT match.
	captured := rows([2]string{"payee", "0x0000000000000000000000000000000000000000"})
	ret := func() ([]common.Address, error) {
		// return also yields zero addresses
		return []common.Address{{}, {}}, nil
	}
	dec, err := doc.EvaluateAccess("payment", getInfo,
		NewCallerIdentity("", []string{"0x0000000000000000000000000000000000000000"}),
		captured, ret, testPaymentABI)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if dec.Allow {
		t.Fatalf("zero address must never match")
	}
}

// H3: conflicting set-once values from different senders poison the key -> deny-all.
func TestMethodPolicy_SetOncePoison(t *testing.T) {
	doc, _ := ParseMethodPolicyDocument([]byte(testPaymentPolicyJSON))
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	getInfo := encodeCall(t, "getPaymentInfo", "PAY-1")

	poisoned := []CapturedField{
		{Field: "payer", Value: "did:test:alice", Merge: "set_once"},
		{Field: "payer", Value: "did:test:mallory", Merge: "set_once"},
	}
	ret := func() ([]common.Address, error) { return nil, nil }
	dec, err := doc.EvaluateAccess("payment", getInfo, NewCallerIdentity("did:test:alice", nil), poisoned, ret, testPaymentABI)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if dec.Allow {
		t.Fatalf("poisoned set-once key must deny all reads")
	}
	if !dec.Poisoned {
		t.Fatalf("expected Poisoned=true")
	}
}
