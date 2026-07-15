package rbac

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// bigInt is a test helper for packing uint256 args.
func bigInt(n int64) *big.Int { return big.NewInt(n) }

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
			name:    "callerIn field not declared and not a literal principal",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"payer":{"source":"sender","merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["ghost"]}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "neither a captured field",
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

// ---- Plan-audit follow-up fixes (post-implementation review) ----

// C-1: a nil policy document must never panic; it denies / reports not-gated.
func TestMethodPolicy_NilDoc_NoPanic(t *testing.T) {
	var doc *MethodPolicyDocument
	getInfo := encodeCall(t, "getPaymentInfo", "PAY-1")

	if _, _, ok := doc.GatedReader(getInfo, testPaymentABI); ok {
		t.Fatalf("nil doc must not report a gated reader")
	}
	dec, err := doc.EvaluateAccess("payment", getInfo, NewCallerIdentity("did:test:alice", nil), nil,
		func() ([]common.Address, error) { return nil, nil }, testPaymentABI)
	if err != nil || dec.Allow {
		t.Fatalf("nil doc must deny without error, got allow=%v err=%v", dec.Allow, err)
	}
}

// H-1: a uint64 record key is a common case and must round-trip (validate,
// capture-decode, key-decode) — not silently brick the record.
func TestMethodPolicy_Uint64Key_RoundTrips(t *testing.T) {
	const abiJSON = `[
      {"type":"function","name":"open","stateMutability":"nonpayable",
       "inputs":[{"name":"id","type":"uint64"},{"name":"cp","type":"address"}],"outputs":[]},
      {"type":"function","name":"get","stateMutability":"view",
       "inputs":[{"name":"id","type":"uint64"}],
       "outputs":[{"name":"owner","type":"address"}]}]`
	const pol = `{"records":{"trade":{
      "capture":[{"method":"open(uint64,address)","key":{"source":"param","index":0},
        "remember":{"initiator":{"source":"sender","merge":"set_once"}}}],
      "access":[{"method":"get(uint64)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["initiator"]}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(pol))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(abiJSON); err != nil {
		t.Fatalf("uint64-key policy must validate: %v", err)
	}
	parsed, _ := abi.JSON(strings.NewReader(abiJSON))
	cd, err := parsed.Pack("open", uint64(4242), addr(payeeAddr))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	caps, err := doc.DecodeCaptures(cd, "did:test:alice", nil, abiJSON)
	if err != nil {
		t.Fatalf("decode captures: %v", err)
	}
	if len(caps) != 1 || caps[0].RecordKey != "4242" || caps[0].Value != "did:test:alice" {
		t.Fatalf("uint64 key capture wrong: %+v", caps)
	}
}

// H-1: a key type the runtime cannot canonicalize (dynamic array) must be
// rejected at Validate, not accepted-then-bricked.
func TestMethodPolicy_UncanonicalizableKey_Rejected(t *testing.T) {
	const abiJSON = `[
      {"type":"function","name":"open","stateMutability":"nonpayable",
       "inputs":[{"name":"ids","type":"address[]"}],"outputs":[]},
      {"type":"function","name":"get","stateMutability":"view",
       "inputs":[{"name":"ids","type":"address[]"}],"outputs":[{"name":"owner","type":"address"}]}]`
	const pol = `{"records":{"t":{
      "capture":[{"method":"open(address[])","key":{"source":"param","index":0},
        "remember":{"x":{"source":"sender","merge":"union"}}}],
      "access":[{"method":"get(address[])","key":{"source":"param","index":0},
        "allow":[{"callerIn":["x"]}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(pol))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(abiJSON); err == nil || !strings.Contains(err.Error(), "canonicaliz") {
		t.Fatalf("expected uncanonicalizable-key rejection, got %v", err)
	}
}

// H-2: the same reader selector under two record types is a nondeterministic
// authorization hazard and must be rejected at Validate.
func TestMethodPolicy_DuplicateSelectorAcrossRecords_Rejected(t *testing.T) {
	const pol = `{"records":{
      "alpha":{"capture":[],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":{"source":"return","paths":["payer"],"kind":"address"}}],"onNoRecord":"deny","else":"deny"}]},
      "beta":{"capture":[],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":{"source":"return","paths":["payee"],"kind":"address"}}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(pol))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err == nil || !strings.Contains(err.Error(), "more than one record") {
		t.Fatalf("expected duplicate-selector rejection, got %v", err)
	}
}

// M-2: the read-side key decoder rejects an empty key, mirroring the writer.
func TestMethodPolicy_DecodeRecordKey_EmptyRejected(t *testing.T) {
	parsed := mustParseABI(t)
	cd := encodeCall(t, "getPaymentInfo", "")
	if _, err := decodeRecordKey(KeySpec{Source: "param", Index: 0}, cd, parsed); err == nil {
		t.Fatalf("empty record key must be rejected")
	}
}

// L-1: unknown fields inside/alongside callerIn are rejected (strict parse).
func TestMethodPolicy_StrictAllowRule(t *testing.T) {
	cases := []string{
		`{"records":{"p":{"capture":[],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":{"source":"return","paths":["payer"],"kind":"address","EVIL":1}}],"onNoRecord":"deny","else":"deny"}]}}}`,
		`{"records":{"p":{"capture":[],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["payer"],"SNEAKY":1}],"onNoRecord":"deny","else":"deny"}]}}}`,
	}
	for i, j := range cases {
		if _, err := ParseMethodPolicyDocument([]byte(j)); err == nil {
			t.Fatalf("case %d: expected strict-parse rejection of unknown allow-rule field", i)
		}
	}
}

// EvaluateReader: single entry point — gated/not, key-scoped capture load,
// capture-then-return, fail-closed.
func TestMethodPolicy_EvaluateReader(t *testing.T) {
	doc, err := ParseMethodPolicyDocument([]byte(testPaymentPolicyJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}

	loadFor := func(rows map[string][]CapturedField) func(string, string) ([]CapturedField, error) {
		return func(rt, key string) ([]CapturedField, error) { return rows["payment|"+key], nil }
	}
	capturedPAY1 := map[string][]CapturedField{
		"payment|PAY-1": {{Field: "payer", Value: "did:test:alice", Merge: "set_once"}},
	}
	retNever := func() ([]common.Address, error) { t.Fatal("resolver must not run"); return nil, nil }

	// not gated: a non-policy method → gated=false, passthrough
	nonGated := encodeCall(t, "createPayment", "PAY-1", addr(payeeAddr), bigInt(1))
	if gated, _, _ := doc.EvaluateReader(nonGated, NewCallerIdentity("did:test:alice", nil), loadFor(capturedPAY1), retNever, testPaymentABI); gated {
		t.Fatalf("createPayment is not a gated reader")
	}

	// gated, captured payer matches → allow, resolver not consulted
	getPAY1 := encodeCall(t, "getPaymentInfo", "PAY-1")
	gated, dec, err := doc.EvaluateReader(getPAY1, NewCallerIdentity("did:test:alice", nil), loadFor(capturedPAY1), retNever, testPaymentABI)
	if err != nil || !gated || !dec.Allow {
		t.Fatalf("payer should be allowed via capture: gated=%v allow=%v err=%v", gated, dec.Allow, err)
	}

	// gated, key with NO captures + return admits payer
	getPAY2 := encodeCall(t, "getPaymentInfo", "PAY-2")
	retPayer := func() ([]common.Address, error) { return []common.Address{addr(payerAddr)}, nil }
	gated, dec, _ = doc.EvaluateReader(getPAY2, NewCallerIdentity("", []string{payerAddr}), loadFor(capturedPAY1), retPayer, testPaymentABI)
	if !gated || !dec.Allow {
		t.Fatalf("payer should be allowed via return for uncaptured key: allow=%v", dec.Allow)
	}

	// store error → deny
	loadErr := func(string, string) ([]CapturedField, error) { return nil, errDecode }
	gated, dec, _ = doc.EvaluateReader(getPAY1, NewCallerIdentity("did:test:alice", nil), loadErr, retPayer, testPaymentABI)
	if !gated || dec.Allow {
		t.Fatalf("store error must deny: allow=%v", dec.Allow)
	}
}

// ---- P1: invariant consolidation (visibleTo⇒union, merge consistency) ----

func TestMethodPolicy_Validate_VisibleToMustBeUnion(t *testing.T) {
	// audience captured from visibleTo with set_once must be rejected at the
	// backend (was wizard-only).
	j := `{"records":{"payment":{
      "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
        "remember":{"audience":{"source":"visibleTo","merge":"set_once"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["audience"]}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(j))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err == nil || !strings.Contains(err.Error(), "must use merge \"union\"") {
		t.Fatalf("expected visibleTo+set_once rejection, got %v", err)
	}
}

func TestMethodPolicy_Validate_MergeConsistencyAcrossCaptures(t *testing.T) {
	// same field name captured on two methods with DIFFERENT merge → reject.
	j := `{"records":{"payment":{
      "capture":[
        {"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
         "remember":{"audience":{"source":"visibleTo","merge":"union"}}},
        {"method":"completePayment(string)","key":{"source":"param","index":0},
         "remember":{"audience":{"source":"visibleTo","merge":"set_once"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["audience"]}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(j))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// the set_once branch is also a visibleTo→union violation; either way it must reject.
	if err := doc.Validate(testPaymentABI); err == nil {
		t.Fatalf("expected rejection for inconsistent/invalid merge across captures")
	}
}

func TestMethodPolicy_Validate_SameFieldAcrossCapturesOK(t *testing.T) {
	// audience captured on BOTH create and complete with the SAME kind+merge is
	// legitimate (draft Example 1) and must validate.
	j := `{"records":{"payment":{
      "capture":[
        {"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
         "remember":{"payer":{"source":"sender","merge":"set_once"},"audience":{"source":"visibleTo","merge":"union"}}},
        {"method":"completePayment(string)","key":{"source":"param","index":0},
         "remember":{"audience":{"source":"visibleTo","merge":"union"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["payer","audience"]}],"onNoRecord":"deny","else":"deny"}]}}}`
	doc, err := ParseMethodPolicyDocument([]byte(j))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("multi-capture same-field policy must validate: %v", err)
	}
}

// ---- P2: where-conditions (Example 4) ----

// ABI with an amount param captured as a scalar for where-conditions.
const testWhereABI = `[
  {"type":"function","name":"createPayment","stateMutability":"nonpayable",
   "inputs":[{"name":"paymentIdentifier","type":"string"},{"name":"payee","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"function","name":"getPaymentInfo","stateMutability":"view",
   "inputs":[{"name":"paymentIdentifier","type":"string"}],
   "outputs":[{"name":"amount","type":"uint256"},{"name":"payer","type":"address"},{"name":"payee","type":"address"}]}
]`

// capture payer(sender)+amount(param2); gate getPaymentInfo: payer always, OR
// did:test:compliance only when amount >= 1000000.
const testWherePolicyJSON = `{"records":{"payment":{
  "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
    "remember":{"payer":{"source":"sender","merge":"set_once"},"amount":{"source":"param","index":2,"merge":"set_once"}}}],
  "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
    "allow":[
      {"callerIn":["payer"]},
      {"callerIn":["did:test:compliance"],"where":{"field":"amount","op":"gte","value":"1000000"}}
    ],"onNoRecord":"deny","else":"deny"}]}}}`

func TestMethodPolicy_Where_Validate(t *testing.T) {
	tests := []struct {
		name, json, wantErr string
	}{
		{name: "valid where policy", json: testWherePolicyJSON},
		{
			name:    "where field not captured",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"payer":{"source":"sender","merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["payer"],"where":{"field":"ghost","op":"gte","value":"1"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "not a captured field",
		},
		{
			name:    "numeric op on non-numeric field",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"payer":{"source":"sender","merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["payer"],"where":{"field":"payer","op":"gte","value":"1"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "requires a numeric field",
		},
		{
			name:    "unparseable numeric value",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"amount":{"source":"param","index":2,"merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["amount"],"where":{"field":"amount","op":"gte","value":"notanumber"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "not a valid integer",
		},
		{
			name:    "bad op",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"amount":{"source":"param","index":2,"merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["amount"],"where":{"field":"amount","op":"between","value":"1"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "unsupported",
		},
		{
			name:    "where on a return rule rejected",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"amount":{"source":"param","index":2,"merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":{"source":"return","paths":["payer"],"kind":"address"},"where":{"field":"amount","op":"gte","value":"1"}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "not supported on a return-source rule",
		},
		{
			name:    "unknown field inside where rejected (strict parse)",
			json:    `{"records":{"p":{"capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},"remember":{"amount":{"source":"param","index":2,"merge":"set_once"}}}],"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["amount"],"where":{"field":"amount","op":"gte","value":"1","EVIL":1}}],"onNoRecord":"deny","else":"deny"}]}}}`,
			wantErr: "", // parse error, asserted below
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseMethodPolicyDocument([]byte(tc.json))
			if tc.name == "unknown field inside where rejected (strict parse)" {
				if err == nil {
					t.Fatalf("expected parse rejection of unknown where field")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = doc.Validate(testWhereABI)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestMethodPolicy_Where_Evaluate(t *testing.T) {
	doc, err := ParseMethodPolicyDocument([]byte(testWherePolicyJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testWhereABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	whereParsed := func(t *testing.T) abi.ABI {
		p, e := abi.JSON(strings.NewReader(testWhereABI))
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	getInfo := func(t *testing.T) []byte {
		data, e := whereParsed(t).Pack("getPaymentInfo", "PAY-1")
		if e != nil {
			t.Fatal(e)
		}
		return data
	}(t)
	retErr := func() ([]common.Address, error) { return nil, errDecode }

	rowsFor := func(amount string) []CapturedField {
		return []CapturedField{
			{Field: "payer", Value: "did:test:alice", Merge: "set_once"},
			{Field: "amount", Value: amount, Merge: "set_once"},
		}
	}

	tests := []struct {
		name   string
		caller CallerIdentity
		amount string
		want   bool
	}{
		{name: "payer always allowed regardless of amount", caller: NewCallerIdentity("did:test:alice", nil), amount: "5", want: true},
		{name: "compliance allowed for large amount", caller: NewCallerIdentity("did:test:compliance", nil), amount: "2000000", want: true},
		{name: "compliance allowed at exact boundary", caller: NewCallerIdentity("did:test:compliance", nil), amount: "1000000", want: true},
		{name: "compliance denied for small amount", caller: NewCallerIdentity("did:test:compliance", nil), amount: "999999", want: false},
		{name: "compliance denied when amount absent", caller: NewCallerIdentity("did:test:compliance", nil), amount: "", want: false},
		{name: "unrelated denied even for large amount", caller: NewCallerIdentity("did:test:diana", nil), amount: "5000000", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := rowsFor(tc.amount)
			if tc.amount == "" {
				rows = []CapturedField{{Field: "payer", Value: "did:test:alice", Merge: "set_once"}}
			}
			dec, err := doc.EvaluateAccess("payment", getInfo, tc.caller, rows, retErr, testWhereABI)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if dec.Allow != tc.want {
				t.Fatalf("allow=%v want %v", dec.Allow, tc.want)
			}
		})
	}
}

// A numeric where must never compare lexically ("9" > "1000000" would be a bug).
func TestMethodPolicy_Where_NumericNotLexical(t *testing.T) {
	doc, _ := ParseMethodPolicyDocument([]byte(testWherePolicyJSON))
	if err := doc.Validate(testWhereABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	p, _ := abi.JSON(strings.NewReader(testWhereABI))
	getInfo, _ := p.Pack("getPaymentInfo", "PAY-1")
	// amount "9" is lexically > "1000000" but numerically far less → must deny.
	rows := []CapturedField{{Field: "amount", Value: "9", Merge: "set_once"}}
	dec, _ := doc.EvaluateAccess("payment", getInfo, NewCallerIdentity("did:test:compliance", nil), rows, func() ([]common.Address, error) { return nil, errDecode }, testWhereABI)
	if dec.Allow {
		t.Fatalf("numeric where compared lexically — 9 must NOT satisfy >= 1000000")
	}
}

// ---- P3: simulator (capture-side, no node call) ----

func TestMethodPolicy_SimulateReader(t *testing.T) {
	doc, err := ParseMethodPolicyDocument([]byte(testWherePolicyJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testWhereABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	load := func(rows []CapturedField) func(string) ([]CapturedField, error) {
		return func(rt string) ([]CapturedField, error) {
			if rt != "payment" {
				t.Fatalf("unexpected record type %q", rt)
			}
			return rows, nil
		}
	}
	rows := []CapturedField{
		{Field: "payer", Value: "did:test:alice", Merge: "set_once"},
		{Field: "amount", Value: "2000000", Merge: "set_once"},
	}

	// payer allowed, no return source in this policy → deterministic.
	res, ok, err := doc.SimulateReader("getPaymentInfo(string)", NewCallerIdentity("did:test:alice", nil), load(rows))
	if err != nil || !ok {
		t.Fatalf("sim ok=%v err=%v", ok, err)
	}
	if !res.Allow || res.MatchedRule != "captured:payer" || res.HasReturnSource {
		t.Fatalf("payer sim wrong: %+v", res)
	}
	// compliance principal allowed via where (amount high).
	res, _, _ = doc.SimulateReader("getPaymentInfo(string)", NewCallerIdentity("did:test:compliance", nil), load(rows))
	if !res.Allow || res.MatchedRule != "principal:did:test:compliance" {
		t.Fatalf("compliance sim wrong: %+v", res)
	}
	// compliance denied when amount low.
	res, _, _ = doc.SimulateReader("getPaymentInfo(string)", NewCallerIdentity("did:test:compliance", nil),
		load([]CapturedField{{Field: "amount", Value: "1", Merge: "set_once"}}))
	if res.Allow {
		t.Fatalf("compliance must be denied for low amount: %+v", res)
	}
	// unknown reader method → not gated.
	if _, ok, _ := doc.SimulateReader("noSuch(string)", NewCallerIdentity("did:test:alice", nil), load(rows)); ok {
		t.Fatalf("unknown method should not be gated")
	}
}

// The simulator must flag HasReturnSource so a capture-side deny is not
// mistaken for an authoritative deny (the live return resolver may admit).
func TestMethodPolicy_SimulateReader_ReturnSourceFlagged(t *testing.T) {
	doc, err := ParseMethodPolicyDocument([]byte(testPaymentPolicyJSON)) // has a return rule
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := doc.Validate(testPaymentABI); err != nil {
		t.Fatalf("validate: %v", err)
	}
	load := func(string) ([]CapturedField, error) { return nil, nil } // no captures
	res, ok, _ := doc.SimulateReader("getPaymentInfo(string)", NewCallerIdentity("did:test:diana", nil), load)
	if !ok {
		t.Fatalf("should be gated")
	}
	if res.Allow {
		t.Fatalf("capture-side should deny with no captures")
	}
	if !res.HasReturnSource {
		t.Fatalf("HasReturnSource must be true so the deny is not read as authoritative")
	}
}

// Final-audit HIGH: a capture field NAME that looks like a DID/address literal
// must be rejected — otherwise a callerIn entry equal to that name admits a
// caller with no captured basis (eval falls through to literal-principal).
func TestMethodPolicy_Validate_RejectsLiteralShapedFieldName(t *testing.T) {
	for _, name := range []string{
		"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		"did:test:role",
	} {
		j := `{"records":{"payment":{
          "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
            "remember":{"` + name + `":{"source":"sender","merge":"set_once"}}}],
          "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
            "allow":[{"callerIn":["` + name + `"]}],"onNoRecord":"deny","else":"deny"}]}}}`
		doc, err := ParseMethodPolicyDocument([]byte(j))
		if err != nil {
			t.Fatalf("parse (%s): %v", name, err)
		}
		if err := doc.Validate(testPaymentABI); err == nil || !strings.Contains(err.Error(), "must not look like a DID/address literal") {
			t.Fatalf("literal-shaped field name %q must be rejected, got %v", name, err)
		}
	}
}
