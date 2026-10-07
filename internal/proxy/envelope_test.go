package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode"
)

// bs is a literal backslash, for building JSON unicode escapes in test bodies.
var bs = string(rune(92))

// maxEnvelopeDepth is encoding/json's nesting limit, which json.Valid (and so
// ParseEnvelope) enforces.
const maxEnvelopeDepth = 10000

// ambiguousEnvelopes are JSON-RPC bodies that different JSON decoders read
// differently. Go's encoding/json matches member names case-insensitively and
// keeps the LAST duplicate; exact-case decoders (Reth/jsonrpsee, Besu/Jackson)
// read only the exact-case member, and some keep the first duplicate or reject.
// The proxy must refuse every one of them, because whichever reading it
// authorises, the node may execute the other.
var ambiguousEnvelopes = []struct {
	name string
	body string
}{
	{"case-variant method after method", `{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","Method":"eth_blockNumber","params":[]}`},
	{"case-variant method before method", `{"jsonrpc":"2.0","id":1,"Method":"eth_blockNumber","method":"eth_getStorageAt","params":[]}`},
	{"lone case-variant method", `{"jsonrpc":"2.0","id":1,"Method":"eth_blockNumber","params":[]}`},
	{"upper-case method member", `{"jsonrpc":"2.0","id":1,"METHOD":"eth_blockNumber","params":[]}`},
	{"duplicate method", `{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","method":"eth_blockNumber","params":[]}`},
	{"escaped duplicate method", `{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","` + bs + `u006dethod":"eth_blockNumber","params":[]}`},
	{"case-variant params", `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x000000000000000000000000000000000000000a","latest"],"Params":["0x000000000000000000000000000000000000000b","latest"]}`},
	{"lone upper-case params", `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","PARAMS":["0x000000000000000000000000000000000000000b","latest"]}`},
	{"duplicate params", `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x000000000000000000000000000000000000000a","latest"],"params":["0x000000000000000000000000000000000000000b","latest"]}`},
	// U+017F (LATIN SMALL LETTER LONG S) simple-folds to 's': Go matches
	// "paramſ" to the params field.
	{"unicode-fold params", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"0x000000000000000000000000000000000000000a\",\"latest\"],\"paramſ\":[\"0x000000000000000000000000000000000000000b\",\"latest\"]}"},
	{"case-variant id", `{"jsonrpc":"2.0","id":1,"ID":2,"method":"eth_blockNumber","params":[]}`},
	{"duplicate id", `{"jsonrpc":"2.0","id":1,"id":2,"method":"eth_blockNumber","params":[]}`},
	{"case-variant jsonrpc", `{"JSONRPC":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
	{"case-variant visibleTo", `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"],"visibleTo":["did:a:b"],"VisibleTo":["did:c:d"]}`},
	{"lone case-variant privateFor", `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"],"privatefor":["did:c:d"]}`},
	{"nested duplicate key in params", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x000000000000000000000000000000000000000a","to":"0x000000000000000000000000000000000000000b"},"latest"]}`},
	{"nested case-variant pair in params", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x000000000000000000000000000000000000000a","To":"0x000000000000000000000000000000000000000b"},"latest"]}`},
	{"deeply nested duplicate key", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"0x000000000000000000000000000000000000000a":{"stateDiff":{"0x01":"0x02","0x01":"0x03"}}}]}`},
}

// TestParseRequest_RejectsAmbiguousEnvelope pins that ParseRequest refuses
// every ambiguous envelope instead of silently picking one reading.
func TestParseRequest_RejectsAmbiguousEnvelope(t *testing.T) {
	for _, tt := range ambiguousEnvelopes {
		t.Run(tt.name, func(t *testing.T) {
			method, params, err := ParseRequest([]byte(tt.body))
			if err == nil {
				t.Fatalf("ParseRequest accepted an ambiguous envelope: method=%q params=%v", method, params)
			}
		})
	}
}

// TestParseRequest_AcceptsUnambiguousEnvelope guards against over-rejection:
// member names that only resemble reserved ones, and nested keys that differ
// by more than letter case, are ordinary JSON.
func TestParseRequest_AcceptsUnambiguousEnvelope(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod string
	}{
		{"canonical", `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`, "eth_blockNumber"},
		{"no params", `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}`, "eth_blockNumber"},
		{"unrelated extra member", `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[],"methods":"x","foo":{"a":1,"b":2}}`, "eth_blockNumber"},
		{"escaped method value", `{"jsonrpc":"2.0","id":1,"method":"eth_get` + bs + `u0042alance","params":["0x000000000000000000000000000000000000000a","latest"]}`, "eth_getBalance"},
		{"data and input in tx object", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x000000000000000000000000000000000000000a","data":"0x01","input":"0x01"},"latest"]}`, "eth_call"},
		{"same key in sibling objects", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"0x000000000000000000000000000000000000000a":{"balance":"0x1"},"0x000000000000000000000000000000000000000b":{"balance":"0x1"}}]}`, "eth_call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, _, err := ParseRequest([]byte(tt.body))
			if err != nil {
				t.Fatalf("ParseRequest rejected an unambiguous envelope: %v", err)
			}
			if method != tt.wantMethod {
				t.Fatalf("method = %q, want %q", method, tt.wantMethod)
			}
		})
	}
}

// TestParseEnvelope_CanonicalBody pins the forwarded bytes: the members the
// proxy read, exact-case, each once, in a fixed order; id and params byte for
// byte; method re-encoded from the decoded string; everything else dropped.
func TestParseEnvelope_CanonicalBody(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod string
		want       string
	}{
		{"canonical order", `{"params":[],"method":"eth_blockNumber","id":1,"jsonrpc":"2.0"}`, "eth_blockNumber",
			`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`},
		{"string id, no params", `{"jsonrpc":"2.0","id":"abc","method":"eth_chainId"}`, "eth_chainId",
			`{"jsonrpc":"2.0","id":"abc","method":"eth_chainId"}`},
		{"absent id stays absent", `{"jsonrpc":"2.0","method":"eth_chainId","params":[]}`, "eth_chainId",
			`{"jsonrpc":"2.0","method":"eth_chainId","params":[]}`},
		{"null id and null params kept", `{"jsonrpc":"2.0","id":null,"method":"eth_chainId","params":null}`, "eth_chainId",
			`{"jsonrpc":"2.0","id":null,"method":"eth_chainId","params":null}`},
		{"big and fractional numbers keep precision", `{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"eth_getBlockByNumber","params":[1.50,123456789012345678901234567890]}`, "eth_getBlockByNumber",
			`{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"eth_getBlockByNumber","params":[1.50,123456789012345678901234567890]}`},
		{"whitespace inside values kept, around dropped", "{ \"jsonrpc\" : \"2.0\" ,\n\t\"id\" : 1 , \"method\" : \"eth_getBalance\" , \"params\" : [ \"0x000000000000000000000000000000000000000a\" , \"latest\" ] }", "eth_getBalance",
			`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[ "0x000000000000000000000000000000000000000a" , "latest" ]}`},
		{"unknown members dropped", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"foo":{"method":"eth_getBalance"},"methods":1}`, "eth_chainId",
			`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`},
		{"visibleTo and privateFor kept", `{"privateFor":["did:a:b"],"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"],"visibleTo":["0x000000000000000000000000000000000000000a"]}`, "eth_sendRawTransaction",
			`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x01"],"visibleTo":["0x000000000000000000000000000000000000000a"],"privateFor":["did:a:b"]}`},
		{"escaped method value decoded", `{"jsonrpc":"2.0","id":1,"method":"eth_get` + bs + `u0042alance","params":[]}`, "eth_getBalance",
			`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[]}`},
		{"escaped member name read as its exact name", `{"jsonrpc":"2.0","id":1,"` + bs + `u006dethod":"eth_chainId","params":[]}`, "eth_chainId",
			`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`},
		{"empty object", `{}`, "", `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(tt.body))
			if err != nil {
				t.Fatalf("ParseEnvelope: %v", err)
			}
			if env.Method != tt.wantMethod {
				t.Errorf("method = %q, want %q", env.Method, tt.wantMethod)
			}
			if string(env.Canonical) != tt.want {
				t.Errorf("canonical =\n  %s\nwant\n  %s", env.Canonical, tt.want)
			}
			if !json.Valid(env.Canonical) {
				t.Errorf("canonical body is not valid JSON: %s", env.Canonical)
			}
		})
	}
}

// TestParseEnvelope_Rejects covers non-ambiguity failures: every one must be
// an error, arrays must be ErrBatchRequest, and ambiguity must be
// ErrAmbiguousRequest (so callers can log it distinctly).
func TestParseEnvelope_Rejects(t *testing.T) {
	bom := "\xef\xbb\xbf"
	tests := []struct {
		name    string
		body    string
		wantErr error // nil = any error
	}{
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}]`, ErrBatchRequest},
		{"batch after whitespace", " \t\r\n[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\"}]", ErrBatchRequest},
		{"nested batch", `[[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}]]`, ErrBatchRequest},
		{"BOM before object", bom + `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}`, nil},
		{"BOM before batch", bom + `[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}]`, nil},
		{"second object", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}{"jsonrpc":"2.0","id":2,"method":"eth_getBalance"}`, nil},
		{"trailing text", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"} x`, nil},
		{"trailing scalar", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"} 1`, nil},
		{"empty", ``, nil},
		{"whitespace only", "  \n", nil},
		{"null", `null`, nil},
		{"string", `"eth_chainId"`, nil},
		{"truncated", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"`, nil},
		{"method not a string", `{"jsonrpc":"2.0","id":1,"method":1}`, nil},
		{"params not an array", `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":{"address":"0x000000000000000000000000000000000000000a"}}`, nil},
		{"jsonrpc not a string", `{"jsonrpc":2,"id":1,"method":"eth_chainId"}`, nil},
		{"too deep", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[` + strings.Repeat(`[`, maxEnvelopeDepth) + strings.Repeat(`]`, maxEnvelopeDepth) + `]}`, nil},
		{"ambiguous", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","Method":"eth_chainId"}`, ErrAmbiguousRequest},
		{"ambiguous nested", `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0x1111","Data":"0x2222"}]}`, ErrAmbiguousRequest},
		// U+212A KELVIN SIGN simple-folds to 'k'.
		{"ambiguous kelvin fold", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"k\":1,\"K\":2}]}", ErrAmbiguousRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(tt.body))
			if err == nil {
				t.Fatalf("ParseEnvelope accepted %q: canonical=%s", tt.body, env.Canonical)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseEnvelope_DepthLimitMatchesEncodingJSON: a body at exactly the
// limit is still parsed, so the new scan refuses nothing encoding/json took.
func TestParseEnvelope_DepthLimitMatchesEncodingJSON(t *testing.T) {
	inner := maxEnvelopeDepth - 2 // the object and params array take two levels
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[` + strings.Repeat(`[`, inner) + strings.Repeat(`]`, inner) + `]}`
	var probe JSONRPCRequest
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		t.Fatalf("encoding/json rejects the at-limit body, adjust the test: %v", err)
	}
	if _, err := ParseEnvelope([]byte(body)); err != nil {
		t.Fatalf("ParseEnvelope rejected a body encoding/json accepts: %v", err)
	}
}

// TestFoldKey_MatchesEqualFold cross-checks foldKey against strings.EqualFold
// for names built from every rune that folds into ASCII.
func TestFoldKey_MatchesEqualFold(t *testing.T) {
	names := []string{"method", "Method", "METHOD", "methoD", "paramſ", "PARAMS", "params", "Key", "key", "Key",
		"visibleTo", "VISIBLETO", "privatefor", "id", "ID", "Id", "jsonrpc", "JSONRPC", "İd", "ıd", "ı", "i", "I", "İ"}
	for _, a := range names {
		for _, b := range names {
			if got, want := foldKey(a) == foldKey(b), strings.EqualFold(a, b); got != want {
				t.Errorf("foldKey(%q)==foldKey(%q) is %v, strings.EqualFold is %v", a, b, got, want)
			}
		}
	}
}

// TestParseEnvelope_ParamFieldCaseVariants: inside params, a Go-based node
// (Geth, Erigon) reads `To` as `to` while the proxy's exact lookup does not
// see it, so a call would be checked as one without a target. Such names are
// reported by ParamsAmbiguity (the caller refuses them for methods whose
// params the proxy reads); names that only look similar, or are not Ethereum
// request fields, are not.
func TestParseEnvelope_ParamFieldCaseVariants(t *testing.T) {
	rejected := map[string]string{
		"call To":                          `[{"To":"0x000000000000000000000000000000000000000b","data":"0x01"},"latest"]`,
		"call tO":                          `[{"tO":"0x000000000000000000000000000000000000000b"},"latest"]`,
		"call Data":                        `[{"to":"0x000000000000000000000000000000000000000a","Data":"0x01"},"latest"]`,
		"call INPUT":                       `[{"to":"0x000000000000000000000000000000000000000a","INPUT":"0x01"},"latest"]`,
		"logs Address":                     `[{"Address":"0x000000000000000000000000000000000000000b"}]`,
		"block BlockHash":                  `["0x000000000000000000000000000000000000000a",{"BlockHash":"0x01"}]`,
		"kelvin blocKHash":                 "[\"0x000000000000000000000000000000000000000a\",{\"blocKHash\":\"0x01\"}]",
		"tx VisibleTo":                     `[{"to":"0x000000000000000000000000000000000000000a","VisibleTo":["did:a:b"]}]`,
		"trace StateOverrides":             `[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"StateOverrides":{}}]`,
		"override Code":                    `[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"0x000000000000000000000000000000000000000a":{"Code":"0x00"}}]`,
		"override MovePrecompileToAddress": `[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"0x0000000000000000000000000000000000000001":{"MovePrecompileToAddress":"0x000000000000000000000000000000000000000b"}}]`,
		"block override Number":            `[{"to":"0x000000000000000000000000000000000000000a"},"latest",{},{"Number":"0x1"}]`,
		"tracer Timeout":                   `[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"tracer":"callTracer","Timeout":"1s"}]`,
		"tx ChainId":                       `[{"to":"0x000000000000000000000000000000000000000a","ChainId":"0x1"},"latest"]`,
		"tx BlobVersionedHashes":           `[{"to":"0x000000000000000000000000000000000000000a","blobVersionedhashes":[]},"latest"]`,
	}
	for name, params := range rejected {
		t.Run("flags "+name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":` + params + `}`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if env.ParamsAmbiguity() == "" {
				t.Fatal("ParamsAmbiguity did not flag the case variant")
			}
		})
	}
	accepted := map[string]string{
		"exact fields":                `[{"from":"0x000000000000000000000000000000000000000a","to":"0x000000000000000000000000000000000000000b","data":"0x01","value":"0x0"},"latest"]`,
		"typed-data type names":       `["0x000000000000000000000000000000000000000a",{"types":{"EIP712Domain":[],"Mail":[{"name":"to","type":"address"}]},"primaryType":"Mail"}]`,
		"checksummed override keys":   `[{"to":"0x000000000000000000000000000000000000000a"},"latest",{"0xAbCd00000000000000000000000000000000000a":{"balance":"0x1"},"0x000000000000000000000000000000000000000B":{"code":"0x00"}}]`,
		"case-variant non-field name": `[{"to":"0x000000000000000000000000000000000000000a","Foo":1}]`,
	}
	for name, params := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":` + params + `}`))
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if r := env.ParamsAmbiguity(); r != "" {
				t.Fatalf("flagged: %s", r)
			}
		})
	}
	// Outside params the field rule does not apply (only the pair rule does).
	env, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"extra":{"To":1}}`))
	if err != nil || env.ParamsAmbiguity() != "" {
		t.Fatalf("a dropped top-level member was held to the params field rule: err=%v", err)
	}
}

// TestParseEnvelope_DataInputConflict: Geth and anvil execute `input` when a
// call object carries both, while the proxy's selector check and trace read
// `data` first. Differing values are flagged; equal values (web3.js sends
// both) are not.
func TestParseEnvelope_DataInputConflict(t *testing.T) {
	cases := map[string]bool{
		`[{"to":"0x0a","data":"0xa9059cbb","input":"0x095ea7b3"},"latest"]`:              false,
		`[{"to":"0x0a","data":"0xA9059CBB","input":"0xa9059cbb"},"latest"]`:              true,
		`[{"to":"0x0a","input":"0xa9059cbb"},"latest"]`:                                  true,
		`[{"blockStateCalls":[{"calls":[{"to":"0x0a","data":"0x01","input":"0x02"}]}]}]`: false,
	}
	for params, clean := range cases {
		env, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":` + params + `}`))
		if err != nil {
			t.Fatalf("parse %s: %v", params, err)
		}
		if got := env.ParamsAmbiguity() == ""; got != clean {
			t.Errorf("%s: clean=%v, want %v (reason %q)", params, got, clean, env.ParamsAmbiguity())
		}
	}
}

// TestParseEnvelope_EncodingEdgeCases covers byte-level input that decoders
// normalise differently.
func TestParseEnvelope_EncodingEdgeCases(t *testing.T) {
	ok := func(name, body, wantCanonical string) {
		t.Run("accepts "+name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(body))
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if wantCanonical != "" && string(env.Canonical) != wantCanonical {
				t.Fatalf("canonical = %s, want %s", env.Canonical, wantCanonical)
			}
		})
	}
	bad := func(name, body string) {
		t.Run("rejects "+name, func(t *testing.T) {
			if env, err := ParseEnvelope([]byte(body)); err == nil {
				t.Fatalf("accepted: canonical=%s", env.Canonical)
			}
		})
	}
	ok("trailing newline", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\"}\n", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}`)
	ok("surrogate pair in a param", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["`+bs+`ud83d`+bs+`ude00"]}`, "")
	// U+0131 and U+0130 have no simple fold to "i" in Go, but a per-character
	// upper/lower-case comparison (Java's equalsIgnoreCase) matches them to
	// "i", so these are refused as case variants rather than dropped.
	bad("dotless i id", "{\"jsonrpc\":\"2.0\",\"ıd\":1,\"method\":\"eth_chainId\"}")
	bad("dotted I id", "{\"jsonrpc\":\"2.0\",\"İd\":1,\"method\":\"eth_chainId\"}")
	t.Run("flags dotless i input in a call", func(t *testing.T) {
		env, err := ParseEnvelope([]byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x000000000000000000000000000000000000000a\",\"ınput\":\"0xdead\"}]}"))
		if err != nil || env.ParamsAmbiguity() == "" {
			t.Fatalf("err=%v, want a parsed envelope with a params ambiguity", err)
		}
	})
	ok("non-ASCII name that folds to no field", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x000000000000000000000000000000000000000a\",\"état\":1}]}", "")
	bad("invalid UTF-8 in a param", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[\"\xff\"]}")
	bad("invalid UTF-8 in a name", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"\xfe\":1}")
	bad("unpaired high surrogate", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["`+bs+`ud800"]}`)
	bad("unpaired low surrogate", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["`+bs+`udc00x"]}`)
	bad("high surrogate then non-surrogate", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["`+bs+`ud800`+bs+`u0041"]}`)
	bad("unpaired surrogate in method", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId`+bs+`udfff"}`)
	bad("non-breaking space before the object", " {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\"}")
	bad("comment", `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"} // x`)
	bad("NaN", `{"jsonrpc":"2.0","id":NaN,"method":"eth_chainId"}`)
}

// TestParseEnvelope_LargeObjects exercises the switch from the small-object
// slice to the map in keySet.
func TestParseEnvelope_LargeObjects(t *testing.T) {
	obj := func(n int, dup bool) string {
		var b strings.Builder
		b.WriteString(`{`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`"k` + strings.Repeat("x", i) + `":1`)
		}
		if dup {
			b.WriteString(`,"K` + strings.Repeat("X", n-1) + `":2`)
		}
		b.WriteString(`}`)
		return `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[` + b.String() + `]}`
	}
	if _, err := ParseEnvelope([]byte(obj(40, false))); err != nil {
		t.Fatalf("40 distinct names rejected: %v", err)
	}
	if _, err := ParseEnvelope([]byte(obj(40, true))); !errors.Is(err, ErrAmbiguousRequest) {
		t.Fatalf("fold duplicate after the map switch: err = %v, want ErrAmbiguousRequest", err)
	}
	if _, err := ParseEnvelope([]byte(obj(5, true))); !errors.Is(err, ErrAmbiguousRequest) {
		t.Fatalf("fold duplicate in a small object: err = %v, want ErrAmbiguousRequest", err)
	}
}

// TestFoldKey_EveryRune checks foldKey against unicode.SimpleFold for every
// code point: each rune maps to a member of its own fold orbit, and every
// member of an orbit maps to the same representative. Together that makes
// foldKey equality exactly strings.EqualFold equality, which is the
// equivalence encoding/json uses to match member names.
func TestFoldKey_EveryRune(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r < 0xE000 {
			continue // surrogates are not valid in UTF-8 strings
		}
		rep := foldKey(string(r))
		if !strings.EqualFold(rep, string(r)) {
			t.Fatalf("foldKey(%U) = %q is not EqualFold to the rune", r, rep)
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if got := foldKey(string(f)); got != rep {
				t.Fatalf("foldKey(%U) = %q but foldKey(%U) = %q; the runes are fold-equal", r, rep, f, got)
			}
		}
	}
}

// FuzzParseEnvelope checks the security invariant on arbitrary input: when a
// body is accepted, every reading of it agrees. Go's case-folding, last-wins
// struct decode of the ORIGINAL body must yield the same method, params and
// id as the exact-case canonical body; the canonical body holds only the
// forwarded members, once each; and parsing it again is a fixed point.
func FuzzParseEnvelope(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`,
		`{"jsonrpc":"2.0","id":"a","method":"eth_call","params":[{"to":"0x01","data":"0x02"},"latest"]}`,
		`{"method":"A","Method":"B"}`,
		`{"method":"A","method":"B"}`,
		`{"params":[1],"Params":[2],"method":"x"}`,
		`{"id":null,"method":"x","visibleTo":["did:a:b"],"extra":{"a":1}}`,
		`{"method":"x","params":[{"To":"0x01"}]}`,
		`[{"method":"x"}]`,
		"\xef\xbb\xbf{}",
		`{"method":"x"} {}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		env, err := ParseEnvelope(body)
		if err != nil {
			return
		}
		if !json.Valid(env.Canonical) {
			t.Fatalf("canonical is not valid JSON: %s", env.Canonical)
		}
		var orig, canon JSONRPCRequest
		if err := json.Unmarshal(body, &orig); err != nil {
			t.Fatalf("accepted body does not decode into the request struct: %v", err)
		}
		if err := json.Unmarshal(env.Canonical, &canon); err != nil {
			t.Fatalf("canonical does not decode: %v", err)
		}
		origJSON, _ := json.Marshal(orig)
		canonJSON, _ := json.Marshal(canon)
		if string(origJSON) != string(canonJSON) {
			t.Fatalf("readings differ:\n  original  %s\n  canonical %s\n  body %q", origJSON, canonJSON, body)
		}
		if orig.Method != env.Method {
			t.Fatalf("method %q, Go decode of original %q", env.Method, orig.Method)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(env.Canonical, &members); err != nil {
			t.Fatalf("canonical is not an object: %v", err)
		}
		forwarded := map[string]bool{}
		for _, name := range forwardedMembers {
			forwarded[name] = true
		}
		for k := range members {
			if !forwarded[k] {
				t.Fatalf("canonical carries non-forwarded member %q", k)
			}
		}
		// Independent check of the name rules over the token stream: nothing
		// the walker accepted may hold a fold-duplicate pair or a top-level
		// case variant, and it must flag a params field variant exactly when
		// the oracle finds one.
		refuse, variant := ambiguityOracle(body)
		if refuse != "" {
			t.Fatalf("accepted an ambiguous body (%s): %q", refuse, body)
		}
		if (variant != "") != (env.fieldVariant != "") {
			t.Fatalf("field variant: walker %q, oracle %q: %q", env.fieldVariant, variant, body)
		}
		again, err := ParseEnvelope(env.Canonical)
		if err != nil {
			t.Fatalf("canonical rejected on re-parse: %v", err)
		}
		if string(again.Canonical) != string(env.Canonical) {
			t.Fatalf("canonical is not a fixed point:\n  %s\n  %s", env.Canonical, again.Canonical)
		}
	})
}

// ambiguityOracle re-derives the name rules from encoding/json's token
// stream, independently of scanEnvelope. refuse is non-empty when an object
// holds two names strings.EqualFold treats as equal, or a top-level name is a
// non-exact case variant (under looseVariantOf) of a forwarded member, or the
// stream does not tokenise. variant names the first params member that is a
// non-exact case variant of a request field.
func ambiguityOracle(body []byte) (refuse, variant string) {
	type frame struct {
		object, wantKey, inParams bool
		names                     []string
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	var stack []*frame
	topKey := ""
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return "", variant
		}
		if err != nil {
			return "token error: " + err.Error(), variant
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			switch d {
			case '{', '[':
				in := top != nil && (top.inParams || (len(stack) == 1 && topKey == "params"))
				stack = append(stack, &frame{object: d == '{', wantKey: d == '{', inParams: in})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].wantKey = true
				}
			}
			continue
		}
		if name, isString := tok.(string); isString && top != nil && top.object && top.wantKey {
			for _, seen := range top.names {
				if strings.EqualFold(seen, name) {
					return "fold pair " + seen + "/" + name, variant
				}
			}
			top.names = append(top.names, name)
			top.wantKey = false
			switch {
			case len(stack) == 1:
				topKey = name
				for _, field := range forwardedMembers {
					if name != field && looseVariantOf(name, field) {
						return "variant " + name + " of " + field, variant
					}
				}
			case top.inParams && variant == "":
				for _, field := range paramFieldNames {
					if name != field && looseVariantOf(name, field) {
						variant = name
					}
				}
			}
			continue
		}
		if top != nil && top.object {
			top.wantKey = true // a scalar value ended
		}
	}
}

// looseVariantOf reports whether name could be matched to the ASCII field by a
// case-insensitive comparison on any common platform: rune by rune, the field
// letter must equal the rune, its upper or lower case, or a member of its
// simple-fold orbit.
func looseVariantOf(name, field string) bool {
	runes := []rune(name)
	if len(runes) != len(field) {
		return false
	}
	for i, r := range runes {
		want := rune(field[i])
		cands := []rune{r, unicode.ToUpper(r), unicode.ToLower(r)}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			cands = append(cands, f)
		}
		match := false
		for _, c := range cands {
			if c < 0x80 && unicode.ToLower(c) == unicode.ToLower(want) {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// TestAmbiguityOracle_AgreesOnFixtures pins the oracle itself on the table
// fixtures, so a broken oracle cannot make the fuzz property vacuous.
func TestAmbiguityOracle_AgreesOnFixtures(t *testing.T) {
	for _, tt := range ambiguousEnvelopes {
		if refuse, _ := ambiguityOracle([]byte(tt.body)); refuse == "" {
			t.Errorf("oracle misses %s", tt.name)
		}
	}
	if refuse, variant := ambiguityOracle([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x01","data":"0x02"},"latest"],"foo":1}`)); refuse != "" || variant != "" {
		t.Errorf("oracle flags a clean body: %q %q", refuse, variant)
	}
	if refuse, variant := ambiguityOracle([]byte(`{"method":"eth_call","params":[{"To":"0x01"}]}`)); refuse != "" || variant != "To" {
		t.Errorf("params field variant: refuse %q variant %q", refuse, variant)
	}
	if _, variant := ambiguityOracle([]byte("{\"method\":\"eth_call\",\"params\":[{\"ınput\":\"0x01\"}]}")); variant == "" {
		t.Error("oracle misses a dotless-i field variant")
	}
}

// TestParseEnvelope_RejectionAgreesWithOracle checks the other direction on a
// generated corpus: every ErrAmbiguousRequest must be one the token-stream
// oracle also refuses, and every accepted body must agree with it, so neither
// implementation over- or under-rejects. The corpus combines member names
// (exact, case variants, look-alikes, escaped) at the top level and inside
// params objects.
func TestParseEnvelope_RejectionAgreesWithOracle(t *testing.T) {
	names := []string{"method", "Method", "params", "PARAMS", "id", "ıd", "to", "To", "data", "Data",
		"input", "ınput", "foo", "Foo", "Key", "key", bs + "u006dethod", "paramſ", "visibleTo", "privatefor"}
	vals := []string{`"x"`, `[]`, `[{"to":"0x01","data":"0x02"}]`, `null`, `1`}
	n := 0
	for _, a := range names {
		for _, b := range names {
			for _, v := range vals {
				for _, nested := range []bool{false, true} {
					var body string
					if nested {
						body = `{"method":"eth_call","params":[{"` + a + `":` + v + `,"` + b + `":1}]}`
					} else {
						body = `{"` + a + `":` + v + `,"` + b + `":1}`
					}
					n++
					env, err := ParseEnvelope([]byte(body))
					refuse, variant := ambiguityOracle([]byte(body))
					switch {
					case errors.Is(err, ErrAmbiguousRequest):
						if refuse == "" {
							t.Errorf("walker refuses, oracle does not: %q", body)
						}
					case err == nil:
						if refuse != "" {
							t.Errorf("walker accepts, oracle refuses (%s): %q", refuse, body)
						}
						if (variant != "") != (env.fieldVariant != "") {
							t.Errorf("field variant: walker %q, oracle %q: %q", env.fieldVariant, variant, body)
						}
					}
				}
			}
		}
	}
	if n < 1000 {
		t.Fatalf("corpus too small: %d", n)
	}
}

// TestParseEnvelope_IDTypes: id must be a string, a number or null.
func TestParseEnvelope_IDTypes(t *testing.T) {
	for _, id := range []string{`"abc"`, `1`, `-1.5e3`, `123456789012345678901234567890`, `null`} {
		if _, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"eth_chainId"}`)); err != nil {
			t.Errorf("id %s rejected: %v", id, err)
		}
	}
	for _, id := range []string{`{"a":1}`, `[1]`, `true`, `1e400`, `{"a":1e400}`} {
		if _, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"eth_chainId"}`)); err == nil {
			t.Errorf("id %s accepted", id)
		}
	}
}

// TestEnvelope_CanonicalWithoutMetadata: the proxy's visibleTo/privateFor are
// left out for methods that do not consume them; everything else is kept.
func TestEnvelope_CanonicalWithoutMetadata(t *testing.T) {
	env, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[],"visibleTo":["did:a:b"],"privateFor":["did:c:d"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(env.CanonicalWithoutMetadata()), `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[]}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if !strings.Contains(string(env.Canonical), `"visibleTo"`) {
		t.Fatalf("Canonical must keep visibleTo for the send paths: %s", env.Canonical)
	}
	plain, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain.CanonicalWithoutMetadata()) != string(plain.Canonical) {
		t.Fatal("without metadata present, both bodies must be identical")
	}
}

// TestCheckDecodedRequest covers params that an admin endpoint decoded itself.
func TestCheckDecodedRequest(t *testing.T) {
	for name, params := range map[string][]any{
		"clean": {map[string]any{"to": "0x01", "data": "0x02"}, "latest"},
		"nil":   nil,
	} {
		env, err := CheckDecodedRequest("eth_call", params)
		if err != nil || env.ParamsAmbiguity() != "" {
			t.Errorf("%s: err=%v ambiguity=%q, want clean", name, err, env.ParamsAmbiguity())
		}
	}
	// Go's decoder already merged exact duplicates, but a pair that differs
	// only in case survives the round trip and is a parse error.
	if _, err := CheckDecodedRequest("eth_call", []any{map[string]any{"to": "0x01", "data": "0x02", "Data": "0x03"}}); !errors.Is(err, ErrAmbiguousRequest) {
		t.Errorf("to and Data: err = %v, want ErrAmbiguousRequest", err)
	}
	for name, params := range map[string][]any{
		"To":                {map[string]any{"To": "0x01"}, "latest"},
		"override Nonce":    {map[string]any{"to": "0x01"}, "latest", map[string]any{"0x01": map[string]any{"Nonce": "0x1"}}},
		"data/input differ": {map[string]any{"to": "0x01", "data": "0x02", "input": "0x03"}},
	} {
		env, err := CheckDecodedRequest("eth_call", params)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if env.ParamsAmbiguity() == "" {
			t.Errorf("%s: not flagged", name)
		}
	}
}
