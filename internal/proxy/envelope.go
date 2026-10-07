package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrAmbiguousRequest is returned for a JSON-RPC request whose member names
// can be read more than one way. JSON decoders disagree on such input: Go's
// encoding/json folds letter case and keeps the last duplicate, while the
// exact-case decoders in Reth and Besu read only the exact-case member, and
// some decoders keep the first duplicate or reject it. Whichever reading the
// proxy authorised, the node might execute another, so the request is refused.
var ErrAmbiguousRequest = errors.New("ambiguous JSON-RPC request: duplicate or case-variant member names")

// forwardedMembers are the top-level members the proxy reads, in the order
// they are written to the forwarded body. visibleTo/privateFor are the
// proxy's own per-transaction metadata (stripped before forwarding on the
// send paths); they stay in the canonical body so those paths can read them.
var forwardedMembers = [...]string{"jsonrpc", "id", "method", "params", "visibleTo", "privateFor"}

const (
	memberJSONRPC = iota
	memberID
	memberMethod
	memberParams
	memberVisibleTo
	memberPrivateFor
)

// paramFieldNames are the standard field names of Ethereum JSON-RPC request
// objects: transaction and call objects, log filters, EIP-1898 block
// selectors, tracer options, and state and block overrides, plus the proxy's
// own visibleTo/privateFor. Inside params, a name that differs from one of
// these only by letter case is refused: a case-insensitive node decoder (Go's
// in Geth and Erigon) matches it to the field while the proxy's exact lookup
// does not see it, so `{"To": X}` would be checked as a call without a target.
var paramFieldNames = []string{
	// transaction / call object
	"from", "to", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas",
	"maxFeePerBlobGas", "value", "data", "input", "nonce", "type", "chainId",
	"accessList", "authorizationList", "blobVersionedHashes", "blobs",
	// log filter and EIP-1898 block selector
	"address", "topics", "fromBlock", "toBlock", "blockHash", "blockNumber",
	"requireCanonical",
	// tracer options
	"tracer", "tracerConfig", "timeout", "reexec", "txIndex", "enableMemory",
	"disableStack", "disableStorage", "enableReturnData", "onlyTopCall",
	"withLog", "diffMode", "stateOverrides", "blockOverrides",
	// state override
	"balance", "code", "state", "stateDiff", "movePrecompileToAddress",
	// block override
	"number", "time", "gasLimit", "feeRecipient", "coinbase", "prevRandao",
	"random", "difficulty", "baseFeePerGas", "blobBaseFee", "beaconRoot",
	"withdrawals",
	// proxy metadata inside a transaction object / options object
	"visibleTo", "privateFor",
}

var (
	reservedLooseFolds   = looseFoldIndex(forwardedMembers[:])
	paramFieldLooseFolds = looseFoldIndex(paramFieldNames)
)

func looseFoldIndex(names []string) map[string]string {
	m := make(map[string]string, len(names))
	for _, name := range names {
		m[looseFoldKey(name)] = name
	}
	return m
}

// Envelope is a JSON-RPC request object parsed without ambiguity.
type Envelope struct {
	Method string
	Params []interface{}
	// Canonical is the request rebuilt from exactly the members the proxy
	// read, each once and under its exact name: jsonrpc, id, method, params,
	// visibleTo and privateFor, in that order, only those that were present.
	// id, params and the proxy metadata are copied byte for byte (number
	// precision and absent-vs-null preserved); method is re-encoded from the
	// decoded string the access decision used. Any other top-level member is
	// dropped.
	Canonical []byte

	members      [len(forwardedMembers)][]byte
	fieldVariant string // first params member name that is a case variant of a request field
}

// ParamsAmbiguity reports, as a log reason, how params could be read one way
// by the proxy's checks and another by the node, or "" when they cannot:
//   - a member name that is a case variant of a standard request field
//     (`{"To": X}`): a case-insensitive node decoder (Go's, in Geth and
//     Erigon) reads it as the field, the proxy's exact lookup does not;
//   - an object carrying both `data` and `input` with different values: Geth
//     and anvil execute `input`, the proxy's selector check and trace read
//     `data` first. Equal values (web3.js sends both) are fine.
//
// The caller refuses the request when the proxy reads the method's params;
// for payloads it never inspects (typed-data signing, wildcard passthrough)
// the names are just data.
func (e *Envelope) ParamsAmbiguity() string {
	if e.fieldVariant != "" {
		return "case variant of a request field in params"
	}
	if dataInputConflict(e.Params) {
		return "data and input differ in params"
	}
	return ""
}

// dataInputConflict reports whether any object inside v carries both data and
// input with values that differ other than in hex letter case.
func dataInputConflict(v any) bool {
	switch v := v.(type) {
	case []any:
		for _, item := range v {
			if dataInputConflict(item) {
				return true
			}
		}
	case map[string]any:
		data, hasData := v["data"]
		input, hasInput := v["input"]
		if hasData && hasInput {
			ds, dok := data.(string)
			is, iok := input.(string)
			if !dok || !iok || !strings.EqualFold(ds, is) {
				return true
			}
		}
		for _, item := range v {
			if dataInputConflict(item) {
				return true
			}
		}
	}
	return false
}

// CanonicalWithoutMetadata is Canonical without the proxy's own top-level
// visibleTo/privateFor members: the body to forward for a method that does
// not consume them.
func (e *Envelope) CanonicalWithoutMetadata() []byte {
	if e.members[memberVisibleTo] == nil && e.members[memberPrivateFor] == nil {
		return e.Canonical
	}
	return buildCanonical(e.members, e.Method, false)
}

// CheckDecodedRequest applies ParseEnvelope to a method and params that a
// handler decoded itself (for example from an admin request body) and
// forwards re-encoded. Go's decoder already merged repeated names, but a pair
// differing only in case, a case variant of a request field (`{"To": X}`) or
// a data/input mismatch survives the round trip and would reach the node in a
// form the proxy's checks did not read. The caller applies ParamsAmbiguity as
// it does for /rpc.
func CheckDecodedRequest(method string, params []interface{}) (*Envelope, error) {
	body, err := json.Marshal(struct {
		Method string        `json:"method"`
		Params []interface{} `json:"params"`
	}{method, params})
	if err != nil {
		return nil, parseError("encode: %w", err)
	}
	return ParseEnvelope(body)
}

func parseError(format string, args ...any) error {
	return fmt.Errorf("failed to parse JSON-RPC request: "+format, args...)
}

// ParseEnvelope parses a single JSON-RPC request object. It returns
// ErrBatchRequest for an array and ErrAmbiguousRequest for member names that
// can be read more than one way; any other malformed input (not exactly one
// JSON object, invalid UTF-8, an unpaired surrogate escape, nesting deeper
// than encoding/json allows, a wrongly typed member) yields a parse error.
func ParseEnvelope(body []byte) (*Envelope, error) {
	if IsBatchRequest(body) {
		return nil, ErrBatchRequest
	}
	if !utf8.Valid(body) {
		return nil, parseError("body is not valid UTF-8")
	}
	// Syntax, nesting depth, a leading byte-order mark and data after the
	// value are all settled here, so the scan below only walks valid JSON.
	if !json.Valid(body) {
		return nil, parseError("malformed JSON")
	}
	members, fieldVariant, err := scanEnvelope(body)
	if err != nil {
		return nil, err
	}

	env := &Envelope{members: members, fieldVariant: fieldVariant}
	// Member types: jsonrpc and method must be strings (or null) and params an
	// array (or null), as the previous struct decode required. id must be a
	// string, a number or null (JSON-RPC 2.0 §4); the struct decode already
	// rejected numbers outside float64 range and now an object or array id is
	// refused too, since it is forwarded as sent.
	if raw := members[memberJSONRPC]; raw != nil {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, parseError("jsonrpc: %w", err)
		}
	}
	if raw := members[memberID]; raw != nil {
		var id any
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, parseError("id: %w", err)
		}
		switch id.(type) {
		case string, float64, nil:
		default:
			return nil, parseError("id must be a string, a number or null")
		}
	}
	if raw := members[memberMethod]; raw != nil {
		if err := json.Unmarshal(raw, &env.Method); err != nil {
			return nil, parseError("method: %w", err)
		}
	}
	if raw := members[memberParams]; raw != nil {
		if err := json.Unmarshal(raw, &env.Params); err != nil {
			return nil, parseError("params: %w", err)
		}
	}

	env.Canonical = buildCanonical(members, env.Method, true)
	return env, nil
}

// buildCanonical writes the forwarded members in forwardedMembers order,
// method re-encoded from the decoded string; withMetadata=false leaves out
// visibleTo/privateFor.
func buildCanonical(members [len(forwardedMembers)][]byte, method string, withMetadata bool) []byte {
	size := 2
	for _, raw := range members {
		size += len(raw) + 16
	}
	var buf bytes.Buffer
	buf.Grow(size + len(method))
	buf.WriteByte('{')
	for idx, name := range forwardedMembers {
		raw := members[idx]
		if raw == nil || (!withMetadata && (idx == memberVisibleTo || idx == memberPrivateFor)) {
			continue
		}
		if idx == memberMethod {
			// Marshalling a Go string cannot fail; invalid UTF-8 was refused
			// before decoding.
			raw, _ = json.Marshal(method)
		}
		if buf.Len() > 1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(name)
		buf.WriteString(`":`)
		buf.Write(raw)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// keySet records the case-folded member names of one object. Small objects
// (the common case) use a slice; larger ones switch to a map so a body with
// tens of thousands of keys in one object stays linear.
type keySet struct {
	small []string
	large map[string]struct{}
}

// add reports false when an equal-under-folding name was already present.
func (s *keySet) add(folded string) bool {
	if s.large != nil {
		if _, dup := s.large[folded]; dup {
			return false
		}
		s.large[folded] = struct{}{}
		return true
	}
	for _, k := range s.small {
		if k == folded {
			return false
		}
	}
	if len(s.small) < 16 {
		s.small = append(s.small, folded)
		return true
	}
	s.large = make(map[string]struct{}, 2*len(s.small))
	for _, k := range s.small {
		s.large[k] = struct{}{}
	}
	s.large[folded] = struct{}{}
	s.small = nil
	return true
}

// scanEnvelope walks a body that json.Valid has accepted. It refuses:
//   - a document that is not a single object;
//   - in any object at any depth, a repeated member name or two names equal
//     under Unicode simple case folding (the equivalence encoding/json uses
//     to match names), escape sequences decoded first;
//   - at the top level, a case variant of a forwarded member (`Method`);
//   - an unpaired UTF-16 surrogate escape in any string.
//
// It returns the raw value of each forwarded member present at the top level,
// indexed like forwardedMembers (nil when absent), and fieldVariant: the first
// params member name that is a case variant of a paramFieldNames entry
// (`To`). That one is reported rather than refused, because whether it matters
// depends on whether the proxy reads that method's params (see
// ParamsAmbiguity).
//
// The case-variant rules compare with looseFoldKey, which is wider than Go's
// folding, so a name that a common case-insensitive matcher could take for a
// forwarded member or a request field is caught.
func scanEnvelope(body []byte) (members [len(forwardedMembers)][]byte, fieldVariant string, err error) {
	type frame struct {
		object   bool
		wantKey  bool // object: the next string is a member name
		inParams bool // inside the top-level params member
		keys     keySet
	}
	i := skipJSONSpace(body, 0)
	if i >= len(body) || body[i] != '{' {
		return members, fieldVariant, parseError("not a JSON object")
	}

	var (
		stack      []frame
		member     = -1 // index of the forwarded top-level member being read
		valueStart int
	)
	endMember := func(end int) {
		if len(stack) == 1 && member >= 0 {
			members[member] = bytes.TrimRight(body[valueStart:end], " \t\r\n")
			member = -1
		}
	}

	for i < len(body) {
		switch c := body[i]; c {
		case '{', '[':
			inParams := false
			if n := len(stack); n > 0 {
				inParams = stack[n-1].inParams || (n == 1 && member == memberParams)
			}
			stack = append(stack, frame{object: c == '{', wantKey: c == '{', inParams: inParams})
			i++
		case '}', ']':
			endMember(i)
			stack = stack[:len(stack)-1]
			i++
			if len(stack) == 0 {
				return members, fieldVariant, nil // json.Valid: nothing but whitespace follows
			}
		case ',':
			endMember(i)
			if top := &stack[len(stack)-1]; top.object {
				top.wantKey = true
			}
			i++
		case '"':
			end, escaped, serr := scanJSONString(body, i)
			if serr != nil {
				return members, fieldVariant, serr
			}
			top := &stack[len(stack)-1]
			if top.object && top.wantKey {
				top.wantKey = false
				key := string(body[i+1 : end])
				if escaped {
					if err := json.Unmarshal(body[i:end+1], &key); err != nil {
						return members, fieldVariant, parseError("member name: %w", err)
					}
				}
				folded := foldKey(key)
				if !top.keys.add(folded) {
					return members, fieldVariant, ErrAmbiguousRequest
				}
				if len(stack) == 1 {
					if canonical, reserved := reservedLooseFolds[looseFoldKey(key)]; reserved {
						if canonical != key {
							return members, fieldVariant, ErrAmbiguousRequest
						}
						for idx, name := range forwardedMembers {
							if name == key {
								member = idx
							}
						}
						// Valid JSON: whitespace, ':', whitespace, value.
						valueStart = skipJSONSpace(body, skipJSONSpace(body, end+1)+1)
					}
				} else if top.inParams && fieldVariant == "" {
					if canonical, known := paramFieldLooseFolds[looseFoldKey(key)]; known && canonical != key {
						fieldVariant = key
					}
				}
			}
			i = end + 1
		default: // whitespace, ':', number and literal bytes
			i++
		}
	}
	return members, fieldVariant, parseError("unterminated object")
}

func skipJSONSpace(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// scanJSONString returns the index of the closing quote of the string that
// opens at b[start], whether it contains escapes, and an error for an
// unpaired surrogate escape (\uD800-\uDFFF not forming a pair). encoding/json
// silently turns those into U+FFFD, so the proxy would authorise a different
// string from the one a strict node decodes. b must be valid JSON.
func scanJSONString(b []byte, start int) (end int, escaped bool, err error) {
	for j := start + 1; j < len(b); {
		switch b[j] {
		case '"':
			return j, escaped, nil
		case '\\':
			escaped = true
			if b[j+1] != 'u' {
				j += 2
				continue
			}
			r := hex4(b[j+2 : j+6])
			switch {
			case r >= 0xD800 && r < 0xDC00:
				if j+11 < len(b) && b[j+6] == '\\' && b[j+7] == 'u' {
					if lo := hex4(b[j+8 : j+12]); lo >= 0xDC00 && lo < 0xE000 {
						j += 12
						continue
					}
				}
				return 0, false, parseError("unpaired surrogate escape")
			case r >= 0xDC00 && r < 0xE000:
				return 0, false, parseError("unpaired surrogate escape")
			}
			j += 6
		default:
			j++
		}
	}
	return 0, false, parseError("unterminated string")
}

// hex4 decodes four hex digits (already validated by json.Valid).
func hex4(h []byte) rune {
	var r rune
	for _, c := range h {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		}
	}
	return r
}

// foldKey maps a member name to a representative of its Unicode simple-fold
// equivalence class: two names get the same key exactly when strings.EqualFold
// (and so encoding/json's name matching) treats them as equal. Each rune maps
// to the smallest rune of its fold orbit, which for ASCII letters is the
// upper-case letter; that keeps the ASCII fast path consistent with the
// general path ("params" and "paramſ" both fold to "PARAMS").
func foldKey(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToUpper(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		lowest := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < lowest {
				lowest = f
			}
		}
		b.WriteRune(lowest)
	}
	return b.String()
}

// looseFoldKey is foldKey widened to the case mappings other platforms use
// for case-insensitive name matching: a rune whose upper- or lower-case form
// is ASCII is taken as that ASCII letter. That catches names Go does not fold
// but a per-character upper/lower-case comparison (Java's equalsIgnoreCase)
// matches to an ASCII field name, such as "ınput" (U+0131 dotless i) for
// "input". It is only
// compared against the fixed ASCII names of forwardedMembers and
// paramFieldNames.
func looseFoldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch u, l := unicode.ToUpper(r), unicode.ToLower(r); {
		case r < utf8.RuneSelf:
			b.WriteRune(unicode.ToUpper(r))
		case u < utf8.RuneSelf:
			b.WriteRune(u)
		case l < utf8.RuneSelf:
			b.WriteRune(unicode.ToUpper(l))
		default:
			b.WriteRune(r)
		}
	}
	return foldKey(b.String())
}
