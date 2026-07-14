package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Method access policies (RD-1206) bind a record-reader call (e.g.
// getPaymentInfo(id)) to the record's stakeholders, so authorization is
// parameter-bound rather than all-or-nothing per function. A policy NEVER
// widens: the method allowlist, contract grant, claims, function-selector
// list and RD-915 tracing all run first and unchanged; this layer only
// narrows an already-permitted call, and every failure path denies.
//
// See docs/rd-1206-method-policies-design.md for the full model and the
// security-audit resolutions this code implements.

// Limits (validated at write time; see design doc "Policy schema").
const (
	MethodPolicyMaxBytes      = 32 * 1024
	MethodPolicyMaxMethods    = 16
	MethodPolicyMaxRemembered = 8
	MethodPolicyMaxAudience   = 256
)

var (
	errDecode           = errors.New("method policy: return decode failed")
	errPolicyTooLarge   = fmt.Errorf("method policy exceeds %d bytes", MethodPolicyMaxBytes)
	errUnsupportedField = errors.New("method policy: unsupported field")
)

// MethodPolicyDocument is the per-contract policy (contracts.method_policies).
type MethodPolicyDocument struct {
	Records map[string]RecordPolicy `json:"records"`
}

// RecordPolicy groups capture (writer) and access (reader) rules for one
// logical record type on a contract.
type RecordPolicy struct {
	Capture []CaptureSpec `json:"capture"`
	Access  []AccessSpec  `json:"access"`
}

// CaptureSpec remembers values from a writer call under a record key.
type CaptureSpec struct {
	Method   string                   `json:"method"` // canonical ABI signature "name(t1,t2)"
	Key      KeySpec                  `json:"key"`
	Remember map[string]RememberField `json:"remember"`
}

// AccessSpec gates a reader call against captured rows and/or its return.
type AccessSpec struct {
	Method     string      `json:"method"`
	Key        KeySpec     `json:"key"`
	Allow      []AllowRule `json:"allow"`
	OnNoRecord string      `json:"onNoRecord"` // "deny" (only supported outcome)
	Else       string      `json:"else"`       // "deny"
}

// KeySpec locates the record key within a call's calldata.
type KeySpec struct {
	Source string `json:"source"` // "param"
	Index  int    `json:"index"`
}

// RememberField describes one captured value's source and merge behavior.
type RememberField struct {
	Source string `json:"source"`          // "param" | "sender" | "visibleTo"
	Index  *int   `json:"index,omitempty"` // required when Source == "param"
	Merge  string `json:"merge"`           // "set_once" | "union"
}

// AllowRule is one alternative that can admit a caller: either a list of
// captured field names (callerIn: ["payer","payee"]) or a return source
// (callerIn: {source:"return", paths:[...], kind:"address"}). An optional
// `where` further RESTRICTS the rule to records whose captured scalar satisfies
// a comparison — the rule admits only if callerIn matches AND where holds.
type AllowRule struct {
	Fields []string
	Return *ReturnSource
	Where  *WhereCondition `json:"where,omitempty"`
}

// ReturnSource names address-typed outputs of the reader to match the caller.
type ReturnSource struct {
	Paths []string `json:"paths"`
	Kind  string   `json:"kind"` // "address"
}

// WhereCondition compares a captured scalar field against a value (Example 4).
// Numeric ops compare as *big.Int; eq/neq also work for string/address/bytes/
// bool by canonical-string equality. It can only further-restrict a rule.
type WhereCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"` // eq | neq | lt | lte | gt | gte
	Value string `json:"value"`
}

// whereOps is the accepted operator set; numericOps require a numeric field.
var whereOps = map[string]bool{"eq": true, "neq": true, "lt": true, "lte": true, "gt": true, "gte": true}
var numericWhereOps = map[string]bool{"lt": true, "lte": true, "gt": true, "gte": true}

// UnmarshalJSON accepts callerIn as either a string array or a return object,
// and rejects unknown fields both alongside and inside callerIn (L-1: keep the
// strict-parse posture the top-level decoder has).
func (a *AllowRule) UnmarshalJSON(data []byte) error {
	wrapDec := json.NewDecoder(bytes.NewReader(data))
	wrapDec.DisallowUnknownFields()
	var wrap struct {
		CallerIn json.RawMessage `json:"callerIn"`
		Where    *WhereCondition `json:"where"`
	}
	if err := wrapDec.Decode(&wrap); err != nil {
		return err
	}
	if len(wrap.CallerIn) == 0 {
		return errors.New("allow rule missing callerIn")
	}
	a.Where = wrap.Where
	trimmed := strings.TrimSpace(string(wrap.CallerIn))
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal(wrap.CallerIn, &a.Fields)
	}
	rsDec := json.NewDecoder(bytes.NewReader(wrap.CallerIn))
	rsDec.DisallowUnknownFields()
	var rs struct {
		Source string   `json:"source"`
		Paths  []string `json:"paths"`
		Kind   string   `json:"kind"`
	}
	if err := rsDec.Decode(&rs); err != nil {
		return err
	}
	if rs.Source != "return" {
		return fmt.Errorf("callerIn object: unsupported source %q", rs.Source)
	}
	a.Return = &ReturnSource{Paths: rs.Paths, Kind: rs.Kind}
	return nil
}

// ParseMethodPolicyDocument unmarshals and size-checks a policy document.
func ParseMethodPolicyDocument(data []byte) (*MethodPolicyDocument, error) {
	if len(data) > MethodPolicyMaxBytes {
		return nil, errPolicyTooLarge
	}
	var doc MethodPolicyDocument
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("method policy: %w", err)
	}
	if doc.Records == nil {
		return nil, errors.New("method policy: no records")
	}
	return &doc, nil
}

// CapturedField is one stored capture value for a record (loaded from the DB).
type CapturedField struct {
	Field string
	Value string
	Merge string // "set_once" | "union"
}

// CapturedWrite is a value to persist from a writer call.
type CapturedWrite struct {
	RecordType string
	RecordKey  string
	Field      string
	Value      string
	Merge      string
}

// CallerIdentity is the authenticated caller's DID + linked addresses,
// already stripped of empty/zero values.
type CallerIdentity struct {
	dids  map[string]bool
	addrs map[string]bool // lowercased hex
}

// NewCallerIdentity builds the match set, excluding empty and zero values (L3).
func NewCallerIdentity(did string, addresses []string) CallerIdentity {
	ci := CallerIdentity{dids: map[string]bool{}, addrs: map[string]bool{}}
	if did != "" {
		ci.dids[did] = true
	}
	for _, a := range addresses {
		if a == "" || isZeroAddress(a) {
			continue
		}
		ci.addrs[strings.ToLower(a)] = true
	}
	return ci
}

func (ci CallerIdentity) matches(value string) bool {
	if value == "" {
		return false
	}
	if looksLikeAddress(value) {
		if isZeroAddress(value) {
			return false
		}
		return ci.addrs[strings.ToLower(value)]
	}
	return ci.dids[value]
}

// Decision is the outcome of evaluating a reader call against a policy.
type Decision struct {
	Allow    bool
	Poisoned bool // set-once conflict on the key (H3) — deny-all
}

// Validate checks the document against the contract's registered ABI. Rejects
// on write so evaluation never has to handle a malformed policy.
func (d *MethodPolicyDocument) Validate(contractABI string) error {
	if contractABI == "" {
		return errors.New("method policy: contract ABI required")
	}
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return fmt.Errorf("method policy: parse ABI: %w", err)
	}
	methodCount := 0
	selectorOwners := map[string]string{} // selector → record type, reject >1 (H-2)
	for recType, rec := range d.Records {
		if recType == "" {
			return errors.New("method policy: empty record type")
		}
		// key types must agree across capture and access for this record type
		var keyType string
		keyTypeOf := func(sig string, key KeySpec) (string, error) {
			m, ok := methodBySig(parsed, sig)
			if !ok {
				return "", fmt.Errorf("method %q not found in ABI", sig)
			}
			if key.Source != "param" {
				return "", fmt.Errorf("key source %q unsupported", key.Source)
			}
			if key.Index < 0 || key.Index >= len(m.Inputs) {
				return "", fmt.Errorf("key index %d out of range for %s", key.Index, sig)
			}
			kt := m.Inputs[key.Index].Type
			if !canonicalizableType(kt) {
				return "", fmt.Errorf("key type %q of %s is not canonicalizable", kt.String(), sig)
			}
			return kt.String(), nil
		}
		claimSelector := func(sig string) error {
			m, ok := methodBySig(parsed, sig)
			if !ok {
				return fmt.Errorf("method %q not found in ABI", sig)
			}
			sel := "0x" + common.Bytes2Hex(m.ID)
			if owner, seen := selectorOwners[sel]; seen && owner != recType {
				return fmt.Errorf("method %q (selector %s) claimed by more than one record type (%q and %q)", sig, sel, owner, recType)
			}
			selectorOwners[sel] = recType
			return nil
		}
		// declared maps a captured field name → its kind: "did" (sender /
		// visibleTo — DID/DID-list values) or the canonical ABI type of a
		// param source (e.g. "uint256", "address"). callerIn checks membership;
		// where checks the field exists and (for numeric ops) is numeric.
		// declaredMerge tracks the merge mode per name. A field name MAY recur
		// across capture specs of the same record (e.g. audience captured on
		// both createPayment and completePayment — required by the spec), but
		// its (kind, merge) MUST stay consistent, else the same name means two
		// different things (a footgun that can poison or silently widen).
		declared := map[string]string{}
		declaredMerge := map[string]string{}

		for _, cap := range rec.Capture {
			methodCount++
			m, ok := methodBySig(parsed, cap.Method)
			if !ok {
				return fmt.Errorf("capture method %q not found in ABI", cap.Method)
			}
			if err := claimSelector(cap.Method); err != nil {
				return err
			}
			kt, err := keyTypeOf(cap.Method, cap.Key)
			if err != nil {
				return err
			}
			if keyType == "" {
				keyType = kt
			} else if keyType != kt {
				return fmt.Errorf("record %q: key type %q disagrees with %q", recType, kt, keyType)
			}
			if len(cap.Remember) == 0 {
				return fmt.Errorf("capture %q: no remembered fields", cap.Method)
			}
			if len(cap.Remember) > MethodPolicyMaxRemembered {
				return fmt.Errorf("capture %q: too many remembered fields", cap.Method)
			}
			for name, rf := range cap.Remember {
				var kind string
				switch rf.Source {
				case "sender", "visibleTo":
					kind = "did"
				case "param":
					if rf.Index == nil {
						return fmt.Errorf("capture %q field %q: param source requires an index", cap.Method, name)
					}
					if *rf.Index < 0 || *rf.Index >= len(m.Inputs) {
						return fmt.Errorf("capture %q field %q: param index out of range", cap.Method, name)
					}
					if !canonicalizableType(m.Inputs[*rf.Index].Type) {
						return fmt.Errorf("capture %q field %q: param type %q is not canonicalizable", cap.Method, name, m.Inputs[*rf.Index].Type.String())
					}
					kind = m.Inputs[*rf.Index].Type.String()
				default:
					return fmt.Errorf("capture %q field %q: %w %q", cap.Method, name, errUnsupportedField, rf.Source)
				}
				// A field re-declared across captures must keep a consistent kind
				// (a name meaning two different things is a footgun).
				if prev, ok := declared[name]; ok && prev != kind {
					return fmt.Errorf("capture field %q is declared with conflicting kinds %q and %q in record %q", name, prev, kind, recType)
				}
				declared[name] = kind
				switch rf.Merge {
				case "set_once", "union":
				default:
					return fmt.Errorf("capture %q field %q: unsupported merge %q", cap.Method, name, rf.Merge)
				}
				if prev, ok := declaredMerge[name]; ok && prev != rf.Merge {
					return fmt.Errorf("capture field %q is declared with conflicting merge modes %q and %q in record %q", name, prev, rf.Merge, recType)
				}
				declaredMerge[name] = rf.Merge
				// P1 invariant (was wizard-only): a visibleTo audience accumulates
				// across txs, so it MUST be union — set_once would keep only the
				// first tx's list and silently under-expose. Enforce it here so
				// raw-JSON authoring is as safe as the wizard.
				if rf.Source == "visibleTo" && rf.Merge == "set_once" {
					return fmt.Errorf("capture %q field %q: a visibleTo audience must use merge \"union\", not \"set_once\"", cap.Method, name)
				}
			}
		}

		for _, ac := range rec.Access {
			methodCount++
			m, ok := methodBySig(parsed, ac.Method)
			if !ok {
				return fmt.Errorf("access method %q not found in ABI", ac.Method)
			}
			if err := claimSelector(ac.Method); err != nil {
				return err
			}
			kt, err := keyTypeOf(ac.Method, ac.Key)
			if err != nil {
				return err
			}
			if keyType == "" {
				keyType = kt
			} else if keyType != kt {
				return fmt.Errorf("record %q: access key type %q disagrees with %q", recType, kt, keyType)
			}
			if ac.OnNoRecord != "" && ac.OnNoRecord != "deny" {
				return fmt.Errorf("access %q: onNoRecord %q unsupported (only deny)", ac.Method, ac.OnNoRecord)
			}
			if ac.Else != "" && ac.Else != "deny" {
				return fmt.Errorf("access %q: else %q unsupported (only deny)", ac.Method, ac.Else)
			}
			if len(ac.Allow) == 0 {
				return fmt.Errorf("access %q: no allow rules", ac.Method)
			}
			for _, rule := range ac.Allow {
				switch {
				case rule.Return != nil:
					if rule.Return.Kind != "address" {
						return fmt.Errorf("access %q: return kind %q unsupported (only address)", ac.Method, rule.Return.Kind)
					}
					if len(rule.Return.Paths) == 0 {
						return fmt.Errorf("access %q: return source with no paths", ac.Method)
					}
					for _, p := range rule.Return.Paths {
						if !outputIsAddress(m, p) {
							return fmt.Errorf("access %q: return path %q is not an address output", ac.Method, p)
						}
					}
				case len(rule.Fields) > 0:
					for _, f := range rule.Fields {
						// A callerIn entry is either a captured field name (matches
						// the caller against that field's captured values) or a
						// LITERAL principal — a DID or ETH address that matches the
						// caller directly (Example 4: a fixed compliance desk).
						// Anything else (a typo'd field name) is rejected, so
						// literals can't silently swallow mistakes.
						if _, ok := declared[f]; ok {
							continue
						}
						if !isLiteralPrincipal(f) {
							return fmt.Errorf("access %q: callerIn %q is neither a captured field of record %q nor a literal DID/address principal", ac.Method, f, recType)
						}
					}
				default:
					return fmt.Errorf("access %q: empty allow rule", ac.Method)
				}
				// where (Example 4) further-restricts the rule; validate its field
				// is a captured scalar and the op/type are coherent. Only allowed
				// on captured-field rules — scoping a where to specific return
				// paths through the single-decode resolver is out of scope and
				// unneeded by any example; keeping where off return rules keeps
				// the C2 "one forward" property trivially intact.
				if rule.Where != nil {
					if rule.Return != nil {
						return fmt.Errorf("access %q: where is not supported on a return-source rule", ac.Method)
					}
					if err := validateWhere(rule.Where, declared, ac.Method, recType); err != nil {
						return err
					}
				}
			}
		}
	}
	if methodCount > MethodPolicyMaxMethods {
		return fmt.Errorf("method policy: too many gated methods (%d > %d)", methodCount, MethodPolicyMaxMethods)
	}
	return nil
}

// ValidateForClient validates the document against the ABI and returns a
// curated, operator-safe reason string (empty when valid). Unlike a raw
// error chain, the returned reason is safe to surface to the admin client:
// every Validate message describes the admin's OWN submitted policy against the
// contract's registered ABI (method signatures, parameter indices, type names,
// field names) — never internal/DB state, file paths, or wrapped driver errors.
// Handlers surface this string directly (RD-934: the sanitization boundary is
// here, not in the handler).
func (d *MethodPolicyDocument) ValidateForClient(contractABI string) string {
	if err := d.Validate(contractABI); err != nil {
		return err.Error()
	}
	return ""
}

// GatedReader returns the AccessSpec (and its record type) matching a reader's
// calldata selector, or ok=false when the call is not gated by any policy.
func (d *MethodPolicyDocument) GatedReader(calldata []byte, contractABI string) (recordType string, spec AccessSpec, ok bool) {
	if d == nil {
		return "", AccessSpec{}, false
	}
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil || len(calldata) < 4 {
		return "", AccessSpec{}, false
	}
	m, err := parsed.MethodById(calldata[:4])
	if err != nil {
		return "", AccessSpec{}, false
	}
	for rt, rec := range d.Records {
		for _, ac := range rec.Access {
			if ac.Method == m.Sig {
				return rt, ac, true
			}
		}
	}
	return "", AccessSpec{}, false
}

// DecodeCaptures decodes a writer call into the values to persist. Returns an
// empty slice (no error) when the call matches no capture spec.
func (d *MethodPolicyDocument) DecodeCaptures(calldata []byte, senderDID string, visibleTo []string, contractABI string) ([]CapturedWrite, error) {
	if len(calldata) < 4 {
		return nil, nil
	}
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil, fmt.Errorf("method policy: parse ABI: %w", err)
	}
	m, err := parsed.MethodById(calldata[:4])
	if err != nil {
		return nil, nil // unknown selector — nothing to capture
	}
	args, err := m.Inputs.Unpack(calldata[4:])
	if err != nil {
		return nil, fmt.Errorf("method policy: unpack calldata: %w", err)
	}

	var out []CapturedWrite
	for recType, rec := range d.Records {
		for _, cap := range rec.Capture {
			if cap.Method != m.Sig {
				continue
			}
			key, err := canonicalizeArg(args, cap.Key.Index)
			if err != nil {
				return nil, err
			}
			if key == "" {
				return nil, fmt.Errorf("method policy: empty record key for %s", cap.Method)
			}
			for name, rf := range cap.Remember {
				switch rf.Source {
				case "sender":
					if senderDID != "" {
						out = append(out, CapturedWrite{recType, key, name, senderDID, rf.Merge})
					}
				case "param":
					v, err := canonicalizeArg(args, *rf.Index)
					if err != nil {
						return nil, err
					}
					if v != "" && !isZeroAddress(v) {
						out = append(out, CapturedWrite{recType, key, name, v, rf.Merge})
					}
				case "visibleTo":
					n := 0
					for _, did := range visibleTo {
						if did == "" {
							continue
						}
						if n >= MethodPolicyMaxAudience {
							break // cap; writer logs the drop at the call site
						}
						out = append(out, CapturedWrite{recType, key, name, did, rf.Merge})
						n++
					}
				}
			}
		}
	}
	return out, nil
}

// EvaluateAccess decides whether the caller may receive the reader's response.
// captured holds the rows already loaded for (org, contract, recordType, key).
// resolveReturn is consulted ONLY when a capture rule did not already admit the
// caller AND the matched access spec has a return source — so a capture-only
// policy never triggers an upstream forward (C2). resolveReturn must decode the
// single already-forwarded response; the caller is responsible for bounding it
// (H2) and for equalizing timing between allow and deny (C2).
func (d *MethodPolicyDocument) EvaluateAccess(
	recordType string,
	calldata []byte,
	caller CallerIdentity,
	captured []CapturedField,
	resolveReturn func() ([]common.Address, error),
	contractABI string,
) (Decision, error) {
	if d == nil {
		return Decision{Allow: false}, nil
	}
	rt, spec, ok := d.GatedReader(calldata, contractABI)
	if !ok || rt != recordType {
		// Not gated (or record-type mismatch) — caller decides passthrough;
		// this function is only invoked for gated readers, so treat a
		// mismatch as fail-closed deny.
		return Decision{Allow: false}, nil
	}

	// H3: a set-once field with ≥2 distinct values is a poisoned key → deny-all.
	if poisoned := setOncePoisoned(captured); poisoned {
		return Decision{Allow: false, Poisoned: true}, nil
	}

	// index captured values by field name
	byField := map[string][]string{}
	for _, c := range captured {
		byField[c.Field] = append(byField[c.Field], c.Value)
	}

	hasReturnRule := false
	for _, rule := range spec.Allow {
		if rule.Return != nil {
			hasReturnRule = true // where is not permitted on return rules (Validate)
			continue
		}
		// A where condition further-restricts this rule: skip it entirely when
		// the record's captured scalar does not satisfy the comparison.
		if rule.Where != nil && !evalWhere(rule.Where, byField) {
			continue
		}
		for _, f := range rule.Fields {
			if vals, ok := byField[f]; ok {
				for _, v := range vals {
					if caller.matches(v) {
						return Decision{Allow: true}, nil
					}
				}
				continue
			}
			// Not a captured field → a literal principal (DID/address); match
			// the caller directly. (Validate guarantees it is one or the other.)
			if isLiteralPrincipal(f) && caller.matches(f) {
				return Decision{Allow: true}, nil
			}
		}
	}

	if !hasReturnRule {
		return Decision{Allow: false}, nil // capture-only: never forward
	}

	addrs, err := resolveReturn()
	if err != nil {
		return Decision{Allow: false}, nil // fail closed (H2)
	}
	for _, a := range addrs {
		if (a == common.Address{}) {
			continue // zero guard (L3)
		}
		if caller.addrs[strings.ToLower(a.Hex())] {
			return Decision{Allow: true}, nil
		}
	}
	return Decision{Allow: false}, nil
}

// EvaluateReader is the request-path entry point. It resolves the gated reader
// for calldata; if none, gated=false and the caller passes the response through
// unchanged. Otherwise it decodes the record key, loads that record's captures
// via loadCaptures, and evaluates (capture ∪ return). resolveReturn is only
// invoked when a capture rule did not already admit the caller AND the matched
// access spec declares a return source (so a capture-only policy never triggers
// an upstream decode). Every error path fails closed (gated=true, Allow=false).
func (d *MethodPolicyDocument) EvaluateReader(
	calldata []byte,
	caller CallerIdentity,
	loadCaptures func(recordType, recordKey string) ([]CapturedField, error),
	resolveReturn func() ([]common.Address, error),
	contractABI string,
) (gated bool, dec Decision, err error) {
	if d == nil {
		return false, Decision{Allow: false}, nil
	}
	rt, spec, ok := d.GatedReader(calldata, contractABI)
	if !ok {
		return false, Decision{Allow: false}, nil
	}
	parsed, perr := abi.JSON(strings.NewReader(contractABI))
	if perr != nil {
		return true, Decision{Allow: false}, nil // gated but ABI unusable → deny
	}
	key, kerr := decodeRecordKey(spec.Key, calldata, parsed)
	if kerr != nil {
		return true, Decision{Allow: false}, nil
	}
	caps, lerr := loadCaptures(rt, key)
	if lerr != nil {
		return true, Decision{Allow: false}, nil // store error → deny (M1)
	}
	decision, derr := d.EvaluateAccess(rt, calldata, caller, caps, resolveReturn, contractABI)
	if derr != nil {
		return true, Decision{Allow: false}, nil
	}
	return true, decision, nil
}

// ReturnAddressPaths returns the union of address output paths declared by the
// gated reader's return-source allow rules (empty when the call is not gated or
// has no return source). The request-path gate uses it to decode only the
// declared address slots from the already-forwarded response.
func (d *MethodPolicyDocument) ReturnAddressPaths(calldata []byte, contractABI string) []string {
	if d == nil {
		return nil
	}
	_, spec, ok := d.GatedReader(calldata, contractABI)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, rule := range spec.Allow {
		if rule.Return == nil {
			continue
		}
		for _, p := range rule.Return.Paths {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// DecodeReturnAddresses decodes the declared address output paths from a
// reader's return bytes. Bounds the input (H2) and decodes the full output
// tuple once, then selects only the named address outputs.
func DecodeReturnAddresses(returnData []byte, calldata []byte, paths []string, contractABI string) ([]common.Address, error) {
	const maxReturnBytes = 128 * 1024
	if len(returnData) > maxReturnBytes {
		return nil, errDecode
	}
	if len(calldata) < 4 {
		return nil, errDecode
	}
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil, errDecode
	}
	m, err := parsed.MethodById(calldata[:4])
	if err != nil {
		return nil, errDecode
	}
	vals, err := m.Outputs.Unpack(returnData)
	if err != nil {
		return nil, errDecode
	}
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	var out []common.Address
	for i, o := range m.Outputs {
		name := o.Name
		if name == "" {
			name = fmt.Sprintf("%d", i)
		}
		if !want[name] {
			continue
		}
		if i >= len(vals) {
			return nil, errDecode
		}
		a, ok := vals[i].(common.Address)
		if !ok {
			return nil, errDecode
		}
		out = append(out, a)
	}
	return out, nil
}

// ---- helpers ----

func setOncePoisoned(captured []CapturedField) bool {
	seen := map[string]string{} // field -> first set-once value
	for _, c := range captured {
		if c.Merge != "set_once" {
			continue
		}
		if prev, ok := seen[c.Field]; ok {
			if prev != c.Value {
				return true
			}
		} else {
			seen[c.Field] = c.Value
		}
	}
	return false
}

// isNumericKind reports whether a declared field kind is an ABI numeric type.
func isNumericKind(kind string) bool {
	return strings.HasPrefix(kind, "uint") || strings.HasPrefix(kind, "int")
}

// isLiteralPrincipal reports whether a callerIn entry is a literal principal —
// a DID (did:…) or a 0x ETH address — as opposed to a captured field name.
func isLiteralPrincipal(s string) bool {
	return strings.HasPrefix(s, "did:") && len(s) > 4 || looksLikeAddress(s)
}

// validateWhere checks a where condition against the declared capture fields.
// declared maps field name → kind ("did" or an ABI type string).
func validateWhere(w *WhereCondition, declared map[string]string, method, recType string) error {
	if w.Field == "" {
		return fmt.Errorf("access %q: where.field is required", method)
	}
	kind, ok := declared[w.Field]
	if !ok {
		return fmt.Errorf("access %q: where.field %q is not a captured field of record %q", method, w.Field, recType)
	}
	if !whereOps[w.Op] {
		return fmt.Errorf("access %q: where.op %q unsupported (eq,neq,lt,lte,gt,gte)", method, w.Op)
	}
	if numericWhereOps[w.Op] {
		if !isNumericKind(kind) {
			return fmt.Errorf("access %q: where.op %q requires a numeric field, but %q is %q", method, w.Op, w.Field, kind)
		}
		if _, ok := new(big.Int).SetString(w.Value, 10); !ok {
			return fmt.Errorf("access %q: where.value %q is not a valid integer for op %q", method, w.Value, w.Op)
		}
	}
	if w.Value == "" && w.Op != "eq" && w.Op != "neq" {
		return fmt.Errorf("access %q: where.value is required", method)
	}
	return nil
}

// evalWhere returns true iff the record's captured scalar for w.Field satisfies
// the comparison. Fail-closed in every ambiguous case (field absent, multiple
// values, unparsable) — a where can only further-restrict, never widen.
func evalWhere(w *WhereCondition, byField map[string][]string) bool {
	vals := byField[w.Field]
	if len(vals) != 1 {
		return false // scalar expected; absent (0) or multi (union misuse) → deny
	}
	got := vals[0]
	gi, gok := new(big.Int).SetString(got, 10)
	wi, wok := new(big.Int).SetString(w.Value, 10)
	if gok && wok { // numeric comparison (never lexical)
		switch c := gi.Cmp(wi); w.Op {
		case "eq":
			return c == 0
		case "neq":
			return c != 0
		case "lt":
			return c < 0
		case "lte":
			return c <= 0
		case "gt":
			return c > 0
		case "gte":
			return c >= 0
		}
		return false
	}
	// non-numeric: only equality is defined; ordering fails closed.
	switch w.Op {
	case "eq":
		return strings.EqualFold(got, w.Value)
	case "neq":
		return !strings.EqualFold(got, w.Value)
	}
	return false
}

func methodBySig(parsed abi.ABI, sig string) (abi.Method, bool) {
	for _, m := range parsed.Methods {
		if m.Sig == sig {
			return m, true
		}
	}
	return abi.Method{}, false
}

func outputIsAddress(m abi.Method, path string) bool {
	for i, o := range m.Outputs {
		name := o.Name
		if name == "" {
			name = fmt.Sprintf("%d", i)
		}
		if name == path {
			return o.Type.T == abi.AddressTy
		}
	}
	return false
}

// decodeRecordKey unpacks calldata and canonicalizes the key parameter.
func decodeRecordKey(key KeySpec, calldata []byte, parsed abi.ABI) (string, error) {
	if len(calldata) < 4 {
		return "", errDecode
	}
	m, err := parsed.MethodById(calldata[:4])
	if err != nil {
		return "", errDecode
	}
	args, err := m.Inputs.Unpack(calldata[4:])
	if err != nil {
		return "", errDecode
	}
	k, err := canonicalizeArg(args, key.Index)
	if err != nil {
		return "", err
	}
	if k == "" {
		return "", errDecode // empty key never matches a stored record (M-2)
	}
	return k, nil
}

// canonicalizeArg renders a decoded ABI argument to its canonical string form,
// operating on the DECODED typed value (never the raw calldata slice) so
// distinct logical values never collide (M2).
func canonicalizeArg(args []any, index int) (string, error) {
	if index < 0 || index >= len(args) {
		return "", fmt.Errorf("method policy: arg index %d out of range (%d args)", index, len(args))
	}
	switch v := args[index].(type) {
	case string:
		return v, nil
	case common.Address:
		return strings.ToLower(v.Hex()), nil
	case common.Hash:
		return strings.ToLower(v.Hex()), nil
	case [32]byte:
		return strings.ToLower(common.BytesToHash(v[:]).Hex()), nil
	case []byte:
		return "0x" + strings.ToLower(common.Bytes2Hex(v)), nil
	case *big.Int:
		if v == nil {
			return "", nil
		}
		return v.String(), nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	default:
		// go-ethereum decodes uintN/intN with N<256 as native Go ints
		// (uint8/16/32/64, int8/…), and bytesN as [N]byte — cover them so
		// common keys (e.g. a uint64 id) round-trip instead of erroring.
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return strconv.FormatUint(rv.Uint(), 10), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return strconv.FormatInt(rv.Int(), 10), nil
		case reflect.Array:
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				b := make([]byte, rv.Len())
				reflect.Copy(reflect.ValueOf(b), rv)
				return "0x" + strings.ToLower(common.Bytes2Hex(b)), nil
			}
		}
		return "", fmt.Errorf("method policy: unsupported key/param type %T", v)
	}
}

// canonicalizableType reports whether canonicalizeArg can render an ABI type of
// this kind. Validate uses it so a policy can never validate on write and then
// fail to decode at runtime (H-1): scalar value types only — never slices,
// non-byte arrays, tuples, or functions.
func canonicalizableType(t abi.Type) bool {
	switch t.T {
	case abi.StringTy, abi.AddressTy, abi.IntTy, abi.UintTy, abi.BoolTy, abi.FixedBytesTy, abi.BytesTy, abi.HashTy:
		return true
	default:
		return false
	}
}

func looksLikeAddress(s string) bool {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return false
	}
	for _, c := range s[2:] {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func isZeroAddress(s string) bool {
	return looksLikeAddress(s) && common.HexToAddress(s) == (common.Address{})
}
