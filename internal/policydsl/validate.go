package policydsl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Catalog supplies the organisation facts a policy is checked against.
//
// It is passed in rather than looked up so that validation is a pure function of
// the document and an explicit snapshot. The same snapshot can then be recorded
// alongside an approved policy, which is what makes a review reproducible.
type Catalog struct {
	// Org is the organisation the policy must declare.
	Org string

	// Groups holds the stable identifiers of regular groups in the organisation.
	Groups map[string]struct{}

	// Contracts maps a lowercase contract address to its registered ABI.
	Contracts map[string]ContractInfo
}

// ContractInfo is the registered state of one contract in the catalog.
type ContractInfo struct {
	// ABI is the canonical ABI JSON text registered for the contract.
	ABI string
}

// argKind is the decoded-argument category a constraint applies to.
type argKind uint8

const (
	argAddress argKind = iota + 1
	argUint
)

// compiledArg is one argument constraint with its comparison prepared.
type compiledArg struct {
	index   int
	kind    argKind
	bits    int // declared width for a uint argument
	source  AddressSource
	literal common.Address
	max     *big.Int
}

// compiledRule is one frame rule with its decoder and call types prepared.
//
// Arguments are read as head slots rather than fully ABI-decoded. Every
// top-level argument occupies exactly one 32-byte head slot, so a statically
// typed argument can be read at a fixed offset whatever its neighbours are. That
// is also all a Solidity policy contract can afford to do, and reading the same
// bytes the same way is what lets the two implementations be proven equivalent
// rather than merely tested side by side.
type compiledRule struct {
	sig       string
	headSlots int  // one per top-level argument
	exactLen  bool // true when every argument is statically sized
	callTypes map[CallType]struct{}
	args      []compiledArg
}

// headLen is the calldata length this rule's arguments occupy, including the
// four selector bytes.
func (r *compiledRule) headLen() int { return 4 + 32*r.headSlots }

// isDynamicType reports whether an ABI type is encoded out of line.
//
// go-ethereum keeps its own copy of this unexported, and the answer decides
// whether a calldata length can be pinned exactly, so it is spelled out here.
func isDynamicType(t abi.Type) bool {
	switch t.T {
	case abi.StringTy, abi.BytesTy, abi.SliceTy:
		return true
	case abi.TupleTy:
		for _, elem := range t.TupleElems {
			if isDynamicType(*elem) {
				return true
			}
		}
		return false
	case abi.ArrayTy:
		return isDynamicType(*t.Elem)
	default:
		return false
	}
}

// frameKey identifies the frame shape a rule applies to.
//
// Code and storage are both part of the key because they are the same account
// only for CALL and STATICCALL. Keying on one alone would let a DELEGATECALL
// satisfy a rule written for the other account.
type frameKey struct {
	storage  common.Address
	code     common.Address
	selector [4]byte
}

// Validated is a policy that passed validation, together with the prepared
// lookup structures the evaluator uses.
//
// Building this is the "compile once" step: ABI parsing, selector resolution and
// argument decoding are done here, at activation time, so that evaluating a
// frame is a map lookup and a comparison rather than a JSON and ABI parse.
type Validated struct {
	policy  *Policy
	byGroup map[string]map[frameKey][]*compiledRule
}

// Policy returns a copy of the document this was built from.
//
// It is a copy so that a display, export or audit path cannot edit the document
// out from under the compiled rules that are actually enforced.
func (v *Validated) Policy() *Policy { return v.policy.clone() }

// knownCallTypes is the closed set of frame kinds a rule may name.
var knownCallTypes = map[CallType]struct{}{
	CallTypeCall:         {},
	CallTypeStaticCall:   {},
	CallTypeDelegateCall: {},
	CallTypeCallCode:     {},
}

// defaultCallTypes applies when a rule names none. Delegatecall and callcode are
// deliberately absent: borrowing another account's storage context is never
// something a rule should permit by omission.
var defaultCallTypes = map[CallType]struct{}{
	CallTypeCall:       {},
	CallTypeStaticCall: {},
}

// Validate checks a parsed policy against a catalog snapshot and prepares it for
// evaluation. Any problem is an error; there is no partial success and no
// best-effort mode, because a half-loaded policy would silently permit frames the
// reviewer believed were constrained.
func Validate(p *Policy, cat Catalog) (*Validated, error) {
	if p == nil {
		return nil, fmt.Errorf("policy: document is missing")
	}
	if p.APIVersion != APIVersion {
		return nil, fmt.Errorf("policy: unsupported apiVersion %q, this build accepts only %q", p.APIVersion, APIVersion)
	}
	if p.Kind != Kind {
		return nil, fmt.Errorf("policy: unsupported kind %q, expected %q", p.Kind, Kind)
	}
	if p.Org == "" || p.Org != cat.Org {
		return nil, fmt.Errorf("policy: org %q does not match the organisation being configured (%q)", p.Org, cat.Org)
	}
	if p.NestedCalls != NestedCallsRequireOwnRule {
		return nil, fmt.Errorf("policy: unsupported nestedCalls %q, this build accepts only %q", p.NestedCalls, NestedCallsRequireOwnRule)
	}

	// Own a copy, so the compiled rules cannot be contradicted by a later edit to
	// the caller's document.
	v := &Validated{
		policy:  p.clone(),
		byGroup: make(map[string]map[frameKey][]*compiledRule, len(p.Bindings)),
	}

	// Parsed ABIs are memoised per contract so that a policy naming many
	// selectors on one contract parses its ABI once.
	parsedABIs := make(map[string]map[string]abi.Method, len(cat.Contracts))

	for bi, b := range p.Bindings {
		if b.Group == "" {
			return nil, fmt.Errorf("policy: binding %d has an empty group", bi)
		}
		if _, ok := cat.Groups[b.Group]; !ok {
			return nil, fmt.Errorf("policy: binding %d names group %q, which does not exist in this organisation", bi, b.Group)
		}
		if _, dup := v.byGroup[b.Group]; dup {
			return nil, fmt.Errorf("policy: group %q appears in more than one binding; merge them so the document has one meaning", b.Group)
		}

		index := make(map[frameKey][]*compiledRule, len(b.Allow))
		for ri, r := range b.Allow {
			key, rule, err := compileRule(r, cat, parsedABIs)
			if err != nil {
				return nil, fmt.Errorf("policy: binding %d (group %q), rule %d: %w", bi, b.Group, ri, err)
			}
			// Two rules on the same contract, code account and selector would be
			// combined with OR, so the looser one decides and the tighter one is
			// dead text a reviewer cannot distinguish from an enforced bound.
			if _, dup := index[key]; dup {
				return nil, fmt.Errorf("policy: binding %d (group %q), rule %d: selector %s on %s is already covered by an earlier rule; combine them, because two rules would be read as either-or and the looser one would decide",
					bi, b.Group, ri, r.Selector, r.StorageAddress)
			}
			index[key] = append(index[key], rule)
		}
		v.byGroup[b.Group] = index
	}

	return v, nil
}

// compileRule validates one frame rule and prepares its decoder.
func compileRule(r FrameRule, cat Catalog, parsedABIs map[string]map[string]abi.Method) (frameKey, *compiledRule, error) {
	var zero frameKey

	if !common.IsHexAddress(r.StorageAddress) {
		return zero, nil, fmt.Errorf("storageAddress %q is not a valid address", r.StorageAddress)
	}
	storageKey := catalogKey(r.StorageAddress)
	if _, ok := cat.Contracts[storageKey]; !ok {
		return zero, nil, fmt.Errorf("storageAddress %s is not a contract registered to this organisation", r.StorageAddress)
	}

	callTypes, err := resolveCallTypes(r)
	if err != nil {
		return zero, nil, err
	}

	// The ABI that matters is the one belonging to the account whose code runs.
	// For a normal call that is the contract itself. Under delegatecall it is the
	// implementation, not the proxy whose storage is being written, so resolving
	// the selector and argument types against the storage account would describe
	// the wrong function and bound the wrong bytes.
	codeKey := storageKey
	if r.CodeAddress != "" {
		if !common.IsHexAddress(r.CodeAddress) {
			return zero, nil, fmt.Errorf("codeAddress %q is not a valid address", r.CodeAddress)
		}
		codeKey = catalogKey(r.CodeAddress)
	}

	code, ok := cat.Contracts[codeKey]
	if !ok {
		return zero, nil, fmt.Errorf("codeAddress %s is not a contract registered to this organisation; its ABI is what decides what the selector and arguments mean, so it must be registered before a rule can name it", r.CodeAddress)
	}

	// A rule naming a separate code account may only permit the frame kinds where
	// the two accounts actually differ. Leaving call in the list would look like a
	// permission but could never match anything.
	if codeKey != storageKey {
		for _, ct := range []CallType{CallTypeCall, CallTypeStaticCall} {
			if _, ok := callTypes[ct]; ok {
				return zero, nil, fmt.Errorf("callTypes includes %q while codeAddress differs from storageAddress; code and storage are the same account for that frame kind, so the entry could never match", ct)
			}
		}
	}

	selector, err := parseSelector(r.Selector)
	if err != nil {
		return zero, nil, err
	}

	if r.ABIDigest == "" {
		return zero, nil, fmt.Errorf("abiDigest is required so that a later ABI change is detected rather than silently reinterpreting argument positions")
	}
	sum := sha256.Sum256([]byte(code.ABI))
	if !strings.EqualFold(r.ABIDigest, hex.EncodeToString(sum[:])) {
		return zero, nil, fmt.Errorf("abiDigest does not match the ABI registered for the executing code at %s; re-derive the policy against the current ABI", displayAddress(r.CodeAddress, r.StorageAddress))
	}

	methods, ok := parsedABIs[codeKey]
	if !ok {
		parsed, perr := abi.JSON(strings.NewReader(code.ABI))
		if perr != nil {
			return zero, nil, fmt.Errorf("the ABI registered for %s does not parse: %w", displayAddress(r.CodeAddress, r.StorageAddress), perr)
		}
		methods = make(map[string]abi.Method, len(parsed.Methods))
		for _, m := range parsed.Methods {
			methods["0x"+hex.EncodeToString(m.ID)] = m
		}
		parsedABIs[codeKey] = methods
	}

	method, ok := methods["0x"+hex.EncodeToString(selector[:])]
	if !ok {
		return zero, nil, fmt.Errorf("selector %s does not appear in the ABI registered for %s", r.Selector, displayAddress(r.CodeAddress, r.StorageAddress))
	}

	args, err := compileArgs(r.Args, method)
	if err != nil {
		return zero, nil, err
	}

	exact := true
	for _, in := range method.Inputs {
		if isDynamicType(in.Type) {
			exact = false
			break
		}
	}

	return frameKey{
			storage:  common.HexToAddress(storageKey),
			code:     common.HexToAddress(codeKey),
			selector: selector,
		}, &compiledRule{
			sig:       method.Sig,
			headSlots: len(method.Inputs),
			exactLen:  exact,
			callTypes: callTypes,
			args:      args,
		}, nil
}

// resolveCallTypes checks the declared frame kinds and their relationship to
// CodeAddress. The two fields constrain each other, so they are checked together.
func resolveCallTypes(r FrameRule) (map[CallType]struct{}, error) {
	if len(r.CallTypes) == 0 {
		if r.CodeAddress != "" {
			return nil, fmt.Errorf("codeAddress is set but callTypes is empty; code and storage differ only for delegatecall or callcode, so name the call type explicitly")
		}
		// Copied rather than shared, so that a rule can never reach the map every
		// other default-typed rule in the process is using.
		out := make(map[CallType]struct{}, len(defaultCallTypes))
		for ct := range defaultCallTypes {
			out[ct] = struct{}{}
		}
		return out, nil
	}

	set := make(map[CallType]struct{}, len(r.CallTypes))
	borrowsStorage := false
	for _, ct := range r.CallTypes {
		if _, ok := knownCallTypes[ct]; !ok {
			return nil, fmt.Errorf("callTypes contains %q, which is not a supported frame kind", ct)
		}
		if _, dup := set[ct]; dup {
			return nil, fmt.Errorf("callTypes lists %q twice", ct)
		}
		set[ct] = struct{}{}
		if ct == CallTypeDelegateCall || ct == CallTypeCallCode {
			borrowsStorage = true
		}
	}

	if borrowsStorage && r.CodeAddress == "" {
		return nil, fmt.Errorf("callTypes permits delegatecall or callcode, so codeAddress must name the account whose code may run against this storage")
	}
	if !borrowsStorage && r.CodeAddress != "" {
		return nil, fmt.Errorf("codeAddress is set but callTypes permits only call or staticcall, where code and storage are the same account; remove one of the two")
	}

	return set, nil
}

// catalogKey normalises an address to the form Catalog is keyed by.
//
// Addresses reach us checksummed, lowercase, or bare, and all three name the
// same account. Normalising through the address type rather than the string
// keeps a formatting difference from being reported as an authorization failure.
func catalogKey(addr string) string {
	return strings.ToLower(common.HexToAddress(addr).Hex())
}

// displayAddress names the account an ABI error is about, falling back to the
// storage address when a rule did not set a separate code address.
func displayAddress(code, storage string) string {
	if code != "" {
		return code
	}
	return storage
}

// isPlainDecimal reports whether s is decimal digits and nothing else.
//
// big.Int accepts a leading sign and underscores, so a bound written as "+100"
// would parse. Requiring plain digits keeps the reviewed text and the enforced
// value the same string.
func isPlainDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseSelector accepts exactly a 0x-prefixed four-byte selector.
//
// Function names are not accepted because overloading makes them ambiguous, and
// an ambiguous rule is one a reviewer cannot check.
func parseSelector(s string) ([4]byte, error) {
	var out [4]byte
	if !strings.HasPrefix(s, "0x") || len(s) != 10 {
		return out, fmt.Errorf("selector %q must be a 0x-prefixed four-byte hex value, for example 0xa9059cbb", s)
	}
	raw, err := hex.DecodeString(s[2:])
	if err != nil {
		return out, fmt.Errorf("selector %q is not valid hex: %w", s, err)
	}
	copy(out[:], raw)
	return out, nil
}

// compileArgs validates argument constraints against the resolved method and
// prepares their comparisons.
func compileArgs(args []ArgConstraint, method abi.Method) ([]compiledArg, error) {
	if len(args) == 0 {
		return nil, nil
	}

	out := make([]compiledArg, 0, len(args))
	seen := make(map[int]struct{}, len(args))

	for _, a := range args {
		if a.Index < 0 || a.Index >= len(method.Inputs) {
			return nil, fmt.Errorf("argument index %d is out of range; %s has %d inputs", a.Index, method.Sig, len(method.Inputs))
		}
		if _, dup := seen[a.Index]; dup {
			return nil, fmt.Errorf("argument index %d is constrained more than once; combine the conditions into one entry", a.Index)
		}
		seen[a.Index] = struct{}{}

		hasAddr := a.AddressEquals != nil
		hasUint := a.UintAtMost != nil
		if hasAddr == hasUint {
			return nil, fmt.Errorf("argument %d must set exactly one of addressEquals or uintAtMost", a.Index)
		}

		input := method.Inputs[a.Index]

		switch {
		case hasAddr:
			if input.Type.T != abi.AddressTy {
				return nil, fmt.Errorf("argument %d of %s has type %s, so it cannot carry an addressEquals constraint", a.Index, method.Sig, input.Type)
			}
			ca, err := compileAddressMatch(a.Index, *a.AddressEquals)
			if err != nil {
				return nil, err
			}
			out = append(out, ca)

		case hasUint:
			if input.Type.T != abi.UintTy {
				return nil, fmt.Errorf("argument %d of %s has type %s, so it cannot carry a uintAtMost constraint", a.Index, method.Sig, input.Type)
			}
			if !isPlainDecimal(*a.UintAtMost) {
				return nil, fmt.Errorf("argument %d: uintAtMost %q is not a plain decimal integer; write large amounts as decimal digits with no sign or prefix", a.Index, *a.UintAtMost)
			}
			max, ok := new(big.Int).SetString(*a.UintAtMost, 10)
			if !ok {
				return nil, fmt.Errorf("argument %d: uintAtMost %q is not a decimal integer; write large amounts as a decimal string", a.Index, *a.UintAtMost)
			}
			// A bound at or above the argument's own ceiling can never reject
			// anything, which is the silent no-op the schema otherwise rejects.
			ceiling := new(big.Int).Lsh(big.NewInt(1), uint(input.Type.Size))
			ceiling.Sub(ceiling, big.NewInt(1))
			if max.Cmp(ceiling) >= 0 {
				return nil, fmt.Errorf("argument %d: uintAtMost %s is not below the maximum of %s, so the bound could never reject a value", a.Index, max, input.Type)
			}
			out = append(out, compiledArg{index: a.Index, kind: argUint, bits: input.Type.Size, max: max})
		}
	}

	return out, nil
}

// compileAddressMatch checks one address comparison and prepares it.
func compileAddressMatch(index int, m AddressMatch) (compiledArg, error) {
	out := compiledArg{index: index, kind: argAddress, source: m.Source}

	switch m.Source {
	case AddressSourceSigner, AddressSourcePrincipalLinked:
		if m.Value != "" {
			return out, fmt.Errorf("argument %d: addressEquals source %q compares against a runtime address, so value must be empty", index, m.Source)
		}
	case AddressSourceLiteral:
		if m.Value == "" {
			return out, fmt.Errorf("argument %d: addressEquals source %q requires value to name the address", index, m.Source)
		}
		if !common.IsHexAddress(m.Value) {
			return out, fmt.Errorf("argument %d: addressEquals value %q is not a valid address", index, m.Value)
		}
		out.literal = common.HexToAddress(m.Value)
	default:
		return out, fmt.Errorf("argument %d: unknown addressEquals source %q", index, m.Source)
	}

	return out, nil
}
