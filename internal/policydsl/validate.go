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
	source  AddressSource
	literal common.Address
	max     *big.Int
}

// compiledRule is one frame rule with its decoder and call types prepared.
type compiledRule struct {
	method    abi.Method
	callTypes map[CallType]struct{}
	args      []compiledArg
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

// Policy returns the document this was built from.
func (v *Validated) Policy() *Policy { return v.policy }

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

	v := &Validated{
		policy:  p,
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
	storageKey := strings.ToLower(r.StorageAddress)
	contract, ok := cat.Contracts[storageKey]
	if !ok {
		return zero, nil, fmt.Errorf("storageAddress %s is not a contract registered to this organisation", r.StorageAddress)
	}

	callTypes, err := resolveCallTypes(r)
	if err != nil {
		return zero, nil, err
	}

	codeAddr := common.HexToAddress(storageKey)
	if r.CodeAddress != "" {
		if !common.IsHexAddress(r.CodeAddress) {
			return zero, nil, fmt.Errorf("codeAddress %q is not a valid address", r.CodeAddress)
		}
		codeAddr = common.HexToAddress(strings.ToLower(r.CodeAddress))
	}

	selector, err := parseSelector(r.Selector)
	if err != nil {
		return zero, nil, err
	}

	if r.ABIDigest == "" {
		return zero, nil, fmt.Errorf("abiDigest is required so that a later ABI change is detected rather than silently reinterpreting argument positions")
	}
	sum := sha256.Sum256([]byte(contract.ABI))
	if !strings.EqualFold(r.ABIDigest, hex.EncodeToString(sum[:])) {
		return zero, nil, fmt.Errorf("abiDigest does not match the ABI registered for %s; re-derive the policy against the current ABI", r.StorageAddress)
	}

	methods, ok := parsedABIs[storageKey]
	if !ok {
		parsed, perr := abi.JSON(strings.NewReader(contract.ABI))
		if perr != nil {
			return zero, nil, fmt.Errorf("the ABI registered for %s does not parse: %w", r.StorageAddress, perr)
		}
		methods = make(map[string]abi.Method, len(parsed.Methods))
		for _, m := range parsed.Methods {
			methods["0x"+hex.EncodeToString(m.ID)] = m
		}
		parsedABIs[storageKey] = methods
	}

	method, ok := methods["0x"+hex.EncodeToString(selector[:])]
	if !ok {
		return zero, nil, fmt.Errorf("selector %s does not appear in the ABI registered for %s", r.Selector, r.StorageAddress)
	}

	args, err := compileArgs(r.Args, method)
	if err != nil {
		return zero, nil, err
	}

	return frameKey{
			storage:  common.HexToAddress(storageKey),
			code:     codeAddr,
			selector: selector,
		}, &compiledRule{
			method:    method,
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
		return defaultCallTypes, nil
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
			max, ok := new(big.Int).SetString(*a.UintAtMost, 10)
			if !ok {
				return nil, fmt.Errorf("argument %d: uintAtMost %q is not a decimal integer; write large amounts as a decimal string", a.Index, *a.UintAtMost)
			}
			if max.Sign() < 0 {
				return nil, fmt.Errorf("argument %d: uintAtMost %q is negative, which no unsigned value can satisfy", a.Index, *a.UintAtMost)
			}
			out = append(out, compiledArg{index: a.Index, kind: argUint, max: max})
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
