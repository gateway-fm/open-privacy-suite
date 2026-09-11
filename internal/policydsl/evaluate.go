package policydsl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Frame is one observed EVM call frame.
//
// Frames are supplied by the caller from actual execution, never predicted. The
// evaluator's guarantee is about what really ran, so a frame that was executed
// and reverted, or whose failure an outer contract caught, is still a frame.
type Frame struct {
	// CallType is the opcode that created this frame.
	CallType CallType

	// StorageAddress is the account whose storage this frame may modify. Under
	// DELEGATECALL this is the caller's account, not the call target.
	StorageAddress common.Address

	// CodeAddress is the account whose code executes in this frame. For CALL and
	// STATICCALL it equals StorageAddress.
	CodeAddress common.Address

	// Calldata is the frame's full input, including the leading four selector
	// bytes. The selector is taken from here rather than supplied separately so
	// that the bytes checked are the bytes that ran.
	Calldata []byte
}

// Context carries the runtime facts a decision depends on.
//
// None of these may be asserted by a policy document. They come from OPS at
// evaluation time, which is what stops a policy from granting itself authority.
type Context struct {
	// Org is the organisation the principal is acting in. It must match the
	// policy's own org: group identifiers are only meaningful within one
	// organisation, so evaluating a principal against another org's policy could
	// otherwise match on a colliding identifier.
	Org string

	// Groups are the principal's current group memberships in the organisation.
	Groups []string

	// Signer is the account that signed the submitted transaction. A zero value
	// means the signer is not known, which is never treated as an address a rule
	// can match.
	Signer common.Address

	// LinkedAddresses are the accounts linked to the authenticated principal.
	LinkedAddresses []common.Address
}

// DenialCode is a stable, client-safe category for a denial.
//
// It carries no policy content, so it is the part of a Decision that may be
// shown to the caller who was denied.
type DenialCode string

const (
	// DenialNoMatchingRule means nothing in the policy permitted a frame.
	DenialNoMatchingRule DenialCode = "no_matching_rule"
	// DenialArgumentConstraint means a frame's arguments were out of bounds.
	DenialArgumentConstraint DenialCode = "argument_constraint"
	// DenialMalformedCalldata means a frame's calldata could not be decoded as
	// the function its selector names.
	DenialMalformedCalldata DenialCode = "malformed_calldata"
	// DenialNoFrames means the execution carried no observed frames.
	DenialNoFrames DenialCode = "no_frames_observed"
	// DenialInvalidContext means the supplied runtime facts cannot support a
	// decision, for example a principal from a different organisation.
	DenialInvalidContext DenialCode = "invalid_context"
)

// Decision is the result of evaluating an execution against a policy.
type Decision struct {
	// Allowed is true only when every frame matched a rule.
	Allowed bool

	// Code categorises a denial. It is safe to return to the denied caller.
	Code DenialCode

	// Reason explains a denial in operator-readable terms, naming the first frame
	// that failed. It quotes bounds and addresses from the policy, so it belongs
	// in operator tooling and audit records and must not be returned to the
	// caller who was denied. Send Code instead.
	Reason string
}

// Evaluate decides whether an execution is permitted.
//
// Every frame must match a rule of its own: reaching one contract through
// another never borrows the outer contract's permission. Any frame that matches
// nothing denies the whole execution, and so does any error encountered on the
// way, including undecodable calldata.
func (v *Validated) Evaluate(ctx Context, frames []Frame) Decision {
	if v == nil {
		return deny(DenialInvalidContext, "no policy is loaded")
	}
	if ctx.Org == "" || ctx.Org != v.policy.Org {
		return deny(DenialInvalidContext, fmt.Sprintf("the principal is acting in organisation %q, but this policy governs %q", ctx.Org, v.policy.Org))
	}
	if len(frames) == 0 {
		// An execution with nothing observed is far more likely to be a
		// collection failure than a legitimate no-op, and denying is the only
		// safe reading of it.
		return deny(DenialNoFrames, "no frames were observed for this execution")
	}

	for i, f := range frames {
		if code, err := v.matchFrame(ctx, f); err != nil {
			return deny(code, fmt.Sprintf("frame %d: %v", i, err))
		}
	}

	return Decision{Allowed: true}
}

// matchFrame reports why a frame is not permitted, or nil when it is.
func (v *Validated) matchFrame(ctx Context, f Frame) (DenialCode, error) {
	if len(f.Calldata) < 4 {
		return DenialMalformedCalldata, fmt.Errorf("calldata is %d bytes, too short to carry a function selector", len(f.Calldata))
	}

	var selector [4]byte
	copy(selector[:], f.Calldata[:4])

	key := frameKey{
		storage:  f.StorageAddress,
		code:     f.CodeAddress,
		selector: selector,
	}

	// firstErr keeps the most specific explanation seen. A frame whose selector
	// and contract are permitted but whose arguments are out of bounds should say
	// so, rather than reporting the same "no rule" as an entirely unknown call.
	var firstErr error
	firstCode := DenialNoMatchingRule

	for _, group := range ctx.Groups {
		index, ok := v.byGroup[group]
		if !ok {
			continue
		}
		for _, rule := range index[key] {
			if _, ok := rule.callTypes[f.CallType]; !ok {
				continue
			}
			code, err := rule.checkArgs(ctx, f.Calldata)
			if err != nil {
				if firstErr == nil {
					firstErr, firstCode = err, code
				}
				continue
			}
			return "", nil
		}
	}

	if firstErr != nil {
		return firstCode, firstErr
	}

	return DenialNoMatchingRule, fmt.Errorf("no rule permits %s of selector 0x%s on %s (code %s)",
		callTypeName(f.CallType), hex.EncodeToString(selector[:]), f.StorageAddress.Hex(), f.CodeAddress.Hex())
}

// checkArgs decodes the frame's arguments once and applies every constraint.
func (r *compiledRule) checkArgs(ctx Context, calldata []byte) (DenialCode, error) {
	values, err := decodeCanonical(r.method, calldata)
	if err != nil {
		return DenialMalformedCalldata, err
	}

	for _, a := range r.args {
		if a.index >= len(values) {
			return DenialMalformedCalldata, fmt.Errorf("could not decode argument %d of %s: only %d values present", a.index, r.method.Sig, len(values))
		}
		if err := a.check(ctx, values[a.index]); err != nil {
			return DenialArgumentConstraint, err
		}
	}

	return "", nil
}

// decodeCanonical decodes a frame's arguments and insists the encoding is the
// canonical one for those values.
//
// Unpack alone ignores anything past the arguments it needs, so calldata can
// carry extra bytes that a callee reading raw input still sees. Re-encoding the
// decoded values and requiring the result to equal the input rejects both those
// trailing bytes and any non-canonical encoding that decodes to the same values.
func decodeCanonical(method abi.Method, calldata []byte) ([]any, error) {
	args := calldata[4:]

	values, err := method.Inputs.Unpack(args)
	if err != nil {
		return nil, fmt.Errorf("could not decode arguments of %s: %w", method.Sig, err)
	}

	reencoded, err := method.Inputs.Pack(values...)
	if err != nil {
		return nil, fmt.Errorf("could not re-encode arguments of %s to check the calldata: %w", method.Sig, err)
	}
	if !bytes.Equal(reencoded, args) {
		return nil, fmt.Errorf("calldata for %s is not the canonical encoding of its arguments: %d argument bytes supplied, %d needed", method.Sig, len(args), len(reencoded))
	}

	return values, nil
}

// check applies one prepared constraint to one decoded value.
func (a compiledArg) check(ctx Context, value any) error {
	switch a.kind {
	case argAddress:
		got, ok := value.(common.Address)
		if !ok {
			return fmt.Errorf("argument %d did not decode as an address", a.index)
		}
		return a.checkAddress(ctx, got)

	case argUint:
		got, ok := toUint(value)
		if !ok {
			return fmt.Errorf("argument %d did not decode as an unsigned integer", a.index)
		}
		if got.Cmp(a.max) > 0 {
			return fmt.Errorf("argument %d is %s, above the permitted maximum of %s", a.index, got, a.max)
		}
		return nil

	default:
		// Unreachable for a validated policy. Denying rather than allowing keeps
		// a future constraint kind from defaulting to permitted.
		return fmt.Errorf("argument %d carries an unsupported constraint", a.index)
	}
}

// checkAddress compares a decoded address against the constraint's source.
func (a compiledArg) checkAddress(ctx Context, got common.Address) error {
	switch a.source {
	case AddressSourceSigner:
		// The zero address is what an unset field looks like, so a caller that
		// failed to recover a signer must not satisfy a rule requiring one.
		if ctx.Signer == (common.Address{}) {
			return fmt.Errorf("argument %d must equal the transaction signer, but no signer was supplied for this execution", a.index)
		}
		if got != ctx.Signer {
			return fmt.Errorf("argument %d is %s, but the rule requires the transaction signer %s", a.index, got.Hex(), ctx.Signer.Hex())
		}
		return nil

	case AddressSourcePrincipalLinked:
		if slices.Contains(ctx.LinkedAddresses, got) {
			return nil
		}
		return fmt.Errorf("argument %d is %s, which is not linked to the authenticated principal", a.index, got.Hex())

	case AddressSourceLiteral:
		if got != a.literal {
			return fmt.Errorf("argument %d is %s, but the rule requires %s", a.index, got.Hex(), a.literal.Hex())
		}
		return nil

	default:
		return fmt.Errorf("argument %d carries an unsupported address source", a.index)
	}
}

// toUint normalises the Go types go-ethereum produces for the various uint
// widths into one comparable value.
func toUint(value any) (*big.Int, bool) {
	switch n := value.(type) {
	case *big.Int:
		if n == nil || n.Sign() < 0 {
			return nil, false
		}
		return n, true
	case uint64:
		return new(big.Int).SetUint64(n), true
	case uint32:
		return new(big.Int).SetUint64(uint64(n)), true
	case uint16:
		return new(big.Int).SetUint64(uint64(n)), true
	case uint8:
		return new(big.Int).SetUint64(uint64(n)), true
	default:
		return nil, false
	}
}

// callTypeName renders a frame's call type for a denial message, including one
// the policy schema does not recognise.
func callTypeName(ct CallType) string {
	if ct == "" {
		return "an unspecified call"
	}
	return string(ct)
}

// deny builds a denial carrying its category and its explanation.
func deny(code DenialCode, reason string) Decision {
	return Decision{Allowed: false, Code: code, Reason: reason}
}
