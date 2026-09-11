package policydsl

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"

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
	// Groups are the principal's current group memberships in the organisation.
	Groups []string

	// Signer is the account that signed the submitted transaction.
	Signer common.Address

	// LinkedAddresses are the accounts linked to the authenticated principal.
	LinkedAddresses []common.Address
}

// Decision is the result of evaluating an execution against a policy.
type Decision struct {
	// Allowed is true only when every frame matched a rule.
	Allowed bool

	// Reason explains a denial in operator-readable terms. It is never empty for
	// a denial, and names the first frame that failed rather than the last.
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
		return deny("no policy is loaded")
	}
	if len(frames) == 0 {
		// An execution with nothing observed is far more likely to be a
		// collection failure than a legitimate no-op, and denying is the only
		// safe reading of it.
		return deny("no frames were observed for this execution")
	}

	for i, f := range frames {
		if err := v.matchFrame(ctx, f); err != nil {
			return deny(fmt.Sprintf("frame %d: %v", i, err))
		}
	}

	return Decision{Allowed: true}
}

// matchFrame reports why a frame is not permitted, or nil when it is.
func (v *Validated) matchFrame(ctx Context, f Frame) error {
	if len(f.Calldata) < 4 {
		return fmt.Errorf("calldata is %d bytes, too short to carry a function selector", len(f.Calldata))
	}

	var selector [4]byte
	copy(selector[:], f.Calldata[:4])

	key := frameKey{
		storage:  f.StorageAddress,
		code:     f.CodeAddress,
		selector: selector,
	}

	// argErr keeps the most specific explanation seen. A frame whose selector and
	// contract are permitted but whose arguments are out of bounds should say so,
	// rather than reporting the same "no rule" as an entirely unknown call.
	var argErr error

	for _, group := range ctx.Groups {
		index, ok := v.byGroup[group]
		if !ok {
			continue
		}
		for _, rule := range index[key] {
			if _, ok := rule.callTypes[f.CallType]; !ok {
				continue
			}
			if err := rule.checkArgs(ctx, f.Calldata); err != nil {
				if argErr == nil {
					argErr = err
				}
				continue
			}
			return nil
		}
	}

	if argErr != nil {
		return argErr
	}

	return fmt.Errorf("no rule permits %s of selector 0x%s on %s (code %s)",
		callTypeName(f.CallType), hex.EncodeToString(selector[:]), f.StorageAddress.Hex(), f.CodeAddress.Hex())
}

// checkArgs decodes the frame's arguments once and applies every constraint.
func (r *compiledRule) checkArgs(ctx Context, calldata []byte) error {
	if len(r.args) == 0 {
		return nil
	}

	values, err := r.method.Inputs.Unpack(calldata[4:])
	if err != nil {
		return fmt.Errorf("could not decode arguments of %s: %w", r.method.Sig, err)
	}

	for _, a := range r.args {
		if a.index >= len(values) {
			return fmt.Errorf("could not decode argument %d of %s: only %d values present", a.index, r.method.Sig, len(values))
		}
		if err := a.check(ctx, values[a.index]); err != nil {
			return err
		}
	}

	return nil
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

// deny builds a denial carrying its explanation.
func deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}
