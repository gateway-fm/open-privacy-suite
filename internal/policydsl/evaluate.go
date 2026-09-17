package policydsl

import (
	"encoding/hex"
	"errors"
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

	// The offline caller must supply resolved owner facts explicitly, matching
	// the node's resolver. Shared flags alone never widen literal-address rules.
	CodeKind         uint8
	UpgradeTargetOrg string
	// GroupClaims contains the current target-specific mask for each group.
	GroupClaims     map[string]uint8
	CallerOrg       string
	CodeOrg         string
	StorageOrg      string
	CodeShared      bool
	StorageShared   bool
	StorageDeployer bool
	StoragePending  bool
	CallerAddress   common.Address
	// Nil Value is zero native value. Depth is zero for the top-level frame.
	Value *big.Int
	Depth uint64
}

// Context carries the runtime facts a decision depends on.
//
// None of these may be asserted by a policy document. They come from OPS at
// evaluation time, which is what stops a policy from granting itself authority.
type Context struct {
	// Org is the selected policy organisation. Registered storage selects its
	// owner; native/shared/unowned/create roots use the authenticated identity
	// organisation. The resolver supplies current memberships in this org.
	Org string

	// Groups are the principal's current group memberships in the organisation.
	Groups []string

	// Signer is the account that signed the submitted transaction. A zero value
	// means the signer is not known, which is never treated as an address a rule
	// can match.
	Signer common.Address

	// LinkedAddresses are the accounts linked to the authenticated principal.
	LinkedAddresses []common.Address
	Claims          uint8
	// ReadRecord is an offline reference-oracle dependency. Production execution
	// runs generated STATICCALLs inside the node's live candidate state instead.
	// A missing reader denies record-party constraints.
	ReadRecord func(common.Address, []byte, uint64) ([]byte, error) `json:"-"`
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
	DenialInvalidContext    DenialCode = "invalid_context"
	DenialOwnership         DenialCode = "ownership"
	DenialValue             DenialCode = "value_constraint"
	DenialDepth             DenialCode = "depth_constraint"
	DenialUnsupportedCreate DenialCode = "unsupported_create"
	DenialCaller            DenialCode = "caller_constraint"
	DenialOperationalClaim  DenialCode = "operational_claim"
	DenialInvalidFacts      DenialCode = "invalid_facts"
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
		if f.Value != nil && (f.Value.Sign() < 0 || f.Value.BitLen() > 256) {
			return deny(DenialInvalidContext, fmt.Sprintf("frame %d: native value must fit uint256", i))
		}
		if code, err := v.matchFrame(ctx, f); err != nil {
			return deny(code, fmt.Sprintf("frame %d: %v", i, err))
		}
	}

	return Decision{Allowed: true}
}

// matchFrame reports why a frame is not permitted, or nil when it is.
func (v *Validated) matchFrame(ctx Context, f Frame) (DenialCode, error) {
	if f.CodeKind > CodePrecompile {
		return DenialInvalidFacts, fmt.Errorf("unknown code kind")
	}
	var selector [4]byte
	if len(f.Calldata) >= 4 {
		copy(selector[:], f.Calldata[:4])
	}
	var firstErr error
	firstCode := DenialNoMatchingRule
	for _, group := range ctx.Groups {
		index := v.byGroup[group]
		for _, key := range sortedFrameKeys(index) {
			if !key.matchesTarget(ctx.Org, f) {
				continue
			}
			if key.selectorMode == selectorExact && (len(f.Calldata) < 4 || key.selector != selector) {
				continue
			}
			if key.selectorMode == selectorEmpty && len(f.Calldata) != 0 {
				continue
			}
			for _, rule := range index[key] {
				if _, ok := rule.callTypes[f.CallType]; !ok {
					continue
				}
				code, err := rule.checkAuthority(ctx, f, f.GroupClaims[group], key)
				if err == nil {
					code, err = rule.checkArgs(ctx, f)
				}
				if err != nil {
					if firstErr == nil {
						firstErr, firstCode = err, code
					}
					continue
				}
				return "", nil
			}
		}
	}
	if firstErr != nil {
		return firstCode, firstErr
	}
	if f.CallType == CallTypeCreate || f.CallType == CallTypeCreate2 {
		return DenialUnsupportedCreate, fmt.Errorf("no deployment rule permits this frame")
	}
	if f.CodeOrg != ctx.Org || f.StorageOrg != ctx.Org {
		return DenialOwnership, fmt.Errorf("no explicit target class permits this ownership")
	}
	if len(f.Calldata) < 4 {
		return DenialMalformedCalldata, fmt.Errorf("calldata has no function selector and no wildcard rule")
	}
	return DenialNoMatchingRule, fmt.Errorf("no rule permits %s of selector 0x%s on %s (code %s)", callTypeName(f.CallType), hex.EncodeToString(selector[:]), f.StorageAddress.Hex(), f.CodeAddress.Hex())
}

// checkArgs applies every constraint to the frame's calldata.
//
// Arguments are read as head slots, which is the same view a policy contract
// has. Nothing is decoded out of line, so a constraint can only ever be placed
// on a statically sized argument, which validation already enforces.
func (r *compiledRule) checkArgs(ctx Context, f Frame) (DenialCode, error) {
	calldata := f.Calldata
	if len(calldata) < r.headLen() {
		return DenialMalformedCalldata, fmt.Errorf("calldata for %s is %d bytes, too short for its %d-word ABI head", r.sig, len(calldata), r.headSlots)
	}
	// Every argument of a fully static signature sits in the head, so anything
	// past it is calldata a callee reading raw input would still see.
	if r.exactLen && len(calldata) != r.headLen() {
		return DenialMalformedCalldata, fmt.Errorf("calldata for %s is %d bytes, but its arguments occupy exactly %d", r.sig, len(calldata), r.headLen())
	}
	if r.maxValue != nil && f.Value != nil && f.Value.Cmp(r.maxValue) > 0 {
		return DenialValue, fmt.Errorf("native value exceeds the rule's bound")
	}
	if r.maxDepth != nil && f.Depth > uint64(*r.maxDepth) {
		return DenialDepth, fmt.Errorf("frame depth exceeds the rule's bound")
	}
	if r.caller != nil && f.CallerAddress != *r.caller {
		return DenialCaller, fmt.Errorf("immediate caller differs from the rule's callerAddress")
	}

	for _, a := range r.args {
		if a.kind == argRecordParty {
			code, err := a.checkRecordParty(ctx, f, r.headLen())
			if err != nil {
				return code, err
			}
			continue
		}
		slot := calldata[a.offset : a.offset+32]
		if err := a.check(ctx, slot); err != nil {
			if errors.Is(err, errMalformedArgument) {
				return DenialMalformedCalldata, err
			}
			return DenialArgumentConstraint, err
		}
	}

	return "", nil
}

// errMalformedArgument marks a slot that does not hold a well-formed value of
// the argument's declared type, as opposed to a value that is merely out of
// bounds. Both deny; they are separated so the denial is categorised honestly.
var errMalformedArgument = errors.New("malformed argument")

// check applies one prepared constraint to one 32-byte head slot.
func (a compiledArg) check(ctx Context, slot []byte) error {
	word := new(big.Int).SetBytes(slot)

	switch a.kind {
	case argAddress:
		// An address occupies the low 20 bytes. A slot with anything above them
		// is not a canonically encoded address, whatever it would truncate to.
		for _, b := range slot[:12] {
			if b != 0 {
				return fmt.Errorf("%w: argument %d is not a canonically encoded address", errMalformedArgument, a.index)
			}
		}
		return a.checkAddress(ctx, common.BytesToAddress(slot))

	case argUint:
		if a.bits < 256 && word.BitLen() > a.bits {
			return fmt.Errorf("%w: argument %d does not fit its declared uint%d", errMalformedArgument, a.index, a.bits)
		}
		if word.Cmp(a.max) > 0 {
			return fmt.Errorf("argument %d is %s, above the permitted maximum of %s", a.index, word, a.max)
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
