// Package policydsl defines the typed, versioned schema for contract execution
// policies and the reference evaluator for them.
//
// A policy is a restriction inside a principal's existing OPS authority. It can
// never widen access: a document cannot manufacture membership, contract
// ownership, KYC state or an administrative bypass. Identity and directory facts
// are supplied at evaluation time by OPS and are never embedded in a policy.
//
// The schema is deliberately closed. Unknown fields, unsupported rule kinds and
// ambiguous references are rejected at validation time so that a policy either
// has exactly one meaning or does not load at all. Every failure path denies.
//
// Known limits of this first grammar, which constrain what a policy can promise:
//
//   - Native value is not modelled. A rule permitting a payable function permits
//     it for any amount of ether. Bounding value needs a field of its own.
//   - Cumulative limits are not supported. A rule can bound one call's argument
//     but not a total across calls, which would need durable counters and a
//     rollback story tied to execution.
//   - Frame completeness is the caller's responsibility. The evaluator denies an
//     empty frame list, but cannot tell a complete trace from a truncated one.
package policydsl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// APIVersion is the only schema version this build accepts.
//
// A document carrying any other value is rejected rather than reinterpreted.
// Introducing a new version means adding a converter into this canonical model,
// never silently changing what an existing document means.
const APIVersion = "privacy.gateway.fm/v1alpha1"

// Kind is the only document kind this package understands.
const Kind = "ContractExecutionPolicy"

// NestedCallsRequireOwnRule is the only supported nested-call semantic.
//
// It means: every frame in an execution, at any depth, must match a rule of its
// own. Reaching contract B through contract A never borrows A's permission.
const NestedCallsRequireOwnRule = "requireOwnRule"

// CallType names an EVM frame's call opcode.
//
// The distinction is load-bearing rather than cosmetic. Under DelegateCall and
// CallCode the executing code and the storage being modified belong to different
// accounts, so a rule that named only one of them would leave the other ungated.
type CallType string

const (
	// CallTypeCall is a normal CALL frame: code and storage are the same account.
	CallTypeCall CallType = "call"
	// CallTypeStaticCall is a STATICCALL frame. It cannot modify state.
	CallTypeStaticCall CallType = "staticcall"
	// CallTypeDelegateCall is a DELEGATECALL frame: the target's code runs against
	// the caller's storage. It must be requested explicitly by a rule.
	CallTypeDelegateCall CallType = "delegatecall"
	// CallTypeCallCode is a CALLCODE frame, the legacy form of DelegateCall.
	CallTypeCallCode CallType = "callcode"
)

// AddressSource names whose address an address constraint compares against.
//
// Signer and Principal are different things and must not be conflated: one
// Ethereum account may be linked to several OPS principals, so recovering a
// signature does not identify the user on whose authority a call runs.
type AddressSource string

const (
	// AddressSourceSigner is the account that signed the submitted transaction.
	AddressSourceSigner AddressSource = "signer"
	// AddressSourcePrincipalLinked is the set of addresses linked to the
	// authenticated OPS principal. The constraint holds if any of them matches.
	AddressSourcePrincipalLinked AddressSource = "principal.linked"
	// AddressSourceLiteral compares against a fixed address written in the policy.
	AddressSourceLiteral AddressSource = "literal"
)

// Policy is one complete, self-contained execution policy document.
type Policy struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`

	// Org is the organisation whose authority this policy restricts. Every
	// contract and group referenced below must belong to it.
	Org string `json:"org"`

	// NestedCalls declares the nested-frame semantic this document was written
	// against. It is explicit so that a later change of default cannot silently
	// alter the meaning of an already-approved document.
	NestedCalls string `json:"nestedCalls"`

	// Bindings map groups to the frames their members may execute. A principal
	// outside every listed group is denied by this policy.
	Bindings []Binding `json:"bindings"`
}

// Binding grants one group a set of permitted execution frames.
type Binding struct {
	// Group is the stable identifier of an existing regular group.
	Group string `json:"group"`

	// Allow is the complete set of frames this group may execute. An empty or
	// absent list denies everything, which is the fail-closed default.
	Allow []FrameRule `json:"allow"`
}

// FrameRule permits one selector on one contract, optionally constrained by
// the decoded arguments of the call.
type FrameRule struct {
	// StorageAddress is the account whose storage the frame may touch. For a
	// normal call this is simply the contract being called.
	StorageAddress string `json:"storageAddress"`

	// CodeAddress is the account whose code executes. Leave it empty for a normal
	// call, where code and storage coincide. A DelegateCall rule must set it,
	// because that is precisely the case where the two differ.
	CodeAddress string `json:"codeAddress,omitempty"`

	// Selector is the exact 4-byte function selector, lowercase hex with an 0x
	// prefix. Selectors are used rather than names because names are ambiguous
	// under overloading.
	Selector string `json:"selector"`

	// ABIDigest pins the ABI this rule was validated against, as lowercase hex
	// sha256 of the canonical ABI text. If the contract's ABI later changes, the
	// mismatch is detectable instead of silently reinterpreting argument indexes.
	ABIDigest string `json:"abiDigest"`

	// CallTypes lists the frame kinds this rule permits. An empty list means
	// call and staticcall only; delegatecall and callcode are never implied.
	CallTypes []CallType `json:"callTypes,omitempty"`

	// Args constrains decoded arguments. All constraints must hold.
	Args []ArgConstraint `json:"args,omitempty"`
}

// ArgConstraint restricts a single decoded argument of a call.
//
// Exactly one of AddressEquals or UintAtMost must be set. A constraint that sets
// neither would be a silent no-op, and one that sets both would have two
// meanings; both are rejected.
type ArgConstraint struct {
	// Index is the zero-based position of the argument in the function's inputs.
	//
	// A document must state it explicitly. Because zero is a meaningful position,
	// an omitted index would quietly constrain the first argument and leave the
	// one the author meant unbounded.
	Index int `json:"index"`

	// AddressEquals constrains an address argument.
	AddressEquals *AddressMatch `json:"addressEquals,omitempty"`

	// UintAtMost is an inclusive upper bound for an unsigned integer argument,
	// written in decimal so that large token amounts survive JSON round-trips.
	UintAtMost *string `json:"uintAtMost,omitempty"`
}

// AddressMatch describes which address an address argument must equal.
type AddressMatch struct {
	Source AddressSource `json:"source"`

	// Value carries the address when Source is literal, and must be empty
	// otherwise so that a document cannot appear to say two different things.
	Value string `json:"value,omitempty"`
}

// clone returns a deep copy of the document.
//
// Validation and evaluation must not be affected by anything the caller does to
// its own copy afterwards, and a document handed out for display or audit must
// not be able to drift from the rules that were actually compiled.
func (p *Policy) clone() *Policy {
	if p == nil {
		return nil
	}

	out := *p
	out.Bindings = make([]Binding, len(p.Bindings))

	for i, b := range p.Bindings {
		nb := b
		nb.Allow = make([]FrameRule, len(b.Allow))

		for j, r := range b.Allow {
			nr := r
			nr.CallTypes = append([]CallType(nil), r.CallTypes...)
			nr.Args = make([]ArgConstraint, len(r.Args))

			for k, a := range r.Args {
				na := a
				if a.AddressEquals != nil {
					m := *a.AddressEquals
					na.AddressEquals = &m
				}
				if a.UintAtMost != nil {
					s := *a.UintAtMost
					na.UintAtMost = &s
				}
				nr.Args[k] = na
			}

			nb.Allow[j] = nr
		}

		out.Bindings[i] = nb
	}

	return &out
}

// UnmarshalJSON decodes an argument constraint, requiring an explicit index.
//
// A custom unmarshaller is needed because the outer decoder's strictness does
// not reach a type that decodes itself, so unknown fields are rejected here too.
func (a *ArgConstraint) UnmarshalJSON(data []byte) error {
	var present map[string]json.RawMessage
	if err := json.Unmarshal(data, &present); err != nil {
		return fmt.Errorf("argument constraint: %w", err)
	}
	if _, ok := present["index"]; !ok {
		return fmt.Errorf("argument constraint: index is required; omitting it would silently constrain argument 0")
	}

	// The alias sheds the method set, so decoding it does not recurse.
	type alias ArgConstraint
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var decoded alias
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("argument constraint: %w", err)
	}

	*a = ArgConstraint(decoded)
	return nil
}

// Parse decodes a policy document into the canonical model.
//
// Decoding is strict: unknown fields are an error rather than being ignored, and
// anything at all after the document is rejected. Parse performs no semantic
// validation; call Validate for that.
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: malformed document: %w", err)
	}

	// Anything after the document, valid JSON or not, means the input was not the
	// single artifact a reviewer approved. More() reports remaining non-whitespace
	// content, so unparseable trailing bytes are caught as well as a second value.
	if dec.More() {
		return nil, fmt.Errorf("policy: unexpected trailing content after document")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("policy: unexpected trailing content after document")
	}

	return &p, nil
}
