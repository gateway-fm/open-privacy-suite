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
package policydsl

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// Parse decodes a policy document into the canonical model.
//
// Decoding is strict: unknown fields are an error rather than being ignored, and
// trailing content after the document is rejected. Parse performs no semantic
// validation; call Validate for that.
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: malformed document: %w", err)
	}

	// A second successful decode means the input held more than one document.
	// Accepting the first and discarding the rest would approve unreviewed text.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err == nil {
		return nil, fmt.Errorf("policy: unexpected trailing content after document")
	}

	return &p, nil
}
