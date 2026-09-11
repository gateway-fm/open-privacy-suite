package apimodels

// Wire models for versioned contract execution policies (RD-1287), served by
// admin_execution_policy.go.
//
// A policy restricts what the members of a group may execute. It never grants
// anything: a decision still requires the caller's existing authority, and a
// document cannot assert membership, ownership or identity.

// ExecutionPolicyRevision summarises one stored revision.
//
// The runtime bytecode is not included here; its digest is what a reviewer
// checks, and the full artifact is on the single-revision route.
type ExecutionPolicyRevision struct {
	ID string `json:"id"`
	// Revision is the monotonic number within the organisation.
	Revision int64 `json:"revision" example:"3"`
	// Status is draft, active, superseded or withdrawn. Only one revision per
	// organisation is active, and only an active one decides anything.
	Status string `json:"status" example:"active"`

	// PolicyDigest identifies the approved document.
	PolicyDigest string `json:"policy_digest"`
	// SolidityDigest identifies the generated contract source.
	SolidityDigest string `json:"solidity_digest"`
	// RuntimeDigest identifies the compiled bytecode that is enforced.
	RuntimeDigest string `json:"runtime_digest"`

	// Compiler is the exact build the artifact was produced with.
	Compiler ExecutionPolicyCompiler `json:"compiler"`

	CreatedAt   string `json:"created_at"`
	ActivatedAt string `json:"activated_at,omitempty"`
}

// ExecutionPolicyCompiler is the pinned build an artifact was produced with.
//
// Declared here rather than reused from the policy engine so that the transport
// layer does not depend on it: a spec schema named after the engine's package
// would rename every time a type moved.
type ExecutionPolicyCompiler struct {
	// Version is the exact compiler, which is pinned rather than ranged.
	Version string `json:"version" example:"0.8.35+commit.47b9dedd"`
	// OptimizerRuns is the optimiser setting used.
	OptimizerRuns int `json:"optimizer_runs" example:"200"`
	// EVMVersion is the target the artifact was built for.
	EVMVersion string `json:"evm_version" example:"shanghai"`
}

// ExecutionPolicyRevisionDetail adds the documents a reviewer reads before
// approving: the submitted policy, the contract generated from it, and the
// bytecode that contract compiled to.
type ExecutionPolicyRevisionDetail struct {
	ExecutionPolicyRevision

	// Source is the candidate exactly as submitted.
	Source string `json:"source"`
	// SoliditySource is the contract generated from it.
	SoliditySource string `json:"solidity_source"`
	// RuntimeBytecode is the compiled code, 0x-prefixed hex.
	RuntimeBytecode string `json:"runtime_bytecode"`
}

// ExecutionPolicyContract is one contract a policy may name.
type ExecutionPolicyContract struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	// HasABI is false when no ABI is registered. Such a contract cannot carry a
	// rule, because nothing says what its selectors and arguments mean.
	HasABI bool `json:"has_abi"`
	// ABIDigest is what a rule on this contract must pin.
	ABIDigest string `json:"abi_digest,omitempty"`
}

// ExecutionPolicyContext is what a policy editor needs before writing a
// candidate.
type ExecutionPolicyContext struct {
	OrgID string `json:"org_id"`

	// BaseRevision is the revision a candidate must declare. A submission
	// written against a stale base is refused rather than merged.
	BaseRevision int64 `json:"base_revision" example:"3"`

	APIVersion  string `json:"api_version"`
	Kind        string `json:"kind"`
	NestedCalls string `json:"nested_calls"`

	// Groups are the regular groups a policy may bind. Administrator groups are
	// omitted: they are a trust root, not ordinary policy.
	Groups []string `json:"groups"`
	// Contracts are the organisation's registered contracts.
	Contracts []ExecutionPolicyContract `json:"contracts"`

	// Active is the policy currently in force, if any.
	Active *ExecutionPolicyRevision `json:"active,omitempty"`
}

// ExecutionPolicySubmitRequest carries a candidate policy document.
type ExecutionPolicySubmitRequest struct {
	// Policy is the candidate document.
	Policy map[string]any `json:"policy"`
	// BaseRevision is the revision the candidate was written against. Zero means
	// the organisation has no policy yet.
	BaseRevision int64 `json:"base_revision" example:"3"`
}

// ExecutionPolicySimulateFrame is one call frame of a hypothetical execution.
type ExecutionPolicySimulateFrame struct {
	// CallType is call, staticcall, delegatecall or callcode.
	CallType string `json:"call_type" example:"call"`
	// StorageAddress is the account whose storage the frame may modify.
	StorageAddress string `json:"storage_address"`
	// CodeAddress is the account whose code runs. It differs from the storage
	// address only for delegatecall and callcode, and defaults to it.
	CodeAddress string `json:"code_address,omitempty"`
	// Calldata is the frame's input, 0x-prefixed hex including the selector.
	Calldata string `json:"calldata"`
}

// ExecutionPolicySimulateRequest describes an execution to test.
type ExecutionPolicySimulateRequest struct {
	// Groups the hypothetical principal belongs to.
	Groups []string `json:"groups"`
	// Signer is the account that would have signed the transaction. Leaving it
	// empty models an execution with no recovered signer, which no rule
	// requiring the signer can satisfy.
	Signer string `json:"signer,omitempty"`
	// LinkedAddresses are the accounts linked to the hypothetical principal.
	LinkedAddresses []string `json:"linked_addresses,omitempty"`
	// Frames are the call frames the execution would produce, outermost first.
	Frames []ExecutionPolicySimulateFrame `json:"frames"`
}

// ExecutionPolicySimulateResponse reports what the policy decided.
type ExecutionPolicySimulateResponse struct {
	// Allowed is the decision. Every frame must be permitted for it to be true.
	Allowed bool `json:"allowed"`
	// Code categorises a denial and is safe to show a denied caller.
	Code string `json:"code,omitempty" example:"argument_constraint"`
	// Reason explains a denial for an operator. It quotes policy bounds and
	// addresses, so it belongs in operator tooling, not in a caller's response.
	Reason string `json:"reason,omitempty"`

	// CompiledAllowed is the decision reached by running the compiled contract
	// on the same inputs.
	CompiledAllowed bool `json:"compiled_allowed"`
	// CompiledCode is that run's denial category.
	CompiledCode string `json:"compiled_code,omitempty"`

	// Agreed reports whether the reference evaluator and the compiled artifact
	// reached the same decision. False would mean the reviewed policy and the
	// enforced policy are not the same thing.
	Agreed bool `json:"agreed"`

	// RuntimeDigest identifies the bytecode that produced CompiledAllowed.
	RuntimeDigest string `json:"runtime_digest"`
}
