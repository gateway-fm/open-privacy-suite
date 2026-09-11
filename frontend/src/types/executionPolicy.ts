// Execution policy types mirroring internal/apimodels/executionpolicy.go.
//
// A policy restricts what the members of a group may execute. It never grants
// anything: a decision still requires the caller's existing authority, so a
// document can only narrow what a principal could already do.

/**
 * Lifecycle of one stored revision. Exactly one revision per organization is
 * `active`, and only an active one decides anything — a `draft` enforces
 * nothing until it is activated.
 */
export type ExecutionPolicyStatus = 'draft' | 'active' | 'superseded' | 'withdrawn';

/** The pinned build an artifact was produced with. */
export interface ExecutionPolicyCompiler {
  version: string;
  optimizer_runs: number;
  evm_version: string;
}

/** Summary of one stored revision, as returned by the list route. */
export interface ExecutionPolicyRevision {
  id: string;
  /** Monotonic number within the organization. */
  revision: number;
  status: ExecutionPolicyStatus;
  /** Identifies the approved document. */
  policy_digest: string;
  /** Identifies the generated contract source. */
  solidity_digest: string;
  /** Identifies the compiled bytecode that is enforced. */
  runtime_digest: string;
  compiler: ExecutionPolicyCompiler;
  created_at: string;
  activated_at?: string;
}

/**
 * A revision plus the artifacts a reviewer reads before approving it: the
 * submitted document, the contract generated from it, and the bytecode that
 * contract compiled to.
 */
export interface ExecutionPolicyRevisionDetail extends ExecutionPolicyRevision {
  source: string;
  solidity_source: string;
  runtime_bytecode: string;
}

/** One contract a policy may name. */
export interface ExecutionPolicyContract {
  address: string;
  name: string;
  /**
   * False when no ABI is registered. Such a contract cannot carry a rule,
   * because nothing says what its selectors and arguments mean.
   */
  has_abi: boolean;
  /** What a rule on this contract must pin. Absent when has_abi is false. */
  abi_digest?: string;
}

/** Everything a policy editor needs before writing a candidate. */
export interface ExecutionPolicyContext {
  org_id: string;
  /**
   * The revision a candidate must declare. A submission written against a
   * stale base is refused rather than merged.
   */
  base_revision: number;
  api_version: string;
  kind: string;
  nested_calls: string;
  /** Regular groups a policy may bind. Administrator groups are omitted. */
  groups: string[];
  contracts: ExecutionPolicyContract[];
  /** The policy currently in force, if any. */
  active?: ExecutionPolicyRevision;
}

/**
 * A candidate policy document. The schema is owned by the backend, which is
 * the only thing that may declare a document valid, so it is carried as an
 * opaque JSON object rather than re-modelled (and re-validated) here.
 */
export type PolicyDocument = Record<string, unknown>;

/** Body of a candidate submission. */
export interface ExecutionPolicySubmitInput {
  policy: PolicyDocument;
  base_revision: number;
}

/**
 * An EVM frame's call opcode. The distinction is load-bearing: under
 * delegatecall and callcode the executing code and the storage being modified
 * belong to different accounts.
 */
export type ExecutionPolicyCallType = 'call' | 'staticcall' | 'delegatecall' | 'callcode';

/** One call frame of a hypothetical execution. */
export interface ExecutionPolicySimulateFrame {
  call_type: ExecutionPolicyCallType;
  /** The account whose storage the frame may modify. */
  storage_address: string;
  /** The account whose code runs; differs from storage only for delegatecall/callcode. */
  code_address?: string;
  /** The frame's input, 0x-prefixed hex including the selector. */
  calldata: string;
}

/** An execution to test against a stored revision. */
export interface ExecutionPolicySimulateInput {
  groups: string[];
  signer?: string;
  linked_addresses?: string[];
  /** The frames the execution would produce, outermost first. */
  frames: ExecutionPolicySimulateFrame[];
}

/** What the policy decided about a simulated execution. */
export interface ExecutionPolicySimulateResult {
  allowed: boolean;
  /** Denial category, safe to show a denied caller. */
  code?: string;
  /** Denial explanation for an operator; quotes policy bounds and addresses. */
  reason?: string;
  /** The decision reached by running the compiled contract on the same inputs. */
  compiled_allowed: boolean;
  compiled_code?: string;
  /**
   * Whether the reference evaluator and the compiled artifact agreed. False
   * means the reviewed policy and the enforced policy are not the same thing.
   */
  agreed: boolean;
  runtime_digest: string;
}
