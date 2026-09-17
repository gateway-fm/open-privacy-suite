//! Immutable execution inputs. Network verification and snapshot ingestion live
//! outside the interpreter; no per-frame database or network access is permitted.

use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256, Bytes, U256};
use std::{fmt::Debug, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionBinding {
    Transaction(B256),
    Simulation { digest: B256, context_id: String },
}

/// Authenticated identity only. Memberships and bans are resolved from the
/// pinned snapshot for each execution, never frozen into this context.
#[derive(Clone, Debug)]
pub struct ExecutionIdentity {
    pub principal_id: String,
    pub org_id: String,
    pub context_id: String,
    pub signer: Address,
    pub binding: ExecutionBinding,
    pub min_snapshot_version: u64,
}

/// Implementations must verify authenticity, validity and exact request binding
/// before returning. The interpreter additionally checks signer and minimum version.
pub trait IdentityResolver: Debug + Send + Sync {
    fn resolve(
        &self,
        binding: &ExecutionBinding,
        transaction: &TxEnv,
    ) -> Result<ExecutionIdentity, String>;

    fn record(
        &self,
        _binding: &ExecutionBinding,
        _outcome: ExecutionOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
    Create,
    Create2,
}

/// Observed from EVM code and the active precompile set, never asserted by OPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CodeKind {
    Unknown = 0,
    NoCode = 1,
    Contract = 2,
    Precompile = 3,
}

#[derive(Clone, Debug)]
pub struct ObservedCall {
    pub kind: FrameKind,
    pub caller: Address,
    pub code_address: Address,
    pub storage_address: Address,
    pub calldata: Bytes,
    pub value: U256,
    pub depth: u64,
    pub code_hash: B256,
    pub storage_code_hash: B256,
    pub code_kind: CodeKind,
}

#[derive(Clone, Debug)]
pub struct PolicyInvocation {
    pub revision: B256,
    pub bytecode: Bytes,
    pub calldata: Bytes,
}

/// A creation observed by the EVM in this execution. The inspector keeps this
/// overlay on the same rollback boundaries as application state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CreatedContract {
    pub address: Address,
    pub org_id: String,
    pub principal_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOutcome {
    pub success: bool,
    pub denied: bool,
    pub reason_code: String,
    pub created: Vec<CreatedContract>,
}

/// Immutable rules and facts for a particular snapshot. This prepares the
/// generated contract's ABI; the contract itself makes the authorization decision.
pub trait FramePolicy: Debug + Send + Sync {
    fn prepare(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
    ) -> Result<PolicyInvocation, String>;

    fn prepare_with_creations(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        _created: &[CreatedContract],
    ) -> Result<PolicyInvocation, String> {
        self.prepare(identity, call)
    }

    fn authorize_policy_read(
        &self,
        _identity: &ExecutionIdentity,
        _guarded: &ObservedCall,
        _account: Address,
        _code_hash: B256,
        _active_precompile: bool,
        _created: &[CreatedContract],
    ) -> Result<(), String> {
        Err("policy read scope unavailable".into())
    }

    fn authorize_diagnostic(
        &self,
        _identity: &ExecutionIdentity,
        _call: &ObservedCall,
        _created: &[CreatedContract],
    ) -> Result<(), String> {
        Err("diagnostic scope unavailable".into())
    }

    fn authorize_diagnostic_account(
        &self,
        _identity: &ExecutionIdentity,
        _account: Address,
        _code_hash: B256,
        _kind: CodeKind,
        _created: &[CreatedContract],
    ) -> Result<(), String> {
        Err("diagnostic account scope unavailable".into())
    }
}

#[derive(Debug)]
pub struct PinnedPolicySnapshot {
    version: u64,
    digest: B256,
    policy: Arc<dyn FramePolicy>,
}

impl PinnedPolicySnapshot {
    pub fn new(version: u64, digest: B256, policy: Arc<dyn FramePolicy>) -> Self {
        Self {
            version,
            digest,
            policy,
        }
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn digest(&self) -> B256 {
        self.digest
    }
    pub(crate) fn prepare(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        created: &[CreatedContract],
    ) -> Result<PolicyInvocation, String> {
        self.policy.prepare_with_creations(identity, call, created)
    }

    pub(crate) fn authorize_policy_read(
        &self,
        identity: &ExecutionIdentity,
        guarded: &ObservedCall,
        account: Address,
        code_hash: B256,
        active_precompile: bool,
        created: &[CreatedContract],
    ) -> Result<(), String> {
        self.policy.authorize_policy_read(
            identity,
            guarded,
            account,
            code_hash,
            active_precompile,
            created,
        )
    }
    pub(crate) fn authorize_diagnostic(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        created: &[CreatedContract],
    ) -> Result<(), String> {
        self.policy.authorize_diagnostic(identity, call, created)
    }
    pub(crate) fn authorize_diagnostic_account(
        &self,
        identity: &ExecutionIdentity,
        account: Address,
        code_hash: B256,
        kind: CodeKind,
        created: &[CreatedContract],
    ) -> Result<(), String> {
        self.policy
            .authorize_diagnostic_account(identity, account, code_hash, kind, created)
    }
}
