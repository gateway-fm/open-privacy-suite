//! Mandatory policy invocation inside the node's own EVM, separate from optional RPC tracing.
//!
//! The policy contract is executed as an ordinary frame of the executing EVM, against the
//! live journal at the exact point of the application's call. There is no second VM: the
//! policy reads the same candidate state the application is about to act on, including
//! writes made earlier in the same transaction. Its frame is static, has its own gas budget,
//! and every journal effect it leaves — including warm-access marks — is reverted, so the
//! user's gas accounting is untouched.

use crate::{
    context::{
        CodeKind, CreatedContract, ExecutionIdentity, ExecutionOutcome, FrameKind,
        IdentityResolver, ObservedCall, PinnedPolicySnapshot, PolicyInvocation,
    },
    transaction::PolicyTx,
};
use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, InvalidTxError,
    eth::{EthEvm, EthEvmBuilder, EthEvmContext},
    precompiles::PrecompilesMap,
    revm::{
        bytecode::Bytecode,
        context::{BlockEnv, CfgEnv, DBErrorMarker},
        context_interface::{
            Cfg, ContextError, ContextTr, CreateScheme, FrameStack, Host, JournalTr,
            LocalContextTr,
            result::{EVMError, HaltReason, InvalidTransaction, ResultAndState},
        },
        handler::{
            EthFrame, EthPrecompiles, FrameResult, ItemOrResult, instructions::EthInstructions,
        },
        inspector::{Inspector, NoOpInspector},
        interpreter::{
            CallInput, CallInputs, CallOutcome, CallScheme, CallValue, CreateInputs, CreateOutcome,
            FrameInput, Gas, InstructionResult, Interpreter, InterpreterResult, SharedMemory,
            interpreter::EthInterpreter,
            interpreter_action::FrameInit,
            interpreter_types::{Jumps, LoopControl},
        },
        primitives::hardfork::SpecId,
    },
};
use alloy_primitives::{Address, Bytes, U256, address, keccak256};
use serde::Serialize;
use std::{
    cell::Cell,
    error::Error,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

const POLICY: Address = address!("0000000000000000000000000000000000000900");
/// The account the node evaluates from. It holds nothing and is never touched.
const NODE_CALLER: Address = address!("0000000000000000000000000000000000000902");
/// Gas available to one policy evaluation. It is node-internal and never charged to the user.
const POLICY_GAS: u64 = 100_000;
const MAX_CHECKS: usize = 128;

#[derive(Debug, Clone)]
pub struct PolicyFactory {
    snapshot: Arc<PinnedPolicySnapshot>,
    identities: Arc<dyn IdentityResolver>,
    diagnostic: Option<Arc<DiagnosticReport>>,
    candidate: Option<(Arc<PinnedPolicySnapshot>, Arc<DiagnosticReport>)>,
    timing: Option<Arc<PolicyTiming>>,
}

/// One measured active policy check: the frame's application depth, how long the
/// facts took to resolve and encode, how long the policy frame ran, and the gas it used.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FrameSample {
    pub depth: u64,
    pub prepare_nanos: u64,
    pub evaluate_nanos: u64,
    pub gas: u64,
}

/// Cost accounting for active policy checks, opted into with `PolicyFactory::timed`.
///
/// Totals are cheap atomics; samples are kept only while a caller holds the handle
/// (measurement runs and diagnostics), never on the production path by default.
#[derive(Debug, Default)]
pub struct PolicyTiming {
    frames: AtomicU64,
    prepare_nanos: AtomicU64,
    evaluate_nanos: AtomicU64,
    gas: AtomicU64,
    samples: Mutex<Vec<FrameSample>>,
}

impl PolicyTiming {
    fn record(&self, sample: FrameSample) {
        self.frames.fetch_add(1, Ordering::Relaxed);
        self.prepare_nanos
            .fetch_add(sample.prepare_nanos, Ordering::Relaxed);
        self.evaluate_nanos
            .fetch_add(sample.evaluate_nanos, Ordering::Relaxed);
        self.gas.fetch_add(sample.gas, Ordering::Relaxed);
        if let Ok(mut samples) = self.samples.lock() {
            samples.push(sample);
        }
    }
    pub fn frames(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }
    pub fn prepare_nanos(&self) -> u64 {
        self.prepare_nanos.load(Ordering::Relaxed)
    }
    pub fn evaluate_nanos(&self) -> u64 {
        self.evaluate_nanos.load(Ordering::Relaxed)
    }
    pub fn gas(&self) -> u64 {
        self.gas.load(Ordering::Relaxed)
    }
    /// Returns and clears the per-frame samples recorded so far.
    pub fn take_samples(&self) -> Vec<FrameSample> {
        self.samples
            .lock()
            .map(|mut samples| std::mem::take(&mut *samples))
            .unwrap_or_default()
    }
}

#[derive(Debug, Default)]
pub struct DiagnosticReport {
    decisions: Mutex<Vec<CallRecord>>,
}
impl DiagnosticReport {
    pub fn value(&self) -> Result<serde_json::Value, String> {
        let decisions = self
            .decisions
            .lock()
            .map_err(|_| "diagnostic report unavailable")?;
        Ok(
            serde_json::json!({"would_allow":decisions.iter().all(|call|call.reason_code==0),"decisions":*decisions}),
        )
    }
}

impl PolicyFactory {
    /// The caller chooses this immutable snapshot once per block or simulation.
    pub fn new(snapshot: Arc<PinnedPolicySnapshot>, identities: Arc<dyn IdentityResolver>) -> Self {
        Self {
            snapshot,
            identities,
            diagnostic: None,
            candidate: None,
            timing: None,
        }
    }

    /// Records the cost of every active policy check made through this factory.
    pub fn timed(mut self) -> (Self, Arc<PolicyTiming>) {
        let timing = Arc::new(PolicyTiming::default());
        self.timing = Some(timing.clone());
        (self, timing)
    }

    pub fn diagnostic(mut self) -> (Self, Arc<DiagnosticReport>) {
        let report = Arc::new(DiagnosticReport::default());
        self.diagnostic = Some(report.clone());
        (self, report)
    }

    pub fn candidate(
        mut self,
        snapshot: Arc<PinnedPolicySnapshot>,
    ) -> (Self, Arc<DiagnosticReport>) {
        let report = Arc::new(DiagnosticReport::default());
        self.candidate = Some((snapshot, report.clone()));
        (self, report)
    }

    /// Base SDK factory. Only a block/simulation coordinator may install an
    /// authenticated execution handle; public RPC cannot inherit ambient identity.
    #[cfg(feature = "reth-sdk")]
    pub(crate) fn unconfigured() -> Self {
        #[derive(Debug)]
        struct MissingContext;
        impl IdentityResolver for MissingContext {
            fn resolve(
                &self,
                _: &crate::context::ExecutionBinding,
                _: &alloy_evm::revm::context::TxEnv,
            ) -> Result<ExecutionIdentity, String> {
                Err("missing authenticated execution context".into())
            }
        }
        impl crate::context::FramePolicy for MissingContext {
            fn prepare(
                &self,
                _: &ExecutionIdentity,
                _: &ObservedCall,
            ) -> Result<PolicyInvocation, String> {
                Err("missing authenticated execution context".into())
            }
        }
        Self::new(
            Arc::new(PinnedPolicySnapshot::new(
                0,
                Default::default(),
                Arc::new(MissingContext),
            )),
            Arc::new(MissingContext),
        )
    }
}

impl EvmFactory for PolicyFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = PolicyEvm<DB, I>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = PolicyTx;
    type Error<D: DBErrorMarker> = EVMError<D, PolicyTxError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, env: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        self.create_evm_with_inspector(db, env, NoOpInspector {})
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<EthEvmContext<DB>>>(
        &self,
        db: DB,
        env: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let spec = env.cfg_env.spec;
        PolicyEvm {
            inner: EthEvmBuilder::new(db, env)
                .activate_inspector((
                    PolicyInspector::new(
                        spec,
                        self.snapshot.clone(),
                        self.diagnostic.clone(),
                        self.candidate.clone(),
                        self.timing.clone(),
                    ),
                    inspector,
                ))
                .build(),
            identities: self.identities.clone(),
        }
    }
}

pub struct PolicyEvm<DB: Database, I> {
    inner: EthEvm<DB, (PolicyInspector<EthEvmContext<DB>>, I), PrecompilesMap>,
    identities: Arc<dyn IdentityResolver>,
}

#[cfg(feature = "reth-sdk")]
impl<DB: Database, I: Inspector<EthEvmContext<DB>>> PolicyEvm<DB, I> {
    pub(crate) fn install_context(&mut self, factory: PolicyFactory) {
        let spec = self.inner.cfg_env().spec;
        self.inner.components_mut().1.0 = PolicyInspector::new(
            spec,
            factory.snapshot,
            factory.diagnostic,
            factory.candidate,
            factory.timing,
        );
        self.identities = factory.identities;
    }
}

impl<DB: Database, I: Inspector<EthEvmContext<DB>>> Evm for PolicyEvm<DB, I> {
    type DB = DB;
    type Tx = PolicyTx;
    type Error = EVMError<DB::Error, PolicyTxError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        self.inner.block()
    }
    fn cfg_env(&self) -> &CfgEnv {
        self.inner.cfg_env()
    }
    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(&mut self, tx: PolicyTx) -> Result<ResultAndState, Self::Error> {
        let deny = |reason: &str| EVMError::Transaction(PolicyTxError::Denied(reason.into()));
        if tx.env.tx_type == 4 || !tx.env.authorization_list.is_empty() {
            return Err(deny(
                "EIP-7702 authorizations are not supported by the policy model",
            ));
        }
        let binding = tx
            .binding
            .as_ref()
            .ok_or_else(|| deny("missing execution binding"))?;
        if (self.inner.components().1.0.diagnostic.is_some()
            || self.inner.components().1.0.candidate.is_some())
            && !matches!(binding, crate::context::ExecutionBinding::Simulation { .. })
        {
            return Err(deny("diagnostic execution requires a simulation binding"));
        }
        let identity = self
            .identities
            .resolve(binding, &tx.env)
            .map_err(|reason| EVMError::Transaction(PolicyTxError::Denied(reason)))?;
        if identity.binding != *binding || identity.signer != tx.env.caller {
            return Err(deny("execution identity binding mismatch"));
        }
        if identity.min_snapshot_version > self.inner.components().1.0.snapshot.version() {
            return Err(deny("execution snapshot is behind identity context"));
        }
        let tx = tx.env;
        let subject = tx.caller;
        let nonce = tx.nonce;
        let block = self.block().number;
        // The factory pins private policy code for this EVM's entire lifetime.
        self.inner.components_mut().1.0.begin_tx(identity);

        let result = self.inner.transact_raw(tx).map_err(map_error);
        let check = &mut self.inner.components_mut().1.0;
        check.active = false;
        if let Some(report) = &check.diagnostic {
            *report
                .decisions
                .lock()
                .map_err(|_| deny("diagnostic report unavailable"))? = check.calls.clone();
        }
        if let Some((_, report)) = &check.candidate {
            *report
                .decisions
                .lock()
                .map_err(|_| deny("candidate report unavailable"))? = check.candidate_calls.clone();
        }
        if check.denied.is_some() || !result.as_ref().is_ok_and(|r| r.result.is_success()) {
            check.created.truncate(check.tx_creation_start);
        }
        let outcome = ExecutionOutcome {
            success: result.as_ref().is_ok_and(|r| r.result.is_success()) && check.denied.is_none(),
            denied: check.denied.is_some() || result.is_err(),
            reason_code: if check.denied.is_some() {
                "POLICY_DENIED"
            } else if result.is_err() {
                "EXECUTION_REJECTED"
            } else if !result.as_ref().is_ok_and(|r| r.result.is_success()) {
                "APPLICATION_REVERTED"
            } else {
                ""
            }
            .into(),
            created: check.created[check.tx_creation_start..].to_vec(),
        };
        if let Err(reason) = self.identities.record(binding, outcome) {
            check.created.truncate(check.tx_creation_start);
            return Err(EVMError::Transaction(PolicyTxError::Denied(reason)));
        }
        if let Some(reason) = check.denied.take() {
            // The result's state, including nonce/fees and caught-revert writes, never reaches
            // the block executor's commit path. A catchable inner revert is not our final veto.
            if decision_log_enabled() {
                let evm_success = result.as_ref().is_ok_and(|r| r.result.is_success());
                eprintln!(
                    "OPS_POLICY_DECISION {}",
                    serde_json::json!({
                        "decision":"deny", "subject":subject, "nonce":nonce, "block":block.to_string(),
                        "reason":reason, "application_returned_success":evm_success,
                        "calls":check.calls,
                    })
                );
            }
            return Err(EVMError::Transaction(PolicyTxError::Denied(reason)));
        }
        if decision_log_enabled() && !check.calls.is_empty() && result.is_ok() {
            eprintln!(
                "OPS_POLICY_DECISION {}",
                serde_json::json!({
                    "decision":"allow", "subject":subject, "nonce":nonce, "block":block.to_string(),
                    "calls":check.calls,
                })
            );
        }
        result
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState, Self::Error> {
        // Protocol system calls are not user transactions and use the stock Reth path.
        self.inner.components_mut().1.0.active = false;
        self.inner
            .transact_system_call(caller, contract, data)
            .map_err(map_error)
    }

    fn finish(self) -> (DB, EvmEnv) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, _enabled: bool) {
        // Optional tracing controls must never turn off mandatory policy enforcement.
        self.inner.set_inspector_enabled(true);
    }

    fn components(&self) -> (&DB, &I, &PrecompilesMap) {
        let (db, inspectors, precompiles) = self.inner.components();
        (db, &inspectors.1, precompiles)
    }

    fn components_mut(&mut self) -> (&mut DB, &mut I, &mut PrecompilesMap) {
        let (db, inspectors, precompiles) = self.inner.components_mut();
        (db, &mut inspectors.1, precompiles)
    }
}

#[derive(Debug)]
pub enum PolicyTxError {
    Ethereum(InvalidTransaction),
    Denied(String),
}

/// Per-transaction decision lines on stderr (`OPS_POLICY_DECISION {...}`) are a
/// development diagnostic, enabled with `OPS_POLICY_DECISION_LOG=1`. They are off by
/// default because on the block-production path they cost a synchronous JSON
/// serialization and write for every transaction (measured at roughly the price of a
/// policy check itself, see tests/frame_cost.rs) and because they record which
/// principal called which selector in the node's log. OPS receives every outcome
/// through the identity record regardless of this setting.
fn decision_log_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("OPS_POLICY_DECISION_LOG").is_some_and(|v| v == "1"))
}

impl fmt::Display for PolicyTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethereum(e) => e.fmt(f),
            Self::Denied(reason) => write!(f, "OPS policy denied transaction: {reason}"),
        }
    }
}
impl Error for PolicyTxError {}
impl InvalidTxError for PolicyTxError {
    fn as_invalid_tx_err(&self) -> Option<&InvalidTransaction> {
        match self {
            Self::Ethereum(e) => Some(e),
            Self::Denied(_) => None,
        }
    }
}

fn map_error<D>(error: EVMError<D>) -> EVMError<D, PolicyTxError> {
    match error {
        EVMError::Transaction(e) => EVMError::Transaction(PolicyTxError::Ethereum(e)),
        EVMError::Header(e) => EVMError::Header(e),
        EVMError::Database(e) => EVMError::Database(e),
        EVMError::Custom(e) => EVMError::Custom(e),
        EVMError::CustomAny(e) => EVMError::CustomAny(e),
    }
}

/// Observes the application's actual calls and consults the policy for each of them.
///
/// Generic over the context so it can hold the instruction table for the node's own
/// interpreter: the policy runs with the same instructions, precompiles and state as the
/// application code it is judging.
struct PolicyInspector<CTX> {
    instructions: EthInstructions<EthInterpreter, CTX>,
    precompiles: EthPrecompiles,
    active: bool,
    identity: Option<ExecutionIdentity>,
    depth: u64,
    denied: Option<String>,
    calls: Vec<CallRecord>,
    snapshot: Arc<PinnedPolicySnapshot>,
    created: Vec<CreatedContract>,
    creation_checkpoints: Vec<usize>,
    tx_creation_start: usize,
    diagnostic: Option<Arc<DiagnosticReport>>,
    candidate: Option<(Arc<PinnedPolicySnapshot>, Arc<DiagnosticReport>)>,
    candidate_calls: Vec<CallRecord>,
    evaluating_candidate: bool,
    timing: Option<Arc<PolicyTiming>>,
    /// Gas spent by the most recent active policy frame, for `timing`.
    last_gas: u64,
}

#[derive(Clone, Debug, Serialize)]
struct CallRecord {
    depth: u64,
    caller: Address,
    code_address: Address,
    storage_address: Address,
    selector: String,
    scheme: String,
    reason_code: u64,
}

impl<CTX: ContextTr + Host> PolicyInspector<CTX> {
    fn new(
        spec: SpecId,
        snapshot: Arc<PinnedPolicySnapshot>,
        diagnostic: Option<Arc<DiagnosticReport>>,
        candidate: Option<(Arc<PinnedPolicySnapshot>, Arc<DiagnosticReport>)>,
        timing: Option<Arc<PolicyTiming>>,
    ) -> Self {
        Self {
            instructions: EthInstructions::new_mainnet_with_spec(spec),
            // Stock precompiles for the spec. A node with custom precompiles would need to
            // hand its own provider in here for the policy to see them.
            precompiles: EthPrecompiles::new(spec),
            active: false,
            identity: None,
            depth: 0,
            denied: None,
            calls: Vec::new(),
            snapshot,
            created: Vec::new(),
            creation_checkpoints: Vec::new(),
            tx_creation_start: 0,
            diagnostic,
            candidate,
            candidate_calls: Vec::new(),
            evaluating_candidate: false,
            timing,
            last_gas: 0,
        }
    }

    fn begin_tx(&mut self, identity: ExecutionIdentity) {
        // Each estimation probe/simulation discards its application state, so it
        // also discards ownership created by an earlier probe on this EVM.
        if matches!(
            identity.binding,
            crate::context::ExecutionBinding::Simulation { .. }
        ) {
            self.created.clear();
        }
        self.active = true;
        self.identity = Some(identity);
        self.depth = 0;
        self.denied = None;
        self.calls.clear();
        self.candidate_calls.clear();
        self.evaluating_candidate = false;
        self.tx_creation_start = self.created.len();
        self.creation_checkpoints.clear();
    }

    fn check_frame(&mut self, context: &mut CTX, observed: &ObservedCall) -> Result<u64, String> {
        let identity = self.identity.as_ref().ok_or("missing execution identity")?;
        if self.diagnostic.is_some()
            && let Err(error) =
                self.snapshot
                    .authorize_diagnostic(identity, observed, &self.created)
        {
            self.denied.get_or_insert(error.clone());
            return Err(error);
        }
        let started = self.timing.as_ref().map(|_| Instant::now());
        let prepared = self.snapshot.prepare(identity, observed, &self.created);
        let prepared_at = started.map(|_| Instant::now());
        self.last_gas = 0;
        let active =
            prepared.and_then(|invocation| self.evaluate_all(context, invocation, observed));
        if let (Some(timing), Some(started), Some(prepared_at)) =
            (&self.timing, started, prepared_at)
        {
            timing.record(FrameSample {
                depth: observed.depth,
                prepare_nanos: (prepared_at - started).as_nanos() as u64,
                evaluate_nanos: prepared_at.elapsed().as_nanos() as u64,
                gas: self.last_gas,
            });
        }
        // A candidate is diagnostic only. Never run a speculative frame denied
        // by the active policy unless the independently scoped admin mode applies.
        if self.diagnostic.is_none() && !matches!(active, Ok(0)) {
            return active;
        }
        if let Some((candidate, _)) = &self.candidate {
            self.evaluating_candidate = true;
            let verdict = candidate
                .prepare(
                    self.identity.as_ref().ok_or("missing execution identity")?,
                    observed,
                    &self.created,
                )
                .and_then(|invocation| self.evaluate_all(context, invocation, observed));
            self.evaluating_candidate = false;
            self.candidate_calls.push(CallRecord {
                depth: observed.depth,
                caller: observed.caller,
                code_address: observed.code_address,
                storage_address: observed.storage_address,
                selector: format!(
                    "0x{}",
                    alloy_primitives::hex::encode(
                        &observed.calldata[..observed.calldata.len().min(4)]
                    )
                ),
                scheme: format!("{:?}", observed.kind),
                reason_code: verdict.unwrap_or(255),
            });
        }
        active
    }

    fn evaluate_all(
        &mut self,
        context: &mut CTX,
        plan: crate::context::PolicyPlan,
        guarded: &ObservedCall,
    ) -> Result<u64, String> {
        let mut specific = None;
        let mut fallback = 1;
        let mut remaining_gas = POLICY_GAS;
        if plan.invocations.is_empty() {
            return Err("missing execution artifacts".into());
        }
        for invocation in plan.invocations {
            // Errors remain fail-closed even if another group might grant access.
            let (reason, spent) = self.evaluate(context, invocation, guarded, remaining_gas)?;
            remaining_gas = remaining_gas.saturating_sub(spent);
            if reason == 0 {
                return Ok(0);
            }
            if plan.per_group && (257..=266).contains(&reason) {
                fallback = reason - 256;
            } else if reason <= 10 {
                specific.get_or_insert(reason);
            } else {
                return Err("unknown policy result".into());
            }
        }
        Ok(specific.unwrap_or(fallback))
    }

    /// Executes `check(...)` on the policy contract as a static frame of the live EVM.
    ///
    /// The frame sees the journal exactly as the application's pending call will. Everything
    /// it does to the journal is reverted afterwards, and the shared memory it used is
    /// released, so the application observes no trace of the evaluation.
    fn evaluate(
        &mut self,
        context: &mut CTX,
        invocation: PolicyInvocation,
        guarded: &ObservedCall,
        gas_limit: u64,
    ) -> Result<(u64, u64), String> {
        let checkpoint = context.journal_mut().checkpoint();
        let buffer = context.local().shared_memory_buffer().clone();
        let memory_len = buffer.borrow().len();

        let outcome = self.run_policy_frame(context, invocation, guarded, gas_limit);

        buffer.borrow_mut().truncate(memory_len);
        context.journal_mut().checkpoint_revert(checkpoint);
        // A database failure inside the policy frame halts it with `FatalExternalError` and
        // parks the error in the context, where the application's next frame boundary would
        // pick it up and abort the whole transaction as a database error. Take it here so the
        // outcome is a policy denial of this transaction, not a failed block build.
        if let Err(e) = core::mem::replace(context.error(), Ok(())) {
            return Err(format!("policy database error: {e:?}"));
        }

        let result = match outcome? {
            FrameResult::Call(outcome) => {
                if !self.evaluating_candidate {
                    self.last_gas = self
                        .last_gas
                        .saturating_add(outcome.result.gas.total_gas_spent());
                }
                outcome.result
            }
            FrameResult::Create(_) => return Err("malformed policy result".into()),
        };
        if result.result == InstructionResult::FatalExternalError {
            return Err("policy database error".into());
        }
        if !result.result.is_ok() {
            return Err("policy reverted or exhausted gas".into());
        }
        if result.output.len() != 32 {
            return Err("malformed policy result".into());
        }
        u64::try_from(U256::from_be_slice(&result.output))
            .map(|reason| (reason, result.gas.total_gas_spent()))
            .map_err(|_| "out-of-range policy result".into())
    }

    fn run_policy_frame(
        &mut self,
        context: &mut CTX,
        invocation: PolicyInvocation,
        guarded: &ObservedCall,
        gas_limit: u64,
    ) -> Result<FrameResult, String> {
        let code = Bytecode::new_raw_checked(invocation.bytecode.clone())
            .map_err(|_| "malformed private policy bytecode".to_owned())?;
        let code_hash = keccak256(&invocation.bytecode);
        if code.is_empty() || code.is_eip7702() {
            return Err("missing or unsupported private policy bytecode".into());
        }

        // The policy frame lives in the executing EVM's shared memory, in a child region
        // that starts past everything the application's frames currently hold.
        let mut memory =
            SharedMemory::new_with_buffer(context.local().shared_memory_buffer().clone())
                .new_child_context();
        memory.set_memory_limit(context.cfg().memory_limit());

        let init = FrameInit {
            // The policy frame has its own stack, so its depth only bounds the calls the
            // policy itself makes. The application's depth is passed to the policy as a fact.
            depth: 1,
            memory,
            frame_input: FrameInput::Call(Box::new(CallInputs {
                input: CallInput::Bytes(invocation.calldata),
                return_memory_offset: 0..0,
                gas_limit,
                reservoir: 0,
                bytecode_address: POLICY,
                known_bytecode: (code_hash, code),
                target_address: POLICY,
                caller: NODE_CALLER,
                // Apparent, not Transfer: no account is touched on the way in.
                value: CallValue::Apparent(U256::ZERO),
                scheme: CallScheme::StaticCall,
                is_static: true,
                charged_new_account_state_gas: false,
            })),
        };
        // An error here leaves the journal depth counter skewed until the transaction is
        // discarded; that is fine because every error path denies the whole transaction.
        let snapshot = self.snapshot.clone();
        let identity = self.identity.as_ref().ok_or("missing execution identity")?;
        let escaped = Cell::new(false);
        let result = run_frames(
            context,
            &self.instructions,
            &mut self.precompiles,
            init,
            !self.evaluating_candidate || self.diagnostic.is_some(),
            |address, code_hash, active_precompile| {
                let result = snapshot.authorize_policy_read(
                    identity,
                    guarded,
                    address,
                    code_hash,
                    active_precompile,
                    &self.created,
                );
                if result.is_err() {
                    escaped.set(true);
                }
                result
            },
        )
        .map_err(|e| format!("policy frame error: {e:?}"));
        if escaped.get() || result.is_err() {
            self.denied
                .get_or_insert("policy read scope or execution unavailable".into());
        }
        result
    }
}

type FrameError<CTX> = ContextError<<<CTX as ContextTr>::Db as alloy_evm::revm::Database>::Error>;

/// Drives one call and everything it spawns to completion on a private frame stack.
///
/// This is the node's frame loop with the inspector hooks left out: the policy's own calls
/// are not policy-checked, and nothing here touches the application's frame stack.
fn run_frames<CTX: ContextTr + Host>(
    context: &mut CTX,
    instructions: &EthInstructions<EthInterpreter, CTX>,
    precompiles: &mut EthPrecompiles,
    first: FrameInit,
    allow_state_reads: bool,
    authorize: impl Fn(Address, alloy_primitives::B256, bool) -> Result<(), String>,
) -> Result<FrameResult, FrameError<CTX>> {
    let mut stack: FrameStack<EthFrame> = FrameStack::new();
    match EthFrame::init_with_context(stack.start_init(), context, precompiles, first)? {
        ItemOrResult::Item(token) => unsafe { stack.end_init(token) },
        ItemOrResult::Result(result) => return Ok(result),
    }
    loop {
        let next = {
            let frame = stack.get();
            // Account-observation opcodes can otherwise create a cross-org
            // policy oracle without spawning another EVM frame.
            let stopped = loop {
                if !allow_state_reads
                    && matches!(
                        frame.interpreter.bytecode.opcode(),
                        0x31 | 0x3b | 0x3c | 0x3f | 0x47 | 0x54 | 0x5c
                    )
                {
                    return Err(ContextError::Custom(
                        "candidate state reads require scoped diagnostics".into(),
                    ));
                }
                if matches!(
                    frame.interpreter.bytecode.opcode(),
                    0x31 | 0x3b | 0x3c | 0x3f
                ) && let Ok(word) = frame.interpreter.stack.peek(0)
                {
                    let address =
                        Address::from_word(alloy_primitives::B256::from(word.to_be_bytes::<32>()));
                    {
                        let account = context
                            .journal_mut()
                            .load_account_with_code(address)
                            .map_err(ContextError::Db)?;
                        if account.info.code.as_ref().is_some_and(Bytecode::is_eip7702) {
                            return Err(ContextError::Custom(
                                "delegated policy read is unsupported".into(),
                            ));
                        }
                        authorize(
                            address,
                            account.info.code_hash(),
                            precompiles.contains(&address),
                        )
                        .map_err(ContextError::Custom)?;
                    }
                }
                if let Err(result) = frame.interpreter.step(
                    instructions.instruction_table(),
                    instructions.gas_table(),
                    context,
                ) {
                    break result;
                }
            };
            if frame.interpreter.bytecode.action().is_none() {
                frame.interpreter.halt(stopped);
            }
            let action = frame.interpreter.take_next_action();
            let next = frame.process_next_action::<CTX, FrameError<CTX>>(context, action)?;
            if next.is_result() {
                frame.set_finished(true);
            }
            next
        };
        let result = match next {
            ItemOrResult::Item(init) => {
                if !allow_state_reads {
                    return Err(ContextError::Custom(
                        "candidate state reads require scoped diagnostics".into(),
                    ));
                }
                match &init.frame_input {
                    FrameInput::Call(call) => {
                        let delegated = context
                            .journal_mut()
                            .load_account_with_code(call.bytecode_address)
                            .map_err(ContextError::Db)?
                            .info
                            .code
                            .as_ref()
                            .is_some_and(Bytecode::is_eip7702);
                        if delegated || call.known_bytecode.1.is_eip7702() {
                            return Err(ContextError::Custom(
                                "delegated policy read is unsupported".into(),
                            ));
                        }
                        for address in [call.bytecode_address, call.target_address] {
                            {
                                let account = context
                                    .journal_mut()
                                    .load_account_with_code(address)
                                    .map_err(ContextError::Db)?;
                                authorize(
                                    address,
                                    account.info.code_hash(),
                                    precompiles.contains(&address),
                                )
                                .map_err(ContextError::Custom)?;
                            }
                        }
                    }
                    _ => {
                        return Err(ContextError::Custom(
                            "policy read attempted creation".into(),
                        ));
                    }
                }
                match EthFrame::init_with_context(stack.get_next(), context, precompiles, init)? {
                    ItemOrResult::Item(token) => {
                        unsafe { stack.push(token) };
                        continue;
                    }
                    // No new frame was created; the current frame receives the result.
                    ItemOrResult::Result(result) => result,
                }
            }
            ItemOrResult::Result(result) => result,
        };
        if stack.get().is_finished() {
            stack.pop();
        }
        if stack.index().is_none() {
            return Ok(result);
        }
        stack
            .get()
            .return_result::<CTX, FrameError<CTX>>(context, result)?;
    }
}

impl<CTX: ContextTr + Host> Inspector<CTX> for PolicyInspector<CTX> {
    fn step(&mut self, interpreter: &mut Interpreter<EthInterpreter>, context: &mut CTX) {
        if !self.active
            || self.diagnostic.is_none()
            || !matches!(interpreter.bytecode.opcode(), 0x31 | 0x3b | 0x3c | 0x3f)
        {
            return;
        }
        let Ok(word) = interpreter.stack.peek(0) else {
            return;
        };
        let account = Address::from_word(alloy_primitives::B256::from(word.to_be_bytes::<32>()));
        let checkpoint = context.journal_mut().checkpoint();
        let info = context
            .journal_mut()
            .load_account_with_code(account)
            .map(|account| {
                (
                    account.info.code_hash(),
                    account.info.code.as_ref().is_none_or(Bytecode::is_empty),
                    account.info.code.as_ref().is_some_and(Bytecode::is_eip7702),
                )
            });
        context.journal_mut().checkpoint_revert(checkpoint);
        let result = info
            .map_err(|_| "diagnostic account unavailable".to_owned())
            .and_then(|(hash, empty, delegated)| {
                if delegated {
                    return Err("delegated diagnostic account unsupported".into());
                }
                let kind = if self.precompiles.contains(&account) {
                    CodeKind::Precompile
                } else if empty {
                    CodeKind::NoCode
                } else {
                    CodeKind::Contract
                };
                self.snapshot.authorize_diagnostic_account(
                    self.identity
                        .as_ref()
                        .ok_or("missing diagnostic identity")?,
                    account,
                    hash,
                    kind,
                    &self.created,
                )
            });
        if let Err(reason) = result {
            self.denied.get_or_insert(reason);
            interpreter.halt(InstructionResult::Revert);
        }
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if !self.active {
            return None;
        }
        let depth = self.depth;
        self.depth += 1;
        self.creation_checkpoints.push(self.created.len());
        let data = inputs.input.bytes(context);
        let reason = if self.calls.len() >= MAX_CHECKS {
            self.denied
                .get_or_insert("policy evaluation count exceeded".into());
            Err("policy evaluation count exceeded".to_owned())
        } else if context
            .journal_mut()
            .load_account_with_code(inputs.bytecode_address)
            .map_err(|_| ())
            .map(|account| account.info.code.as_ref().is_some_and(Bytecode::is_eip7702))
            != Ok(false)
        {
            // Revm has already loaded this account and may have replaced known
            // bytecode with its delegated implementation. Preserve the namespace
            // boundary until delegated code and authorization writes are modeled.
            self.denied.get_or_insert(
                "EIP-7702 delegated execution is unsupported or code is unavailable".into(),
            );
            Err("EIP-7702 delegated execution is unsupported or code is unavailable".to_owned())
        } else {
            let storage_code_hash = match context
                .journal_mut()
                .load_account_with_code(inputs.target_address)
            {
                Ok(account) => account.info.code_hash(),
                Err(_) => {
                    self.denied
                        .get_or_insert("storage account code unavailable".into());
                    return Some(CallOutcome::new(
                        InterpreterResult {
                            result: InstructionResult::Revert,
                            gas: Gas::new_with_regular_gas_and_reservoir(
                                inputs.gas_limit,
                                inputs.reservoir,
                            ),
                            output: Bytes::new(),
                        },
                        inputs.return_memory_offset.clone(),
                    ));
                }
            };
            let observed = ObservedCall {
                kind: match inputs.scheme {
                    CallScheme::Call => FrameKind::Call,
                    CallScheme::StaticCall => FrameKind::StaticCall,
                    CallScheme::DelegateCall => FrameKind::DelegateCall,
                    CallScheme::CallCode => FrameKind::CallCode,
                },
                caller: inputs.caller,
                code_address: inputs.bytecode_address,
                storage_address: inputs.target_address,
                calldata: data.clone(),
                value: inputs.call_value(),
                depth,
                code_hash: inputs.known_bytecode.0,
                storage_code_hash,
                code_kind: if self.precompiles.contains(&inputs.bytecode_address) {
                    CodeKind::Precompile
                } else if inputs.known_bytecode.1.is_empty() {
                    CodeKind::NoCode
                } else {
                    CodeKind::Contract
                },
            };
            self.check_frame(context, &observed)
        };
        let code = reason.as_ref().copied().unwrap_or(255);
        if self.calls.len() < MAX_CHECKS {
            self.calls.push(CallRecord {
                depth,
                caller: inputs.caller,
                code_address: inputs.bytecode_address,
                storage_address: inputs.target_address,
                selector: format!(
                    "0x{}",
                    alloy_primitives::hex::encode(&data[..data.len().min(4)])
                ),
                scheme: format!("{:?}", inputs.scheme),
                reason_code: code,
            });
        }
        if code == 0 || (self.diagnostic.is_some() && self.denied.is_none()) {
            return None;
        }
        self.denied.get_or_insert_with(|| {
            reason.err().unwrap_or_else(|| {
                format!(
                    "rule {code}: call depth {depth}, {} -> {}",
                    inputs.caller, inputs.bytecode_address
                )
            })
        });
        let mut outcome = CallOutcome::new(
            InterpreterResult {
                result: InstructionResult::Revert,
                gas: Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir),
                output: Bytes::new(),
            },
            inputs.return_memory_offset.clone(),
        );
        outcome.charged_new_account_state_gas = inputs.charged_new_account_state_gas;
        Some(outcome)
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        if self.active {
            self.depth = self.depth.saturating_sub(1);
            if let Some(checkpoint) = self.creation_checkpoints.pop()
                && !outcome.result.result.is_ok()
            {
                self.created.truncate(checkpoint);
            }
        }
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        if !self.active {
            return None;
        }
        let depth = self.depth;
        self.depth += 1;
        self.creation_checkpoints.push(self.created.len());
        let mut address = Address::ZERO;
        let reason = (|| {
            if self.calls.len() >= MAX_CHECKS {
                self.denied
                    .get_or_insert("policy evaluation count exceeded".into());
                return Err("policy evaluation count exceeded".into());
            }
            let kind = match inputs.scheme() {
                CreateScheme::Create => FrameKind::Create,
                CreateScheme::Create2 { .. } => FrameKind::Create2,
                CreateScheme::Custom { .. } => {
                    self.denied
                        .get_or_insert("custom creation scheme is unsupported".into());
                    return Err("custom creation scheme is unsupported".into());
                }
            };
            // Revm increments the creator nonce after this inspector boundary.
            let nonce = context
                .journal_mut()
                .load_account(inputs.caller())
                .map_err(|_| "creator account unavailable")?
                .info
                .nonce;
            address = inputs.created_address(nonce);
            let checkpoint = context.journal_mut().checkpoint();
            let account = context
                .journal_mut()
                .load_account_with_code(address)
                .map(|account| {
                    (
                        account.info.code_hash(),
                        account.info.code.as_ref().is_none_or(Bytecode::is_empty),
                    )
                });
            context.journal_mut().checkpoint_revert(checkpoint);
            let (code_hash, empty) = account.map_err(|_| "created account unavailable")?;
            let observed = ObservedCall {
                kind,
                caller: inputs.caller(),
                code_address: address,
                storage_address: address,
                calldata: inputs.init_code().clone(),
                value: inputs.value(),
                depth,
                code_hash,
                storage_code_hash: code_hash,
                code_kind: if empty {
                    CodeKind::NoCode
                } else {
                    CodeKind::Contract
                },
            };
            self.check_frame(context, &observed)
        })();
        let code = reason.as_ref().copied().unwrap_or(255);
        if self.calls.len() < MAX_CHECKS {
            self.calls.push(CallRecord {
                depth,
                caller: inputs.caller(),
                code_address: address,
                storage_address: address,
                selector: "0x".into(),
                scheme: format!("{:?}", inputs.scheme()),
                reason_code: code,
            });
        }
        if code == 0 || (self.diagnostic.is_some() && self.denied.is_none()) {
            let identity = self
                .identity
                .as_ref()
                .expect("identity validated before policy");
            self.created.push(CreatedContract {
                address,
                org_id: identity.org_id.clone(),
                principal_id: identity.principal_id.clone(),
            });
            return None;
        }
        self.denied.get_or_insert_with(|| {
            reason.err().unwrap_or_else(|| {
                format!(
                    "rule {code}: create depth {depth}, {} -> {address}",
                    inputs.caller()
                )
            })
        });
        let mut outcome = CreateOutcome::new(
            InterpreterResult {
                result: InstructionResult::Revert,
                gas: Gas::new_with_regular_gas_and_reservoir(
                    inputs.gas_limit(),
                    inputs.reservoir(),
                ),
                output: Bytes::new(),
            },
            None,
        );
        outcome.charged_create_state_gas = inputs.charged_create_state_gas();
        Some(outcome)
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if self.active {
            self.depth = self.depth.saturating_sub(1);
            if let Some(checkpoint) = self.creation_checkpoints.pop()
                && !outcome.result.result.is_ok()
            {
                self.created.truncate(checkpoint);
            }
        }
    }

    fn selfdestruct(&mut self, _contract: Address, _target: Address, _value: U256) {
        if self.active {
            self.denied
                .get_or_insert("selfdestruct outside PoC policy scope".into());
        }
    }
}
