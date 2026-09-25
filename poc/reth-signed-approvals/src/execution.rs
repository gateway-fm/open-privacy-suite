//! Producer-only EVM wrapper: inspect one provisional execution and veto before commit.
use crate::{approvals::Selection, call_hash, direct, fingerprint, profile};
use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, InvalidTxError,
    eth::{EthEvm, EthEvmBuilder, EthEvmContext},
    precompiles::PrecompilesMap,
    revm::{
        DatabaseRef,
        bytecode::Bytecode,
        context::{BlockEnv, CfgEnv, DBErrorMarker, TxEnv},
        context_interface::{
            Transaction,
            result::{EVMError, HaltReason, InvalidTransaction, ResultAndState},
        },
        inspector::{Inspector, NoOpInspector},
        interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome},
        primitives::hardfork::SpecId,
        state::AccountInfo,
    },
};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rpc_types_trace::geth::{CallConfig, PreStateConfig};
use revm_inspectors::tracing::{TracingInspector, TracingInspectorConfig};
use std::{cell::RefCell, error::Error, fmt};

#[derive(Debug, Clone)]
pub struct ApprovalFactory {
    pub selection: Selection,
    pub profile: Option<profile::Shared>,
    pub legacy: bool,
    pub verify: bool,
}
impl EvmFactory for ApprovalFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = ApprovalEvm<DB, I>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<D: DBErrorMarker> = EVMError<D, ApprovalTxError>;
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
        i: I,
    ) -> Self::Evm<DB, I> {
        ApprovalEvm {
            inner: EthEvmBuilder::new(db, env)
                .activate_inspector((inspector(), (FeeObserver::default(), i)))
                .build(),
            selection: self.selection.clone(),
            profile: self.profile.clone(),
            legacy: self.legacy,
            verify: self.verify,
            scratch: Vec::with_capacity(2048),
            clock: crate::approvals::unix_ms,
        }
    }
}
fn inspector() -> TracingInspector {
    TracingInspector::new(TracingInspectorConfig::from_geth_call_config(&CallConfig {
        with_log: Some(true),
        ..Default::default()
    }))
}
// Identify an account loaded solely by protocol fee settlement. Debug preflight
// disables those fees, so such an account must not enter the application witness.
// Observe frame boundaries only: no per-opcode work or external calls.
#[derive(Default)]
struct FeeObserver {
    depth: usize,
    beneficiary_in_execution: bool,
}
impl FeeObserver {
    fn end<DB: Database>(&mut self, ctx: &EthEvmContext<DB>) {
        self.depth -= 1;
        if self.depth == 0 {
            self.beneficiary_in_execution = ctx
                .journaled_state
                .inner
                .state
                .contains_key(&ctx.block.beneficiary);
        }
    }
}
impl<DB: Database> Inspector<EthEvmContext<DB>> for FeeObserver {
    fn call(&mut self, _: &mut EthEvmContext<DB>, _: &mut CallInputs) -> Option<CallOutcome> {
        self.depth += 1;
        None
    }
    fn create(&mut self, _: &mut EthEvmContext<DB>, _: &mut CreateInputs) -> Option<CreateOutcome> {
        self.depth += 1;
        None
    }
    fn call_end(&mut self, ctx: &mut EthEvmContext<DB>, _: &CallInputs, _: &mut CallOutcome) {
        self.end(ctx);
    }
    fn create_end(&mut self, ctx: &mut EthEvmContext<DB>, _: &CreateInputs, _: &mut CreateOutcome) {
        self.end(ctx);
    }
}

pub struct ApprovalEvm<DB: Database, I> {
    inner: EthEvm<DB, (TracingInspector, (FeeObserver, I)), PrecompilesMap>,
    selection: Selection,
    profile: Option<profile::Shared>,
    legacy: bool,
    verify: bool,
    scratch: Vec<u8>,
    clock: fn() -> u64,
}
impl<DB: Database, I: Inspector<EthEvmContext<DB>>> Evm for ApprovalEvm<DB, I> {
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error, ApprovalTxError>;
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
    fn transact_raw(&mut self, tx: TxEnv) -> Result<ResultAndState, Self::Error> {
        let mut timer = profile::Timer::new(self.profile.is_some());
        let selected = self.selection.lock().unwrap().take().ok_or_else(|| {
            EVMError::Transaction(ApprovalTxError::Denied("missing selection".into()))
        })?;
        self.require_unexpired(selected.approval.expires_at)?;
        if !selected.approval.valid_mode()
            || selected.approval.chain_id != self.chain_id()
            || selected.sender != tx.caller
            || selected.nonce != tx.nonce
        {
            return Err(EVMError::Transaction(ApprovalTxError::Denied(
                "selection mismatch".into(),
            )));
        }
        if self.legacy {
            self.inner.components_mut().1.0 = inspector();
        } else {
            self.inner.components_mut().1.0.fuse();
        }
        self.inner.components_mut().1.1.0 = FeeObserver::default();
        timer.lap(0);
        let sender = tx.caller;
        let beneficiary = self.inner.block().beneficiary;
        let basefee = self.inner.block().basefee as u128;
        let price = tx.effective_gas_price(basefee);
        let result = self.inner.transact_raw(tx).map_err(map_error)?;
        // The provisional EVM execution may cross the signed deadline. Never return its state
        // for commit once the selected approval has expired.
        self.require_unexpired(selected.approval.expires_at)?;
        timer.lap(1);
        let gas = U256::from(result.result.tx_gas_used());
        let fees = direct::Fees {
            sender,
            beneficiary,
            charge: gas * U256::from(price),
            reward: gas * U256::from(price.saturating_sub(basefee)),
        };
        let (db, inspectors, _) = self.inner.components_mut();
        let fee_only = (!inspectors.1.0.beneficiary_in_execution).then_some(beneficiary);
        let builder = inspectors.0.geth_builder();
        let calls = builder.geth_call_traces(
            CallConfig {
                with_log: Some(true),
                ..Default::default()
            },
            result.result.tx_gas_used(),
        );
        timer.lap(2);
        if selected.approval.hash_mode == 3 {
            let mut code_error = None;
            let actual = call_hash::fingerprint(
                &calls,
                |address| match db.basic(address) {
                    Ok(info) => {
                        let info = info.unwrap_or_default();
                        Ok(if info.is_code_hash_empty_or_zero() {
                            alloy_primitives::KECCAK256_EMPTY
                        } else {
                            info.code_hash
                        })
                    }
                    Err(err) => {
                        code_error = Some(err);
                        Err("code lookup failed".into())
                    }
                },
                &mut self.scratch,
                &mut timer,
            );
            if let Some(err) = code_error {
                return Err(EVMError::Database(err));
            }
            drop(calls);
            timer.lap(9);
            timer.record(&self.profile);
            if actual.as_ref() != Ok(&selected.approval.fingerprint) {
                eprintln!(
                    "OPS_APPROVAL_DECISION {}",
                    serde_json::json!({"decision":"deny","hash_mode":3,"tx_hash":selected.approval.tx_hash,"expected":selected.approval.fingerprint,"actual":format!("{actual:?}")})
                );
                return Err(EVMError::Transaction(ApprovalTxError::Denied(
                    "call fingerprint mismatch".into(),
                )));
            }
            self.require_unexpired(selected.approval.expires_at)?;
            return Ok(result);
        }
        let fast = if self.legacy {
            None
        } else {
            let mut codes = direct::code_hashes(db, &result.state).map_err(EVMError::Database)?;
            codes.retain(|(address, _)| Some(*address) != fee_only);
            Some(direct::fingerprint(
                &calls,
                &result.state,
                &codes,
                fees,
                &mut self.scratch,
                &mut timer,
            ))
        };
        let actual = if self.legacy || self.verify {
            // Diagnostic/reference path only. Never change the execution result we commit.
            let mut comparison = result.clone();
            if let Some(address) = fee_only {
                comparison.state.remove(&address);
            }
            for (address, account) in &mut comparison.state {
                account.info.balance = fees
                    .balance(*address, account.info.balance, account.is_selfdestructed())
                    .map_err(|e| EVMError::Transaction(ApprovalTxError::Denied(e)))?;
            }
            let db = RefDb(RefCell::new(db));
            let pre = builder
                .geth_prestate_traces(&comparison, &PreStateConfig::default(), &db)
                .map_err(EVMError::Database)?;
            timer.lap(3);
            let diff = builder
                .geth_prestate_traces(
                    &comparison,
                    &PreStateConfig {
                        diff_mode: Some(true),
                        ..Default::default()
                    },
                    &db,
                )
                .map_err(EVMError::Database)?;
            timer.lap(4);
            let calls = serde_json::to_value(calls).expect("trace serializable");
            let pre = serde_json::to_value(pre).expect("pre serializable");
            let diff = serde_json::to_value(diff).expect("diff serializable");
            timer.lap(5);
            let actual = fingerprint::profiled_fingerprint(&calls, &pre, &diff, &mut timer);
            drop((calls, pre, diff));
            timer.lap(9);
            actual
        } else {
            drop(calls);
            timer.lap(9);
            fast.as_ref().expect("direct mode").clone()
        };
        if self.verify {
            let fast = fast.as_ref().expect("verification requires direct mode");
            if fast != &actual && !(fast.is_err() && actual.is_err()) {
                return Err(EVMError::Transaction(ApprovalTxError::Denied(format!(
                    "differential fingerprint mismatch: direct={fast:?} legacy={actual:?}"
                ))));
            }
            eprintln!("OPS_FINGERPRINT_EQUIVALENT {}", selected.approval.tx_hash);
        }
        timer.record(&self.profile);
        if actual.as_ref() != Ok(&selected.approval.fingerprint) {
            eprintln!(
                "OPS_APPROVAL_DECISION {}",
                serde_json::json!({"decision":"deny","tx_hash":selected.approval.tx_hash,"expected":selected.approval.fingerprint,"actual":format!("{actual:?}")})
            );
            return Err(EVMError::Transaction(ApprovalTxError::Denied(
                "execution fingerprint mismatch".into(),
            )));
        }
        self.require_unexpired(selected.approval.expires_at)?;
        Ok(result)
    }
    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState, Self::Error> {
        self.inner
            .transact_system_call(caller, contract, data)
            .map_err(map_error)
    }
    fn finish(self) -> (DB, EvmEnv) {
        self.inner.finish()
    }
    fn set_inspector_enabled(&mut self, _: bool) {
        self.inner.set_inspector_enabled(true)
    }
    fn components(&self) -> (&DB, &I, &PrecompilesMap) {
        let (db, i, p) = self.inner.components();
        (db, &i.1.1, p)
    }
    fn components_mut(&mut self) -> (&mut DB, &mut I, &mut PrecompilesMap) {
        let (db, i, p) = self.inner.components_mut();
        (db, &mut i.1.1, p)
    }
}
impl<DB: Database, I> ApprovalEvm<DB, I> {
    fn require_unexpired(
        &self,
        expires_at: u64,
    ) -> Result<(), EVMError<DB::Error, ApprovalTxError>> {
        if (self.clock)() >= expires_at {
            return Err(EVMError::Transaction(ApprovalTxError::Denied(
                "approval expired".into(),
            )));
        }
        Ok(())
    }
}
struct RefDb<'a, D>(RefCell<&'a mut D>);
impl<D: Database> DatabaseRef for RefDb<'_, D> {
    type Error = D::Error;
    fn basic_ref(&self, a: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.0.borrow_mut().basic(a)
    }
    fn code_by_hash_ref(&self, h: B256) -> Result<Bytecode, Self::Error> {
        self.0.borrow_mut().code_by_hash(h)
    }
    fn storage_ref(&self, a: Address, k: U256) -> Result<U256, Self::Error> {
        self.0.borrow_mut().storage(a, k)
    }
    fn block_hash_ref(&self, n: u64) -> Result<B256, Self::Error> {
        self.0.borrow_mut().block_hash(n)
    }
}
#[derive(Debug)]
pub enum ApprovalTxError {
    Ethereum(InvalidTransaction),
    Denied(String),
}

impl fmt::Display for ApprovalTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethereum(e) => e.fmt(f),
            Self::Denied(reason) => write!(f, "OPS approval denied transaction: {reason}"),
        }
    }
}
impl Error for ApprovalTxError {}
impl InvalidTxError for ApprovalTxError {
    fn as_invalid_tx_err(&self) -> Option<&InvalidTransaction> {
        match self {
            Self::Ethereum(e) => Some(e),
            Self::Denied(_) => None,
        }
    }
}

fn map_error<D>(error: EVMError<D>) -> EVMError<D, ApprovalTxError> {
    match error {
        EVMError::Transaction(e) => EVMError::Transaction(ApprovalTxError::Ethereum(e)),
        EVMError::Header(e) => EVMError::Header(e),
        EVMError::Database(e) => EVMError::Database(e),
        EVMError::Custom(e) => EVMError::Custom(e),
        EVMError::CustomAny(e) => EVMError::CustomAny(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::{Approval, Selected};
    use alloy_evm::revm::database::InMemoryDB;
    use alloy_primitives::TxKind;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn expiry_during_execution_vetoes_the_provisional_result_in_both_modes() {
        static CLOCK: AtomicU64 = AtomicU64::new(0);
        struct AdvanceClock;
        impl<DB: Database> Inspector<EthEvmContext<DB>> for AdvanceClock {
            fn call_end(&mut self, _: &mut EthEvmContext<DB>, _: &CallInputs, _: &mut CallOutcome) {
                CLOCK.store(10, Ordering::SeqCst);
            }
        }
        for (mode, expires_at) in [(0, 10), (0, 11), (3, 10), (3, 11)] {
            CLOCK.store(9, Ordering::SeqCst);
            let sender = Address::with_last_byte(1);
            let selection = Arc::new(Mutex::new(Some(Selected {
                approval: Approval {
                    hash_mode: mode,
                    chain_id: 1,
                    tx_hash: B256::ZERO,
                    fingerprint: if mode == 0 {
                        // Strict fingerprint of this zero-value transfer with the sender nonce
                        // advancing from zero to one and no fee or application-state changes.
                        "217b497205c80ce4d1b6afe618da66ada0cdb089f9eed0e4e9fca4382af85ef7"
                            .parse()
                            .unwrap()
                    } else {
                        call_hash::fingerprint(
                            &alloy_rpc_types_trace::geth::CallFrame {
                                from: sender,
                                to: Some(Address::with_last_byte(100)),
                                typ: "CALL".into(),
                                ..Default::default()
                            },
                            |_| Ok(alloy_primitives::KECCAK256_EMPTY),
                            &mut vec![],
                            &mut profile::Timer::new(false),
                        )
                        .unwrap()
                    },
                    key_id: "default".into(),
                    issued_at: 0,
                    expires_at,
                },
                sender,
                nonce: 0,
            })));
            let factory = ApprovalFactory {
                selection,
                profile: None,
                legacy: false,
                verify: false,
            };
            let mut db = InMemoryDB::default();
            db.insert_account_info(
                sender,
                AccountInfo {
                    balance: U256::from(1_000_000),
                    ..Default::default()
                },
            );
            let mut evm = factory.create_evm_with_inspector(db, EvmEnv::default(), AdvanceClock);
            evm.clock = || CLOCK.load(Ordering::SeqCst);
            let result = evm.transact_raw(TxEnv {
                caller: sender,
                kind: TxKind::Call(Address::with_last_byte(100)),
                gas_limit: 30_000,
                gas_price: 0,
                ..Default::default()
            });
            assert_eq!(
                CLOCK.load(Ordering::SeqCst),
                10,
                "the provisional execution ran"
            );
            if expires_at == 10 {
                assert!(
                    matches!(result, Err(EVMError::Transaction(ApprovalTxError::Denied(ref reason))) if reason == "approval expired"),
                    "{result:?}"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "an otherwise identical unexpired approval commits: {result:?}"
                );
            }
        }
    }
}
