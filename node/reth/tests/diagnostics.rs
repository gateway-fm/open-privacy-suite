use alloy_evm::{
    Evm, EvmEnv, EvmFactory,
    revm::{
        bytecode::Bytecode,
        context::{CfgEnv, TxEnv},
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::AccountInfo,
    },
};
use alloy_primitives::{Address, B256, Bytes, U256, address, hex, keccak256};
use ops_reth_policy::{
    context::{
        CodeKind, CreatedContract, ExecutionBinding, ExecutionIdentity, FramePolicy,
        IdentityResolver, ObservedCall, PinnedPolicySnapshot, PolicyInvocation,
    },
    policy::PolicyFactory,
    transaction::PolicyTx,
};
use std::sync::Arc;
const SIGNER: Address = address!("0000000000000000000000000000000000001000");
const TARGET: Address = address!("0000000000000000000000000000000000002000");
const FOREIGN: Address = address!("0000000000000000000000000000000000003000");
#[derive(Debug)]
struct Context;
impl IdentityResolver for Context {
    fn resolve(&self, binding: &ExecutionBinding, _: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "banned-user".into(),
            org_id: "org-a".into(),
            context_id: "diagnostic".into(),
            signer: SIGNER,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
#[derive(Debug)]
struct DenyingPolicy;
impl FramePolicy for DenyingPolicy {
    fn prepare(&self, _: &ExecutionIdentity, _: &ObservedCall) -> Result<PolicyInvocation, String> {
        Ok(PolicyInvocation {
            revision: B256::ZERO,
            bytecode: Bytes::from_static(&hex!("600160005260206000f3")),
            calldata: Bytes::new(),
        })
    }
    fn authorize_diagnostic(
        &self,
        _: &ExecutionIdentity,
        call: &ObservedCall,
        _: &[CreatedContract],
    ) -> Result<(), String> {
        if call.code_address == TARGET && call.storage_address == TARGET {
            Ok(())
        } else {
            Err("foreign frame".into())
        }
    }
    fn authorize_diagnostic_account(
        &self,
        _: &ExecutionIdentity,
        account: Address,
        _: B256,
        _: CodeKind,
        _: &[CreatedContract],
    ) -> Result<(), String> {
        if account == TARGET {
            Ok(())
        } else {
            Err("foreign account read".into())
        }
    }
}
fn factory() -> PolicyFactory {
    PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            1,
            B256::ZERO,
            Arc::new(DenyingPolicy),
        )),
        Arc::new(Context),
    )
}
#[derive(Debug)]
struct AllowingPolicy;
impl FramePolicy for AllowingPolicy {
    fn authorize_policy_read(
        &self,
        _: &ExecutionIdentity,
        _: &ObservedCall,
        account: Address,
        _: B256,
        _: bool,
        _: &[CreatedContract],
    ) -> Result<(), String> {
        if account == TARGET {
            Ok(())
        } else {
            Err("foreign private read".into())
        }
    }
    fn prepare(&self, _: &ExecutionIdentity, _: &ObservedCall) -> Result<PolicyInvocation, String> {
        Ok(PolicyInvocation {
            revision: B256::ZERO,
            bytecode: Bytes::from_static(&hex!("600060005260206000f3")),
            calldata: Bytes::new(),
        })
    }
}

#[derive(Debug)]
struct ReadingCandidate(Bytes);
impl FramePolicy for ReadingCandidate {
    fn prepare(&self, _: &ExecutionIdentity, _: &ObservedCall) -> Result<PolicyInvocation, String> {
        Ok(PolicyInvocation {
            revision: B256::ZERO,
            bytecode: self.0.clone(),
            calldata: Bytes::new(),
        })
    }
}

#[test]
fn ordinary_candidate_cannot_probe_unapproved_getters_or_account_storage() {
    for read in [
        hex!("6120003150").to_vec(),
        hex!("600060006000600061200061fffffa50").to_vec(),
        hex!("60005450").to_vec(),
        hex!("4750").to_vec(),
    ] {
        let mut program = read;
        program.extend_from_slice(&hex!("600060005260206000f3"));
        let candidate = Arc::new(PinnedPolicySnapshot::new(
            1,
            B256::ZERO,
            Arc::new(ReadingCandidate(program.into())),
        ));
        let (preview, _) = PolicyFactory::new(allowing(), Arc::new(Context)).candidate(candidate);
        assert!(
            preview
                .create_evm(db(&[0]), env())
                .transact_raw(tx(true))
                .is_err(),
            "candidate exposed an unapproved live-state predicate"
        );
    }
}
fn allowing() -> Arc<PinnedPolicySnapshot> {
    Arc::new(PinnedPolicySnapshot::new(
        1,
        B256::ZERO,
        Arc::new(AllowingPolicy),
    ))
}

#[test]
fn candidate_preview_never_authorizes_an_active_policy_denial() {
    let (preview, _) = factory().candidate(allowing());
    assert!(
        preview
            .create_evm(db(&hex!("602a60005260206000f3")), env())
            .transact_raw(tx(true))
            .is_err()
    );
    assert!(
        preview
            .create_evm(db(&[0]), env())
            .transact_raw(tx(false))
            .is_err()
    );
}

#[test]
fn candidate_denial_is_reported_without_changing_active_execution() {
    let active = PolicyFactory::new(allowing(), Arc::new(Context));
    let candidate = Arc::new(PinnedPolicySnapshot::new(
        1,
        B256::ZERO,
        Arc::new(DenyingPolicy),
    ));
    let (preview, report) = active.clone().candidate(candidate);
    let result = preview
        .create_evm(db(&hex!("602a60005260206000f3")), env())
        .transact_raw(tx(true))
        .unwrap();
    assert!(result.result.is_success());
    assert_eq!(report.value().unwrap()["would_allow"], false);
    assert_eq!(report.value().unwrap()["decisions"][0]["reason_code"], 1);
    assert!(
        active
            .create_evm(db(&[0]), env())
            .transact_raw(tx(true))
            .unwrap()
            .result
            .is_success()
    );
}
fn db(code: &[u8]) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        SIGNER,
        AccountInfo {
            balance: U256::from(1000000000),
            ..Default::default()
        },
    );
    db.insert_account_info(
        TARGET,
        AccountInfo {
            code_hash: keccak256(code),
            code: Some(Bytecode::new_raw(Bytes::copy_from_slice(code))),
            ..Default::default()
        },
    );
    db.insert_account_info(
        FOREIGN,
        AccountInfo {
            code_hash: keccak256([0]),
            code: Some(Bytecode::new_raw(Bytes::from_static(&[0]))),
            ..Default::default()
        },
    );
    db
}
fn env() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
        ..Default::default()
    }
}
fn tx(simulation: bool) -> PolicyTx {
    PolicyTx::bound(
        TxEnv::builder()
            .caller(SIGNER)
            .to(TARGET)
            .gas_limit(300000)
            .gas_price(0)
            .build()
            .unwrap(),
        if simulation {
            ExecutionBinding::Simulation {
                digest: B256::ZERO,
                context_id: "diagnostic".into(),
            }
        } else {
            ExecutionBinding::Transaction(B256::ZERO)
        },
    )
}
#[test]
fn diagnostic_reports_would_deny_and_executes_only_inside_mandatory_scope() {
    let code = hex!("602a60005260206000f3");
    assert!(
        factory()
            .create_evm(db(&code), env())
            .transact_raw(tx(true))
            .is_err()
    );
    let (factory, report) = factory().diagnostic();
    let result = factory
        .create_evm(db(&code), env())
        .transact_raw(tx(true))
        .unwrap();
    assert!(result.result.is_success());
    let value = report.value().unwrap();
    assert_eq!(value["would_allow"], false);
    assert_eq!(value["decisions"][0]["reason_code"], 1);
    assert!(
        factory
            .create_evm(db(&code), env())
            .transact_raw(tx(false))
            .is_err(),
        "diagnostic cannot authorize a real transaction"
    );
}
#[test]
fn diagnostic_does_not_return_caught_foreign_call_or_account_read_results() {
    for code in [
        hex!("6000600060006000600061300061fffff150602a60005260206000f3").to_vec(),
        hex!("6130003150602a60005260206000f3").to_vec(),
        hex!("6130003b50602a60005260206000f3").to_vec(),
    ] {
        let (factory, _) = factory().diagnostic();
        assert!(
            factory
                .create_evm(db(&code), env())
                .transact_raw(tx(true))
                .is_err()
        );
    }
}
