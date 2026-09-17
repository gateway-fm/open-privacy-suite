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
        CodeKind, ExecutionBinding, ExecutionIdentity, FrameKind, FramePolicy, IdentityResolver,
        ObservedCall, PinnedPolicySnapshot, PolicyInvocation,
    },
    policy::PolicyFactory,
    transaction::PolicyTx,
};
use std::sync::{Arc, Mutex};
const SIGNER: Address = address!("0000000000000000000000000000000000001000");

#[derive(Debug)]
struct Contexts;
impl IdentityResolver for Contexts {
    fn resolve(&self, binding: &ExecutionBinding, _: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "alice".into(),
            org_id: "org-a".into(),
            context_id: "ctx".into(),
            signer: SIGNER,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
#[derive(Debug)]
struct Capture(Arc<Mutex<Vec<ObservedCall>>>);
impl FramePolicy for Capture {
    fn prepare(
        &self,
        _: &ExecutionIdentity,
        call: &ObservedCall,
    ) -> Result<PolicyInvocation, String> {
        self.0.lock().unwrap().push(call.clone());
        Ok(PolicyInvocation {
            revision: B256::ZERO,
            bytecode: Bytes::from_static(&hex!("600060005260206000f3")),
            calldata: Bytes::new(),
        })
    }
}

fn observe(spec: SpecId, target: Address, code: &[u8]) -> ObservedCall {
    try_observe(spec, target, code).unwrap()
}

fn try_observe(spec: SpecId, target: Address, code: &[u8]) -> Result<ObservedCall, String> {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let factory = PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            1,
            B256::ZERO,
            Arc::new(Capture(observed.clone())),
        )),
        Arc::new(Contexts),
    );
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        SIGNER,
        AccountInfo {
            balance: U256::from(1_000_000_000),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo {
            code_hash: keccak256(code),
            code: Some(Bytecode::new_raw(Bytes::copy_from_slice(code))),
            ..Default::default()
        },
    );
    let mut evm = factory.create_evm(
        db,
        EvmEnv {
            cfg_env: CfgEnv::new_with_spec(spec),
            ..Default::default()
        },
    );
    let tx = TxEnv::builder()
        .caller(SIGNER)
        .to(target)
        .gas_limit(100_000)
        .gas_price(0)
        .build()
        .unwrap();
    let _ = evm
        .transact_raw(PolicyTx::bound(
            tx,
            ExecutionBinding::Transaction(B256::ZERO),
        ))
        .map_err(|err| err.to_string())?;
    Ok(observed.lock().unwrap().remove(0))
}

#[test]
fn delegated_code_cannot_masquerade_as_the_invoked_account() {
    let delegated = address!("0000000000000000000000000000000000002000");
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend_from_slice(address!("0000000000000000000000000000000000003000").as_slice());
    let result = try_observe(SpecId::PRAGUE, delegated, &code);
    assert!(
        result.is_err(),
        "legacy transaction invoked delegated account without authorization model"
    );
}

#[test]
fn code_classification_comes_from_live_execution_and_active_fork() {
    let ordinary = address!("0000000000000000000000000000000000002000");
    assert_eq!(
        observe(SpecId::SHANGHAI, ordinary, &[]).code_kind,
        CodeKind::NoCode
    );
    let contract = observe(SpecId::SHANGHAI, ordinary, &[0x00]);
    assert_eq!(contract.code_kind, CodeKind::Contract);
    assert_eq!(contract.code_hash, keccak256([0x00]));
    let kzg = address!("000000000000000000000000000000000000000a");
    assert_eq!(
        observe(SpecId::SHANGHAI, kzg, &[]).code_kind,
        CodeKind::NoCode
    );
    assert_eq!(
        observe(SpecId::CANCUN, kzg, &[]).code_kind,
        CodeKind::Precompile
    );
}

#[test]
fn creation_uses_the_actual_address_and_constructor_bytes() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let factory = PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            1,
            B256::ZERO,
            Arc::new(Capture(observed.clone())),
        )),
        Arc::new(Contexts),
    );
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        SIGNER,
        AccountInfo {
            balance: U256::from(1_000_000_000),
            ..Default::default()
        },
    );
    let mut evm = factory.create_evm(
        db,
        EvmEnv {
            cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
            ..Default::default()
        },
    );
    let init = Bytes::from_static(&hex!("600060005360016000f3"));
    let tx = TxEnv::builder()
        .caller(SIGNER)
        .create()
        .data(init.clone())
        .gas_limit(300_000)
        .gas_price(0)
        .build()
        .unwrap();
    let result = evm
        .transact_raw(PolicyTx::bound(
            tx,
            ExecutionBinding::Transaction(B256::ZERO),
        ))
        .expect("compiled allow policy permits deployment");
    assert!(result.result.is_success());
    let calls = observed.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, FrameKind::Create);
    assert_eq!(calls[0].code_address, SIGNER.create(0));
    assert_eq!(calls[0].storage_address, SIGNER.create(0));
    assert_eq!(calls[0].calldata, init);
    assert_eq!(calls[0].depth, 0);
}
