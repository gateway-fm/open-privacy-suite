#![cfg(feature = "reth-sdk")]
use alloy_evm::{
    EvmEnv,
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
        ExecutionBinding, ExecutionIdentity, FramePolicy, IdentityResolver, ObservedCall,
        PinnedPolicySnapshot, PolicyInvocation,
    },
    policy::PolicyFactory,
    simulation::run,
    transaction::PolicyTx,
};
use std::sync::Arc;
const SIGNER: Address = address!("0000000000000000000000000000000000001000");
const TARGET: Address = address!("0000000000000000000000000000000000002000");
#[derive(Debug)]
struct Context;
impl IdentityResolver for Context {
    fn resolve(&self, binding: &ExecutionBinding, _: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "alice".into(),
            org_id: "org-a".into(),
            context_id: "sim".into(),
            signer: SIGNER,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
#[derive(Debug)]
struct Policy(bool);
impl FramePolicy for Policy {
    fn prepare(&self, _: &ExecutionIdentity, _: &ObservedCall) -> Result<PolicyInvocation, String> {
        Ok(PolicyInvocation {
            revision: B256::ZERO,
            bytecode: Bytes::copy_from_slice(if self.0 {
                &hex!("600060005260206000f3")
            } else {
                &hex!("600160005260206000f3")
            }),
            calldata: Bytes::new(),
        })
    }
}
fn factory(allow: bool) -> PolicyFactory {
    PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            1,
            B256::ZERO,
            Arc::new(Policy(allow)),
        )),
        Arc::new(Context),
    )
}
fn db(code: &[u8]) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        SIGNER,
        AccountInfo {
            balance: U256::from(1_000_000_000),
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
    db
}
fn env() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
        ..Default::default()
    }
}
fn tx() -> PolicyTx {
    PolicyTx::bound(
        TxEnv::builder()
            .caller(SIGNER)
            .to(TARGET)
            .gas_limit(1_000_000)
            .gas_price(0)
            .build()
            .unwrap(),
        ExecutionBinding::Simulation {
            digest: B256::repeat_byte(1),
            context_id: "sim".into(),
        },
    )
}

#[test]
fn gas_estimation_evaluates_policy_even_for_plain_transfers() {
    assert!(
        run(
            factory(false),
            db(&[]),
            env(),
            tx(),
            "eth_estimateGas",
            None
        )
        .is_err()
    );
    assert_eq!(
        run(factory(true), db(&[]), env(), tx(), "eth_estimateGas", None).unwrap(),
        "0x5208"
    );
}

#[test]
fn calls_and_traces_never_expose_private_interpreter_frames() {
    let code = hex!("602a60005260206000f3");
    let output = run(factory(true), db(&code), env(), tx(), "eth_call", None).unwrap();
    assert_eq!(output, format!("0x{}2a", "00".repeat(31)));
    let options = serde_json::from_value(serde_json::json!({"tracer":"callTracer"})).unwrap();
    let trace = run(
        factory(true),
        db(&code),
        env(),
        tx(),
        "debug_traceCall",
        Some(options),
    )
    .unwrap();
    assert_eq!(trace["to"], format!("{TARGET:#x}"));
    assert!(
        trace
            .get("calls")
            .is_none_or(|calls| calls.as_array().unwrap().is_empty())
    );
}
