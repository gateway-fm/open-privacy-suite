use alloy_evm::{
    Evm, EvmEnv, EvmFactory,
    revm::{
        DatabaseCommit,
        context::{CfgEnv, TxEnv},
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::AccountInfo,
    },
};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::{
    context::{
        CreatedContract, ExecutionBinding, ExecutionIdentity, FramePolicy, IdentityResolver,
        ObservedCall, PinnedPolicySnapshot, PolicyInvocation,
    },
    facts::FactsPolicy,
    policy::PolicyFactory,
    stream::FactStream,
    transaction::PolicyTx,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
const AT: i64 = 1800000010;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap()
}
fn signer() -> Address {
    fixture()["snapshot"]["principals"][0]["linked_addresses"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}
#[derive(Debug)]
struct Identity;
impl IdentityResolver for Identity {
    fn resolve(&self, binding: &ExecutionBinding, tx: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "fixture_principal".into(),
            org_id: "org_acme".into(),
            context_id: "create".into(),
            signer: tx.caller,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
#[derive(Debug)]
struct Capture {
    facts: FactsPolicy,
    seen: Arc<Mutex<Vec<Vec<CreatedContract>>>>,
}
impl FramePolicy for Capture {
    fn prepare(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
    ) -> Result<PolicyInvocation, String> {
        self.prepare_with_creations(identity, call, &[])
    }
    fn prepare_with_creations(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
        created: &[CreatedContract],
    ) -> Result<PolicyInvocation, String> {
        self.seen.lock().unwrap().push(created.to_vec());
        self.facts.prepare_with_creations(identity, call, created)
    }
}
fn factory() -> (PolicyFactory, Arc<Mutex<Vec<Vec<CreatedContract>>>>) {
    let snapshot = fixture()["snapshot"].clone();
    let payload = serde_json::to_vec(&snapshot).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut signed = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [b"snapshot".as_slice(), b"ops", &payload] {
        signed.extend_from_slice(&(part.len() as u32).to_be_bytes());
        signed.extend_from_slice(part);
    }
    let envelope=serde_json::to_vec(&json!({"version":1,"kind":"snapshot","key_id":"ops","payload":STANDARD.encode(payload),"signature":STANDARD.encode(key.sign(&signed).to_bytes())})).unwrap();
    let stream = FactStream::new(Verifier::new(
        serde_json::from_value::<Network>(snapshot["network"].clone()).unwrap(),
        BTreeMap::from([("ops".into(), key.verifying_key())]),
    ));
    stream.accept("snapshot", &envelope, AT).unwrap();
    let facts = stream.pin(AT, 1).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    (
        PolicyFactory::new(
            Arc::new(PinnedPolicySnapshot::new(
                facts.version(),
                facts.digest(),
                Arc::new(Capture {
                    facts: FactsPolicy::new(facts, AT).unwrap(),
                    seen: seen.clone(),
                }),
            )),
            Arc::new(Identity),
        ),
        seen,
    )
}
fn db() -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        signer(),
        AccountInfo {
            balance: U256::from(1_000_000_000),
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
fn create(init: Bytes, nonce: u64, simulation: bool) -> PolicyTx {
    PolicyTx::bound(
        TxEnv::builder()
            .caller(signer())
            .nonce(nonce)
            .create()
            .data(init)
            .gas_limit(500_000)
            .gas_price(0)
            .build()
            .unwrap(),
        if simulation {
            ExecutionBinding::Simulation {
                digest: B256::ZERO,
                context_id: "sim".into(),
            }
        } else {
            ExecutionBinding::Transaction(B256::repeat_byte(nonce as u8))
        },
    )
}
fn nested_constructor(create2: bool, revert: bool) -> Bytes {
    let child = hex!("600060005360016000f3");
    let mut code = hex!("600a6000600039").to_vec();
    if create2 {
        code.extend_from_slice(&hex!("6001"));
    }
    code.extend_from_slice(&hex!("600a60006000"));
    code.extend_from_slice(&[if create2 { 0xf5 } else { 0xf0 }, 0x50]);
    code.extend_from_slice(if revert {
        &hex!("60006000fd")
    } else {
        &hex!("600060005360016000f3")
    });
    code[3] = code.len() as u8;
    code.extend_from_slice(&child);
    code.into()
}
#[test]
fn nested_constructor_uses_pending_parent_owner_and_retains_successful_children() {
    for create2 in [false, true] {
        let (factory, seen) = factory();
        let mut evm = factory.create_evm(db(), env());
        // Copy a ten-byte child constructor, CREATE it, return a one-byte STOP parent.
        let init = nested_constructor(create2, false);
        let result = evm.transact_raw(create(init, 0, false)).unwrap();
        assert!(result.result.is_success());
        let parent = signer().create(0);
        let child = if create2 {
            parent.create2(
                U256::from(1).to_be_bytes::<32>(),
                keccak256(hex!("600060005360016000f3")),
            )
        } else {
            parent.create(1)
        };
        assert!(
            result.state.get(&child).is_some_and(|a| a
                .info
                .code
                .as_ref()
                .is_some_and(|c| !c.is_empty()))
        );
        evm.components_mut().0.commit(result.state);
        let data: Bytes = fixture()["cases"][0]["call"]["data_hex"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let tx = TxEnv::builder()
            .caller(signer())
            .nonce(1)
            .to(child)
            .data(data)
            .gas_limit(200_000)
            .gas_price(0)
            .build()
            .unwrap();
        assert!(
            evm.transact_raw(PolicyTx::bound(
                tx,
                ExecutionBinding::Transaction(B256::repeat_byte(2))
            ))
            .unwrap()
            .result
            .is_success()
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].len(), 0);
        assert_eq!(seen[1][0].address, parent);
        assert_eq!(seen[2].len(), 2);
        assert_eq!(seen[2][1].address, child);
    }
}
#[test]
fn reverted_constructor_and_simulation_probes_leave_no_pending_ownership() {
    for (init, simulation) in [
        (Bytes::from_static(&hex!("60006000fd")), false),
        (nested_constructor(false, true), false),
        (nested_constructor(true, true), false),
        (Bytes::from_static(&hex!("600060005360016000f3")), true),
    ] {
        let (factory, seen) = factory();
        let mut evm = factory.create_evm(db(), env());
        let first = evm.transact_raw(create(init, 0, simulation)).unwrap();
        if !simulation {
            assert!(!first.result.is_success());
        }
        let second = evm
            .transact_raw(create(
                Bytes::from_static(&hex!("600060005360016000f3")),
                0,
                simulation,
            ))
            .unwrap();
        assert!(second.result.is_success());
        assert!(
            seen.lock().unwrap().last().unwrap().is_empty(),
            "previous reverted execution or simulation probe leaked creation ownership"
        );
    }
}
