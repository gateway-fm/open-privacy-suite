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
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::{
    context::{
        ExecutionBinding, ExecutionIdentity, FramePolicy, IdentityResolver, ObservedCall,
        PinnedPolicySnapshot, PolicyInvocation,
    },
    facts::FactsPolicy,
    policy::PolicyFactory,
    stream::FactStream,
    transaction::PolicyTx,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/record-party-v1.json"
    ))
    .unwrap()
}
#[derive(Debug)]
struct Context;
impl IdentityResolver for Context {
    fn resolve(&self, binding: &ExecutionBinding, tx: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "fixture_principal".into(),
            org_id: "org_acme".into(),
            context_id: "record".into(),
            signer: tx.caller,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
fn setup(
    record_code: Bytes,
    implementation: Option<(Address, Bytes)>,
) -> (PolicyFactory, InMemoryDB) {
    setup_with_pin(record_code, implementation, false)
}
fn setup_with_pin(
    record_code: Bytes,
    implementation: Option<(Address, Bytes)>,
    incorrect_pin: bool,
) -> (PolicyFactory, InMemoryDB) {
    let vector = fixture();
    let mut snapshot: Value = serde_json::from_str::<Value>(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap()["snapshot"]
        .clone();
    let code: Bytes = vector["policy_runtime_hex"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    snapshot["policies"][0]["bytecode"] = json!(STANDARD.encode(&code));
    snapshot["policies"][0]["runtime_digest"] = json!(hex::encode(Sha256::digest(&code)));
    snapshot["policies"][0]["policy_digest"] = vector["policy_digest"].clone();
    let mut db = InMemoryDB::default();
    let signer: Address = vector["signer"].as_str().unwrap().parse().unwrap();
    db.insert_account_info(
        signer,
        AccountInfo {
            balance: U256::from(1000000000),
            ..Default::default()
        },
    );
    let target: Address = vector["record_address"].as_str().unwrap().parse().unwrap();
    db.insert_account_info(
        target,
        AccountInfo {
            code_hash: keccak256(&record_code),
            code: Some(Bytecode::new_raw(record_code)),
            ..Default::default()
        },
    );
    if let Some((address, code)) = implementation {
        snapshot["contracts"].as_array_mut().unwrap().push(json!({"address":format!("{address:#x}"),"org_id":"org_acme","shared_infrastructure":false,"code_hash":"","deployer_principal_id":"","pending":false}));
        if incorrect_pin {
            snapshot["contracts"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap()["code_hash"] = json!(format!("{:#x}", keccak256([0])));
        }
        db.insert_account_info(
            address,
            AccountInfo {
                code_hash: keccak256(&code),
                code: Some(Bytecode::new_raw(code)),
                ..Default::default()
            },
        );
    }
    let payload = serde_json::to_vec(&snapshot).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [b"snapshot".as_slice(), b"ops", &payload] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let envelope=serde_json::to_vec(&json!({"version":1,"kind":"snapshot","key_id":"ops","payload":STANDARD.encode(&payload),"signature":STANDARD.encode(key.sign(&bytes).to_bytes())})).unwrap();
    let stream = FactStream::new(Verifier::new(
        serde_json::from_value::<Network>(snapshot["network"].clone()).unwrap(),
        BTreeMap::from([("ops".into(), key.verifying_key())]),
    ));
    stream.accept("snapshot", &envelope, 1800000010).unwrap();
    let facts = stream.pin(1800000010, 1).unwrap();
    (
        PolicyFactory::new(
            Arc::new(PinnedPolicySnapshot::new(
                facts.version(),
                facts.digest(),
                Arc::new(FactsPolicy::new(facts, 1800000010).unwrap()),
            )),
            Arc::new(Context),
        ),
        db,
    )
}
fn execute(factory: PolicyFactory, db: InMemoryDB) -> bool {
    execute_at(factory, db, SpecId::SHANGHAI)
}
fn execute_at(factory: PolicyFactory, db: InMemoryDB, spec: SpecId) -> bool {
    execute_bound(factory, db, spec, ExecutionBinding::Transaction(B256::ZERO))
}
fn execute_bound(
    factory: PolicyFactory,
    db: InMemoryDB,
    spec: SpecId,
    binding: ExecutionBinding,
) -> bool {
    let vector = fixture();
    let signer: Address = vector["signer"].as_str().unwrap().parse().unwrap();
    let nonce = db
        .cache
        .accounts
        .get(&signer)
        .map_or(0, |account| account.info.nonce);
    let mut evm = factory.create_evm(
        db,
        EvmEnv {
            cfg_env: CfgEnv::new_with_spec(spec),
            ..Default::default()
        },
    );
    let tx = TxEnv::builder()
        .nonce(nonce)
        .caller(vector["signer"].as_str().unwrap().parse().unwrap())
        .to(vector["record_address"].as_str().unwrap().parse().unwrap())
        .data(vector["call_data_hex"].as_str().unwrap().parse().unwrap())
        .gas_limit(400000)
        .gas_price(0)
        .build()
        .unwrap();
    evm.transact_raw(PolicyTx::bound(tx, binding)).is_ok()
}

#[derive(Debug)]
struct CandidateGetter;
impl FramePolicy for CandidateGetter {
    fn prepare(&self, _: &ExecutionIdentity, _: &ObservedCall) -> Result<PolicyInvocation, String> {
        let vector = fixture();
        Ok(PolicyInvocation {
            revision: B256::ZERO,
            bytecode: vector["policy_runtime_hex"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            calldata: vector["check_calldata_hex"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        })
    }
}
#[test]
fn candidate_record_getter_requires_scoped_human_diagnostics() {
    let vector = fixture();
    let (factory, mut db) = setup(
        vector["record_runtime_hex"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        None,
    );
    let target = vector["record_address"].as_str().unwrap().parse().unwrap();
    for (slot, value) in vector["cases"][0]["storage"].as_object().unwrap() {
        db.insert_account_storage(
            target,
            slot.parse().unwrap(),
            value.as_str().unwrap().parse().unwrap(),
        )
        .unwrap();
    }
    assert!(
        execute(factory.clone(), db.clone()),
        "approved active getter remains functional"
    );
    let candidate = Arc::new(PinnedPolicySnapshot::new(
        1,
        B256::ZERO,
        Arc::new(CandidateGetter),
    ));
    let binding = ExecutionBinding::Simulation {
        digest: B256::ZERO,
        context_id: "preview".into(),
    };
    let (preview, _) = factory.clone().candidate(candidate.clone());
    assert!(!execute_bound(
        preview,
        db.clone(),
        SpecId::SHANGHAI,
        binding.clone()
    ));
    let (diagnostic, report) = factory.diagnostic().0.candidate(candidate);
    assert!(execute_bound(diagnostic, db, SpecId::SHANGHAI, binding));
    assert_eq!(report.value().unwrap()["would_allow"], true);
}
#[test]
fn generated_record_party_getter_vectors_execute_in_live_candidate_state() {
    let vector = fixture();
    for case in vector["cases"].as_array().unwrap() {
        let (factory, mut db) = setup(
            vector["record_runtime_hex"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            None,
        );
        let target = vector["record_address"].as_str().unwrap().parse().unwrap();
        for (slot, value) in case["storage"].as_object().unwrap() {
            db.insert_account_storage(
                target,
                slot.parse().unwrap(),
                value.as_str().unwrap().parse().unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            execute(factory, db),
            case["expected_reason"] == 0,
            "{}",
            case["name"]
        );
    }
}
#[test]
fn getter_cannot_hide_foreign_calls_or_foreign_account_reads() {
    let vector = fixture();
    let foreign = Address::repeat_byte(0xcc);
    let linked: Address = vector["signer"].as_str().unwrap().parse().unwrap();
    for opcode in [0xfa, 0x31, 0x3b, 0x3f] {
        let mut code = hex!("60003560e01c63018fce0e14601057005b").to_vec();
        if opcode == 0xfa {
            code.extend_from_slice(&hex!("6000600060006000"));
        }
        code.push(0x73);
        code.extend_from_slice(foreign.as_slice());
        if opcode == 0xfa {
            code.extend_from_slice(&hex!("61c350"));
        }
        code.extend_from_slice(&[opcode, 0x50]);
        for offset in [0x40, 0x60] {
            code.push(0x73);
            code.extend_from_slice(linked.as_slice());
            code.extend_from_slice(&[0x60, offset, 0x52]);
        }
        code.extend_from_slice(&hex!("60a06000f3"));
        let (factory, db) = setup(code.into(), None);
        assert!(
            !execute(factory, db),
            "getter hid foreign opcode {opcode:x}"
        );
    }
}
#[test]
fn same_org_proxy_getter_reads_guarded_storage() {
    assert!(proxy_getter(false));
}

#[test]
fn same_org_private_getter_cannot_bypass_a_signed_implementation_pin() {
    assert!(!proxy_getter(true));
}

fn proxy_getter(incorrect_pin: bool) -> bool {
    let vector = fixture();
    let implementation = Address::repeat_byte(0xdd);
    let mut code = hex!("60003560e01c63018fce0e14601057005b365f5f376000600036600073").to_vec();
    code.extend_from_slice(implementation.as_slice());
    code.extend_from_slice(&hex!("5af4503d600060003e3d6000f3"));
    let (factory, mut db) = setup_with_pin(
        code.into(),
        Some((
            implementation,
            vector["record_runtime_hex"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        )),
        incorrect_pin,
    );
    let target = vector["record_address"].as_str().unwrap().parse().unwrap();
    for (slot, value) in vector["cases"][0]["storage"].as_object().unwrap() {
        db.insert_account_storage(
            target,
            slot.parse().unwrap(),
            value.as_str().unwrap().parse().unwrap(),
        )
        .unwrap();
    }
    execute(factory, db)
}

#[test]
fn getter_cannot_use_owned_delegation_to_reach_foreign_implementation() {
    let vector = fixture();
    let delegated = Address::repeat_byte(0xdd);
    let foreign = Address::repeat_byte(0xee);
    let linked: Address = vector["signer"].as_str().unwrap().parse().unwrap();
    let mut getter = hex!("60003560e01c63018fce0e14601057005b600060006000600073").to_vec();
    getter.extend_from_slice(delegated.as_slice());
    getter.extend_from_slice(&hex!("61c350fa50"));
    for offset in [0x40, 0x60] {
        getter.push(0x73);
        getter.extend_from_slice(linked.as_slice());
        getter.extend_from_slice(&[0x60, offset, 0x52]);
    }
    getter.extend_from_slice(&hex!("60a06000f3"));
    let mut designator = hex!("ef0100").to_vec();
    designator.extend_from_slice(foreign.as_slice());
    let (factory, mut db) = setup(getter.into(), Some((delegated, designator.into())));
    let code = Bytes::from_static(&hex!("60006000f3"));
    db.insert_account_info(
        foreign,
        AccountInfo {
            code_hash: keccak256(&code),
            code: Some(Bytecode::new_raw(code)),
            ..Default::default()
        },
    );
    assert!(!execute_at(factory, db, SpecId::PRAGUE));
}

#[test]
fn unchanged_pinned_facts_observe_actual_setter_state_from_earlier_in_the_block() {
    use alloy_evm::{eth::EthEvmFactory, revm::DatabaseCommit};
    let vector = fixture();
    let (factory, mut db) = setup(
        vector["record_runtime_hex"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        None,
    );
    let target = vector["record_address"].as_str().unwrap().parse().unwrap();
    for (slot, value) in vector["cases"][0]["storage"].as_object().unwrap() {
        db.insert_account_storage(
            target,
            slot.parse().unwrap(),
            value.as_str().unwrap().parse().unwrap(),
        )
        .unwrap();
    }
    assert!(execute(factory.clone(), db.clone()));
    // Apply the real setter bytecode as an independently authorised earlier
    // transaction. The record check reuses the exact same immutable facts handle.
    let mut setter = EthEvmFactory::default().create_evm(
        db,
        EvmEnv {
            cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
            ..Default::default()
        },
    );
    let tx = TxEnv::builder()
        .caller(vector["signer"].as_str().unwrap().parse().unwrap())
        .to(target)
        .data(
            vector["mutation_calldata_hex"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        )
        .gas_limit(300000)
        .gas_price(0)
        .build()
        .unwrap();
    let result = setter.transact_raw(tx).unwrap();
    assert!(result.result.is_success());
    setter.components_mut().0.commit(result.state);
    let (db, _) = setter.finish();
    assert!(
        !execute(factory, db),
        "cached party result ignored committed candidate state"
    );
}
