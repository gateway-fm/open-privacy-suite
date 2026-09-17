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
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor},
    context::ExecutionBinding,
    runtime::PolicyRuntime,
    transaction::PolicyTx,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

fn seal(kind: &str, payload: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(payload).unwrap();
    let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [kind.as_bytes(), b"ops", payload.as_slice()] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    serde_json::to_vec(&json!({"version":1,"kind":kind,"key_id":"ops","payload":STANDARD.encode(payload),"signature":STANDARD.encode(SigningKey::from_bytes(&[7;32]).sign(&bytes).to_bytes())})).unwrap()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap()
}
fn network() -> Network {
    Network {
        chain_id: 31337,
        deployment_id: "compiler-fixture".into(),
    }
}
fn descriptor() -> BlockDescriptor {
    BlockDescriptor {
        network: network(),
        hash: B256::repeat_byte(10),
        parent_hash: B256::repeat_byte(9),
        number: 1,
        timestamp: 1800000010,
        transactions: vec![B256::repeat_byte(1)],
    }
}
fn execute(handle: &ops_reth_policy::runtime::ExecutionHandle) -> bool {
    let case = &fixture()["cases"][0];
    let signer = case["facts"]["signer"]
        .as_str()
        .unwrap()
        .parse::<Address>()
        .unwrap();
    let target = case["call"]["code_address"]
        .as_str()
        .unwrap()
        .parse::<Address>()
        .unwrap();
    let data = case["call"]["data_hex"]
        .as_str()
        .unwrap()
        .parse::<Bytes>()
        .unwrap();
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        signer,
        AccountInfo {
            balance: U256::from(1_000_000_000),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo {
            code_hash: keccak256([0]),
            code: Some(Bytecode::new_raw(Bytes::from_static(&[0]))),
            ..Default::default()
        },
    );
    let mut evm = handle.factory().create_evm(
        db,
        EvmEnv {
            cfg_env: CfgEnv::new_with_spec(SpecId::PRAGUE),
            ..Default::default()
        },
    );
    let tx = TxEnv::builder()
        .caller(signer)
        .to(target)
        .data(data)
        .gas_limit(200_000)
        .gas_price(0)
        .build()
        .unwrap();
    evm.transact_raw(PolicyTx::bound(
        tx,
        ExecutionBinding::Transaction(B256::repeat_byte(1)),
    ))
    .is_ok()
}

#[test]
fn produced_block_replays_original_facts_after_revocation_and_restart() {
    let directory = std::env::temp_dir().join(format!("ops-runtime-replay-{}", std::process::id()));
    let verifier = Verifier::new(
        network(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let runtime = PolicyRuntime::new(
        verifier.clone(),
        Arc::new(ArtifactStore::open(&directory).unwrap()),
        16,
    );
    let mut snapshot = fixture()["snapshot"].clone();
    runtime
        .feed
        .accept("snapshot", &seal("snapshot", &snapshot), 1800000010)
        .unwrap();
    let identity = json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":"ctx-a","principal_id":"fixture_principal","org_id":"org_acme","signer":snapshot["principals"][0]["linked_addresses"][0],"binding_hash":format!("{:#x}",B256::repeat_byte(1)),"min_snapshot_version":1});
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    let original = runtime.pin_candidate(1800000010).unwrap();
    assert!(
        original.persist(&runtime.archive, &descriptor()).is_err(),
        "unexecuted transaction has no retained identity"
    );
    assert!(execute(&original));
    let mut renewed = identity.clone();
    renewed["context_id"] = json!("renewed-context");
    renewed["issued_at"] = json!(1800000010);
    renewed["expires_at"] = json!(1800000070);
    runtime
        .accept_identity(&seal("identity", &renewed), 1800000010)
        .unwrap();
    original.persist(&runtime.archive, &descriptor()).unwrap();
    let manifest = runtime.archive.load_for_block(&descriptor()).unwrap();
    let captured = runtime
        .verifier()
        .open_identity(
            &runtime
                .archive
                .get(manifest.identities[0].envelope)
                .unwrap(),
            1800000010,
        )
        .unwrap();
    assert_eq!(
        captured.context_id, "ctx-a",
        "manifest must retain the identity that actually executed, not a concurrent renewal"
    );
    assert_eq!(
        runtime
            .transaction_status(B256::repeat_byte(1), Some(descriptor().hash))
            .unwrap()
            .unwrap()
            .status,
        "produced"
    );
    snapshot["version"] = json!(2);
    snapshot["principals"][0]["banned"] = json!(true);
    runtime
        .feed
        .accept("snapshot", &seal("snapshot", &snapshot), 1800000020)
        .unwrap();
    assert!(!execute(&runtime.pin_candidate(1800000020).unwrap()));
    assert_eq!(
        runtime
            .transaction_status(B256::repeat_byte(1), None)
            .unwrap()
            .unwrap()
            .status,
        "denied"
    );
    drop(runtime);
    let restarted = PolicyRuntime::new(
        verifier,
        Arc::new(ArtifactStore::open(&directory).unwrap()),
        16,
    );
    assert!(
        restarted.pin_candidate(1800000020).is_err(),
        "replay facts must not become current user permissions"
    );
    assert!(execute(&restarted.replay(&descriptor()).unwrap()));
    assert_eq!(
        restarted
            .retained_identity(B256::repeat_byte(1))
            .unwrap()
            .context_id,
        "renewed-context"
    );
    assert!(restarted.retained_identity(B256::repeat_byte(2)).is_err());
    let mut wrong = descriptor();
    wrong.hash = B256::repeat_byte(99);
    assert!(restarted.replay(&wrong).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn canonical_status_releases_capacity_without_releasing_durable_identity_binding() {
    let directory =
        std::env::temp_dir().join(format!("ops-runtime-terminal-{}", std::process::id()));
    let verifier = Verifier::new(
        network(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let archive = Arc::new(ArtifactStore::open(&directory).unwrap());
    let runtime = PolicyRuntime::new(verifier.clone(), archive.clone(), 1);
    let snapshot = fixture()["snapshot"].clone();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot), 1800000010)
        .unwrap();
    let mut identity = json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":"ctx-a","principal_id":"fixture_principal","org_id":"org_acme","signer":snapshot["principals"][0]["linked_addresses"][0],"binding_hash":format!("{:#x}",B256::repeat_byte(1)),"min_snapshot_version":1});
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    let handle = runtime.pin_candidate(1800000010).unwrap();
    assert!(execute(&handle));
    handle.persist(&archive, &descriptor()).unwrap();
    assert!(
        runtime
            .reconcile_included(B256::repeat_byte(1), B256::repeat_byte(99))
            .is_err()
    );
    runtime
        .reconcile_included(B256::repeat_byte(1), descriptor().hash)
        .unwrap();
    assert!(
        runtime
            .identities
            .lookup(
                &ExecutionBinding::Transaction(B256::repeat_byte(1)),
                1800000010
            )
            .is_err()
    );
    identity["principal_id"] = json!("another-principal");
    assert!(
        runtime
            .accept_identity(&seal("identity", &identity), 1800000010)
            .is_err()
    );
    identity["principal_id"] = json!("fixture_principal");
    identity["binding_hash"] = json!(format!("{:#x}", B256::repeat_byte(2)));
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    drop(runtime);
    let restarted = PolicyRuntime::open(verifier, archive, 1, 1800000100).unwrap();
    assert!(
        restarted.pin_candidate(1800000100).is_err(),
        "expired retained facts must not become fresh"
    );
    assert_eq!(
        restarted
            .retained_identity(B256::repeat_byte(1))
            .unwrap()
            .principal_id,
        "fixture_principal"
    );
    assert!(
        restarted
            .transaction_status(B256::repeat_byte(1), Some(descriptor().hash))
            .unwrap()
            .is_some()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn renewed_admission_after_canonical_reconciliation_is_restored_on_restart() {
    let directory =
        std::env::temp_dir().join(format!("ops-runtime-renewal-{}", std::process::id()));
    let verifier = Verifier::new(
        network(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let archive = Arc::new(ArtifactStore::open(&directory).unwrap());
    let runtime = PolicyRuntime::new(verifier.clone(), archive.clone(), 1);
    let snapshot = fixture()["snapshot"].clone();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot), 1800000010)
        .unwrap();
    let mut identity = json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":"original","principal_id":"fixture_principal","org_id":"org_acme","signer":snapshot["principals"][0]["linked_addresses"][0],"binding_hash":format!("{:#x}",B256::repeat_byte(1)),"min_snapshot_version":1});
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    let handle = runtime.pin_candidate(1800000010).unwrap();
    assert!(execute(&handle));
    handle.persist(&archive, &descriptor()).unwrap();
    runtime
        .reconcile_included(B256::repeat_byte(1), descriptor().hash)
        .unwrap();
    // The receipt disappears in a reorg; OPS explicitly admits the same signed
    // transaction again with a fresh context after checking current permissions.
    identity["context_id"] = json!("post-reorg");
    identity["issued_at"] = json!(1800000010);
    identity["expires_at"] = json!(1800000070);
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    drop(runtime);
    let restarted = PolicyRuntime::open(verifier, archive, 1, 1800000010).unwrap();
    assert_eq!(
        restarted
            .identities
            .lookup(
                &ExecutionBinding::Transaction(B256::repeat_byte(1)),
                1800000010
            )
            .unwrap()
            .context_id,
        "post-reorg"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
