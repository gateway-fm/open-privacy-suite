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
    context::{
        CodeKind, ExecutionBinding, ExecutionIdentity, FrameKind, FramePolicy, IdentityResolver,
        ObservedCall, PinnedPolicySnapshot,
    },
    facts::FactsPolicy,
    policy::PolicyFactory,
    stream::FactStream,
    transaction::PolicyTx,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

const AT: i64 = 1800000010;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/per-group-v1.json"
    ))
    .unwrap()
}
fn signed(kind: &str, value: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(value).unwrap();
    let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [kind.as_bytes(), b"ops", &payload] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let signature = SigningKey::from_bytes(&[7; 32]).sign(&bytes);
    serde_json::to_vec(&json!({"version":1,"kind":kind,"key_id":"ops","payload":STANDARD.encode(payload),"signature":STANDARD.encode(signature.to_bytes())})).unwrap()
}
fn stream() -> FactStream {
    FactStream::new(Verifier::new(
        serde_json::from_value::<Network>(fixture()["snapshot"]["network"].clone()).unwrap(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    ))
}
fn facts(change: impl FnOnce(&mut Value)) -> FactsPolicy {
    let mut snapshot = fixture()["snapshot"].clone();
    change(&mut snapshot);
    let feed = stream();
    feed.accept("snapshot", &signed("snapshot", &snapshot), AT)
        .unwrap();
    FactsPolicy::new(feed.pin(AT, 1).unwrap(), AT).unwrap()
}
#[derive(Debug)]
struct Identity;
impl IdentityResolver for Identity {
    fn resolve(&self, binding: &ExecutionBinding, tx: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "fixture_principal".into(),
            org_id: "org_acme".into(),
            context_id: "groups".into(),
            signer: tx.caller,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
fn addresses() -> (Address, Address) {
    let f = fixture();
    (
        f["snapshot"]["principals"][0]["linked_addresses"][0]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        f["snapshot"]["contracts"][0]["address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    )
}
fn run(adapter: FactsPolicy, data: Bytes, diagnostic: bool) -> (bool, Option<u64>) {
    let (signer, target) = addresses();
    let factory = PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(1, B256::ZERO, Arc::new(adapter))),
        Arc::new(Identity),
    );
    let (factory, report) = if diagnostic {
        let (f, r) = factory.diagnostic();
        (f, Some(r))
    } else {
        (factory, None)
    };
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        signer,
        AccountInfo {
            balance: U256::from(1000000000),
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
    let tx = TxEnv::builder()
        .caller(signer)
        .to(target)
        .data(data)
        .gas_limit(400000)
        .gas_price(0)
        .build()
        .unwrap();
    let binding = if diagnostic {
        ExecutionBinding::Simulation {
            digest: B256::ZERO,
            context_id: "groups".into(),
        }
    } else {
        ExecutionBinding::Transaction(B256::ZERO)
    };
    let result = factory
        .create_evm(
            db,
            EvmEnv {
                cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
                ..Default::default()
            },
        )
        .transact_raw(PolicyTx::bound(tx, binding));
    (
        result.is_ok_and(|r| r.result.is_success()),
        report
            .and_then(|r| r.value().ok())
            .and_then(|r| r["decisions"][0]["reason_code"].as_u64()),
    )
}

#[test]
fn compiler_group_artifacts_match_whole_document_verdicts_in_the_node_evm() {
    for case in fixture()["cases"].as_array().unwrap() {
        let data: Bytes = case["calldata"].as_str().unwrap().parse().unwrap();
        let want = case["expected"].as_u64().unwrap();
        let (signer, target) = addresses();
        let tx = TxEnv::builder().caller(signer).build().unwrap();
        let identity = Identity
            .resolve(&ExecutionBinding::Transaction(B256::ZERO), &tx)
            .unwrap();
        let call = ObservedCall {
            kind: FrameKind::Call,
            caller: signer,
            code_address: target,
            storage_address: target,
            calldata: data.clone(),
            value: U256::ZERO,
            depth: 0,
            code_hash: keccak256([0]),
            storage_code_hash: keccak256([0]),
            code_kind: CodeKind::Contract,
        };
        let plan = facts(|_| {}).prepare_all(&identity, &call, &[]).unwrap();
        assert!(plan.per_group);
        assert_eq!(plan.invocations.len(), 2);
        for invocation in plan.invocations {
            assert_eq!(
                invocation.calldata,
                case["input"].as_str().unwrap().parse::<Bytes>().unwrap()
            );
        }
        assert_eq!(
            run(facts(|_| {}), data.clone(), false).0,
            want == 0,
            "{}",
            case["name"]
        );
        assert_eq!(
            run(facts(|_| {}), data, true).1,
            Some(want),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn membership_and_candidate_replacement_never_inherit_removed_group_rules() {
    let data: Bytes = fixture()["cases"][0]["calldata"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(run(facts(|_| {}), data.clone(), false).0);
    let removed = facts(|s| {
        s["principals"][0]["memberships"] = json!([{"group_id":"grp_auditors","expires_at":0}]);
    });
    assert!(!run(removed, data.clone(), false).0);
    let candidates = serde_json::from_value::<Vec<ops_reth_policy::wire::PolicyArtifact>>(
        fixture()["snapshot"]["policies"].clone(),
    )
    .unwrap();
    let auditor = candidates
        .iter()
        .find(|p| p.group_id == "grp_auditors")
        .unwrap()
        .clone();
    let replaced = facts(|_| {})
        .with_candidates(&[auditor], "org_acme")
        .unwrap();
    assert!(!run(replaced, data.clone(), false).0);
    assert!(
        !run(
            facts(|_| {}).with_candidates(&[], "org_acme").unwrap(),
            data.clone(),
            false
        )
        .0
    );
    assert!(
        facts(|_| {})
            .with_candidates(&candidates, "other-org")
            .is_err()
    );
    assert!(
        run(facts(|_| {}), data, false).0,
        "candidate must not mutate signed active state"
    );
}

#[test]
fn signed_group_delta_deletes_only_its_composite_key_and_rejects_mixed_revisions() {
    let snapshot = fixture()["snapshot"].clone();
    let feed = stream();
    feed.accept("snapshot", &signed("snapshot", &snapshot), AT)
        .unwrap();
    let before = feed.pin(AT, 1).unwrap();
    let remaining = snapshot["policies"][1].clone();
    let deleted = format!(
        "{}\0{}",
        snapshot["policies"][0]["org_id"].as_str().unwrap(),
        snapshot["policies"][0]["group_id"].as_str().unwrap()
    );
    let mut delta = json!({"network":snapshot["network"],"issued_at":1800000000,"expires_at":1800000060,"previous_version":1,"previous_digest":alloy_primitives::hex::encode(before.digest()),"version":2,"upserts":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]},"deletes":{"principals":[],"groups":[],"contracts":[],"policies":[deleted],"sanctions":[]}});
    let mut changed = remaining.clone();
    changed["revision"] = json!(2);
    delta["upserts"]["policies"] = json!([changed]);
    let mut partial = delta.clone();
    partial["deletes"]["policies"] = json!([]);
    assert!(
        feed.accept("delta", &signed("delta", &partial), AT)
            .is_err()
    );
    assert_eq!(feed.pin(AT, 1).unwrap().version(), 1);
    feed.accept("delta", &signed("delta", &delta), AT).unwrap();
    assert_eq!(before.snapshot().policies.len(), 2);
    assert_eq!(feed.pin(AT, 2).unwrap().snapshot().policies.len(), 1);
}

#[test]
fn group_artifacts_share_the_frame_gas_budget_and_errors_fail_closed() {
    use sha2::{Digest, Sha256};
    let data: Bytes = fixture()["cases"][0]["calldata"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let costly = |reason: u16| {
        // 2,000 empty KECCAK256 operations cost about 72k gas, within the
        // 100k frame budget individually, but two cannot receive fresh budgets.
        let mut code = [0x5f, 0x5f, 0x20, 0x50].repeat(2000);
        code.extend_from_slice(&[
            0x61,
            (reason >> 8) as u8,
            reason as u8,
            0x5f,
            0x52,
            0x60,
            0x20,
            0x5f,
            0xf3,
        ]);
        code
    };
    let set_code = |snapshot: &mut Value, index: usize, code: Vec<u8>| {
        snapshot["policies"][index]["bytecode"] = json!(STANDARD.encode(&code));
        snapshot["policies"][index]["runtime_digest"] =
            json!(alloy_primitives::hex::encode(Sha256::digest(&code)));
    };
    let both = facts(|s| {
        set_code(s, 0, costly(257));
        set_code(s, 1, costly(0));
    });
    assert!(
        !run(both, data.clone(), false).0,
        "each group must not get a new 100k budget"
    );
    let only_allowing = facts(|s| {
        set_code(s, 0, costly(257));
        set_code(s, 1, costly(0));
        s["principals"][0]["memberships"]
            .as_array_mut()
            .unwrap()
            .retain(|m| m["group_id"] != "grp_auditors");
    });
    assert!(run(only_allowing, data.clone(), false).0);
    for unknown in [256u16, 267] {
        let adapter = facts(|s| {
            set_code(
                s,
                0,
                vec![
                    0x61,
                    (unknown >> 8) as u8,
                    unknown as u8,
                    0x5f,
                    0x52,
                    0x60,
                    0x20,
                    0x5f,
                    0xf3,
                ],
            );
            set_code(s, 1, costly(0));
        });
        assert!(
            !run(adapter, data.clone(), false).0,
            "unknown result must fail closed"
        );
    }
    let malformed = facts(|s| {
        set_code(s, 0, vec![0]);
        set_code(s, 1, costly(0));
    });
    assert!(
        !run(malformed, data, false).0,
        "an invalid artifact must not be skipped for an allowing group"
    );
}

#[test]
fn empty_active_policy_denies_calls_but_retains_scoped_diagnostics() {
    let data: Bytes = fixture()["cases"][0]["calldata"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(!run(facts(|s| s["policies"] = json!([])), data.clone(), false).0);
    let (executed, verdict) = run(facts(|s| s["policies"] = json!([])), data.clone(), true);
    assert!(
        executed,
        "authorized diagnostics still execute within their independent organization scope"
    );
    assert_eq!(verdict, Some(255), "empty active set must report denial");
    let candidates = serde_json::from_value::<Vec<ops_reth_policy::wire::PolicyArtifact>>(
        fixture()["snapshot"]["policies"].clone(),
    )
    .unwrap();
    assert!(
        facts(|s| s["policies"] = json!([]))
            .with_candidates(&candidates, "org_acme")
            .is_ok()
    );
}
