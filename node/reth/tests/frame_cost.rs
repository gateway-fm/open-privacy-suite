//! Cost of one active policy check, measured inside the node.
//!
//! This is the number the load harness cannot give: the harness is bounded by
//! its signed admission path and the development miner. Here the fixture policy
//! (`internal/policydsl/testdata/lifecycle-v1.json`, compiled with the pinned
//! solc) is evaluated by the real inspector on the real EVM for transactions
//! whose application contract forwards its call to itself `k` times, so a
//! transaction has exactly `k + 1` checked frames. Run with
//! `cargo test --release --features reth-sdk --test frame_cost -- --ignored --nocapture`.
use alloy_evm::{
    EthEvmFactory, Evm, EvmEnv, EvmFactory,
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
    context::{ExecutionBinding, ExecutionIdentity, IdentityResolver, PinnedPolicySnapshot},
    facts::FactsPolicy,
    policy::{FrameSample, PolicyFactory},
    stream::FactStream,
    transaction::PolicyTx,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

const AT: i64 = 1_800_000_010;
/// Forwarding contract: if calldata is longer than a plain `transfer(address,uint256)`
/// call (68 bytes), CALL itself with the calldata minus its last 32 bytes; otherwise stop.
/// Every level is one checked frame, so `68 + 32·k` bytes of calldata give `k + 1` frames.
const FORWARDER: [u8; 32] =
    hex!("36604410600857005b366000600037600060006020360360006000305af15000");

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap()
}

#[derive(Debug)]
struct Identity(Address);
impl IdentityResolver for Identity {
    fn resolve(&self, binding: &ExecutionBinding, _: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "fixture_principal".into(),
            org_id: "org_acme".into(),
            context_id: "frame-cost".into(),
            signer: self.0,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}

/// The fixture snapshot, with `principals` filler principals added so the fact
/// index has a realistic size; the fixture principal stays first.
fn factory(principals: usize) -> (PolicyFactory, Address, Address) {
    let mut snapshot = fixture()["snapshot"].clone();
    let signer: Address = snapshot["principals"][0]["linked_addresses"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let contract: Address = snapshot["contracts"][0]["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let filler = snapshot["principals"].as_array_mut().unwrap();
    for i in 1..principals {
        filler.push(json!({
            "id": format!("principal-{i}"),
            "banned": false,
            "kyc": true,
            "linked_addresses": [format!("0x{:040x}", 0x1000_0000u64 + i as u64)],
            "memberships": [{"group_id": "grp_traders", "expires_at": 0}],
        }));
    }
    let payload = serde_json::to_vec(&snapshot).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut signed = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [b"snapshot".as_slice(), b"ops", &payload] {
        signed.extend_from_slice(&(part.len() as u32).to_be_bytes());
        signed.extend_from_slice(part);
    }
    let envelope = serde_json::to_vec(&json!({
        "version": 1, "kind": "snapshot", "key_id": "ops",
        "payload": STANDARD.encode(&payload),
        "signature": STANDARD.encode(key.sign(&signed).to_bytes()),
    }))
    .unwrap();
    let stream = FactStream::new(Verifier::new(
        serde_json::from_value::<Network>(snapshot["network"].clone()).unwrap(),
        BTreeMap::from([("ops".into(), key.verifying_key())]),
    ));
    stream.accept("snapshot", &envelope, AT).unwrap();
    let facts = stream.pin(AT, 1).unwrap();
    let factory = PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            facts.version(),
            facts.digest(),
            Arc::new(FactsPolicy::new(facts, AT).unwrap()),
        )),
        Arc::new(Identity(signer)),
    );
    (factory, signer, contract)
}

fn db(signer: Address, contract: Address) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        signer,
        AccountInfo {
            balance: U256::from(1_000_000_000u64),
            ..Default::default()
        },
    );
    db.insert_account_info(
        contract,
        AccountInfo {
            code_hash: keccak256(FORWARDER),
            code: Some(Bytecode::new_raw(Bytes::from_static(&FORWARDER))),
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

fn calldata(nested: usize) -> Bytes {
    let mut data = hex!("a9059cbb").to_vec();
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&hex!("aaaa000000000000000000000000000000000001"));
    data.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());
    data.extend(std::iter::repeat_n(0u8, 32 * nested));
    Bytes::from(data)
}

fn tx_env(signer: Address, contract: Address, nested: usize) -> TxEnv {
    TxEnv::builder()
        .caller(signer)
        .to(contract)
        .data(calldata(nested))
        .gas_limit(30_000_000)
        .gas_price(0)
        .build()
        .unwrap()
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn summary(samples: &[FrameSample]) -> Value {
    let mut evaluate: Vec<u64> = samples.iter().map(|s| s.evaluate_nanos).collect();
    let mut prepare: Vec<u64> = samples.iter().map(|s| s.prepare_nanos).collect();
    let mut total: Vec<u64> = samples
        .iter()
        .map(|s| s.evaluate_nanos + s.prepare_nanos)
        .collect();
    evaluate.sort_unstable();
    prepare.sort_unstable();
    total.sort_unstable();
    let mean = |v: &[u64]| v.iter().sum::<u64>() as f64 / v.len().max(1) as f64;
    json!({
        "samples": samples.len(),
        "gas_per_check_mean": samples.iter().map(|s| s.gas).sum::<u64>() as f64 / samples.len().max(1) as f64,
        "prepare_us": {"mean": mean(&prepare) / 1e3, "p50": percentile(&prepare, 0.5) as f64 / 1e3, "p95": percentile(&prepare, 0.95) as f64 / 1e3},
        "evaluate_us": {"mean": mean(&evaluate) / 1e3, "p50": percentile(&evaluate, 0.5) as f64 / 1e3, "p95": percentile(&evaluate, 0.95) as f64 / 1e3, "p99": percentile(&evaluate, 0.99) as f64 / 1e3},
        "check_us": {"mean": mean(&total) / 1e3, "p50": percentile(&total, 0.5) as f64 / 1e3, "p95": percentile(&total, 0.95) as f64 / 1e3, "p99": percentile(&total, 0.99) as f64 / 1e3, "max": *total.last().unwrap_or(&0) as f64 / 1e3},
    })
}

#[test]
#[ignore = "measurement, not a correctness test; run explicitly with --ignored --nocapture"]
fn policy_check_cost_per_frame() {
    let warmup = 200usize;
    let rounds = 2_000usize;
    let mut report = Vec::new();
    for principals in [1_000usize, 10_000] {
        let (factory, signer, contract) = factory(principals);
        let (factory, timing) = factory.timed();
        let base = db(signer, contract);
        for nested in [0usize, 1, 2] {
            // Baseline: the same transaction on a stock EVM, no policy at all.
            let baseline_factory = EthEvmFactory::default();
            let mut baseline = Duration::ZERO;
            for i in 0..warmup + rounds {
                let mut evm = baseline_factory.create_evm(base.clone(), env());
                let started = Instant::now();
                let result = evm.transact_raw(tx_env(signer, contract, nested)).unwrap();
                let elapsed = started.elapsed();
                assert!(
                    result.result.is_success(),
                    "baseline failed: {:?}",
                    result.result
                );
                if i >= warmup {
                    baseline += elapsed;
                }
            }
            // Policy: identical transaction through the guarded factory.
            timing.take_samples();
            let mut guarded = Duration::ZERO;
            for i in 0..warmup + rounds {
                let mut evm = factory.create_evm(base.clone(), env());
                let tx = PolicyTx::bound(
                    tx_env(signer, contract, nested),
                    ExecutionBinding::Transaction(B256::from(U256::from(i as u64))),
                );
                let started = Instant::now();
                let result = evm.transact_raw(tx).unwrap();
                let elapsed = started.elapsed();
                assert!(
                    result.result.is_success(),
                    "policy denied or failed: {:?}",
                    result.result
                );
                if i == warmup - 1 {
                    timing.take_samples();
                }
                if i >= warmup {
                    guarded += elapsed;
                }
            }
            let samples = timing.take_samples();
            let frames = nested + 1;
            assert_eq!(samples.len(), rounds * frames, "one active check per frame");
            let guarded_us = guarded.as_secs_f64() * 1e6 / rounds as f64;
            let baseline_us = baseline.as_secs_f64() * 1e6 / rounds as f64;
            let entry = json!({
                "principals": principals,
                "frames_per_tx": frames,
                "rounds": rounds,
                "tx_wall_us": {"baseline_no_policy": baseline_us, "with_policy": guarded_us, "overhead_per_frame": (guarded_us - baseline_us) / frames as f64},
                "per_check": summary(&samples),
            });
            println!("{entry}");
            report.push(entry);
        }
    }
    if let Ok(path) = std::env::var("OPS_FRAME_COST_REPORT") {
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&json!({
                "schema": 1,
                "binary": "in-process test, --release",
                "policy_fixture": "internal/policydsl/testdata/lifecycle-v1.json",
                "rounds_per_config": rounds,
                "results": report,
            }))
            .unwrap(),
        )
        .unwrap();
        println!("report written to {path}");
    }
}

/// Measure the exact 60 artifacts compiled by the real HTTP acceptance run.
/// OPS_GROUP_COST_FIXTURE points at group-cost-fixture.json from that run.
/// Setup/signing/index construction are outside the timed frame evaluation.
#[test]
#[ignore = "live artifact measurement; requires OPS_GROUP_COST_FIXTURE"]
fn group_policy_check_cost() {
    let path = std::env::var("OPS_GROUP_COST_FIXTURE").expect("run group_acceptance.py first");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let org = fixture["org"].as_str().unwrap();
    let signer: Address = fixture["signer"].as_str().unwrap().parse().unwrap();
    let target: Address = fixture["target"].as_str().unwrap().parse().unwrap();
    let groups = fixture["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 60);
    let mut base = db(signer, target);
    base.insert_account_info(
        target,
        AccountInfo {
            code_hash: keccak256([0]),
            code: Some(Bytecode::new_raw(Bytes::from_static(&[0]))),
            ..Default::default()
        },
    );
    let warmup = 100;
    let rounds = 1000;
    let mut report = Vec::new();
    // Compare directory sizes while retaining exactly the same caller groups.
    for directory_groups in [7, 60] {
        for memberships in [1, 2, 5, 10, 11, 12, 20, 40, 60] {
            if memberships > directory_groups {
                continue;
            }
            let selected: Vec<_> = groups
                .iter()
                .take(directory_groups - 1)
                .chain(std::iter::once(&groups[59]))
                .collect();
            let caller_groups: Vec<_> = selected
                .iter()
                .take(memberships - 1)
                .copied()
                .chain(std::iter::once(&groups[59]))
                .collect();
            let snapshot = json!({
                "network": {"chain_id":31337,"deployment_id":"live-group-cost"},
                "issued_at":1800000000i64,"expires_at":1800000060i64,"version":1,
                "principals":[{"id":"fixture_principal","banned":false,"kyc":true,
                    "linked_addresses":[signer],"memberships":caller_groups.iter().map(|g|
                        json!({"group_id":g,"expires_at":0})).collect::<Vec<_>>()}],
                "groups":selected.iter().map(|g|json!({"id":g,"org_id":org,"claims":0,
                    "org_admin":false,"contract_claims":[]})).collect::<Vec<_>>(),
                "contracts":[{"address":target,"org_id":org,"shared_infrastructure":false,
                    "code_hash":"","deployer_principal_id":"","pending":false}],
                "policies":selected.iter().map(|g| {
                    let a = &fixture["artifacts"][g.as_str().unwrap()];
                    json!({"org_id":org,"group_id":g,"revision":1,"policy_digest":a["policy_digest"],
                        "runtime_digest":a["runtime_digest"],"bytecode":a["runtime_bytecode"]})
                }).collect::<Vec<_>>(), "sanctions":[]
            });
            let payload = serde_json::to_vec(&snapshot).unwrap();
            let key = SigningKey::from_bytes(&[7; 32]);
            let mut signed = b"OPS_NODE_POLICY_V1\0".to_vec();
            for part in [b"snapshot".as_slice(), b"ops", &payload] {
                signed.extend_from_slice(&(part.len() as u32).to_be_bytes());
                signed.extend_from_slice(part);
            }
            let envelope = serde_json::to_vec(&json!({"version":1,"kind":"snapshot","key_id":"ops",
                "payload":STANDARD.encode(&payload),"signature":STANDARD.encode(key.sign(&signed).to_bytes())})).unwrap();
            let stream = FactStream::new(Verifier::new(
                serde_json::from_value::<Network>(snapshot["network"].clone()).unwrap(),
                BTreeMap::from([("ops".into(), key.verifying_key())]),
            ));
            stream.accept("snapshot", &envelope, AT).unwrap();
            let facts = stream.pin(AT, 1).unwrap();
            #[derive(Debug)]
            struct GroupIdentity {
                org: String,
                signer: Address,
            }
            impl IdentityResolver for GroupIdentity {
                fn resolve(
                    &self,
                    binding: &ExecutionBinding,
                    _: &TxEnv,
                ) -> Result<ExecutionIdentity, String> {
                    Ok(ExecutionIdentity {
                        principal_id: "fixture_principal".into(),
                        org_id: self.org.clone(),
                        context_id: "group-cost".into(),
                        signer: self.signer,
                        binding: binding.clone(),
                        min_snapshot_version: 1,
                    })
                }
            }
            let (factory, timing) = PolicyFactory::new(
                Arc::new(PinnedPolicySnapshot::new(
                    facts.version(),
                    facts.digest(),
                    Arc::new(FactsPolicy::new(facts, AT).unwrap()),
                )),
                Arc::new(GroupIdentity {
                    org: org.into(),
                    signer,
                }),
            )
            .timed();
            for (mode, selector) in [("allow-first", "d09de08a"), ("allow-last", "3fa4f245")] {
                let mut outcomes = Vec::new();
                timing.take_samples();
                for i in 0..warmup + rounds {
                    let tx = TxEnv::builder()
                        .caller(signer)
                        .to(target)
                        .data(Bytes::from(hex::decode(selector).unwrap()))
                        .gas_limit(30_000_000)
                        .gas_price(0)
                        .build()
                        .unwrap();
                    let result =
                        factory
                            .create_evm(base.clone(), env())
                            .transact_raw(PolicyTx::bound(
                                tx,
                                ExecutionBinding::Transaction(B256::from(U256::from(i as u64))),
                            ));
                    let ok = result.is_ok_and(|r| r.result.is_success());
                    if i == warmup - 1 {
                        timing.take_samples();
                    }
                    if i >= warmup {
                        outcomes.push(ok);
                    }
                }
                assert!(
                    outcomes.iter().all(|v| *v == outcomes[0]),
                    "unstable verdict"
                );
                if mode == "allow-first" || memberships <= 2 {
                    assert!(outcomes[0]);
                }
                let samples = timing.take_samples();
                assert_eq!(samples.len(), rounds);
                if !outcomes[0] {
                    assert!(
                        samples.iter().all(|s| s.gas == 100_000),
                        "a measurement may deny only at the shared gas limit"
                    );
                }
                let row = json!({"directory_groups":directory_groups,"memberships":memberships,
                    "mode":mode,"allowed":outcomes[0],"frame":summary(&samples)});
                println!("{row}");
                report.push(row);
            }
        }
    }
    if let Ok(path) = std::env::var("OPS_GROUP_COST_REPORT") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&json!({
                "binary":"in-process --release", "rounds_per_config":rounds,"warmup":warmup,
                "policy_gas_limit":100000,"results":report,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
