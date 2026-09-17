use alloy_primitives::B256;
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor, BlockManifest, BoundIdentity},
    wire::Network,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "ops-policy-archive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn block() -> BlockDescriptor {
    BlockDescriptor {
        network: Network {
            chain_id: 31337,
            deployment_id: "test-a".into(),
        },
        hash: B256::repeat_byte(1),
        parent_hash: B256::repeat_byte(2),
        number: 3,
        timestamp: 1020,
        transactions: vec![B256::repeat_byte(4), B256::repeat_byte(5)],
    }
}
fn manifest(store: &ArtifactStore) -> BlockManifest {
    let envelope = store.put(b"exact signed envelope bytes").unwrap();
    BlockManifest {
        format_version: 1,
        block: block(),
        facts_version: 7,
        facts_digest: B256::repeat_byte(6),
        checkpoint: store
            .put(b"exact retained snapshot + delta + lease envelopes")
            .unwrap(),
        identities: block()
            .transactions
            .into_iter()
            .map(|transaction_hash| BoundIdentity {
                transaction_hash,
                envelope,
                outcome: ops_reth_policy::context::ExecutionOutcome {
                    success: true,
                    denied: false,
                    reason_code: String::new(),
                    created: Vec::new(),
                },
            })
            .collect(),
    }
}

#[test]
fn immutable_artifacts_and_manifest_survive_restart() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let expected = manifest(&store);
    store.publish(&expected).unwrap();
    store.publish(&expected).unwrap(); // Idempotent retry after acknowledgement loss.
    drop(store);
    let reopened = ArtifactStore::open(&temp.0).unwrap();
    let recovered = reopened.load_for_block(&block()).unwrap();
    assert_eq!(recovered, expected);
    assert_eq!(
        reopened.get(recovered.identities[0].envelope).unwrap(),
        b"exact signed envelope bytes"
    );
    assert_eq!(fs::read_dir(temp.0.join("objects")).unwrap().count(), 2);
}

#[test]
fn exact_block_and_transaction_order_are_required() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    store.publish(&manifest(&store)).unwrap();
    for changed in 0..5 {
        let mut wrong = block();
        match changed {
            0 => wrong.hash = B256::repeat_byte(9),
            1 => wrong.parent_hash = B256::repeat_byte(9),
            2 => wrong.timestamp += 1,
            3 => wrong.transactions.reverse(),
            _ => wrong.network.deployment_id = "test-b".into(),
        }
        assert!(
            store.load_for_block(&wrong).is_err(),
            "accepted different block field {changed}"
        );
    }
}

#[test]
fn conflicting_manifest_and_incomplete_evidence_cannot_be_published() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let original = manifest(&store);
    let mut missing = original.clone();
    missing.checkpoint = store.put(b"missing checkpoint").unwrap();
    fs::remove_file(temp.0.join("objects").join(missing.checkpoint.to_string())).unwrap();
    assert!(store.publish(&missing).is_err());
    assert!(store.load_for_block(&block()).is_err());
    store.publish(&original).unwrap();
    let mut conflicting = original.clone();
    conflicting.facts_version += 1;
    assert!(store.publish(&conflicting).is_err());
    assert_eq!(store.load_for_block(&block()).unwrap(), original);
    let mut incomplete = original.clone();
    incomplete.identities.pop();
    assert!(store.publish(&incomplete).is_err());
}

#[test]
fn corrupt_content_never_becomes_replay_evidence() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let expected = manifest(&store);
    store.publish(&expected).unwrap();
    fs::write(
        temp.0.join("objects").join(expected.checkpoint.to_string()),
        b"tampered",
    )
    .unwrap();
    assert!(store.get(expected.checkpoint).is_err());
    assert!(store.load_for_block(&block()).is_err());
    assert!(
        store
            .put(b"exact retained snapshot + delta + lease envelopes")
            .is_err()
    );
}
