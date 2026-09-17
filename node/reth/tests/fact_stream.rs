use alloy_primitives::hex;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::{
    stream::FactStream,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn verifier() -> Verifier {
    Verifier::new(
        Network {
            chain_id: 31337,
            deployment_id: "local".into(),
        },
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    )
}
fn envelope(kind: &str, value: &Value) -> (Vec<u8>, String) {
    let payload = serde_json::to_vec_pretty(value).unwrap();
    let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [kind.as_bytes(), b"ops", payload.as_slice()] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    let signature = SigningKey::from_bytes(&[7; 32]).sign(&bytes);
    (serde_json::to_vec(&json!({"version":1,"kind":kind,"key_id":"ops","payload":STANDARD.encode(&payload),"signature":STANDARD.encode(signature.to_bytes())})).unwrap(),hex::encode(Sha256::digest(payload)))
}
fn snapshot() -> Value {
    json!({"network":{"chain_id":31337,"deployment_id":"local"},"issued_at":1000,"expires_at":1100,"version":1,
    "principals":[{"id":"alice","banned":false,"kyc":true,"linked_addresses":["0x0000000000000000000000000000000000001000"],"memberships":[{"group_id":"g-a","expires_at":0}]}],
    "groups":[{"id":"g-a","org_id":"org-a","claims":0,"org_admin":false,"contract_claims":[]}],"contracts":[],"policies":[],"sanctions":[]})
}
fn delta(previous: &str) -> Value {
    json!({"network":{"chain_id":31337,"deployment_id":"local"},"issued_at":1020,"expires_at":1120,"previous_version":1,"previous_digest":previous,"version":3,
    "upserts":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]},
    "deletes":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]}})
}
fn heartbeat(digest: &str, version: u64) -> Value {
    json!({"network":{"chain_id":31337,"deployment_id":"local"},"issued_at":1080,"expires_at":1180,"version":version,"digest":digest})
}

#[test]
fn heartbeat_extends_only_matching_state_and_old_handles_stay_immutable() {
    let stream = FactStream::new(verifier());
    let (wire, digest) = envelope("snapshot", &snapshot());
    stream.accept("snapshot", &wire, 1020).unwrap();
    let first = stream.pin(1020, 1).unwrap();
    assert_eq!(hex::encode(first.digest()), digest);
    assert!(stream.pin(1100, 1).is_err());
    let (beat, _) = envelope("heartbeat", &heartbeat(&digest, 1));
    stream.accept("heartbeat", &beat, 1080).unwrap();
    let renewed = stream.pin(1150, 1).unwrap();
    assert_eq!(renewed.digest(), first.digest());
    assert_eq!(renewed.version(), first.version());
    assert_eq!(first.expires_at(), 1100);
    assert_eq!(renewed.expires_at(), 1180);
    assert!(stream.pin(1180, 1).is_err());
    assert!(
        stream
            .accept(
                "heartbeat",
                &envelope("heartbeat", &heartbeat(&digest, 2)).0,
                1080
            )
            .is_err()
    );
    // Valid duplicate cannot erase a newer heartbeat; expired input is rejected.
    stream.accept("snapshot", &wire, 1090).unwrap();
    assert!(stream.accept("snapshot", &wire, 1150).is_err());
    assert_eq!(stream.pin(1150, 1).unwrap().expires_at(), 1180);
}

#[test]
fn delta_jumps_apply_atomically_and_use_exact_new_payload_digest() {
    let stream = FactStream::new(verifier());
    let (wire, digest) = envelope("snapshot", &snapshot());
    stream.accept("snapshot", &wire, 1020).unwrap();
    let before = stream.pin(1020, 1).unwrap();
    let mut update = delta(&digest);
    let mut banned = snapshot()["principals"][0].clone();
    banned["banned"] = json!(true);
    update["upserts"]["principals"] = json!([banned]);
    let (wire, new_digest) = envelope("delta", &update);
    stream.accept("delta", &wire, 1020).unwrap();
    let after = stream.pin(1020, 3).unwrap();
    assert_eq!(hex::encode(after.digest()), new_digest);
    assert!(!before.snapshot().principals[0].banned);
    assert!(after.snapshot().principals[0].banned);
    assert!(stream.pin(1020, 4).is_err());
    stream.accept("delta", &wire, 1020).unwrap();
    assert_eq!(stream.pin(1020, 3).unwrap().digest(), after.digest());
}

#[test]
fn gaps_conflicts_duplicate_keys_and_invalid_final_graph_leave_state_unchanged() {
    let stream = FactStream::new(verifier());
    let (wire, digest) = envelope("snapshot", &snapshot());
    stream.accept("snapshot", &wire, 1020).unwrap();
    for case in 0..6 {
        let mut update = delta(&digest);
        match case {
            0 => update["previous_version"] = json!(2),
            1 => update["previous_digest"] = json!("aa".repeat(32)),
            2 => update["deletes"]["groups"] = json!(["g-a"]),
            3 => update["deletes"]["principals"] = json!(["missing"]),
            4 => {
                let principal = snapshot()["principals"][0].clone();
                update["upserts"]["principals"] = json!([principal.clone(), principal]);
            }
            _ => {
                update["upserts"]["principals"] = json!([snapshot()["principals"][0].clone()]);
                update["deletes"]["principals"] = json!(["alice"]);
            }
        }
        assert!(
            stream
                .accept("delta", &envelope("delta", &update).0, 1020)
                .is_err(),
            "case {case}"
        );
        assert_eq!(stream.pin(1020, 1).unwrap().version(), 1);
    }
    let mut conflicting = snapshot();
    conflicting["principals"][0]["banned"] = json!(true);
    assert!(
        stream
            .accept("snapshot", &envelope("snapshot", &conflicting).0, 1020)
            .is_err()
    );
    assert_eq!(hex::encode(stream.pin(1020, 1).unwrap().digest()), digest);
}

#[test]
fn a_new_snapshot_resynchronizes_but_old_versions_cannot_roll_back() {
    let stream = FactStream::new(verifier());
    let (original, _) = envelope("snapshot", &snapshot());
    stream.accept("snapshot", &original, 1020).unwrap();
    let mut newer = snapshot();
    newer["version"] = json!(8);
    newer["principals"][0]["banned"] = json!(true);
    stream
        .accept("snapshot", &envelope("snapshot", &newer).0, 1020)
        .unwrap();
    assert!(stream.accept("snapshot", &original, 1020).is_err());
    assert_eq!(stream.pin(1020, 8).unwrap().version(), 8);
}

#[test]
fn checkpoint_restart_reverifies_signed_chain_and_freshness() {
    use ops_reth_policy::archive::ArtifactStore;
    let directory =
        std::env::temp_dir().join(format!("ops-stream-checkpoint-{}", std::process::id()));
    let store = ArtifactStore::open(&directory).unwrap();
    let stream = FactStream::new(verifier());
    let (wire, digest) = envelope("snapshot", &snapshot());
    stream.accept("snapshot", &wire, 1020).unwrap();
    let (delta_wire, delta_digest) = envelope("delta", &delta(&digest));
    stream.accept("delta", &delta_wire, 1020).unwrap();
    stream
        .accept(
            "heartbeat",
            &envelope("heartbeat", &heartbeat(&delta_digest, 3)).0,
            1080,
        )
        .unwrap();
    let checkpoint = stream.pin(1150, 3).unwrap().checkpoint(&store).unwrap();
    let restored = FactStream::restore(verifier(), &store, checkpoint, 1150).unwrap();
    assert_eq!(
        hex::encode(restored.pin(1150, 3).unwrap().digest()),
        delta_digest
    );
    assert!(FactStream::restore(verifier(), &store, checkpoint, 1180).is_err());
    let mut doc: Value = serde_json::from_slice(&store.get(checkpoint).unwrap()).unwrap();
    doc["facts_version"] = json!(4);
    let altered = store.put(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert!(FactStream::restore(verifier(), &store, altered, 1150).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}
