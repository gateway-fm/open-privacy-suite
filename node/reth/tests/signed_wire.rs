use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::wire::{Network, Verifier};
use serde_json::json;
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
fn payload() -> serde_json::Value {
    json!({"network":{"chain_id":31337,"deployment_id":"local"},"issued_at":1000,"expires_at":1100,"scope":"transaction","context_id":"ctx-1","principal_id":"user-a","org_id":"org-a","signer":"0x0000000000000000000000000000000000001000","binding_hash":"0x0101010101010101010101010101010101010101010101010101010101010101","min_snapshot_version":1})
}
fn seal_payload(kind: &str, bytes: &[u8]) -> Vec<u8> {
    let mut signed = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [kind.as_bytes(), b"ops", bytes] {
        signed.extend_from_slice(&(part.len() as u32).to_be_bytes());
        signed.extend_from_slice(part);
    }
    let signature = SigningKey::from_bytes(&[7; 32]).sign(&signed);
    serde_json::to_vec(&json!({"version":1,"kind":kind,"key_id":"ops","payload":STANDARD.encode(bytes),"signature":STANDARD.encode(signature.to_bytes())})).unwrap()
}
fn seal(value: &serde_json::Value) -> Vec<u8> {
    seal_payload("identity", &serde_json::to_vec(value).unwrap())
}

#[test]
fn captured_identity_retains_exact_evidence_across_renewal() {
    use ops_reth_policy::{context::ExecutionBinding, identity::IdentityRegistry};
    let registry = IdentityRegistry::new(verifier(), 2);
    let first = seal(&payload());
    registry.accept(&first, 1000).unwrap();
    let binding = ExecutionBinding::Transaction(alloy_primitives::B256::repeat_byte(1));
    let captured = registry.capture(&binding, 1020).unwrap();
    let mut newer = payload();
    newer["issued_at"] = json!(1020);
    newer["expires_at"] = json!(1120);
    newer["min_snapshot_version"] = json!(2);
    registry.accept(&seal(&newer), 1020).unwrap();
    assert_eq!(captured.envelope, first);
    assert_eq!(captured.identity.min_snapshot_version, 1);
    assert_eq!(
        verifier()
            .open_identity(&captured.envelope, 1020)
            .unwrap()
            .min_snapshot_version,
        1
    );
    assert_eq!(
        registry
            .capture(&binding, 1020)
            .unwrap()
            .identity
            .min_snapshot_version,
        2
    );
}

#[test]
fn verifies_exact_payload_bytes_and_identity_fields() {
    let bytes = serde_json::to_vec_pretty(&payload()).unwrap();
    let identity = verifier()
        .open_identity(&seal_payload("identity", &bytes), 1000)
        .unwrap();
    assert_eq!(identity.principal_id, "user-a");
    assert_eq!(identity.context_id, "ctx-1");
}

#[test]
fn rejects_tampering_wrong_network_expiry_and_wrong_domain() {
    let mut wire: serde_json::Value = serde_json::from_slice(&seal(&payload())).unwrap();
    let mut changed = payload();
    changed["principal_id"] = json!("user-b");
    wire["payload"] = json!(STANDARD.encode(serde_json::to_vec(&changed).unwrap()));
    assert!(
        verifier()
            .open_identity(&serde_json::to_vec(&wire).unwrap(), 1000)
            .is_err()
    );
    let mut network = payload();
    network["network"]["deployment_id"] = json!("other");
    assert!(verifier().open_identity(&seal(&network), 1000).is_err());
    assert!(verifier().open_identity(&seal(&payload()), 1100).is_err());
    assert!(verifier().open_identity(&seal(&payload()), 900).is_err());
    assert!(
        verifier()
            .open_identity(
                &seal_payload("snapshot", &serde_json::to_vec(&payload()).unwrap()),
                1000
            )
            .is_err()
    );
}

#[test]
fn rejects_ambiguous_and_incomplete_json_even_when_signed() {
    let text = serde_json::to_string(&payload()).unwrap();
    let duplicate = text.replacen("{", "{\"principal_id\":\"user-b\",", 1);
    assert!(
        verifier()
            .open_identity(&seal_payload("identity", duplicate.as_bytes()), 1000)
            .is_err()
    );
    let mut unknown = payload();
    unknown["principalId"] = json!("user-b");
    assert!(verifier().open_identity(&seal(&unknown), 1000).is_err());
    let mut missing = payload();
    missing
        .as_object_mut()
        .unwrap()
        .remove("min_snapshot_version");
    assert!(verifier().open_identity(&seal(&missing), 1000).is_err());
    let mut empty = payload();
    empty["principal_id"] = json!("");
    assert!(verifier().open_identity(&seal(&empty), 1000).is_err());
}

#[test]
fn rejects_noncanonical_base64_envelope_aliases_and_oversized_identity() {
    let mut wire: serde_json::Value = serde_json::from_slice(&seal(&payload())).unwrap();
    let sig = wire["signature"].as_str().unwrap().to_owned();
    wire["signature"] = json!(format!("{sig}\n"));
    assert!(
        verifier()
            .open_identity(&serde_json::to_vec(&wire).unwrap(), 1000)
            .is_err()
    );
    let text = String::from_utf8(seal(&payload())).unwrap();
    assert!(
        verifier()
            .open_identity(text.replacen("{", "{\"version\":1,", 1).as_bytes(), 1000)
            .is_err()
    );
    assert!(verifier().open_identity(&vec![b' '; 16385], 1000).is_err());
}

#[test]
fn verifies_go_signed_identity_snapshot_and_simulation_golden_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../internal/nodepolicy/testdata/envelopes-v1.json"
    ))
    .unwrap();
    let key: [u8; 32] = STANDARD
        .decode(fixture["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifier = Verifier::new(
        Network {
            chain_id: 31337,
            deployment_id: "ops-test".into(),
        },
        BTreeMap::from([(
            "ops-a".into(),
            ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap(),
        )]),
    );
    let now = fixture["now"].as_i64().unwrap();
    let identity = verifier
        .open_identity(&serde_json::to_vec(&fixture["identity"]).unwrap(), now)
        .unwrap();
    assert_eq!(identity.principal_id, "user-a");
    let snapshot = verifier
        .open_snapshot(&serde_json::to_vec(&fixture["snapshot"]).unwrap(), now)
        .unwrap();
    assert_eq!(snapshot.version, identity.min_snapshot_version);
    assert_eq!(snapshot.principals.len(), 2);
    let stream = ops_reth_policy::stream::FactStream::new(verifier.clone());
    for kind in ["snapshot", "delta", "heartbeat"] {
        stream
            .accept(kind, &serde_json::to_vec(&fixture[kind]).unwrap(), now)
            .unwrap();
    }
    let updated = stream.pin(now, 10).unwrap();
    assert_eq!(updated.version(), 10);
    assert!(
        updated
            .snapshot()
            .principals
            .iter()
            .find(|p| p.id == "user-a")
            .unwrap()
            .banned
    );
    assert_eq!(updated.expires_at(), 1115);
    let request = STANDARD
        .decode(fixture["simulation"].as_str().unwrap())
        .unwrap();
    let hash = ops_reth_policy::wire::simulation_hash(&request).unwrap();
    assert_eq!(
        format!("0x{}", alloy_primitives::hex::encode(hash)),
        fixture["simulation_hash"].as_str().unwrap()
    );
    let parsed = ops_reth_policy::wire::parse_simulation(&request, &hash).unwrap();
    assert!(!parsed.dry_run);
    let mut altered = vec![b' '];
    altered.extend_from_slice(&request);
    assert!(ops_reth_policy::wire::parse_simulation(&altered, &hash).is_err());
}

#[test]
fn pending_transaction_cannot_be_rebound_even_after_ticket_expiry() {
    use ops_reth_policy::{context::ExecutionBinding, identity::IdentityRegistry};
    let registry = IdentityRegistry::new(verifier(), 10);
    registry.accept(&seal(&payload()), 1000).unwrap();
    let binding = ExecutionBinding::Transaction(alloy_primitives::B256::repeat_byte(1));
    assert_eq!(
        registry.lookup(&binding, 1050).unwrap().principal_id,
        "user-a"
    );
    assert!(registry.lookup(&binding, 1100).is_err());
    let mut other = payload();
    other["principal_id"] = json!("user-b");
    other["issued_at"] = json!(1100);
    other["expires_at"] = json!(1200);
    assert!(registry.accept(&seal(&other), 1100).is_err());
}

#[test]
fn identical_simulations_have_independent_contexts_and_cannot_rebind_context_id() {
    use ops_reth_policy::{context::ExecutionBinding, identity::IdentityRegistry};
    let registry = IdentityRegistry::new(verifier(), 10);
    let mut alice = payload();
    alice["scope"] = json!("simulation");
    registry.accept(&seal(&alice), 1000).unwrap();
    let mut bob = alice.clone();
    bob["principal_id"] = json!("user-b");
    bob["context_id"] = json!("ctx-2");
    registry.accept(&seal(&bob), 1000).unwrap();
    let binding = ExecutionBinding::Simulation {
        digest: alloy_primitives::B256::repeat_byte(1),
        context_id: "ctx-2".into(),
    };
    assert_eq!(
        registry.lookup(&binding, 1020).unwrap().principal_id,
        "user-b"
    );
    bob["binding_hash"] = json!(format!("0x{}", "02".repeat(32)));
    assert!(registry.accept(&seal(&bob), 1000).is_err());
}

#[test]
fn identity_ingestion_is_bounded_idempotent_and_rejects_stale_renewals() {
    use ops_reth_policy::identity::IdentityRegistry;
    let registry = IdentityRegistry::new(verifier(), 1);
    registry.accept(&seal(&payload()), 1000).unwrap();
    registry.accept(&seal(&payload()), 1000).unwrap();
    let mut fresh = payload();
    fresh["issued_at"] = json!(1010);
    fresh["expires_at"] = json!(1110);
    registry.accept(&seal(&fresh), 1020).unwrap();
    assert!(registry.accept(&seal(&payload()), 1020).is_err());
    fresh["binding_hash"] = json!(format!("0x{}", "02".repeat(32)));
    assert!(registry.accept(&seal(&fresh), 1020).is_err());
}

#[test]
fn simulation_requires_explicit_nullable_candidate_and_authentic_artifact_digest() {
    use ops_reth_policy::wire::{parse_simulation, simulation_hash};
    use serde_json::Value;
    let mut request = json!({"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000001000"}],"dry_run":false});
    let parse = |request: &Value| {
        let bytes = serde_json::to_vec(request).unwrap();
        parse_simulation(&bytes, &simulation_hash(&bytes).unwrap())
    };
    assert!(parse(&request).is_err());
    request["candidate_policy"] = Value::Null;
    assert!(parse(&request).unwrap().candidate_policy.is_none());
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap();
    request["candidate_policy"] = fixture["snapshot"]["policies"][0].clone();
    assert!(parse(&request).unwrap().candidate_policy.is_some());
    request["candidate_policy"]["bytecode"] = json!(STANDARD.encode([0]));
    assert!(parse(&request).is_err());
}

#[test]
fn authenticated_simulations_cannot_replace_code_storage_or_block_context() {
    use ops_reth_policy::wire::{parse_simulation, simulation_hash};
    let from = "0x0000000000000000000000000000000000001000";
    for method in ["eth_call", "eth_estimateGas", "debug_traceCall"] {
        for dry_run in [false, true] {
            for change in [
                json!({from:{"code":"0x60005460005260206000f3"}}),
                json!({from:{"state":{"0x00":"0x01"}}}),
                json!([{}]),
                json!("invalid"),
            ] {
                let options = if method == "debug_traceCall" {
                    json!({"stateOverrides":change})
                } else {
                    change
                };
                let request=serde_json::to_vec(&json!({"method":method,"params":[{"from":from},"latest",options],"dry_run":dry_run,"candidate_policy":null})).unwrap();
                assert!(
                    parse_simulation(&request, &simulation_hash(&request).unwrap()).is_err(),
                    "user override accepted for {method}, diagnostic={dry_run}"
                );
            }
        }
    }
    for options in [
        json!({"blockOverrides":{"number":"0x1"}}),
        json!({"blockOverrides":{"number":null}}),
    ] {
        let request=serde_json::to_vec(&json!({"method":"debug_traceCall","params":[{"from":from},"latest",options],"dry_run":true,"candidate_policy":null})).unwrap();
        assert!(parse_simulation(&request, &simulation_hash(&request).unwrap()).is_err());
    }
    for (method, options) in [
        ("eth_call", json!({})),
        ("eth_call", json!(null)),
        (
            "debug_traceCall",
            json!({"tracer":"callTracer","stateOverrides":{},"blockOverrides":null}),
        ),
    ] {
        let request=serde_json::to_vec(&json!({"method":method,"params":[{"from":from},"latest",options],"dry_run":false,"candidate_policy":null})).unwrap();
        assert!(parse_simulation(&request, &simulation_hash(&request).unwrap()).is_ok());
    }
}
