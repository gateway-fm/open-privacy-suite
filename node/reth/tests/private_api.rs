use alloy_primitives::{B256, Bytes};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use ops_reth_policy::{
    api::{ExecutionBackend, PrivateApi},
    archive::ArtifactStore,
    runtime::PolicyRuntime,
    wire::{Identity, Network, SimulationRequest, Verifier},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Default)]
struct Backend {
    simulations: AtomicUsize,
    mode: AtomicUsize,
    identities: Option<Arc<ops_reth_policy::identity::IdentityRegistry>>,
}
#[async_trait]
impl ExecutionBackend for Backend {
    fn capabilities(&self) -> Vec<String> {
        [
            "per_frame_a5",
            "signed_identity_v1",
            "fact_stream_v1",
            "simulation_v1",
            "archive_v1",
            "candidate_simulation_v1",
            "scoped_diagnostics_v1",
            "finalized_status_v1",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }
    async fn submit(&self, _identity: Identity, raw: Bytes) -> Result<B256, String> {
        use alloy_eips::eip2718::Decodable2718;
        let transaction = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_ref())
            .map_err(|_| "invalid fixture")?;
        Ok(*transaction.tx_hash())
    }
    async fn transaction_status(&self, _hash: B256) -> Result<Value, String> {
        Ok(
            json!({"status":"pending","facts_version":7,"block_hash":null,"block_number":null,"reason_code":"","created":[]}),
        )
    }
    async fn simulate(
        &self,
        _identity: Identity,
        _request: SimulationRequest,
        _exact: Bytes,
    ) -> Result<Value, String> {
        self.simulations.fetch_add(1, Ordering::SeqCst);
        match self.mode.load(Ordering::SeqCst) {
            1 => return Err("fixture simulation failed".into()),
            2 => return std::future::pending().await,
            _ => {}
        }
        Ok(json!("0x1234"))
    }
}

#[tokio::test]
async fn exact_go_signed_transactions_and_simulations_reach_only_the_private_backend() {
    let (api, backend, path) = fixture("execution");
    let gold = golden();
    let applied = call(
        &api,
        "ops_policyApply",
        json!([gold["transaction_snapshot"]]),
    )
    .await;
    assert_eq!(applied["result"]["version"], 7);
    let submitted = call(
        &api,
        "ops_submitTransaction",
        json!([gold["transaction_identity"], gold["raw_transaction"]]),
    )
    .await;
    assert_eq!(submitted["result"]["status"], "accepted", "{submitted}");
    assert_eq!(submitted["result"]["context_id"], "tx-1");
    let status = call(
        &api,
        "ops_transactionStatus",
        json!([submitted["result"]["transaction_hash"]]),
    )
    .await;
    assert_eq!(status["result"]["context_id"], "tx-1", "{status}");
    assert_eq!(status["result"]["principal_id"], "user-b");
    assert_eq!(status["result"]["execution"]["status"], "pending");
    let unknown = call(
        &api,
        "ops_transactionStatus",
        json!([format!("{:#x}", B256::ZERO)]),
    )
    .await;
    assert!(
        unknown.get("error").is_some(),
        "unknown transaction disclosed a status"
    );
    let retry = call(
        &api,
        "ops_submitTransaction",
        json!([gold["transaction_identity"], gold["raw_transaction"]]),
    )
    .await;
    assert_eq!(retry["result"], submitted["result"]);
    let blob = call(
        &api,
        "ops_submitTransaction",
        json!([gold["blob_identity"], gold["blob_transaction"]]),
    )
    .await;
    assert_eq!(blob["result"]["context_id"], "blob-1", "{blob}");
    let simulation = call(
        &api,
        "ops_simulate",
        json!([gold["simulation_identity"], gold["simulation"]]),
    )
    .await;
    assert_eq!(simulation["result"], "0x1234", "{simulation}");
    assert_eq!(backend.simulations.load(Ordering::SeqCst), 1);
    let raw = STANDARD
        .decode(gold["simulation"].as_str().unwrap())
        .unwrap();
    let modified = STANDARD.encode([raw.as_slice(), b" "].concat());
    assert!(
        call(
            &api,
            "ops_simulate",
            json!([gold["simulation_identity"], modified])
        )
        .await
        .get("error")
        .is_some()
    );
    assert_eq!(backend.simulations.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(path).unwrap();
}
fn golden() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/nodepolicy/testdata/envelopes-v1.json"
    ))
    .unwrap()
}
fn fixture(name: &str) -> (PrivateApi, Arc<Backend>, std::path::PathBuf) {
    let gold = golden();
    let key: [u8; 32] = STANDARD
        .decode(gold["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifier = Verifier::new(
        Network {
            chain_id: 31337,
            deployment_id: "ops-test".into(),
        },
        BTreeMap::from([("ops-a".into(), VerifyingKey::from_bytes(&key).unwrap())]),
    );
    let path = std::env::temp_dir().join(format!("ops-private-api-{name}-{}", std::process::id()));
    let runtime = Arc::new(PolicyRuntime::new(
        verifier,
        Arc::new(ArtifactStore::open(&path).unwrap()),
        16,
    ));
    let backend = Arc::new(Backend {
        identities: Some(runtime.identities.clone()),
        ..Default::default()
    });
    let api = PrivateApi::new(
        runtime,
        backend.clone(),
        "private-test-token".into(),
        Arc::new(|| 1020),
    )
    .unwrap();
    (api, backend, path)
}

#[tokio::test]
async fn simulation_context_capacity_is_released_on_success_error_and_cancellation() {
    use ops_reth_policy::context::ExecutionBinding;
    let (api, backend, path) = fixture("cleanup");
    let gold = golden();
    call(&api, "ops_policyApply", json!([gold["snapshot"]])).await;
    let binding = ExecutionBinding::Simulation {
        context_id: "sim-1".into(),
        digest: gold["simulation_hash"].as_str().unwrap().parse().unwrap(),
    };
    for mode in 0..3 {
        backend.mode.store(mode, Ordering::SeqCst);
        let request = request(
            "ops_simulate",
            json!([gold["simulation_identity"], gold["simulation"]]),
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            api.process("Bearer private-test-token", &request),
        )
        .await;
        assert_eq!(result.is_err(), mode == 2);
        assert!(
            backend
                .identities
                .as_ref()
                .unwrap()
                .lookup(&binding, 1020)
                .is_err(),
            "simulation mode {mode} leaked a registry slot"
        );
    }
    std::fs::remove_dir_all(path).unwrap();
}
fn request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"ops-1","method":method,"params":params}))
        .unwrap()
}
async fn call(api: &PrivateApi, method: &str, params: Value) -> Value {
    let response = api
        .process("Bearer private-test-token", &request(method, params))
        .await;
    assert_eq!(response.status, 200);
    serde_json::from_slice(&response.body).unwrap()
}

#[tokio::test]
async fn private_status_and_fact_apply_require_authentication_and_durable_valid_facts() {
    let (api, _, path) = fixture("facts");
    assert_eq!(
        api.process("", &request("ops_policyStatus", json!([])))
            .await
            .status,
        401
    );
    assert_eq!(
        api.process(
            "Bearer incorrect-token",
            &request("ops_policyStatus", json!([]))
        )
        .await
        .status,
        401
    );
    let before = call(&api, "ops_policyStatus", json!([])).await;
    assert_eq!(before["result"]["version"], 0);
    assert_eq!(before["result"]["ready"], false);
    for (kind, version) in [("snapshot", 7), ("delta", 10), ("heartbeat", 10)] {
        let applied = call(&api, "ops_policyApply", json!([golden()[kind]])).await;
        assert_eq!(applied["id"], "ops-1");
        assert_eq!(applied["result"]["version"], version, "{applied}");
        assert_eq!(applied["result"]["digest"].as_str().unwrap().len(), 64);
    }
    let ready = call(&api, "ops_policyStatus", json!([])).await;
    assert_eq!(ready["result"]["ready"], true);
    assert_eq!(ready["result"]["expires_at"], 1115);
    let wrong = call(&api, "ops_policyApply", json!([golden()["identity"]])).await;
    assert!(wrong.get("error").is_some());
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn private_api_rejects_ambiguous_unknown_and_mismatched_requests() {
    let (api, backend, path) = fixture("reject");
    for raw in [
        br#"{"jsonrpc":"2.0","id":"ops-1","id":"ops-2","method":"ops_policyStatus","params":[]}"#
            .as_slice(),
        br#"{"jsonrpc":"2.0","id":"ops-1","method":"ops_policyStatus","params":[],"secret":true}"#
            .as_slice(),
        br#"[{"jsonrpc":"2.0","id":"ops-1","method":"ops_policyStatus","params":[]}]"#.as_slice(),
    ] {
        let reply = api.process("Bearer private-test-token", raw).await;
        let value: Value = serde_json::from_slice(&reply.body).unwrap();
        assert!(value.get("error").is_some(), "{value}");
    }
    assert!(
        call(&api, "eth_sendRawTransaction", json!(["0x1234"]))
            .await
            .get("error")
            .is_some()
    );
    assert!(
        call(
            &api,
            "ops_submitTransaction",
            json!([golden()["identity"], "0x1234"])
        )
        .await
        .get("error")
        .is_some()
    );
    assert!(
        call(
            &api,
            "ops_simulate",
            json!([golden()["identity"], golden()["simulation"]])
        )
        .await
        .get("error")
        .is_some()
    );
    assert_eq!(backend.simulations.load(Ordering::SeqCst), 0);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dedicated_http_listener_authenticates_before_dispatch_and_shuts_down() {
    use std::io::{Read, Write};
    let (api, _, path) = fixture("http");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(ops_reth_policy::api::serve(
        listener,
        Arc::new(api),
        async {
            let _ = stopped.await;
        },
    ));
    let responses=tokio::task::spawn_blocking(move||{
        let body=request("ops_policyStatus",json!([]));
        ["","Authorization: Bearer private-test-token\r\n"].into_iter().map(|authorization|{
            let mut socket=std::net::TcpStream::connect(address).unwrap();
            socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            write!(socket,"POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n{authorization}Content-Length: {}\r\n\r\n",body.len()).unwrap();
            socket.write_all(&body).unwrap();
            let mut response=String::new();socket.read_to_string(&mut response).unwrap();response
        }).collect::<Vec<_>>()
    }).await.unwrap();
    assert!(responses[0].starts_with("HTTP/1.1 401"), "{}", responses[0]);
    assert!(responses[1].starts_with("HTTP/1.1 200"), "{}", responses[1]);
    assert!(responses[1].contains("\"ready\":false"));
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
