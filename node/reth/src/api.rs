//! Authenticated private listener. This module never registers an `ops_*`
//! method on Reth's public RPC server.

use crate::{
    context::ExecutionBinding,
    identity::IdentityRegistry,
    runtime::PolicyRuntime,
    wire::{Identity, MAX_ENVELOPE_BYTES, SimulationRequest, decode_strict, parse_simulation},
};
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, Bytes, hex};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, future::Future, io, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

const MAX_REQUEST_BYTES: usize = MAX_ENVELOPE_BYTES + 4096;
const REQUIRED_CAPABILITIES: [&str; 8] = [
    "per_frame_a5",
    "signed_identity_v1",
    "fact_stream_v1",
    "simulation_v1",
    "archive_v1",
    "candidate_simulation_v1",
    "scoped_diagnostics_v1",
    "finalized_status_v1",
];

#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    /// Advertise a capability only after its production path is wired.
    fn capabilities(&self) -> Vec<String>;
    async fn submit(&self, identity: Identity, raw: Bytes) -> Result<B256, String>;
    async fn transaction_status(&self, _hash: B256) -> Result<Value, String> {
        Err("transaction status is unavailable".into())
    }
    async fn simulate(
        &self,
        identity: Identity,
        request: SimulationRequest,
        exact: Bytes,
    ) -> Result<Value, String>;
}

pub struct PrivateApi {
    runtime: Arc<PolicyRuntime>,
    backend: Arc<dyn ExecutionBackend>,
    bearer: Vec<u8>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: Vec<Value>,
}

pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Simulations have no pending-pool lifecycle. Release their capacity even if
/// the backend errors or the HTTP task is cancelled while awaiting execution.
struct SimulationRegistration {
    identities: Arc<IdentityRegistry>,
    binding: ExecutionBinding,
}

impl Drop for SimulationRegistration {
    fn drop(&mut self) {
        let _ = self.identities.finish(&self.binding);
    }
}

impl PrivateApi {
    pub fn new(
        runtime: Arc<PolicyRuntime>,
        backend: Arc<dyn ExecutionBackend>,
        bearer: String,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, String> {
        if bearer.len() < 16
            || bearer
                .bytes()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return Err("private RPC requires a service credential of at least 16 bytes".into());
        }
        Ok(Self {
            runtime,
            backend,
            bearer: format!("Bearer {bearer}").into_bytes(),
            clock,
        })
    }

    fn authenticated(&self, authorization: &str) -> bool {
        bool::from(authorization.as_bytes().ct_eq(&self.bearer))
    }

    pub async fn process(&self, authorization: &str, body: &[u8]) -> ApiResponse {
        if !self.authenticated(authorization) {
            return ApiResponse {
                status: 401,
                body: br#"{"error":"unauthorized"}"#.to_vec(),
            };
        }
        if body.len() > MAX_REQUEST_BYTES {
            return ApiResponse {
                status: 413,
                body: br#"{"error":"request too large"}"#.to_vec(),
            };
        }
        let request: RpcRequest = match decode_strict(body) {
            Ok(request) => request,
            Err(_) => return rpc_error(Value::Null, -32600, "invalid private request"),
        };
        if request.jsonrpc != "2.0" || request.id.is_empty() || request.id.len() > 128 {
            return rpc_error(Value::Null, -32600, "invalid private request");
        }
        let id = json!(request.id);
        match self.dispatch(request, (self.clock)()).await {
            Ok(result) => ApiResponse {
                status: 200,
                body: serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result}))
                    .expect("serializable RPC result"),
            },
            Err(error) if error.starts_with("resynchronisation required") => {
                rpc_error(id, -32011, "policy resynchronisation required")
            }
            Err(_) => rpc_error(id, -32000, "private execution request rejected"),
        }
    }

    async fn dispatch(&self, request: RpcRequest, now: i64) -> Result<Value, String> {
        match request.method.as_str() {
            "ops_policyStatus" => {
                require_count(&request.params, 0)?;
                let latest = self.runtime.feed.latest()?;
                let mut capabilities = self.backend.capabilities();
                capabilities.sort();
                capabilities.dedup();
                let complete = REQUIRED_CAPABILITIES
                    .iter()
                    .all(|required| capabilities.iter().any(|value| value == required));
                let fresh = self.runtime.feed.pin(now, 1).is_ok();
                let (version, digest, expires) = latest
                    .as_ref()
                    .map(|facts| {
                        (
                            facts.version(),
                            hex::encode(facts.digest()),
                            facts.expires_at(),
                        )
                    })
                    .unwrap_or((0, String::new(), 0));
                Ok(
                    json!({"protocol_version":1,"network":self.runtime.network(),"capabilities":capabilities,"version":version,"digest":digest,"expires_at":expires,"ready":fresh&&complete,"reason":if !complete{"runtime_incomplete"}else if !fresh{"facts_unavailable"}else{""}}),
                )
            }
            "ops_policyApply" => {
                require_count(&request.params, 1)?;
                let kind = request.params[0]
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or("missing policy kind")?;
                if !matches!(kind, "snapshot" | "delta" | "heartbeat") {
                    return Err("invalid policy kind".into());
                }
                let wire = serde_json::to_vec(&request.params[0])
                    .map_err(|_| "invalid policy envelope")?;
                let facts = self.runtime.accept_facts(kind, &wire, now)?;
                Ok(
                    json!({"version":facts.version(),"digest":hex::encode(facts.digest()),"expires_at":facts.expires_at()}),
                )
            }
            "ops_transactionStatus" => {
                require_count(&request.params, 1)?;
                let hash = request.params[0]
                    .as_str()
                    .ok_or("invalid transaction hash")?
                    .parse::<B256>()
                    .map_err(|_| "invalid transaction hash")?;
                // Expiry limits execution authority, not later status access on
                // this authenticated service listener. No unknown hash lookup.
                let identity = self.runtime.retained_identity(hash)?;
                let execution = self.backend.transaction_status(hash).await?;
                Ok(
                    json!({"transaction_hash":format!("{hash:#x}"),"principal_id":identity.principal_id,
                    "org_id":identity.org_id,"context_id":identity.context_id,"execution":execution}),
                )
            }
            "ops_submitTransaction" => {
                require_count(&request.params, 2)?;
                let wire = serde_json::to_vec(&request.params[0])
                    .map_err(|_| "invalid identity envelope")?;
                let identity = self.runtime.verifier().open_identity(&wire, now)?;
                if identity.scope != "transaction" {
                    return Err("invalid identity scope".into());
                }
                let raw = request.params[1]
                    .as_str()
                    .and_then(|v| v.strip_prefix("0x"))
                    .ok_or("invalid raw transaction")?;
                if raw.len() > 16 << 20 {
                    return Err("raw transaction too large".into());
                }
                let raw = hex::decode(raw).map_err(|_| "invalid raw transaction")?;
                let mut remaining = raw.as_slice();
                let tx = TxEnvelope::decode_2718(&mut remaining)
                    .map_err(|_| "invalid signed transaction")?;
                if !remaining.is_empty()
                    || tx.chain_id() != Some(self.runtime.network().chain_id)
                    || matches!(tx, TxEnvelope::Eip7702(_))
                {
                    return Err("unsupported transaction envelope".into());
                }
                let recovered = tx
                    .recover_signer()
                    .map_err(|_| "invalid transaction signature")?;
                // Blob sidecars wrap the consensus envelope and are validated
                // by the pool. Their bytes are not part of the transaction hash.
                let hash = *tx.tx_hash();
                if identity.binding_hash != format!("{hash:#x}")
                    || identity.signer != format!("{recovered:#x}")
                {
                    return Err("transaction identity mismatch".into());
                }
                self.runtime.feed.pin(now, identity.min_snapshot_version)?;
                let context_id = identity.context_id.clone();
                // Durable identity precedes pool insertion. An ambiguous pool
                // result must never free this hash for another principal.
                let identity = self.runtime.accept_identity(&wire, now)?;
                let accepted = self.backend.submit(identity, raw.into()).await?;
                if accepted != hash {
                    return Err("transaction pool returned a different hash".into());
                }
                Ok(
                    json!({"transaction_hash":format!("{hash:#x}"),"context_id":context_id,"status":"accepted"}),
                )
            }
            "ops_simulate" => {
                require_count(&request.params, 2)?;
                let wire = serde_json::to_vec(&request.params[0])
                    .map_err(|_| "invalid identity envelope")?;
                let identity = self.runtime.verifier().open_identity(&wire, now)?;
                if identity.scope != "simulation" {
                    return Err("invalid identity scope".into());
                }
                let encoded = request.params[1]
                    .as_str()
                    .ok_or("invalid simulation encoding")?;
                let exact = STANDARD
                    .decode(encoded)
                    .map_err(|_| "invalid simulation encoding")?;
                if STANDARD.encode(&exact) != encoded {
                    return Err("noncanonical simulation encoding".into());
                }
                let digest = identity
                    .binding_hash
                    .parse::<B256>()
                    .map_err(|_| "invalid simulation hash")?;
                let request = parse_simulation(&exact, digest.as_ref())?;
                if request.params[0].get("from").and_then(Value::as_str)
                    != Some(identity.signer.as_str())
                {
                    return Err("simulation signer mismatch".into());
                }
                self.runtime.feed.pin(now, identity.min_snapshot_version)?;
                let identity = self.runtime.accept_identity(&wire, now)?;
                let _registration = SimulationRegistration {
                    identities: self.runtime.identities.clone(),
                    binding: ExecutionBinding::Simulation {
                        context_id: identity.context_id.clone(),
                        digest,
                    },
                };
                self.backend.simulate(identity, request, exact.into()).await
            }
            _ => Err("unknown private method".into()),
        }
    }
}

fn require_count(params: &[Value], count: usize) -> Result<(), String> {
    if params.len() != count {
        return Err("invalid private parameters".into());
    }
    Ok(())
}
fn rpc_error(id: Value, code: i32, message: &str) -> ApiResponse {
    ApiResponse {
        status: 200,
        body: serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
        )
        .expect("serializable RPC error"),
    }
}

/// Dedicated private HTTP listener with bounded bodies, connections and time.
/// Shutdown stops acceptance and drains existing requests for at most 10 sec.
pub async fn serve(
    listener: TcpListener,
    api: Arc<PrivateApi>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    let limit = Arc::new(Semaphore::new(128));
    let mut requests = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            Some(_)=requests.join_next(),if !requests.is_empty()=>{},
            incoming=listener.accept()=>{
                let (stream,_)=incoming?;
                let Ok(permit)=limit.clone().try_acquire_owned() else {drop(stream);continue;};
                let api=api.clone();
                requests.spawn(async move {
                    let _permit=permit;
                    let service=service_fn(move |req|handle_http(api.clone(),req));
                    let mut builder=http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                    let connection=builder.serve_connection(TokioIo::new(stream),service);
                    let _=tokio::time::timeout(Duration::from_secs(60),connection).await;
                });
            }
        }
    }
    let drained = async { while requests.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drained)
        .await
        .is_err()
    {
        requests.abort_all();
    }
    Ok(())
}
async fn handle_http(
    api: Arc<PrivateApi>,
    request: Request<Incoming>,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let response = if !api.authenticated(&authorization) {
        ApiResponse {
            status: 401,
            body: br#"{"error":"unauthorized"}"#.to_vec(),
        }
    } else if request.method() != hyper::Method::POST
        || request.uri().path() != "/"
        || request.uri().query().is_some()
    {
        ApiResponse {
            status: 404,
            body: br#"{"error":"not found"}"#.to_vec(),
        }
    } else {
        match tokio::time::timeout(
            Duration::from_secs(15),
            Limited::new(request.into_body(), MAX_REQUEST_BYTES).collect(),
        )
        .await
        {
            Ok(Ok(body)) => match tokio::time::timeout(
                Duration::from_secs(30),
                api.process(&authorization, &body.to_bytes()),
            )
            .await
            {
                Ok(response) => response,
                Err(_) => ApiResponse {
                    status: 503,
                    body: br#"{"error":"execution node unavailable"}"#.to_vec(),
                },
            },
            _ => ApiResponse {
                status: 413,
                body: br#"{"error":"invalid request body"}"#.to_vec(),
            },
        }
    };
    let mut result = Response::new(Full::new(bytes::Bytes::from(response.body)));
    *result.status_mut() =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    result.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    result.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    Ok(result)
}
