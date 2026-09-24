//! The approval delivery endpoint: `ops.approvals.v1.ApprovalDelivery` over gRPC
//! (docs/implementation/approvals-wire-contract.md). One unary call per signed batch; its status
//! is the confirmation. Checks run on the dedicated verification workers, in contract order.
use crate::{
    approvals::{Now, Store},
    batch::{Envelope, Refusal, Trust, parse_key_set},
    verification::{Input, Outcome, Verifier},
};
use ipnet::IpNet;
use pb::{
    DeliverRequest, DeliverResponse, StatusRequest, StatusResponse,
    approval_delivery_server::{ApprovalDelivery, ApprovalDeliveryServer},
};
use std::{
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_stream::{Stream, StreamExt};
use tonic::{
    Request, Response, Status,
    metadata::MetadataValue,
    transport::{
        Server,
        server::{Connected, TcpConnectInfo, TcpIncoming},
    },
};

pub mod pb {
    tonic::include_proto!("ops.approvals.v1");
}

/// Requests above this are refused by the transport before any check (contract §1).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Batches waiting for a verification worker; a full queue makes further calls wait.
const QUEUE: usize = 64;

/// The node's approval settings. Names and defaults mirror the Besu plugin's
/// `--plugin-ops-approval-*` options (contract §7), as `OPS_APPROVAL_*` environment variables.
#[derive(Clone, Debug)]
pub struct Settings {
    pub listen: String,
    pub trust: Trust,
    pub capacity: usize,
    pub wait: Duration,
    /// Sources allowed to connect; empty means any.
    pub allowed_sources: Vec<IpNet>,
    pub max_connections: usize,
    /// Concurrent calls per connection (HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`).
    pub max_concurrent_calls: u32,
    pub verify_workers: usize,
}
impl Settings {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let required = |name: &str| get(name).ok_or_else(|| format!("{name} is required"));
        let number = |name: &str, default: u64, min: u64| -> Result<u64, String> {
            let value = get(name).map_or(Ok(default), |v| {
                v.trim()
                    .parse()
                    .map_err(|_| format!("{name} must be a whole number"))
            })?;
            if value < min {
                return Err(format!("{name} must be at least {min}"));
            }
            Ok(value)
        };
        let verify_workers = number("OPS_APPROVAL_VERIFY_WORKERS", 2, 1)?;
        if verify_workers > 32 {
            return Err("OPS_APPROVAL_VERIFY_WORKERS must be at most 32".into());
        }
        Ok(Self {
            listen: required("OPS_APPROVAL_LISTEN")?,
            trust: Trust {
                chain: required("OPS_APPROVAL_CHAIN_ID")?
                    .trim()
                    .parse()
                    .map_err(|_| "OPS_APPROVAL_CHAIN_ID must be a whole number".to_string())?,
                keys: parse_key_set(&required("OPS_APPROVAL_PUBLIC_KEYS")?)
                    .map_err(|e| format!("OPS_APPROVAL_PUBLIC_KEYS: {e}"))?,
                max_ttl_ms: number("OPS_APPROVAL_MAX_TTL_MS", 3_600_000, 1)?,
            },
            capacity: number("OPS_APPROVAL_CAPACITY", 100_000, 1)? as usize,
            wait: Duration::from_millis(number("OPS_APPROVAL_WAIT_MS", 5_000, 0)?),
            allowed_sources: get("OPS_APPROVAL_ALLOWED_SOURCES")
                .map_or(Ok(vec![]), |spec| parse_sources(&spec))
                .map_err(|e| format!("OPS_APPROVAL_ALLOWED_SOURCES: {e}"))?,
            max_connections: number("OPS_APPROVAL_MAX_CONNECTIONS", 32, 1)? as usize,
            max_concurrent_calls: u32::try_from(number(
                "OPS_APPROVAL_MAX_CONCURRENT_CALLS",
                32,
                1,
            )?)
            .map_err(|_| "OPS_APPROVAL_MAX_CONCURRENT_CALLS is too large".to_string())?,
            verify_workers: verify_workers as usize,
        })
    }
}

/// `a.b.c.d/n`, `a:b::c/n` or a bare address, comma-separated.
pub fn parse_sources(spec: &str) -> Result<Vec<IpNet>, String> {
    spec.split(',')
        .map(str::trim)
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| format!("{entry:?} is not an address or CIDR block"))
        })
        .collect()
}

/// A random 128-bit identifier of this process start, in hex (contract §4).
pub fn boot_id() -> io::Result<String> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(io::Error::other)?;
    Ok(alloy_primitives::hex::encode(id))
}

pub struct Delivery {
    verifier: Verifier,
    store: Arc<Store>,
    status: StatusResponse,
    profile: bool,
}
impl Delivery {
    /// `clock` reads the receiver's time in Unix milliseconds.
    pub fn new(
        settings: &Settings,
        store: Arc<Store>,
        boot_id: String,
        clock: fn() -> u64,
    ) -> io::Result<Self> {
        let status = StatusResponse {
            boot_id,
            chain_id: settings.trust.chain,
            trusted_key_ids: settings.trust.keys.keys().cloned().collect(),
            max_ttl_ms: settings.trust.max_ttl_ms,
            capacity: settings.capacity as u64,
            wait_ms: settings.wait.as_millis() as u64,
        };
        let (s, trust) = (store.clone(), settings.trust.clone());
        let verifier = Verifier::spawn(settings.verify_workers, QUEUE, move |input| {
            let outcome = check(&s, &trust, clock, input);
            if matches!(outcome, Err(r) if r != Refusal::StoreFull) {
                s.invalid_envelope();
            }
            outcome
        })?;
        Ok(Self {
            verifier,
            profile: store.hops.is_some(),
            store,
            status,
        })
    }
}

/// Checks 1–8 in contract order, on a verification worker.
fn check(store: &Store, trust: &Trust, clock: fn() -> u64, input: Input) -> Outcome {
    let profile = store.hops.is_some();
    let stamp = || if profile { crate::hops::now() } else { 0 };
    let mut stages = crate::hops::Stages {
        received: input.received,
        worker_start: stamp(),
        ..Default::default()
    };
    let envelope = Envelope::decode(&input.bytes)?;
    stages.parsed = stamp();
    let start = Instant::now();
    let now = clock();
    let approvals = envelope.verify(trust, now)?;
    let elapsed = start.elapsed();
    stages.verified = stamp();
    let hashes: Vec<_> = approvals.iter().map(|a| a.tx_hash).collect();
    store.put_batch(
        approvals,
        Now {
            at: Instant::now(),
            ms: now,
        },
    )?;
    store.verified_batch(&hashes, elapsed, stages);
    Ok(hashes.len() as u32)
}

/// The contract's status for each refusal (§3). Messages name the failed check and nothing else.
fn refused(refusal: Refusal) -> Status {
    match refusal {
        Refusal::Malformed(why) => Status::invalid_argument(format!("malformed batch: {why}")),
        Refusal::UntrustedKey => Status::permission_denied("key id not trusted"),
        Refusal::BadSignature => Status::unauthenticated("signature does not verify"),
        Refusal::WrongChain => Status::invalid_argument("approval for another chain"),
        Refusal::TtlTooLong => Status::invalid_argument("lifetime above the maximum TTL"),
        Refusal::IssuedInFuture => Status::failed_precondition("issued_at ahead of this clock"),
        Refusal::Expired => Status::failed_precondition("batch expired"),
        Refusal::StoreFull => {
            let mut status = Status::unavailable("approval store full");
            status.metadata_mut().insert(
                "ops-approval-reason",
                MetadataValue::from_static("store-full"),
            );
            status
        }
    }
}

#[tonic::async_trait]
impl ApprovalDelivery for Delivery {
    async fn deliver(
        &self,
        request: Request<DeliverRequest>,
    ) -> Result<Response<DeliverResponse>, Status> {
        let input = Input {
            bytes: request.into_inner().batch,
            received: if self.profile { crate::hops::now() } else { 0 },
        };
        match self.verifier.run(input).await {
            Some(Ok(stored)) => Ok(Response::new(DeliverResponse {
                boot_id: self.status.boot_id.clone(),
                stored,
            })),
            Some(Err(refusal)) => Err(refused(refusal)),
            None => Err(Status::unavailable("approval verification is stopping")),
        }
    }

    async fn status(&self, _: Request<StatusRequest>) -> Result<Response<StatusResponse>, Status> {
        self.store.status_seen(Now::current());
        Ok(Response::new(self.status.clone()))
    }
}

/// Serves until `shutdown` resolves; in-flight calls then finish and connections are told to go.
pub async fn serve(
    listener: TcpListener,
    delivery: Delivery,
    settings: &Settings,
    shutdown: impl Future<Output = ()>,
) -> Result<(), tonic::transport::Error> {
    let service =
        ApprovalDeliveryServer::new(delivery).max_decoding_message_size(MAX_REQUEST_BYTES);
    Server::builder()
        .max_concurrent_streams(settings.max_concurrent_calls)
        .serve_with_incoming_shutdown(
            service,
            incoming(
                listener,
                settings.allowed_sources.clone(),
                settings.max_connections,
            ),
            shutdown,
        )
        .await
}

/// Accepted connections from allowed sources, at most `max` open at once; any other is closed.
fn incoming(
    listener: TcpListener,
    allowed: Vec<IpNet>,
    max: usize,
) -> impl Stream<Item = io::Result<Connection>> {
    let permits = Arc::new(Semaphore::new(max));
    TcpIncoming::from(listener)
        .with_nodelay(Some(true))
        .filter_map(move |accepted| {
            let stream = match accepted {
                Ok(stream) => stream,
                Err(err) => return Some(Err(err)),
            };
            let source = stream.peer_addr().ok()?.ip().to_canonical();
            if !allowed.is_empty() && !allowed.iter().any(|net| net.contains(&source)) {
                tracing::debug!(%source, "approval delivery connection from a source not allowed");
                return None;
            }
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                tracing::debug!(%source, "approval delivery connection above the cap");
                return None;
            };
            Some(Ok(Connection {
                stream,
                _permit: permit,
            }))
        })
}

/// An admitted connection; its permit returns to the cap when the connection closes.
struct Connection {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}
impl Connected for Connection {
    type ConnectInfo = TcpConnectInfo;
    fn connect_info(&self) -> TcpConnectInfo {
        self.stream.connect_info()
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::tests::{
        CHAIN, EXPIRES, ISSUED, envelope, fixture_key, golden_batch, member, signed, trust,
    };
    use alloy_primitives::B256;
    use ed25519_dalek::SigningKey;
    use pb::approval_delivery_client::ApprovalDeliveryClient;
    use std::net::SocketAddr;
    use tonic::{Code, transport::Channel};

    fn settings() -> Settings {
        Settings {
            listen: "127.0.0.1:0".into(),
            trust: trust(),
            capacity: 100,
            wait: Duration::from_secs(5),
            allowed_sources: vec![],
            max_connections: 32,
            max_concurrent_calls: 32,
            verify_workers: 2,
        }
    }

    struct Receiver {
        address: SocketAddr,
        store: Arc<Store>,
        boot_id: String,
    }

    /// A receiver on loopback whose clock stands at the golden vectors' `issued_at`.
    async fn start(settings: Settings) -> Receiver {
        let listener = TcpListener::bind(&settings.listen).await.unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(Store::new(settings.wait, settings.capacity, Instant::now()));
        let boot_id = boot_id().unwrap();
        let delivery = Delivery::new(&settings, store.clone(), boot_id.clone(), || ISSUED).unwrap();
        tokio::spawn(async move {
            serve(listener, delivery, &settings, std::future::pending())
                .await
                .unwrap()
        });
        Receiver {
            address,
            store,
            boot_id,
        }
    }
    async fn client(address: SocketAddr) -> ApprovalDeliveryClient<Channel> {
        ApprovalDeliveryClient::connect(format!("http://{address}"))
            .await
            .unwrap()
    }
    async fn deliver(
        c: &mut ApprovalDeliveryClient<Channel>,
        batch: Vec<u8>,
    ) -> Result<DeliverResponse, Status> {
        c.deliver(DeliverRequest { batch })
            .await
            .map(Response::into_inner)
    }

    #[tokio::test]
    async fn a_golden_batch_is_stored_and_status_describes_the_receiver() {
        let r = start(settings()).await;
        let mut c = client(r.address).await;
        let reply = deliver(&mut c, golden_batch()).await.unwrap();
        assert_eq!(
            (reply.boot_id.as_str(), reply.stored),
            (r.boot_id.as_str(), 3)
        );
        // Equal issued_at and key id: the greatest fingerprint of the three wins.
        let kept = r.store.usable(&B256::with_last_byte(1), ISSUED).unwrap();
        assert_eq!(kept.fingerprint, B256::with_last_byte(4));
        assert_eq!(kept.expires_at, EXPIRES);
        // Delivery is idempotent.
        assert_eq!(deliver(&mut c, golden_batch()).await.unwrap().stored, 3);
        let status = c.status(StatusRequest {}).await.unwrap().into_inner();
        assert_eq!(
            status,
            StatusResponse {
                boot_id: r.boot_id.clone(),
                chain_id: CHAIN,
                trusted_key_ids: vec!["default".into()],
                max_ttl_ms: 3_600_000,
                capacity: 100,
                wait_ms: 5_000,
            }
        );
    }

    #[tokio::test]
    async fn each_refusal_has_its_contract_status_and_stores_nothing() {
        let r = start(settings()).await;
        let mut c = client(r.address).await;
        let other = SigningKey::from_bytes(&[9; 32]);
        let tx = |chain| vec![member(3, chain, B256::with_last_byte(1), B256::ZERO)];
        let hour = 3_600_000;
        let cases = [
            (b"OPS_APPROVAL_BATCH_V1\0".to_vec(), Code::InvalidArgument),
            (
                envelope(&fixture_key(), "rotated", ISSUED, ISSUED + 1, &tx(CHAIN)),
                Code::PermissionDenied,
            ),
            (
                envelope(&other, "default", ISSUED, ISSUED + 1, &tx(CHAIN)),
                Code::Unauthenticated,
            ),
            (
                envelope(&fixture_key(), "default", ISSUED, ISSUED + 1, &tx(1)),
                Code::InvalidArgument,
            ),
            (signed(1, ISSUED, ISSUED + hour + 1), Code::InvalidArgument),
            (
                signed(1, ISSUED + 5_001, ISSUED + 6_000),
                Code::FailedPrecondition,
            ),
            (signed(1, ISSUED - 2, ISSUED), Code::FailedPrecondition),
        ];
        for (batch, code) in cases {
            let status = deliver(&mut c, batch).await.unwrap_err();
            assert_eq!(status.code(), code, "{status:?}");
            assert!(status.metadata().get("ops-approval-reason").is_none());
        }
        assert!(r.store.usable(&B256::with_last_byte(1), ISSUED).is_none());
        assert_eq!(r.store.stats()["invalid_envelopes"], 7);
    }

    #[tokio::test]
    async fn a_full_store_answers_unavailable_with_the_store_full_trailer() {
        let r = start(Settings {
            capacity: 2,
            ..settings()
        })
        .await;
        let mut c = client(r.address).await;
        let status = deliver(&mut c, signed(3, ISSUED, EXPIRES))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(
            status.metadata().get("ops-approval-reason").unwrap(),
            "store-full"
        );
        assert!(r.store.usable(&B256::with_last_byte(1), ISSUED).is_none());
        assert_eq!(
            deliver(&mut c, signed(2, ISSUED, EXPIRES))
                .await
                .unwrap()
                .stored,
            2
        );
    }

    #[tokio::test]
    async fn requests_above_64_kib_are_refused_before_any_check() {
        let r = start(settings()).await;
        let mut c = client(r.address).await;
        // DeliverRequest adds a tag and a three-byte length to the batch.
        let at_limit = vec![0; MAX_REQUEST_BYTES - 4];
        assert_eq!(
            deliver(&mut c, at_limit).await.unwrap_err().code(),
            Code::InvalidArgument
        );
        let above = vec![0; MAX_REQUEST_BYTES - 3];
        assert_eq!(
            deliver(&mut c, above).await.unwrap_err().code(),
            Code::OutOfRange
        );
        assert_eq!(r.store.stats()["invalid_envelopes"], 1);
    }

    /// A raw HTTP/2 connection, so the test controls exactly which frames are sent.
    async fn h2_connection(
        address: SocketAddr,
    ) -> (
        h2::client::SendRequest<prost::bytes::Bytes>,
        h2::PingPong,
        tokio::task::JoinHandle<Result<(), h2::Error>>,
    ) {
        let tcp = TcpStream::connect(address).await.unwrap();
        let (send, mut connection) = h2::client::handshake(tcp).await.unwrap();
        let pings = connection.ping_pong().unwrap();
        (send, pings, tokio::spawn(connection))
    }

    #[tokio::test]
    async fn an_idle_connection_accepts_keepalive_pings_every_ten_seconds() {
        let r = start(settings()).await;
        let (mut send, mut pings, connection) = h2_connection(r.address).await;
        for round in 0..3 {
            if round > 0 {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            // No call is in flight; each ping must be answered and the connection kept.
            tokio::time::timeout(Duration::from_secs(5), pings.ping(h2::Ping::opaque()))
                .await
                .expect("pong")
                .expect("ping accepted");
            assert!(!connection.is_finished(), "closed after ping {round}");
        }
        // The same connection still carries a call.
        let request = http::Request::post(format!(
            "http://{}/ops.approvals.v1.ApprovalDelivery/Status",
            r.address
        ))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
        send = send.ready().await.unwrap();
        let (response, mut body) = send.send_request(request, false).unwrap();
        body.send_data(prost::bytes::Bytes::from_static(&[0; 5]), true)
            .unwrap();
        let mut response = response.await.unwrap().into_body();
        let mut message = vec![];
        while let Some(chunk) = response.data().await {
            message.extend_from_slice(&chunk.unwrap());
        }
        let trailers = response.trailers().await.unwrap().unwrap();
        assert_eq!(trailers["grpc-status"], "0");
        let status = <StatusResponse as prost::Message>::decode(&message[5..]).unwrap();
        assert_eq!(status.boot_id, r.boot_id);
    }

    #[tokio::test]
    async fn the_concurrent_call_cap_is_advertised_to_clients() {
        let r = start(Settings {
            max_concurrent_calls: 3,
            ..settings()
        })
        .await;
        let (send, mut pings, _connection) = h2_connection(r.address).await;
        // The server's SETTINGS frame precedes its pong, so it has been applied by then.
        pings.ping(h2::Ping::opaque()).await.unwrap();
        assert_eq!(send.current_max_send_streams(), 3);
    }

    /// Whether the receiver closes a new connection without a word: an accepted one answers the
    /// HTTP/2 client preface with its SETTINGS frame.
    async fn refused_connection(address: SocketAddr) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tcp = TcpStream::connect(address).await.unwrap();
        let _ = tcp.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
        let mut frame = [0; 9];
        let read = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut frame))
            .await
            .expect("neither answered nor closed");
        matches!(read, Ok(0) | Err(_))
    }

    #[tokio::test]
    async fn sources_outside_the_allowed_list_are_closed() {
        let r = start(Settings {
            allowed_sources: parse_sources("10.0.0.0/8").unwrap(),
            ..settings()
        })
        .await;
        assert!(refused_connection(r.address).await);
        let r = start(Settings {
            allowed_sources: parse_sources("10.0.0.0/8, 127.0.0.1").unwrap(),
            ..settings()
        })
        .await;
        assert!(!refused_connection(r.address).await);
        assert!(
            client(r.address)
                .await
                .status(StatusRequest {})
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn connections_above_the_cap_are_closed_until_one_ends() {
        let r = start(Settings {
            max_connections: 1,
            ..settings()
        })
        .await;
        let mut first = client(r.address).await;
        assert!(first.status(StatusRequest {}).await.is_ok());
        assert!(refused_connection(r.address).await);
        drop(first);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            client(r.address)
                .await
                .status(StatusRequest {})
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_first_status_call_after_boot_starts_the_wait_windows() {
        let r = start(settings()).await;
        let tx = B256::with_last_byte(7);
        r.store.seen_at(tx, Instant::now(), Now::current());
        let before = r.store.stats()["retained_entries"].clone();
        client(r.address)
            .await
            .status(StatusRequest {})
            .await
            .unwrap();
        // The placeholder's timer now ends one wait window after the Status call, not a minute
        // after boot.
        let mut dropped = vec![];
        let later = Now {
            at: Instant::now() + Duration::from_secs(6),
            ms: ISSUED,
        };
        r.store
            .sweep(later, usize::MAX, |_| true, |h| dropped.push(h));
        assert_eq!((before, dropped), (1.into(), vec![tx]));
    }

    #[tokio::test]
    async fn a_restarted_receiver_stores_a_redelivered_batch_under_its_new_boot_id() {
        let batch = signed(4, ISSUED, EXPIRES);
        let before = start(settings()).await;
        let after = start(settings()).await;
        let first = deliver(&mut client(before.address).await, batch.clone())
            .await
            .unwrap();
        let again = deliver(&mut client(after.address).await, batch)
            .await
            .unwrap();
        assert_ne!(first.boot_id, again.boot_id);
        assert_eq!((first.stored, again.stored), (4, 4));
        assert!(
            after
                .store
                .usable(&B256::with_last_byte(4), ISSUED)
                .is_some()
        );
    }

    #[test]
    fn boot_ids_are_random_128_bit_hex() {
        let (a, b) = (boot_id().unwrap(), boot_id().unwrap());
        assert_ne!(a, b);
        for id in [a, b] {
            assert_eq!(id.len(), 32);
            assert!(
                id.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
        }
    }

    #[test]
    fn settings_mirror_the_plugin_options() {
        let key = alloy_primitives::hex::encode(fixture_key().verifying_key());
        let base = [
            ("OPS_APPROVAL_LISTEN", "127.0.0.1:9000".to_string()),
            ("OPS_APPROVAL_CHAIN_ID", "31337".to_string()),
            ("OPS_APPROVAL_PUBLIC_KEYS", format!("default={key}")),
        ];
        let lookup = |extra: &[(&'static str, &'static str)]| {
            let vars: Vec<(String, String)> = base
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .chain(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())))
                .collect();
            Settings::from_lookup(move |name| {
                vars.iter()
                    .rev()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            })
        };
        let s = lookup(&[]).unwrap();
        assert_eq!(
            (
                s.trust.chain,
                s.trust.max_ttl_ms,
                s.capacity,
                s.wait,
                s.allowed_sources.len(),
                s.max_connections,
                s.max_concurrent_calls,
                s.verify_workers
            ),
            (
                31337,
                3_600_000,
                100_000,
                Duration::from_secs(5),
                0,
                32,
                32,
                2
            )
        );
        let s = lookup(&[
            ("OPS_APPROVAL_MAX_TTL_MS", "600000"),
            ("OPS_APPROVAL_CAPACITY", "7"),
            ("OPS_APPROVAL_WAIT_MS", "1200"),
            ("OPS_APPROVAL_ALLOWED_SOURCES", "10.1.0.0/16,::1"),
            ("OPS_APPROVAL_MAX_CONNECTIONS", "4"),
            ("OPS_APPROVAL_MAX_CONCURRENT_CALLS", "16"),
        ])
        .unwrap();
        assert_eq!(
            (
                s.trust.max_ttl_ms,
                s.capacity,
                s.wait,
                s.max_connections,
                s.max_concurrent_calls
            ),
            (600_000, 7, Duration::from_millis(1200), 4, 16)
        );
        assert!(s.allowed_sources[1].contains(&"::1".parse::<IpAddr>().unwrap()));
        for bad in [
            ("OPS_APPROVAL_PUBLIC_KEYS", "default=00"),
            ("OPS_APPROVAL_CHAIN_ID", "main"),
            ("OPS_APPROVAL_MAX_TTL_MS", "0"),
            ("OPS_APPROVAL_CAPACITY", "0"),
            ("OPS_APPROVAL_ALLOWED_SOURCES", "10.0.0.0/33"),
            ("OPS_APPROVAL_ALLOWED_SOURCES", ""),
            ("OPS_APPROVAL_MAX_CONNECTIONS", "0"),
            ("OPS_APPROVAL_MAX_CONCURRENT_CALLS", "-1"),
            ("OPS_APPROVAL_VERIFY_WORKERS", "33"),
        ] {
            assert!(lookup(&[bad]).is_err(), "{bad:?}");
        }
        assert!(Settings::from_lookup(|_| None).is_err());
    }
}
