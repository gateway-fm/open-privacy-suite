use alloy_primitives::{Address, B256};
use ed25519_dalek::{Signature, VerifyingKey};
use reth_ethereum::pool::{TransactionListenerKind, TransactionPool};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    sync::{Notify, Semaphore},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    #[serde(default, skip_serializing_if = "is_strict")]
    pub hash_mode: u8,
    pub chain_id: u64,
    pub tx_hash: B256,
    pub fingerprint: B256,
    pub principal: B256,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}
fn is_strict(mode: &u8) -> bool {
    *mode == 0
}
impl Approval {
    pub fn valid_mode(&self) -> bool {
        matches!(self.hash_mode, 0 | 3)
    }
    pub fn message(&self) -> Vec<u8> {
        let mut bytes = if self.hash_mode == 3 {
            b"OPS_APPROVAL_V3\0"
        } else {
            b"OPS_APPROVAL_V1\0"
        }
        .to_vec();
        bytes.extend(self.chain_id.to_be_bytes());
        bytes.extend(self.tx_hash);
        bytes.extend(self.fingerprint);
        bytes.extend(self.principal);
        bytes
    }
    pub fn verify(&self, key: &VerifyingKey, chain: u64) -> Result<(), String> {
        if !self.valid_mode() {
            return Err("unknown approval hash mode".into());
        }
        if self.chain_id != chain {
            return Err("wrong chain".into());
        }
        let bytes = alloy_primitives::hex::decode(&self.signature).map_err(|e| e.to_string())?;
        let signature = Signature::from_slice(&bytes).map_err(|e| e.to_string())?;
        key.verify_strict(&self.message(), &signature)
            .map_err(|e| e.to_string())
    }
}
#[derive(Clone, Debug)]
pub struct Selected {
    pub approval: Approval,
    pub sender: Address,
    pub nonce: u64,
}
pub type Selection = Arc<Mutex<Option<Selected>>>;
#[derive(Debug)]
struct Entry {
    approval: Option<Approval>,
    deadline: Instant,
    generation: u64,
    seen: bool,
}
#[derive(Debug, Default)]
struct State {
    entries: HashMap<B256, Entry>,
    deadlines: BTreeSet<(Instant, u64, B256)>,
    generation: u64,
}
#[derive(Debug)]
pub struct Store {
    pub hops: Option<crate::hops::Hops>,
    state: Mutex<State>,
    notify: Notify,
    pub wait: Duration,
    capacity: usize,
    ready_first: AtomicU64,
    waiting_first: AtomicU64,
    verified: AtomicU64,
    verification_ns: AtomicU64,
    verified_batches: AtomicU64,
    batch_sizes: [AtomicU64; 33],
    invalid_envelopes: AtomicU64,
    verification_queue_full: AtomicU64,
    capacity_rejections: AtomicU64,
    resolved_waits: AtomicU64,
    wait_ns: AtomicU64,
    max_wait_ns: AtomicU64,
    wait_histogram: [AtomicU64; 8],
}
impl Store {
    pub fn new(wait: Duration, capacity: usize) -> Self {
        Self {
            hops: crate::hops::Hops::from_env(),
            state: Mutex::default(),
            notify: Notify::new(),
            wait,
            capacity,
            ready_first: AtomicU64::new(0),
            waiting_first: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            verification_ns: AtomicU64::new(0),
            verified_batches: AtomicU64::new(0),
            batch_sizes: std::array::from_fn(|_| AtomicU64::new(0)),
            invalid_envelopes: AtomicU64::new(0),
            verification_queue_full: AtomicU64::new(0),
            capacity_rejections: AtomicU64::new(0),
            resolved_waits: AtomicU64::new(0),
            wait_ns: AtomicU64::new(0),
            max_wait_ns: AtomicU64::new(0),
            wait_histogram: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    // Every transaction gets its own timer. No sleeping in pool validation or the payload builder.
    #[cfg(test)]
    pub fn seen(&self, hash: B256) -> bool {
        self.seen_at(hash, Instant::now())
    }
    pub fn seen_at(&self, hash: B256, arrived: Instant) -> bool {
        let mut s = self.state.lock().unwrap();
        if let Some(e) = s.entries.get_mut(&hash) {
            let first_ready = !e.seen && e.approval.is_some();
            if !e.seen
                && let Some(h) = &self.hops
            {
                h.arrival(hash, arrived);
            }
            if !e.seen && e.approval.is_some() {
                self.ready_first.fetch_add(1, Ordering::Relaxed);
            }
            e.seen = true;
            if first_ready {
                let old = (e.deadline, e.generation, hash);
                e.deadline = Instant::now() + Duration::from_secs(1);
                let next = (e.deadline, e.generation, hash);
                s.deadlines.remove(&old);
                s.deadlines.insert(next);
                self.notify.notify_one();
            }
            return true;
        }
        let accepted = self.insert(&mut s, hash, None, true, arrived);
        if accepted {
            if let Some(h) = &self.hops {
                h.arrival(hash, arrived);
            }
            self.waiting_first.fetch_add(1, Ordering::Relaxed);
        }
        accepted
    }
    pub fn stats(&self) -> serde_json::Value {
        if let Some(h) = &self.hops {
            h.flush();
        }
        serde_json::json!({"ready_on_first_seen":self.ready_first.load(Ordering::Relaxed),
            "waiting_on_first_seen":self.waiting_first.load(Ordering::Relaxed),
            "verified":self.verified.load(Ordering::Relaxed),
            "verification_ns":self.verification_ns.load(Ordering::Relaxed),
            "verified_batches":self.verified_batches.load(Ordering::Relaxed),
            "batch_sizes":self.batch_sizes.iter().map(|x|x.load(Ordering::Relaxed)).collect::<Vec<_>>(),
            "invalid_envelopes":self.invalid_envelopes.load(Ordering::Relaxed),
            "verification_queue_full":self.verification_queue_full.load(Ordering::Relaxed),
            "capacity_rejections":self.capacity_rejections.load(Ordering::Relaxed),
            "retained_entries":self.state.lock().unwrap().entries.len(),
            "resolved_waits":self.resolved_waits.load(Ordering::Relaxed),
            "wait_ns":self.wait_ns.load(Ordering::Relaxed),
            "max_wait_ns":self.max_wait_ns.load(Ordering::Relaxed),
            "wait_bucket_upper_us":[100,500,1000,5000,10000,50000,100000,null],
            "wait_histogram":self.wait_histogram.iter().map(|x|x.load(Ordering::Relaxed)).collect::<Vec<_>>()})
    }
    pub fn invalid_envelope(&self) {
        self.invalid_envelopes.fetch_add(1, Ordering::Relaxed);
    }
    pub fn verified_batch(
        &self,
        approvals: Vec<Approval>,
        elapsed: Duration,
        stages: crate::hops::Stages,
    ) {
        self.verified
            .fetch_add(approvals.len() as u64, Ordering::Relaxed);
        self.verified_batches.fetch_add(1, Ordering::Relaxed);
        self.batch_sizes[approvals.len()].fetch_add(1, Ordering::Relaxed);
        self.verification_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        for a in approvals {
            let hash = a.tx_hash;
            if self.put(a)
                && let Some(h) = &self.hops
            {
                h.approval(
                    hash,
                    crate::hops::Stages {
                        published: crate::hops::now(),
                        ..stages
                    },
                );
            }
        }
    }
    fn insert(
        &self,
        s: &mut State,
        hash: B256,
        approval: Option<Approval>,
        seen: bool,
        arrived: Instant,
    ) -> bool {
        if s.entries.len() >= self.capacity {
            self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        s.generation += 1;
        let generation = s.generation;
        // Early approvals have bounded residence, not policy revocation semantics.
        let deadline = arrived
            + if approval.is_some() {
                Duration::from_secs(300)
            } else {
                self.wait
            };
        s.entries.insert(
            hash,
            Entry {
                approval,
                deadline,
                generation,
                seen,
            },
        );
        s.deadlines.insert((deadline, generation, hash));
        self.notify.notify_one();
        true
    }
    pub fn put(&self, a: Approval) -> bool {
        let mut s = self.state.lock().unwrap();
        if let Some(e) = s.entries.get_mut(&a.tx_hash) {
            // An active wait cannot be prolonged by retransmission. A new approval may replace
            // a previous fingerprint after a NEW OPS preflight for the same signed transaction.
            if e.approval.is_none() && Instant::now() >= e.deadline {
                return false;
            }
            if e.approval.is_none() {
                // Pool insertion timestamp to permission publication, for approvals
                // that were still missing when the listener observed the transaction.
                let elapsed = Instant::now().saturating_duration_since(e.deadline - self.wait);
                let ns = elapsed.as_nanos() as u64;
                self.resolved_waits.fetch_add(1, Ordering::Relaxed);
                self.wait_ns.fetch_add(ns, Ordering::Relaxed);
                self.max_wait_ns.fetch_max(ns, Ordering::Relaxed);
                let bucket = [100, 500, 1000, 5000, 10000, 50000, 100000]
                    .iter()
                    .position(|us| elapsed.as_nanos() <= us * 1000)
                    .unwrap_or(7);
                self.wait_histogram[bucket].fetch_add(1, Ordering::Relaxed);
            }
            e.approval = Some(a);
            self.notify.notify_one();
            return true;
        }
        self.insert(&mut s, a.tx_hash, Some(a), false, Instant::now())
    }
    pub fn get(&self, hash: &B256) -> Option<Approval> {
        self.state
            .lock()
            .unwrap()
            .entries
            .get(hash)?
            .approval
            .clone()
    }

    pub fn start<P: TransactionPool + 'static>(self: &Arc<Self>, pool: P) {
        let mut arrivals = pool.new_transactions_listener_for(TransactionListenerKind::All);
        let this = self.clone();
        let p = pool.clone();
        tokio::spawn(async move {
            while let Some(event) = arrivals.recv().await {
                let hash = *event.transaction.hash();
                if !this.seen_at(hash, event.transaction.timestamp) {
                    p.remove_transactions(vec![hash]);
                }
            }
        });
        // Recover restored pool entries and any dropped bounded listener notifications.
        // This maintenance task never runs on the payload executor. Deadlines stay anchored
        // to the pool's insertion timestamp; scanning cannot extend a transaction's wait.
        let this = self.clone();
        let p = pool.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tick.tick().await;
                for (i, tx) in p.all_transactions().into_iter().enumerate() {
                    if !this.seen_at(*tx.hash(), tx.timestamp) {
                        p.remove_transactions(vec![*tx.hash()]);
                    }
                    if i % 64 == 63 {
                        tokio::task::yield_now().await;
                    }
                }
            }
        });
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let next = {
                    let mut s = this.state.lock().unwrap();
                    let mut expired = 0;
                    while let Some((deadline, generation, hash)) = s.deadlines.first().copied() {
                        if deadline > Instant::now() || expired == 16 {
                            break;
                        }
                        expired += 1;
                        s.deadlines.pop_first();
                        if let Some(e) = s.entries.get(&hash) {
                            if e.generation != generation {
                                continue;
                            }
                            if e.approval.is_none() {
                                // Synchronous removal under the short store lock closes arrival/timeout race.
                                pool.remove_transactions(vec![hash]);
                                eprintln!(
                                    "OPS_APPROVAL_EVENT {{\"event\":\"timeout\",\"tx_hash\":\"{hash}\"}}"
                                );
                                s.entries.remove(&hash);
                            } else if pool.get(&hash).is_none() {
                                s.entries.remove(&hash);
                            } else {
                                // Keep approvals for transactions still queued; bounded by capacity.
                                let later = Instant::now() + Duration::from_secs(1);
                                s.entries.get_mut(&hash).unwrap().deadline = later;
                                s.deadlines.insert((later, generation, hash));
                            }
                        }
                    }
                    s.deadlines
                        .first()
                        .map(|v| v.0)
                        .unwrap_or(Instant::now() + Duration::from_secs(300))
                };
                tokio::select! {_ = tokio::time::sleep_until(next.into())=>{},_ = this.notify.notified()=>{}}
                // A large simultaneous expiry must not monopolize this runtime worker/store lock.
                tokio::task::yield_now().await;
            }
        });
    }
}

pub async fn serve(
    listener: TcpListener,
    store: Arc<Store>,
    verifier: crate::verification::Verifier,
) {
    if verifier.is_direct() {
        serve_direct(listener, verifier).await;
        return;
    }
    let connections = Arc::new(Semaphore::new(32));
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            break;
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let store = store.clone();
        let verifier = verifier.clone();
        tokio::spawn(async move {
            let _permit = permit;
            loop {
                let frame = async {
                    let len = socket.read_u32().await? as usize;
                    if len > crate::batch::MAX_FRAME {
                        return Err(std::io::Error::other("oversize approval"));
                    }
                    let mut bytes = vec![0; len];
                    socket.read_exact(&mut bytes).await?;
                    Ok(bytes)
                }
                .await;
                let Ok(bytes) = frame else {
                    break;
                };
                let Some(completed) = verifier.submit(bytes) else {
                    store
                        .verification_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                // Async wait preserves ordering on this connection only. Other
                // connections and the execution path continue independently.
                if completed.await.is_err() {
                    break;
                }
            }
        });
    }
}

// One bounded OS worker owns each persistent connection: kernel read wakeup,
// frame parsing, signature verification and publication. No Tokio -> CPU queue
// -> Tokio roundtrip per batch, and no EVM work on this thread.
async fn serve_direct(listener: TcpListener, verifier: crate::verification::Verifier) {
    let connections = Arc::new(Semaphore::new(32));
    let mut sequence = 0u64;
    while let Ok((socket, _)) = listener.accept().await {
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let Ok(mut socket) = socket.into_std() else {
            continue;
        };
        if socket.set_nonblocking(false).is_err() {
            continue;
        }
        let verifier = verifier.clone();
        sequence += 1;
        if let Err(err) = std::thread::Builder::new()
            .name(format!("ops-ingress-{sequence}"))
            .spawn(move || {
                let _permit = permit;
                use std::io::Read;
                loop {
                    let mut header = [0u8; 4];
                    if socket.read_exact(&mut header).is_err() {
                        break;
                    }
                    let len = u32::from_be_bytes(header) as usize;
                    if len == 0 || len > crate::batch::MAX_FRAME {
                        break;
                    }
                    let mut bytes = vec![0u8; len];
                    if socket.read_exact(&mut bytes).is_err() {
                        break;
                    }
                    verifier.verify_on_receiver(bytes);
                }
            })
        {
            tracing::warn!(%err,"approval receiver thread unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[tokio::test(flavor = "current_thread")]
    async fn partial_frame_does_not_block_another_connection_and_coalesced_frames_work() {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(Store::new(Duration::from_secs(5), 100));
        let verifier = crate::verification::Verifier::new(
            store.clone(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            31337,
            2,
            64,
            true,
        )
        .unwrap();
        let task = tokio::spawn(serve(listener, store.clone(), verifier));
        let payload = crate::batch::tests::golden_wire();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend(payload);
        let mut partial = tokio::net::TcpStream::connect(address).await.unwrap();
        partial.write_all(&frame[..2]).await.unwrap();
        let mut ready = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut two = frame.clone();
        two.extend(&frame);
        ready.write_all(&two).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.verified.load(Ordering::Relaxed) != 6 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        partial.write_all(&frame[2..]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.verified.load(Ordering::Relaxed) != 9 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(partial);
        drop(ready);
        task.abort();
    }
    #[test]
    fn signature_binds_every_field() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut a = Approval {
            hash_mode: 0,
            chain_id: 31337,
            tx_hash: B256::repeat_byte(1),
            fingerprint: B256::repeat_byte(2),
            principal: B256::repeat_byte(3),
            signature: String::new(),
        };
        a.signature = alloy_primitives::hex::encode(key.sign(&a.message()).to_bytes());
        assert!(a.verify(&key.verifying_key(), 31337).is_ok());
        for field in 0..4 {
            let mut b = a.clone();
            match field {
                0 => b.tx_hash = B256::ZERO,
                1 => b.fingerprint = B256::ZERO,
                2 => b.principal = B256::ZERO,
                _ => b.chain_id = 1,
            };
            assert!(b.verify(&key.verifying_key(), 31337).is_err());
        }
    }
    #[test]
    fn early_approval_is_rechecked_promptly_after_transaction_arrives() {
        let store = Store::new(Duration::from_secs(5), 2);
        let hash = B256::repeat_byte(1);
        assert!(store.put(Approval {
            hash_mode: 0,
            chain_id: 31337,
            tx_hash: hash,
            fingerprint: B256::ZERO,
            principal: B256::ZERO,
            signature: String::new()
        }));
        assert!(store.seen(hash));
        let deadline = store.state.lock().unwrap().entries[&hash].deadline;
        assert!(deadline <= Instant::now() + Duration::from_secs(2));
        assert!(store.seen(hash));
        let state = store.state.lock().unwrap();
        assert_eq!(state.entries[&hash].deadline, deadline);
        assert_eq!(
            state.deadlines.len(),
            1,
            "old residence timer must be removed"
        );
    }
    #[test]
    fn duplicates_keep_deadline_and_capacity_is_bounded() {
        let store = Store::new(Duration::from_secs(5), 1);
        let h = B256::repeat_byte(1);
        assert!(store.seen(h));
        let first = store.state.lock().unwrap().entries[&h].deadline;
        assert!(store.seen(h));
        assert_eq!(first, store.state.lock().unwrap().entries[&h].deadline);
        assert!(!store.seen(B256::ZERO));
    }
}
