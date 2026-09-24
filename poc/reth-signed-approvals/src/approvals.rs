use crate::batch::Refusal;
use alloy_primitives::{Address, B256};
use reth_chain_state::ForkChoiceSubscriptions;
use reth_ethereum::{
    EthPrimitives,
    pool::{TransactionListenerKind, TransactionPool},
    primitives::AlloyBlockHeader,
    provider::CanonStateSubscriptions,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, broadcast};

/// How often an approval whose transaction is pooled is checked against the pool.
const RECHECK: Duration = Duration::from_secs(1);
/// After a restart the wait windows start at the first `Status` call, at most this long after boot
/// (contract §4): the RPC nodes may re-announce pooled transactions before OPS has reconnected.
const RESTART_WINDOW: Duration = Duration::from_secs(60);

/// One verified approval, with the batch fields the store and the gate need. The reserved
/// 32 bytes of the wire format are signed over and otherwise ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub hash_mode: u8,
    pub chain_id: u64,
    pub tx_hash: B256,
    pub fingerprint: B256,
    pub key_id: Arc<str>,
    /// Unix milliseconds, from the signed batch.
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Approval {
    pub fn valid_mode(&self) -> bool {
        matches!(self.hash_mode, 0 | 3)
    }
    /// Per transaction the store keeps the greatest (issued_at, key id, fingerprint), compared as
    /// unsigned integer and then bytewise, so every receiver keeps the same one (contract §3).
    fn rank(&self) -> (u64, &[u8], &B256) {
        (self.issued_at, self.key_id.as_bytes(), &self.fingerprint)
    }
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A moment on both clocks the store uses: `at` for its own timers, `ms` (Unix milliseconds) for
/// the signed `issued_at`/`expires_at`.
#[derive(Clone, Copy, Debug)]
pub struct Now {
    pub at: Instant,
    pub ms: u64,
}
impl Now {
    pub fn current() -> Self {
        Self {
            at: Instant::now(),
            ms: unix_ms(),
        }
    }
    /// When the Unix time `ms` arrives, as far as this pair of readings can tell.
    fn instant_of(self, ms: u64) -> Instant {
        self.at + Duration::from_millis(ms.saturating_sub(self.ms))
    }
}

#[derive(Clone, Debug)]
pub struct Selected {
    pub approval: Approval,
    pub sender: Address,
    pub nonce: u64,
}
pub type Selection = Arc<Mutex<Option<Selected>>>;

/// One transaction hash the store knows: an approval, a pooled transaction waiting for one (a
/// placeholder), or both.
#[derive(Debug)]
struct Entry {
    approval: Option<Approval>,
    /// Pool admission, while the transaction is pooled.
    pooled: Option<Instant>,
    /// The canonical block that included the transaction, until that block is final.
    included: Option<u64>,
    deadline: Instant,
    generation: u64,
}

/// Classes of approvals the store may evict for a new batch, in eviction order after expired ones.
const INCLUDED: u8 = 0;
const ORPHAN: u8 = 1;

/// Entries and their indexes. Every entry has exactly one timer in `deadlines`; `approvals`,
/// `by_expiry`, `evictable` and `included` are derived from the entries by `index`. Every change
/// goes through `insert`, `remove` or `modify`, which keep both in step.
#[derive(Debug, Default)]
struct State {
    entries: HashMap<B256, Entry>,
    deadlines: BTreeSet<(Instant, u64, B256)>,
    generation: u64,
    /// Entries holding an approval: what capacity counts. Placeholders do not.
    approvals: usize,
    by_expiry: BTreeSet<(u64, B256)>,
    /// (class, issued_at, hash) of approvals whose transaction is not pooled.
    evictable: BTreeSet<(u8, u64, B256)>,
    /// (block, hash) of included approvals waiting for their block to become final.
    included: BTreeSet<(u64, B256)>,
    finalized: u64,
    first_status: Option<Instant>,
}
impl State {
    fn index(&mut self, hash: B256, add: bool) {
        let Some(e) = self.entries.get(&hash) else {
            return;
        };
        let Some(a) = &e.approval else {
            return;
        };
        let class = match (e.pooled, e.included) {
            (Some(_), _) => None,
            (None, Some(_)) => Some(INCLUDED),
            (None, None) => Some(ORPHAN),
        };
        let expiry = (a.expires_at, hash);
        let evictable = class.map(|c| (c, a.issued_at, hash));
        let included = e.included.map(|block| (block, hash));
        if add {
            self.approvals += 1;
            self.by_expiry.insert(expiry);
            self.evictable.extend(evictable);
            self.included.extend(included);
        } else {
            self.approvals -= 1;
            self.by_expiry.remove(&expiry);
            if let Some(key) = evictable {
                self.evictable.remove(&key);
            }
            if let Some(key) = included {
                self.included.remove(&key);
            }
        }
    }
    fn insert(&mut self, hash: B256, mut entry: Entry) {
        self.generation += 1;
        entry.generation = self.generation;
        self.deadlines
            .insert((entry.deadline, entry.generation, hash));
        self.entries.insert(hash, entry);
        self.index(hash, true);
    }
    fn remove(&mut self, hash: B256) -> Option<Entry> {
        self.index(hash, false);
        let e = self.entries.remove(&hash)?;
        self.deadlines.remove(&(e.deadline, e.generation, hash));
        Some(e)
    }
    /// Applies `change` to an entry, keeping the indexes and its timer in step.
    fn modify(&mut self, hash: B256, change: impl FnOnce(&mut Entry)) {
        self.index(hash, false);
        let Some(e) = self.entries.get_mut(&hash) else {
            return;
        };
        let timer = (e.deadline, e.generation, hash);
        change(e);
        let next = (e.deadline, e.generation, hash);
        if next != timer {
            self.deadlines.remove(&timer);
            self.deadlines.insert(next);
        }
        self.index(hash, true);
    }
    fn has_approval(&self, hash: &B256) -> bool {
        self.entries.get(hash).is_some_and(|e| e.approval.is_some())
    }
    /// Up to `needed` approvals to evict for a new batch: expired ones first, then those of
    /// included transactions, then the oldest orphans. Pooled ones only once expired; young
    /// ones (issued less than `grace` ago) never; nothing the batch itself names.
    fn victims(&self, needed: usize, now: u64, grace: u64, keep: &[B256]) -> Vec<B256> {
        let mut victims = Vec::with_capacity(needed);
        for &(expires_at, hash) in &self.by_expiry {
            if expires_at > now || victims.len() == needed {
                break;
            }
            if !keep.contains(&hash) {
                victims.push(hash);
            }
        }
        for class in [INCLUDED, ORPHAN] {
            let range = (class, 0, B256::ZERO)..=(class, u64::MAX, B256::repeat_byte(0xff));
            for &(_, issued, hash) in self.evictable.range(range) {
                // Ordered by issued_at: everything after a young approval is young too.
                if victims.len() == needed || now.saturating_sub(issued) < grace {
                    break;
                }
                if !keep.contains(&hash) && !victims.contains(&hash) {
                    victims.push(hash);
                }
            }
        }
        victims
    }
}

#[derive(Debug)]
pub struct Store {
    pub hops: Option<crate::hops::Hops>,
    state: Mutex<State>,
    notify: Notify,
    pub wait: Duration,
    capacity: usize,
    boot: Instant,
    ready_first: AtomicU64,
    waiting_first: AtomicU64,
    verified: AtomicU64,
    verification_ns: AtomicU64,
    verified_batches: AtomicU64,
    batch_sizes: [AtomicU64; 33],
    invalid_envelopes: AtomicU64,
    store_full: AtomicU64,
    expired: AtomicU64,
    evicted: AtomicU64,
    released: AtomicU64,
    resolved_waits: AtomicU64,
    wait_ns: AtomicU64,
    max_wait_ns: AtomicU64,
    wait_histogram: [AtomicU64; 8],
}
impl Store {
    pub fn new(wait: Duration, capacity: usize, boot: Instant) -> Self {
        Self {
            hops: crate::hops::Hops::from_env(),
            state: Mutex::default(),
            notify: Notify::new(),
            wait,
            capacity,
            boot,
            ready_first: AtomicU64::new(0),
            waiting_first: AtomicU64::new(0),
            verified: AtomicU64::new(0),
            verification_ns: AtomicU64::new(0),
            verified_batches: AtomicU64::new(0),
            batch_sizes: std::array::from_fn(|_| AtomicU64::new(0)),
            invalid_envelopes: AtomicU64::new(0),
            store_full: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            released: AtomicU64::new(0),
            resolved_waits: AtomicU64::new(0),
            wait_ns: AtomicU64::new(0),
            max_wait_ns: AtomicU64::new(0),
            wait_histogram: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    /// When a transaction admitted at `arrived` stops waiting for its approval: one wait window
    /// after admission, or after the first `Status` call if that came later, but never counting
    /// from later than a minute after boot (contract §4). Until that call, a transaction pooled in
    /// the first minute waits as if the call came a minute after boot; the call brings it forward.
    fn wait_end(&self, s: &State, arrived: Instant) -> Instant {
        let cap = self.boot + RESTART_WINDOW;
        let start = s.first_status.map_or(cap, |status| status.min(cap));
        arrived.max(start) + self.wait
    }

    /// The pool admitted, or re-announced, the transaction. A transaction already pooled keeps
    /// its timer: a re-announcement cannot prolong a wait.
    pub fn seen_at(&self, hash: B256, arrived: Instant, now: Now) {
        let mut s = self.state.lock().unwrap();
        match s.entries.get(&hash) {
            Some(e) if e.pooled.is_some() => return,
            Some(e) => {
                // An approval that arrived first: re-check it against the pool promptly.
                let expiry = e.approval.as_ref().map(|a| now.instant_of(a.expires_at));
                if let Some(expiry) = expiry {
                    self.ready_first.fetch_add(1, Ordering::Relaxed);
                    s.modify(hash, |e| {
                        e.pooled = Some(arrived);
                        e.deadline = expiry.min(now.at + RECHECK);
                    });
                }
            }
            None => {
                self.waiting_first.fetch_add(1, Ordering::Relaxed);
                let deadline = self.wait_end(&s, arrived);
                s.insert(
                    hash,
                    Entry {
                        approval: None,
                        pooled: Some(arrived),
                        included: None,
                        deadline,
                        generation: 0,
                    },
                );
            }
        }
        drop(s);
        if let Some(h) = &self.hops {
            h.arrival(hash, arrived);
        }
        self.notify.notify_one();
    }

    /// The approval the gate may use: stored and not expired (contract §6).
    pub fn usable(&self, hash: &B256, now_ms: u64) -> Option<Approval> {
        let s = self.state.lock().unwrap();
        let a = s.entries.get(hash)?.approval.as_ref()?;
        (now_ms < a.expires_at).then(|| a.clone())
    }

    /// Check 8 and storage, all or nothing. Room for every approval that needs a slot is
    /// counted — free capacity plus what may be evicted — before anything is evicted.
    pub fn put_batch(&self, batch: Vec<Approval>, now: Now) -> Result<(), Refusal> {
        let mut s = self.state.lock().unwrap();
        let named: Vec<B256> = batch.iter().map(|a| a.tx_hash).collect();
        let mut fresh = Vec::with_capacity(batch.len());
        for hash in &named {
            if !s.has_approval(hash) && !fresh.contains(hash) {
                fresh.push(*hash);
            }
        }
        let free = self.capacity.saturating_sub(s.approvals);
        if fresh.len() > free {
            let needed = fresh.len() - free;
            let grace = self.wait.as_millis() as u64;
            let victims = s.victims(needed, now.ms, grace, &named);
            if victims.len() < needed {
                self.store_full.fetch_add(1, Ordering::Relaxed);
                return Err(Refusal::StoreFull);
            }
            for hash in victims {
                self.evicted.fetch_add(1, Ordering::Relaxed);
                self.evict(&mut s, hash);
            }
        }
        for a in batch {
            self.put(&mut s, a, now);
        }
        drop(s);
        self.notify.notify_one();
        Ok(())
    }

    fn evict(&self, s: &mut State, hash: B256) {
        let pooled = s.entries.get(&hash).and_then(|e| e.pooled);
        match pooled {
            // Only an expired approval of a pooled transaction is a victim: it waits on.
            Some(arrived) => {
                let deadline = self.wait_end(s, arrived);
                s.modify(hash, |e| {
                    e.approval = None;
                    e.deadline = deadline;
                });
            }
            None => {
                s.remove(hash);
            }
        }
    }

    fn put(&self, s: &mut State, a: Approval, now: Now) {
        let hash = a.tx_hash;
        let expiry = now.instant_of(a.expires_at);
        let Some(e) = s.entries.get(&hash) else {
            s.insert(
                hash,
                Entry {
                    approval: Some(a),
                    pooled: None,
                    included: None,
                    deadline: expiry,
                    generation: 0,
                },
            );
            return;
        };
        // Keep the greatest (issued_at, key id, fingerprint); an equal one is a no-op.
        if e.approval
            .as_ref()
            .is_some_and(|old| old.rank() >= a.rank())
        {
            return;
        }
        if e.approval.is_none()
            && let Some(arrived) = e.pooled
        {
            // Pool admission to approval, for transactions that were already waiting.
            let elapsed = now.at.saturating_duration_since(arrived);
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
        let pooled = e.pooled.is_some();
        s.modify(hash, |e| {
            e.approval = Some(a);
            e.deadline = if pooled {
                expiry.min(now.at + RECHECK)
            } else {
                expiry
            };
        });
    }

    /// The first `Status` call after boot starts the wait windows of the transactions pooled
    /// before it.
    pub fn status_seen(&self, now: Now) {
        let mut s = self.state.lock().unwrap();
        if s.first_status.is_some() {
            return;
        }
        s.first_status = Some(now.at);
        let waiting: Vec<_> = s
            .entries
            .iter()
            .filter(|(_, e)| e.approval.is_none())
            .filter_map(|(hash, e)| Some((*hash, e.pooled?)))
            .collect();
        for (hash, arrived) in waiting {
            let deadline = self.wait_end(&s, arrived);
            s.modify(hash, |e| e.deadline = deadline);
        }
        drop(s);
        self.notify.notify_one();
    }

    /// A canonical block included these transactions.
    pub fn included(&self, block: u64, hashes: impl IntoIterator<Item = B256>, now: Now) {
        let mut s = self.state.lock().unwrap();
        for hash in hashes {
            let Some(e) = s.entries.get(&hash) else {
                continue;
            };
            let Some(expires_at) = e.approval.as_ref().map(|a| a.expires_at) else {
                // A placeholder: its transaction was mined elsewhere and no longer waits.
                s.remove(hash);
                continue;
            };
            if block <= s.finalized {
                self.released.fetch_add(1, Ordering::Relaxed);
                s.remove(hash);
                continue;
            }
            s.modify(hash, |e| {
                e.included = Some(block);
                e.pooled = None;
                e.deadline = now.instant_of(expires_at);
            });
        }
    }

    /// A block that included these transactions left the canonical chain. Their approvals stay:
    /// the transactions return to the pool and need no new preflight.
    pub fn reverted(&self, block: u64, hashes: impl IntoIterator<Item = B256>) {
        let mut s = self.state.lock().unwrap();
        for hash in hashes {
            if s.entries.get(&hash).and_then(|e| e.included) == Some(block) {
                s.modify(hash, |e| e.included = None);
            }
        }
    }

    /// The finalized block advanced: approvals of transactions included at or below it go.
    pub fn finalized(&self, block: u64) {
        let mut s = self.state.lock().unwrap();
        s.finalized = s.finalized.max(block);
        while let Some(&(included, hash)) = s.included.first() {
            if included > s.finalized {
                break;
            }
            self.released.fetch_add(1, Ordering::Relaxed);
            s.remove(hash);
        }
    }

    /// Handles at most `limit` due timers and returns the next deadline. `remove_tx` removes a
    /// transaction from the pool; it runs under the store lock, which closes the race between an
    /// arriving approval and the timeout.
    pub fn sweep(
        &self,
        now: Now,
        limit: usize,
        in_pool: impl Fn(&B256) -> bool,
        mut remove_tx: impl FnMut(B256),
    ) -> Option<Instant> {
        let mut s = self.state.lock().unwrap();
        let mut handled = 0;
        while let Some(&(deadline, _, hash)) = s.deadlines.first() {
            if deadline > now.at || handled == limit {
                break;
            }
            handled += 1;
            let Some(e) = s.entries.get(&hash) else {
                // Unreachable while every change goes through State; never panic under the lock.
                s.deadlines.pop_first();
                continue;
            };
            let (approval, pooled, included) = (e.approval.clone(), e.pooled, e.included);
            let timeout = |s: &mut State, remove_tx: &mut dyn FnMut(B256)| {
                remove_tx(hash);
                eprintln!("OPS_APPROVAL_EVENT {{\"event\":\"timeout\",\"tx_hash\":\"{hash}\"}}");
                s.remove(hash);
            };
            match (approval, pooled) {
                (None, Some(arrived)) => {
                    let end = self.wait_end(&s, arrived);
                    if now.at >= end {
                        timeout(&mut s, &mut remove_tx);
                    } else {
                        s.modify(hash, |e| e.deadline = end);
                    }
                }
                (Some(a), pooled) if a.expires_at <= now.ms => {
                    // Expired: absent from now on. A pooled transaction waits out its window.
                    self.expired.fetch_add(1, Ordering::Relaxed);
                    let Some(arrived) = pooled else {
                        s.remove(hash);
                        continue;
                    };
                    let end = self.wait_end(&s, arrived);
                    if now.at >= end {
                        timeout(&mut s, &mut remove_tx);
                    } else {
                        s.modify(hash, |e| {
                            e.approval = None;
                            e.deadline = end;
                        });
                    }
                }
                (Some(a), Some(_)) if included.is_none() => {
                    let expiry = now.instant_of(a.expires_at);
                    if in_pool(&hash) {
                        s.modify(hash, |e| e.deadline = expiry.min(now.at + RECHECK));
                    } else {
                        // Left the pool without inclusion: an orphan until it expires.
                        s.modify(hash, |e| {
                            e.pooled = None;
                            e.deadline = expiry;
                        });
                    }
                }
                (Some(a), _) => {
                    // An orphan or an included approval: nothing to do before it expires.
                    let expiry = now.instant_of(a.expires_at);
                    s.modify(hash, |e| e.deadline = expiry);
                }
                (None, None) => {
                    s.remove(hash);
                }
            }
        }
        s.deadlines.first().map(|d| d.0)
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
            "store_full_batches":self.store_full.load(Ordering::Relaxed),
            "expired_approvals":self.expired.load(Ordering::Relaxed),
            "evicted_approvals":self.evicted.load(Ordering::Relaxed),
            "released_on_finality":self.released.load(Ordering::Relaxed),
            "retained_entries":self.state.lock().unwrap().entries.len(),
            "resolved_waits":self.resolved_waits.load(Ordering::Relaxed),
            "wait_ns":self.wait_ns.load(Ordering::Relaxed),
            "max_wait_ns":self.max_wait_ns.load(Ordering::Relaxed),
            "wait_bucket_upper_us":[100,500,1000,5000,10000,50000,100000,null],
            "wait_histogram":self.wait_histogram.iter().map(|x|x.load(Ordering::Relaxed)).collect::<Vec<_>>()})
    }
    /// A delivered batch failed one of checks 1–7.
    pub fn invalid_envelope(&self) {
        self.invalid_envelopes.fetch_add(1, Ordering::Relaxed);
    }
    /// Counters for a batch `put_batch` accepted.
    pub fn verified_batch(&self, hashes: &[B256], elapsed: Duration, stages: crate::hops::Stages) {
        self.verified
            .fetch_add(hashes.len() as u64, Ordering::Relaxed);
        self.verified_batches.fetch_add(1, Ordering::Relaxed);
        self.batch_sizes[hashes.len()].fetch_add(1, Ordering::Relaxed);
        self.verification_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        if let Some(h) = &self.hops {
            for hash in hashes {
                h.approval(
                    *hash,
                    crate::hops::Stages {
                        published: crate::hops::now(),
                        ..stages
                    },
                );
            }
        }
    }

    pub fn start<P: TransactionPool + 'static>(self: &Arc<Self>, pool: P) {
        let mut arrivals = pool.new_transactions_listener_for(TransactionListenerKind::All);
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(event) = arrivals.recv().await {
                this.seen_at(
                    *event.transaction.hash(),
                    event.transaction.timestamp,
                    Now::current(),
                );
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
                    this.seen_at(*tx.hash(), tx.timestamp, Now::current());
                    if i % 64 == 63 {
                        tokio::task::yield_now().await;
                    }
                }
            }
        });
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let next = this
                    .sweep(
                        Now::current(),
                        16,
                        |hash| pool.get(hash).is_some(),
                        |hash| {
                            pool.remove_transactions(vec![hash]);
                        },
                    )
                    .unwrap_or(Instant::now() + Duration::from_secs(300));
                tokio::select! {_ = tokio::time::sleep_until(next.into())=>{},_ = this.notify.notified()=>{}}
                // A large simultaneous expiry must not monopolize this runtime worker/store lock.
                tokio::task::yield_now().await;
            }
        });
    }

    /// Follows the canonical chain: inclusions, reorganisations and finality (contract §6).
    pub fn follow<P>(self: &Arc<Self>, provider: P)
    where
        P: CanonStateSubscriptions<Primitives = EthPrimitives>
            + ForkChoiceSubscriptions<Header: AlloyBlockHeader>
            + 'static,
    {
        let mut canonical = provider.subscribe_to_canonical_state();
        let mut finalized = provider.subscribe_finalized_block().0;
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    note = canonical.recv() => match note {
                        Ok(note) => {
                            if let Some(old) = note.reverted() {
                                for block in old.blocks_iter() {
                                    this.reverted(block.number(), block.body().transactions().map(|tx| *tx.tx_hash()));
                                }
                            }
                            for block in note.committed().blocks_iter() {
                                this.included(block.number(), block.body().transactions().map(|tx| *tx.tx_hash()), Now::current());
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            // Missed inclusions leave approvals to their expiry; nothing is let through.
                            tracing::warn!(missed, "approval store missed canonical chain notifications");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    changed = finalized.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let number = finalized.borrow_and_update().as_ref().map(|h| h.number());
                        if let Some(number) = number {
                            this.finalized(number);
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_secs(5);
    const T0: u64 = 1_790_000_000_000;
    const TTL: u64 = 600_000;

    fn hash(n: u8) -> B256 {
        B256::with_last_byte(n)
    }
    fn approval(tx: u8, issued_at: u64) -> Approval {
        Approval {
            hash_mode: 3,
            chain_id: 31337,
            tx_hash: hash(tx),
            fingerprint: B256::ZERO,
            key_id: "default".into(),
            issued_at,
            expires_at: issued_at + TTL,
        }
    }
    /// A store booted at `boot` whose first `Status` call came right away, so wait windows count
    /// from pool admission.
    fn store(capacity: usize) -> (Store, Now) {
        let now = Now {
            at: Instant::now(),
            ms: T0,
        };
        let store = Store::new(WAIT, capacity, now.at);
        store.status_seen(now);
        (store, now)
    }
    fn later(now: Now, ms: u64) -> Now {
        Now {
            at: now.at + Duration::from_millis(ms),
            ms: now.ms + ms,
        }
    }
    fn fingerprint(store: &Store, tx: u8, now: Now) -> Option<B256> {
        store.usable(&hash(tx), now.ms).map(|a| a.fingerprint)
    }
    fn stored(store: &Store) -> usize {
        store
            .state
            .lock()
            .unwrap()
            .entries
            .values()
            .filter(|e| e.approval.is_some())
            .count()
    }
    /// Runs every timer due at `now`; returns the transactions dropped from the pool.
    fn sweep(store: &Store, now: Now, pool: &[u8]) -> Vec<B256> {
        let mut dropped = vec![];
        store.sweep(
            now,
            usize::MAX,
            |h| pool.iter().any(|n| hash(*n) == *h),
            |h| dropped.push(h),
        );
        dropped
    }

    #[test]
    fn a_batch_is_stored_all_or_nothing() {
        let (store, now) = store(2);
        let three = vec![approval(1, T0), approval(2, T0), approval(3, T0)];
        assert_eq!(store.put_batch(three, now), Err(Refusal::StoreFull));
        assert_eq!(stored(&store), 0);
        assert_eq!(
            store.put_batch(vec![approval(1, T0), approval(2, T0)], now),
            Ok(())
        );
        assert_eq!(stored(&store), 2);
        // Hashes that already hold an approval take no new slot.
        assert_eq!(
            store.put_batch(vec![approval(1, T0 + 1), approval(2, T0)], now),
            Ok(())
        );
    }

    #[test]
    fn pooled_transactions_waiting_for_an_approval_take_no_capacity() {
        let (store, now) = store(1);
        for tx in 1..=5 {
            store.seen_at(hash(tx), now.at, now);
        }
        assert_eq!(store.put_batch(vec![approval(9, T0)], now), Ok(()));
        assert_eq!(
            store.put_batch(vec![approval(1, T0)], now),
            Err(Refusal::StoreFull)
        );
        // A full store never ejects a pooled transaction.
        assert!(sweep(&store, later(now, 1_000), &[1, 2, 3, 4, 5]).is_empty());
    }

    #[test]
    fn room_is_counted_before_anything_is_evicted() {
        let (store, now) = store(2);
        store
            .put_batch(vec![approval(1, T0), approval(2, T0)], now)
            .unwrap();
        let now = later(now, 60_000);
        // Two old orphans could go, but three slots are needed: refuse and keep both.
        let three = vec![
            approval(3, now.ms),
            approval(4, now.ms),
            approval(5, now.ms),
        ];
        assert_eq!(store.put_batch(three, now), Err(Refusal::StoreFull));
        assert!(fingerprint(&store, 1, now).is_some() && fingerprint(&store, 2, now).is_some());
        assert_eq!(store.put_batch(vec![approval(3, now.ms)], now), Ok(()));
        assert_eq!(stored(&store), 2);
    }

    #[test]
    fn eviction_goes_expired_then_included_then_oldest_orphans_never_young_or_pooled() {
        let (store, now) = store(5);
        let short = Approval {
            expires_at: T0 + 10_000,
            ..approval(1, T0)
        };
        store
            .put_batch(
                vec![
                    short,
                    approval(2, T0 + 1),
                    approval(3, T0 + 2),
                    approval(4, T0 + 3),
                    approval(5, T0 + 4),
                ],
                now,
            )
            .unwrap();
        store.included(7, [hash(4)], now);
        store.seen_at(hash(5), now.at, now);
        let now = later(now, 30_000);
        let fresh = |tx| approval(tx, now.ms);
        // 1 has expired; 4 is included; 2 and 3 are orphans, 2 the older; 5 is pooled.
        store.put_batch(vec![fresh(11)], now).unwrap();
        assert!(!has(&store, 1));
        store.put_batch(vec![fresh(12)], now).unwrap();
        assert!(!has(&store, 4));
        store.put_batch(vec![fresh(13)], now).unwrap();
        assert!(!has(&store, 2) && has(&store, 3));
        store.put_batch(vec![fresh(14)], now).unwrap();
        assert!(!has(&store, 3));
        // Left: the pooled 5 and four approvals younger than the grace period (the wait window).
        assert_eq!(
            store.put_batch(vec![fresh(15)], now),
            Err(Refusal::StoreFull)
        );
        let now = later(now, WAIT.as_millis() as u64);
        store.put_batch(vec![approval(15, now.ms)], now).unwrap();
        assert!(has(&store, 5) && !has(&store, 11));
        assert_eq!(store.stats()["evicted_approvals"], 5);
    }
    fn has(store: &Store, tx: u8) -> bool {
        store
            .state
            .lock()
            .unwrap()
            .entries
            .get(&hash(tx))
            .is_some_and(|e| e.approval.is_some())
    }

    #[test]
    fn youth_counts_from_issued_at_so_a_replay_cannot_make_old_approvals_young() {
        let (store, now) = store(1);
        let now = later(now, 60_000);
        // Delivered just now, but issued a minute ago: old, so it may go for a fresh one.
        store.put_batch(vec![approval(1, T0)], now).unwrap();
        assert_eq!(store.put_batch(vec![approval(2, now.ms)], now), Ok(()));
        assert!(fingerprint(&store, 1, now).is_none());
    }

    #[test]
    fn the_greatest_issued_at_key_id_and_fingerprint_wins_in_any_order() {
        let a = |issued: u64, key: &str, fp: u8| Approval {
            key_id: key.into(),
            fingerprint: B256::with_last_byte(fp),
            ..approval(1, issued)
        };
        let batches = [
            a(T0, "default", 9),
            a(T0 + 1, "a", 1),
            a(T0 + 1, "b", 1),
            a(T0 + 1, "b", 2),
            a(T0 + 1, "ab", 7),
        ];
        let expected = B256::with_last_byte(2);
        for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [3, 0, 4, 2, 1]] {
            let (store, now) = store(4);
            for i in order {
                assert_eq!(store.put_batch(vec![batches[i].clone()], now), Ok(()));
            }
            assert_eq!(fingerprint(&store, 1, now), Some(expected), "{order:?}");
            // Re-delivering the stored approval is a no-op OK.
            assert_eq!(store.put_batch(vec![batches[3].clone()], now), Ok(()));
            assert_eq!(fingerprint(&store, 1, now), Some(expected));
        }
    }

    #[test]
    fn a_late_approval_is_stored_and_never_fails_its_batch() {
        let (store, now) = store(4);
        store.seen_at(hash(1), now.at, now);
        store.seen_at(hash(2), now.at, now);
        let now = later(now, WAIT.as_millis() as u64 + 1);
        // One timer runs: 1 is dropped by the timeout; 2's wait is over but not yet swept.
        let mut dropped = vec![];
        store.sweep(now, 1, |_| true, |h| dropped.push(h));
        assert_eq!(dropped, vec![hash(1)]);
        let batch = vec![
            approval(1, now.ms),
            approval(2, now.ms),
            approval(3, now.ms),
        ];
        assert_eq!(store.put_batch(batch, now), Ok(()));
        assert!(fingerprint(&store, 1, now).is_some());
        assert!(fingerprint(&store, 2, now).is_some());
        // Stored, the late approval keeps its transaction.
        assert!(sweep(&store, later(now, 1), &[1, 2]).is_empty());
    }

    #[test]
    fn an_expired_approval_is_absent_at_the_gate_and_evicted() {
        let (store, now) = store(4);
        store.put_batch(vec![approval(1, T0)], now).unwrap();
        assert!(store.usable(&hash(1), T0 + TTL - 1).is_some());
        assert!(store.usable(&hash(1), T0 + TTL).is_none());
        assert!(sweep(&store, later(now, TTL), &[]).is_empty());
        assert!(!store.state.lock().unwrap().entries.contains_key(&hash(1)));
        assert_eq!(store.stats()["expired_approvals"], 1);
    }

    #[test]
    fn a_pooled_transaction_whose_approval_expires_waits_out_its_window() {
        let (store, now) = store(4);
        let short = |tx, issued| Approval {
            expires_at: issued + 1_000,
            ..approval(tx, issued)
        };
        store
            .put_batch(vec![short(1, T0), short(2, T0)], now)
            .unwrap();
        // 1 has been pooled for longer than the wait window when its approval expires: dropped.
        store.seen_at(hash(1), now.at, now);
        let expiry = later(now, 1_000);
        // 2 arrived just before; it keeps waiting for a fresh approval.
        store.seen_at(hash(2), later(now, 900).at, later(now, 900));
        let dropped = sweep(&store, later(now, WAIT.as_millis() as u64 + 1), &[1, 2]);
        assert_eq!(dropped, vec![hash(1)]);
        assert!(store.usable(&hash(2), expiry.ms).is_none());
        store
            .put_batch(vec![approval(2, expiry.ms)], expiry)
            .unwrap();
        assert!(sweep(&store, later(now, WAIT.as_millis() as u64 + 950), &[2]).is_empty());
        assert!(store.usable(&hash(2), expiry.ms).is_some());
    }

    #[test]
    fn included_approvals_stay_until_final_and_survive_a_reorg() {
        let (store, now) = store(4);
        store
            .put_batch(vec![approval(1, T0), approval(2, T0)], now)
            .unwrap();
        store.seen_at(hash(1), now.at, now);
        store.included(5, [hash(1)], now);
        store.finalized(4);
        assert!(fingerprint(&store, 1, now).is_some());
        // The block is reorganised away; the transaction returns to the pool and is included
        // again with the approval it already had.
        store.reverted(5, [hash(1)]);
        store.seen_at(hash(1), now.at, now);
        store.included(6, [hash(1)], now);
        store.finalized(5);
        assert!(fingerprint(&store, 1, now).is_some());
        store.finalized(6);
        assert!(fingerprint(&store, 1, now).is_none());
        // Inclusion in a block that is already final releases at once.
        store.included(6, [hash(2)], now);
        assert!(fingerprint(&store, 2, now).is_none());
        assert_eq!(store.stats()["released_on_finality"], 2);
    }

    #[test]
    fn after_boot_wait_windows_start_at_the_first_status_call_for_at_most_a_minute() {
        let now = Now {
            at: Instant::now(),
            ms: T0,
        };
        let wait = WAIT.as_millis() as u64;
        let store = Store::new(WAIT, 4, now.at);
        // Re-announced right after boot, before OPS has reconnected.
        store.seen_at(hash(1), later(now, 100).at, later(now, 100));
        assert!(sweep(&store, later(now, 100 + wait + 1_000), &[1]).is_empty());
        // OPS calls Status 8 s after boot: the window runs from there.
        store.status_seen(later(now, 8_000));
        assert!(sweep(&store, later(now, 8_000 + wait - 1), &[1]).is_empty());
        assert_eq!(sweep(&store, later(now, 8_000 + wait), &[1]), vec![hash(1)]);
        // Later Status calls change nothing; later arrivals wait from their own admission.
        store.status_seen(later(now, 20_000));
        store.seen_at(hash(2), later(now, 21_000).at, later(now, 21_000));
        assert_eq!(
            sweep(&store, later(now, 21_000 + wait), &[2]),
            vec![hash(2)]
        );

        // With no Status call at all, the extension ends a minute after boot.
        let store = Store::new(WAIT, 4, now.at);
        store.seen_at(hash(3), later(now, 100).at, later(now, 100));
        assert!(sweep(&store, later(now, 60_000 + wait - 1), &[3]).is_empty());
        assert_eq!(
            sweep(&store, later(now, 60_000 + wait), &[3]),
            vec![hash(3)]
        );
    }

    #[test]
    fn early_approval_is_rechecked_promptly_after_transaction_arrives() {
        let (store, now) = store(2);
        store.put_batch(vec![approval(1, T0)], now).unwrap();
        store.seen_at(hash(1), now.at, now);
        let deadline = store.state.lock().unwrap().entries[&hash(1)].deadline;
        assert!(deadline <= now.at + Duration::from_secs(2));
        store.seen_at(hash(1), now.at, now);
        let state = store.state.lock().unwrap();
        assert_eq!(state.entries[&hash(1)].deadline, deadline);
        assert_eq!(
            state.deadlines.len(),
            1,
            "old residence timer must be removed"
        );
    }

    #[test]
    fn a_re_announcement_does_not_prolong_a_wait() {
        let (store, now) = store(1);
        store.seen_at(hash(1), now.at, now);
        let first = store.state.lock().unwrap().entries[&hash(1)].deadline;
        store.seen_at(hash(1), later(now, 2_000).at, later(now, 2_000));
        assert_eq!(
            first,
            store.state.lock().unwrap().entries[&hash(1)].deadline
        );
    }

    #[test]
    fn an_approval_whose_transaction_leaves_the_pool_unincluded_stays_until_it_expires() {
        let (store, now) = store(2);
        store.put_batch(vec![approval(1, T0)], now).unwrap();
        store.seen_at(hash(1), now.at, now);
        assert!(sweep(&store, later(now, 1_000), &[]).is_empty());
        assert!(fingerprint(&store, 1, later(now, 1_000)).is_some());
        // Re-announced later, it is usable at once.
        store.seen_at(hash(1), later(now, 2_000).at, later(now, 2_000));
        assert!(fingerprint(&store, 1, later(now, 2_000)).is_some());
    }
}
