//! Bounded dedicated CPU workers. No curve arithmetic or JSON decoding on Tokio
//! networking workers or the EVM/payload thread. Preserve order within each connection.
use crate::{approvals::Store, batch::Packet};
use ed25519_dalek::VerifyingKey;
use std::{
    sync::{Arc, Mutex, mpsc},
    time::Instant,
};
use tokio::sync::oneshot;

struct Job {
    input: Input,
    completed: oneshot::Sender<()>,
}

struct Input {
    bytes: Vec<u8>,
    received: u64,
}

#[derive(Clone)]
pub struct Verifier {
    queue: Option<mpsc::SyncSender<Job>>,
    handle: Arc<dyn Fn(Input) + Send + Sync>,
    profile: bool,
}
impl Verifier {
    pub fn new(
        store: Arc<Store>,
        key: VerifyingKey,
        chain: u64,
        workers: usize,
        capacity: usize,
        direct: bool,
    ) -> std::io::Result<Self> {
        let profile = store.hops.is_some();
        let handle = move |input: Input| {
            let mut stages = crate::hops::Stages {
                received: input.received,
                worker_start: if profile { crate::hops::now() } else { 0 },
                ..Default::default()
            };
            let Ok(incoming) = Packet::decode(&input.bytes) else {
                store.invalid_envelope();
                return;
            };
            if profile {
                stages.parsed = crate::hops::now();
            }
            let start = Instant::now();
            match incoming.verify(&key, chain) {
                Ok(approvals) => {
                    let elapsed = start.elapsed();
                    if profile {
                        stages.verified = crate::hops::now();
                    }
                    store.verified_batch(approvals, elapsed, stages)
                }
                Err(_) => store.invalid_envelope(),
            }
        };
        let mut pool = if direct {
            Self {
                queue: None,
                profile,
                handle: Arc::new(handle),
            }
        } else {
            Self::spawn(workers, capacity, handle)?
        };
        pool.profile = profile;
        Ok(pool)
    }

    fn spawn(
        workers: usize,
        capacity: usize,
        handle: impl Fn(Input) + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        if !(1..=32).contains(&workers) || !(1..=4096).contains(&capacity) {
            return Err(std::io::Error::other(
                "verification workers must be 1..32 and queue capacity 1..4096",
            ));
        }
        let (queue, receiver) = mpsc::sync_channel::<Job>(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let handle = Arc::new(handle);
        for i in 0..workers {
            let receiver = receiver.clone();
            let handle = handle.clone();
            std::thread::Builder::new()
                .name(format!("ops-verify-{i}"))
                .spawn(move || {
                    loop {
                        // The receiver lock is released before parsing, crypto or store access.
                        let job = receiver.lock().unwrap().recv();
                        let Ok(job) = job else {
                            break;
                        };
                        handle(job.input);
                        let _ = job.completed.send(());
                    }
                })?;
        }
        Ok(Self {
            queue: Some(queue),
            handle,
            profile: false,
        })
    }

    pub fn is_direct(&self) -> bool {
        self.queue.is_none()
    }
    pub fn verify_on_receiver(&self, bytes: Vec<u8>) {
        (self.handle)(Input {
            bytes,
            received: if self.profile { crate::hops::now() } else { 0 },
        });
    }

    /// Nonblocking admission. Full queue fails closed; completion is internal
    /// coordination only, never an ACK to OPS.
    pub fn submit(&self, bytes: Vec<u8>) -> Option<oneshot::Receiver<()>> {
        let (completed, wait) = oneshot::channel();
        let input = Input {
            bytes,
            received: if self.profile { crate::hops::now() } else { 0 },
        };
        self.queue
            .as_ref()?
            .try_send(Job { input, completed })
            .ok()?;
        Some(wait)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Condvar,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test(flavor = "current_thread")]
    async fn busy_cpu_worker_does_not_block_runtime_or_other_worker() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let entered = Arc::new(AtomicBool::new(false));
        let g = gate.clone();
        let e = entered.clone();
        let pool = Verifier::spawn(2, 4, move |bytes| {
            assert!(
                std::thread::current()
                    .name()
                    .unwrap()
                    .starts_with("ops-verify-")
            );
            if bytes.bytes == [0] {
                e.store(true, Ordering::Release);
                let (lock, cv) = &*g;
                let _guard = cv.wait_while(lock.lock().unwrap(), |open| !*open).unwrap();
            }
        })
        .unwrap();
        let busy = pool.submit(vec![0]).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let ready = pool.submit(vec![1]).unwrap();
        let ready_result = tokio::time::timeout(std::time::Duration::from_secs(1), ready).await;
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        ready_result.unwrap().unwrap();
        busy.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_queue_rejects_without_waiting() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let entered = Arc::new(AtomicBool::new(false));
        let g = gate.clone();
        let e = entered.clone();
        let pool = Verifier::spawn(1, 1, move |bytes| {
            if bytes.bytes == [0] {
                e.store(true, Ordering::Release);
                let (lock, cv) = &*g;
                let _guard = cv.wait_while(lock.lock().unwrap(), |open| !*open).unwrap();
            }
        })
        .unwrap();
        let busy = pool.submit(vec![0]).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let queued = pool.submit(vec![1]);
        let rejected = pool.submit(vec![2]).is_none();
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(rejected);
        busy.await.unwrap();
        queued.unwrap().await.unwrap();
    }
}
