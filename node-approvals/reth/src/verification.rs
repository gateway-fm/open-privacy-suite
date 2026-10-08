//! Bounded dedicated CPU workers for delivered batches: no curve arithmetic on Tokio networking
//! workers or the EVM/payload thread. A full queue makes the call wait — its deadline bounds that —
//! rather than refusing a batch the contract would accept.
use crate::batch::Refusal;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

pub struct Input {
    pub bytes: Vec<u8>,
    /// Hop timestamp of the call's arrival, when hops are recorded.
    pub received: u64,
}

pub type Outcome = Result<u32, Refusal>;

struct Job {
    input: Input,
    done: oneshot::Sender<Outcome>,
}

#[derive(Clone)]
pub struct Verifier {
    jobs: mpsc::Sender<Job>,
}
impl Verifier {
    pub fn spawn(
        workers: usize,
        queue: usize,
        check: impl Fn(Input) -> Outcome + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        if !(1..=32).contains(&workers) || queue == 0 {
            return Err(std::io::Error::other(
                "verification workers must be 1..32 and the queue non-empty",
            ));
        }
        let (jobs, receiver) = mpsc::channel::<Job>(queue);
        let receiver = Arc::new(Mutex::new(receiver));
        let check = Arc::new(check);
        for i in 0..workers {
            let receiver = receiver.clone();
            let check = check.clone();
            std::thread::Builder::new()
                .name(format!("ops-verify-{i}"))
                .spawn(move || {
                    loop {
                        // The receiver lock is released before parsing, crypto or store access.
                        let job = receiver.lock().unwrap().blocking_recv();
                        let Some(job) = job else {
                            break;
                        };
                        // A caller that gave up (deadline passed) still gets its batch stored:
                        // delivery is idempotent, so the retry finds it.
                        let _ = job.done.send(check(job.input));
                    }
                })?;
        }
        Ok(Self { jobs })
    }

    /// Runs the check on a worker, waiting for queue room. `None` once the workers are gone.
    pub async fn run(&self, input: Input) -> Option<Outcome> {
        let (done, outcome) = oneshot::channel();
        self.jobs.send(Job { input, done }).await.ok()?;
        outcome.await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Condvar,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    /// A check that blocks on input `[0]` until the gate opens.
    fn gated(
        gate: Arc<(Mutex<bool>, Condvar)>,
        entered: Arc<AtomicBool>,
    ) -> impl Fn(Input) -> Outcome + Send + Sync + 'static {
        move |input| {
            assert!(
                std::thread::current()
                    .name()
                    .unwrap()
                    .starts_with("ops-verify-")
            );
            if input.bytes == [0] {
                entered.store(true, Ordering::Release);
                let (lock, cv) = &*gate;
                let _guard = cv.wait_while(lock.lock().unwrap(), |open| !*open).unwrap();
            }
            Ok(input.bytes[0].into())
        }
    }
    fn input(byte: u8) -> Input {
        Input {
            bytes: vec![byte],
            received: 0,
        }
    }
    async fn entered(flag: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !flag.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn open(gate: &(Mutex<bool>, Condvar)) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_busy_worker_blocks_neither_the_runtime_nor_the_other_worker() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = Arc::new(AtomicBool::new(false));
        let pool = Verifier::spawn(2, 4, gated(gate.clone(), flag.clone())).unwrap();
        let p = pool.clone();
        let busy = tokio::spawn(async move { p.run(input(0)).await });
        entered(&flag).await;
        let ready = tokio::time::timeout(Duration::from_secs(1), pool.run(input(1))).await;
        open(&gate);
        assert_eq!(ready.unwrap(), Some(Ok(1)));
        assert_eq!(busy.await.unwrap(), Some(Ok(0)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_full_queue_makes_the_caller_wait_instead_of_refusing() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = Arc::new(AtomicBool::new(false));
        let pool = Verifier::spawn(1, 1, gated(gate.clone(), flag.clone())).unwrap();
        let calls: Vec<_> = (0..3)
            .map(|b| {
                let p = pool.clone();
                tokio::spawn(async move { p.run(input(b)).await })
            })
            .collect();
        entered(&flag).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(calls.iter().all(|c| !c.is_finished()), "nothing is refused");
        open(&gate);
        for (b, call) in calls.into_iter().enumerate() {
            assert_eq!(call.await.unwrap(), Some(Ok(b as u32)));
        }
    }
}
