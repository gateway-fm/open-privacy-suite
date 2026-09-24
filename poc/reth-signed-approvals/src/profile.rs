//! Opt-in stage instrumentation. Disabled for throughput comparisons.
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

pub const NAMES: [&str; 11] = [
    "selection_and_reset",
    "evm_with_inspector",
    "geth_call_frames",
    "geth_prestate",
    "geth_diff",
    "reports_to_json_values",
    "canonical_json_tree",
    "encode_canonical_json",
    "keccak",
    "drop_reports",
    "direct_fingerprint",
];
#[derive(Debug, Default, Serialize)]
pub struct Stages {
    pub transactions: u64,
    pub ns: [u64; 11],
}
pub type Shared = Arc<Mutex<Stages>>;
pub struct Timer {
    last: Option<Instant>,
    ns: [u64; 11],
}
impl Timer {
    pub fn new(enabled: bool) -> Self {
        Self {
            last: enabled.then(Instant::now),
            ns: [0; 11],
        }
    }
    pub fn lap(&mut self, index: usize) {
        if let Some(last) = self.last {
            let now = Instant::now();
            self.ns[index] += now.duration_since(last).as_nanos() as u64;
            self.last = Some(now);
        }
    }
    pub fn record(self, shared: &Option<Shared>) {
        if let Some(s) = shared {
            let mut s = s.lock().unwrap();
            s.transactions += 1;
            for (total, n) in s.ns.iter_mut().zip(self.ns) {
                *total += n;
            }
        }
    }
}
pub fn report(s: &Shared) -> serde_json::Value {
    let s = s.lock().unwrap();
    let stages: std::collections::BTreeMap<_, _> = NAMES.into_iter().zip(s.ns).collect();
    serde_json::json!({"transactions":s.transactions,"stage_ns":stages})
}
