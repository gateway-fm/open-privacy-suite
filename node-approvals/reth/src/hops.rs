//! Opt-in, bounded diagnostics. Same-host Unix timestamps, not protocol fields.
use alloy_primitives::B256;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct Stages {
    pub received: u64,
    pub worker_start: u64,
    pub parsed: u64,
    pub verified: u64,
    pub published: u64,
    pub pool_inserted: u64,
}
#[derive(Debug)]
pub struct Hops {
    path: String,
    rows: Mutex<HashMap<B256, Stages>>,
}
impl Hops {
    pub fn from_env() -> Option<Self> {
        std::env::var("OPS_APPROVAL_HOPS_FILE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|path| Self {
                path,
                rows: Mutex::default(),
            })
    }
    pub fn arrival(&self, hash: B256, arrived: Instant) {
        let epoch = now()
            .saturating_sub(Instant::now().saturating_duration_since(arrived).as_nanos() as u64);
        let mut rows = self.rows.lock().unwrap();
        if rows.len() >= 8192 && !rows.contains_key(&hash) {
            return;
        }
        let r = rows.entry(hash).or_default();
        if r.pool_inserted == 0 {
            r.pool_inserted = epoch;
        }
    }
    pub fn approval(&self, hash: B256, stages: Stages) {
        let mut rows = self.rows.lock().unwrap();
        if rows.len() >= 8192 && !rows.contains_key(&hash) {
            return;
        }
        let r = rows.entry(hash).or_default();
        *r = Stages {
            pool_inserted: r.pool_inserted,
            ..stages
        };
    }
    // Called after payload timing, when the test driver requests the block.
    pub fn flush(&self) {
        let rows = self.rows.lock().unwrap();
        if let Ok(data) = serde_json::to_vec(&*rows) {
            let _ = std::fs::write(&self.path, data);
        }
    }
}
