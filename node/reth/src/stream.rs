//! Authenticated atomic fact stream. A heartbeat changes only the freshness lease;
//! all handles already pinned by an execution remain immutable.

use crate::{
    archive::{ArtifactId, ArtifactStore},
    wire::{
        Delta, Header, Heartbeat, Sanction, Snapshot, Verifier, decode_strict, hex_digest,
        validate_snapshot,
    },
};
use alloy_primitives::{B256, hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
};

const MAX_CHAIN_BYTES: usize = 256 << 20;
const MAX_CHAIN_RECORDS: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    format_version: u32,
    facts_version: u64,
    facts_digest: B256,
    records: Vec<ArchivedRecord>,
    heartbeat: Option<ArtifactId>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivedRecord {
    kind: String,
    envelope: ArtifactId,
}

#[derive(Clone, Debug)]
pub(crate) struct RecordedEnvelope {
    pub kind: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AppliedFacts {
    snapshot: Arc<Snapshot>,
    digest: B256,
    lease: Header,
    pub(crate) records: Vec<Arc<RecordedEnvelope>>,
    pub(crate) heartbeat: Option<Arc<RecordedEnvelope>>,
}

impl AppliedFacts {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn version(&self) -> u64 {
        self.snapshot.version
    }
    pub fn digest(&self) -> B256 {
        self.digest
    }
    pub fn expires_at(&self) -> i64 {
        self.lease.expires_at
    }

    pub fn checkpoint(&self, store: &ArtifactStore) -> Result<ArtifactId, String> {
        let records = self
            .records
            .iter()
            .map(|record| {
                Ok(ArchivedRecord {
                    kind: record.kind.clone(),
                    envelope: store.put(&record.bytes)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let heartbeat = self
            .heartbeat
            .as_ref()
            .map(|record| store.put(&record.bytes))
            .transpose()?;
        let checkpoint = Checkpoint {
            format_version: 1,
            facts_version: self.version(),
            facts_digest: self.digest,
            records,
            heartbeat,
        };
        store.put(&serde_json::to_vec(&checkpoint).map_err(|_| "invalid policy checkpoint")?)
    }
}

#[derive(Debug)]
pub struct FactStream {
    verifier: Verifier,
    current: Mutex<Option<Arc<AppliedFacts>>>,
}

impl FactStream {
    pub fn new(verifier: Verifier) -> Self {
        Self {
            verifier,
            current: Mutex::new(None),
        }
    }

    /// Reverify archived signatures and the entire linked stream. `at` is the
    /// current time for startup, or the exact block timestamp for trusted replay.
    /// Restoring an expired chain never grants a new lease.
    pub fn restore(
        verifier: Verifier,
        store: &ArtifactStore,
        checkpoint: ArtifactId,
        at: i64,
    ) -> Result<Self, String> {
        Self::restore_with_freshness(verifier, store, checkpoint, at, true)
    }

    pub(crate) fn restore_retained(
        verifier: Verifier,
        store: &ArtifactStore,
        checkpoint: ArtifactId,
        at: i64,
    ) -> Result<Self, String> {
        Self::restore_with_freshness(verifier, store, checkpoint, at, false)
    }

    fn restore_with_freshness(
        verifier: Verifier,
        store: &ArtifactStore,
        checkpoint: ArtifactId,
        at: i64,
        require_fresh: bool,
    ) -> Result<Self, String> {
        let checkpoint: Checkpoint = decode_strict(&store.get(checkpoint)?)?;
        if checkpoint.format_version != 1
            || checkpoint.records.is_empty()
            || checkpoint.records.len() > MAX_CHAIN_RECORDS
        {
            return Err("invalid policy checkpoint".into());
        }
        let stream = Self::new(verifier);
        for (index, record) in checkpoint.records.iter().enumerate() {
            if record.kind != if index == 0 { "snapshot" } else { "delta" } {
                return Err("invalid checkpoint record order".into());
            }
            let bytes = store.get(record.envelope)?;
            stream.restore_record(&record.kind, &bytes, at)?;
        }
        if let Some(id) = checkpoint.heartbeat {
            stream.restore_record("heartbeat", &store.get(id)?, at)?;
        }
        let facts = stream.latest()?.ok_or("missing retained policy facts")?;
        if require_fresh {
            stream.verifier.validate_header(&facts.lease, at)?;
        }
        if facts.version() != checkpoint.facts_version || facts.digest() != checkpoint.facts_digest
        {
            return Err("policy checkpoint state mismatch".into());
        }
        Ok(stream)
    }

    fn restore_record(&self, kind: &str, wire: &[u8], at: i64) -> Result<(), String> {
        let payload = self.verifier.open(kind, wire)?;
        let value: serde_json::Value = decode_strict(&payload)?;
        let issued = value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .ok_or("invalid archived policy timestamp")?;
        if issued > at.saturating_add(5) {
            return Err("future archived policy facts".into());
        }
        self.accept(kind, wire, issued)?;
        Ok(())
    }

    pub fn pin(&self, now: i64, minimum_version: u64) -> Result<Arc<AppliedFacts>, String> {
        let current = self.current.lock().map_err(|_| "fact stream unavailable")?;
        let facts = current.as_ref().ok_or("missing policy facts")?;
        self.verifier.validate_header(&facts.lease, now)?;
        if facts.version() < minimum_version {
            return Err("policy facts are behind execution context".into());
        }
        Ok(facts.clone())
    }

    /// Watermark/status only; this does not authorize execution with expired facts.
    pub fn latest(&self) -> Result<Option<Arc<AppliedFacts>>, String> {
        Ok(self
            .current
            .lock()
            .map_err(|_| "fact stream unavailable")?
            .clone())
    }

    pub fn accept(
        &self,
        kind: &str,
        envelope: &[u8],
        now: i64,
    ) -> Result<Arc<AppliedFacts>, String> {
        let payload = self.verifier.open(kind, envelope)?;
        let digest = B256::from_slice(&Sha256::digest(&payload));
        let mut current = self.current.lock().map_err(|_| "fact stream unavailable")?;
        let record = Arc::new(RecordedEnvelope {
            kind: kind.into(),
            bytes: envelope.to_vec(),
        });
        let next = match kind {
            "snapshot" => {
                let snapshot: Snapshot = decode_strict(&payload)?;
                self.verifier.validate_header(&snapshot.header, now)?;
                validate_snapshot(&snapshot)?;
                if let Some(old) = current.as_ref() {
                    if snapshot.version == old.version() && digest == old.digest {
                        return Ok(old.clone());
                    }
                    if snapshot.version <= old.version() {
                        return Err("conflicting or stale policy snapshot".into());
                    }
                }
                self.verifier.validate_header(&snapshot.header, now)?;
                AppliedFacts {
                    lease: snapshot.header.clone(),
                    snapshot: Arc::new(snapshot),
                    digest,
                    records: vec![record],
                    heartbeat: None,
                }
            }
            "delta" => {
                let delta: Delta = decode_strict(&payload)?;
                self.verifier.validate_header(&delta.header, now)?;
                if delta.previous_version == 0
                    || delta.version <= delta.previous_version
                    || !hex_digest(&delta.previous_digest)
                {
                    return Err("invalid policy delta".into());
                }
                let old = current
                    .as_ref()
                    .ok_or("missing bootstrap policy snapshot")?;
                if delta.version == old.version() && digest == old.digest {
                    return Ok(old.clone());
                }
                if delta.previous_version != old.version()
                    || delta.previous_digest != hex::encode(old.digest)
                {
                    return Err("resynchronisation required: policy delta gap or conflict".into());
                }
                self.verifier.validate_header(&delta.header, now)?;
                if old.records.len() >= MAX_CHAIN_RECORDS
                    || old.records.iter().map(|r| r.bytes.len()).sum::<usize>() + envelope.len()
                        > MAX_CHAIN_BYTES
                {
                    return Err("resynchronisation required: policy checkpoint limit".into());
                }
                let snapshot = apply_delta(old.snapshot(), &delta)?;
                let mut records = old.records.clone();
                records.push(record);
                AppliedFacts {
                    lease: delta.header,
                    snapshot: Arc::new(snapshot),
                    digest,
                    records,
                    heartbeat: None,
                }
            }
            "heartbeat" => {
                let heartbeat: Heartbeat = decode_strict(&payload)?;
                self.verifier.validate_header(&heartbeat.header, now)?;
                let old = current
                    .as_ref()
                    .ok_or("missing bootstrap policy snapshot")?;
                if heartbeat.version != old.version() || heartbeat.digest != hex::encode(old.digest)
                {
                    return Err("policy heartbeat state mismatch".into());
                }
                if heartbeat.header.issued_at < old.lease.issued_at
                    || heartbeat.header.expires_at < old.lease.expires_at
                {
                    return Err("stale policy heartbeat".into());
                }
                if heartbeat.header.expires_at == old.lease.expires_at
                    && heartbeat.header.issued_at == old.lease.issued_at
                {
                    return Ok(old.clone());
                }
                AppliedFacts {
                    lease: heartbeat.header,
                    heartbeat: Some(record),
                    ..old.as_ref().clone()
                }
            }
            _ => return Err("unexpected policy fact message kind".into()),
        };
        let next = Arc::new(next);
        *current = Some(next.clone());
        Ok(next)
    }
}

fn apply_delta(previous: &Snapshot, delta: &Delta) -> Result<Snapshot, String> {
    let mut next = previous.clone();
    update_rows(
        &mut next.principals,
        &delta.upserts.principals,
        &delta.deletes.principals,
        |p| p.id.clone(),
    )?;
    update_rows(
        &mut next.groups,
        &delta.upserts.groups,
        &delta.deletes.groups,
        |g| g.id.clone(),
    )?;
    update_rows(
        &mut next.contracts,
        &delta.upserts.contracts,
        &delta.deletes.contracts,
        |c| c.address.clone(),
    )?;
    update_rows(
        &mut next.policies,
        &delta.upserts.policies,
        &delta.deletes.policies,
        |p| {
            if p.group_id.is_empty() {
                p.org_id.clone()
            } else {
                format!("{}\0{}", p.org_id, p.group_id)
            }
        },
    )?;
    let deleted_sanctions = delta
        .deletes
        .sanctions
        .iter()
        .map(sanction_key)
        .collect::<Vec<_>>();
    update_rows(
        &mut next.sanctions,
        &delta.upserts.sanctions,
        &deleted_sanctions,
        sanction_key,
    )?;
    next.version = delta.version;
    next.header = delta.header.clone();
    validate_snapshot(&next)?;
    Ok(next)
}

fn sanction_key(sanction: &Sanction) -> String {
    format!("{}\0{}", sanction.org_id, sanction.address)
}

fn update_rows<T: Clone>(
    rows: &mut Vec<T>,
    upserts: &[T],
    deletes: &[String],
    key: impl Fn(&T) -> String,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    let mut indexed: BTreeMap<String, T> = rows.iter().map(|row| (key(row), row.clone())).collect();
    for row in upserts {
        let id = key(row);
        if !seen.insert(id.clone()) {
            return Err("duplicate policy delta key".into());
        }
        indexed.insert(id, row.clone());
    }
    for id in deletes {
        if !seen.insert(id.clone()) || indexed.remove(id).is_none() {
            return Err("conflicting or missing policy delta key".into());
        }
    }
    *rows = indexed.into_values().collect();
    Ok(())
}
