//! Explicit execution handles tie policy facts and the exact identity evidence to
//! each candidate block. Replay handles are built only from exact block manifests.

use crate::{
    archive::{ArtifactStore, BlockDescriptor, BlockManifest, BoundIdentity},
    context::{
        CreatedContract, ExecutionBinding, ExecutionIdentity, ExecutionOutcome, IdentityResolver,
        PinnedPolicySnapshot,
    },
    facts::FactsPolicy,
    identity::{CapturedIdentity, IdentityRegistry},
    policy::{DiagnosticReport, PolicyFactory},
    stream::{AppliedFacts, FactStream},
    wire::{Identity, Network, PolicyArtifact, Verifier},
};
use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub struct PolicyRuntime {
    pub feed: Arc<FactStream>,
    pub identities: Arc<IdentityRegistry>,
    pub archive: Arc<ArtifactStore>,
    verifier: Verifier,
    ingestion: Mutex<()>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    pub status: String,
    pub facts_version: u64,
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub reason_code: String,
    pub created: Vec<CreatedContract>,
    pub finalized: bool,
    pub finalized_block_hash: Option<B256>,
    pub finalized_block_number: Option<u64>,
}

impl TransactionStatus {
    /// Evidence comes from the node's canonical forkchoice provider, never a
    /// receipt or a locally counted number of confirmations alone.
    pub fn observe_finality(&mut self, canonical_hash: B256, number: u64, hash: B256) {
        self.finalized = matches!(self.status.as_str(), "included" | "reverted")
            && self.block_hash == Some(canonical_hash)
            && self.block_number.is_some_and(|included| {
                included <= number && (included != number || self.block_hash == Some(hash))
            });
        self.finalized_block_hash = self.finalized.then_some(hash);
        self.finalized_block_number = self.finalized.then_some(number);
    }
}

impl PolicyRuntime {
    pub fn new(verifier: Verifier, archive: Arc<ArtifactStore>, capacity: usize) -> Self {
        Self {
            feed: Arc::new(FactStream::new(verifier.clone())),
            identities: Arc::new(IdentityRegistry::new(verifier.clone(), capacity)),
            archive,
            verifier,
            ingestion: Mutex::new(()),
        }
    }
    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    /// Restore retained facts and pending transaction bindings. Expired facts are
    /// retained for stream continuity/status but `pin_candidate` still rejects.
    pub fn open(
        verifier: Verifier,
        archive: Arc<ArtifactStore>,
        capacity: usize,
        now: i64,
    ) -> Result<Self, String> {
        let mut runtime = Self::new(verifier.clone(), archive, capacity);
        if let Some(checkpoint) = runtime.archive.pointer("facts-head")? {
            runtime.feed = Arc::new(FactStream::restore_retained(
                verifier.clone(),
                &runtime.archive,
                checkpoint,
                now,
            )?);
        }
        for id in runtime.archive.pointers("tx-")? {
            let envelope = runtime.archive.get(id)?;
            let payload = verifier.open("identity", &envelope)?;
            let value: serde_json::Value = crate::wire::decode_strict(&payload)?;
            let issued = value
                .get("issued_at")
                .and_then(|v| v.as_i64())
                .ok_or("invalid retained execution identity")?;
            let identity = verifier.open_identity(&envelope, issued)?;
            if identity.scope != "transaction" {
                return Err("invalid retained execution identity scope".into());
            }
            if identity.header.expires_at > now
                && runtime
                    .archive
                    .pointer(&format!("terminal-{}", &identity.binding_hash[2..]))?
                    .is_none()
            {
                runtime.identities.accept(&envelope, issued)?;
            }
        }
        Ok(runtime)
    }
    pub fn network(&self) -> &Network {
        self.verifier.network()
    }

    /// Status lookup authenticates retained identity evidence, but deliberately
    /// does not renew its execution lease or confer historical execution rights.
    pub fn retained_identity(&self, hash: B256) -> Result<Identity, String> {
        let id = self
            .archive
            .pointer(&format!("tx-{}", alloy_primitives::hex::encode(hash)))?
            .ok_or("unknown execution identity")?;
        let envelope = self.archive.get(id)?;
        let payload = self.verifier.open("identity", &envelope)?;
        let value: serde_json::Value = crate::wire::decode_strict(&payload)?;
        let issued = value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .ok_or("invalid retained identity")?;
        let identity = self.verifier.open_identity(&envelope, issued)?;
        if identity.scope != "transaction" || identity.binding_hash != format!("{hash:#x}") {
            return Err("retained identity mismatch".into());
        }
        Ok(identity)
    }

    pub fn transaction_status(
        &self,
        hash: B256,
        canonical_block: Option<B256>,
    ) -> Result<Option<TransactionStatus>, String> {
        let key = match canonical_block {
            Some(block) => format!(
                "included-{}-{}",
                alloy_primitives::hex::encode(hash),
                alloy_primitives::hex::encode(block)
            ),
            None => format!("status-{}", alloy_primitives::hex::encode(hash)),
        };
        self.archive
            .pointer(&key)?
            .map(|id| crate::wire::decode_strict(&self.archive.get(id)?))
            .transpose()
    }

    pub fn accept_facts(
        &self,
        kind: &str,
        wire: &[u8],
        now: i64,
    ) -> Result<Arc<AppliedFacts>, String> {
        let _guard = self
            .ingestion
            .lock()
            .map_err(|_| "policy ingestion unavailable")?;
        let facts = self.feed.accept(kind, wire, now)?;
        let checkpoint = facts.checkpoint(&self.archive)?;
        self.archive.set_pointer("facts-head", checkpoint)?;
        Ok(facts)
    }

    pub fn accept_identity(&self, wire: &[u8], now: i64) -> Result<Identity, String> {
        let _guard = self
            .ingestion
            .lock()
            .map_err(|_| "policy ingestion unavailable")?;
        let proposed = self.verifier.open_identity(wire, now)?;
        if proposed.scope == "transaction"
            && self
                .archive
                .pointer(&format!("tx-{}", &proposed.binding_hash[2..]))?
                .is_some()
        {
            let old = self.retained_identity(
                proposed
                    .binding_hash
                    .parse()
                    .map_err(|_| "invalid transaction binding")?,
            )?;
            if old.principal_id != proposed.principal_id
                || old.org_id != proposed.org_id
                || old.signer != proposed.signer
                || old.header.issued_at > proposed.header.issued_at
                || old.header.expires_at > proposed.header.expires_at
                || old.min_snapshot_version > proposed.min_snapshot_version
            {
                return Err("durable execution binding conflict".into());
            }
        }
        self.identities.release_expired(now)?;
        let identity = self.identities.accept(wire, now)?;
        if identity.scope == "transaction" {
            let evidence = self.archive.put(wire)?;
            self.archive
                .set_pointer(&format!("tx-{}", &identity.binding_hash[2..]), evidence)?;
            // Explicit renewed admission can follow a reorg. A prior canonical
            // reconciliation must not suppress this new pending lease on restart.
            self.archive
                .remove_pointer(&format!("terminal-{}", &identity.binding_hash[2..]))?;
        }
        Ok(identity)
    }

    /// Called only after the backend observes a canonical receipt. The signed
    /// binding remains durable after the bounded pending slot is released.
    pub fn reconcile_included(&self, hash: B256, block: B256) -> Result<(), String> {
        let _guard = self
            .ingestion
            .lock()
            .map_err(|_| "policy ingestion unavailable")?;
        self.retained_identity(hash)?;
        self.transaction_status(hash, Some(block))?
            .ok_or("canonical execution evidence unavailable")?;
        let marker = self
            .archive
            .put(&serde_json::to_vec(&block).map_err(|_| "invalid inclusion marker")?)?;
        let key = format!("terminal-{}", alloy_primitives::hex::encode(hash));
        if self.archive.pointer(&key)? != Some(marker) {
            self.archive.set_pointer(&key, marker)?;
        }
        self.identities.finish(&ExecutionBinding::Transaction(hash))
    }

    pub fn pin_candidate(&self, at: i64) -> Result<Arc<ExecutionHandle>, String> {
        let facts = self.feed.pin(at, 1)?;
        let facts_version = facts.version();
        ExecutionHandle::new(
            facts,
            at,
            self.network().clone(),
            RecordingResolver {
                source: Some(self.identities.clone()),
                at,
                captured: Mutex::new(HashMap::new()),
                outcomes: Mutex::new(HashMap::new()),
                expected: None,
                archive: Some(self.archive.clone()),
                facts_version,
            },
        )
    }

    /// Identity has been authenticated by the private API. Freeze it before any
    /// asynchronous state lookup so request cleanup cannot affect concurrent work.
    pub fn pin_simulation(
        &self,
        identity: Identity,
        at: i64,
    ) -> Result<Arc<ExecutionHandle>, String> {
        self.verifier.validate_header(&identity.header, at)?;
        if identity.scope != "simulation" {
            return Err("invalid simulation identity scope".into());
        }
        let binding = ExecutionBinding::Simulation {
            digest: identity
                .binding_hash
                .parse()
                .map_err(|_| "invalid simulation digest")?,
            context_id: identity.context_id.clone(),
        };
        let facts = self.feed.pin(at, identity.min_snapshot_version)?;
        ExecutionHandle::new(
            facts,
            at,
            self.network().clone(),
            RecordingResolver {
                source: None,
                at,
                captured: Mutex::new(HashMap::from([(
                    binding,
                    CapturedIdentity {
                        identity,
                        envelope: Vec::new(),
                    },
                )])),
                outcomes: Mutex::new(HashMap::new()),
                expected: None,
                archive: None,
                facts_version: 0,
            },
        )
    }

    pub fn replay(&self, block: &BlockDescriptor) -> Result<Arc<ExecutionHandle>, String> {
        if &block.network != self.network() {
            return Err("execution replay network mismatch".into());
        }
        let at = i64::try_from(block.timestamp).map_err(|_| "invalid block timestamp")?;
        let manifest = self.archive.load_for_block(block)?;
        let restored = FactStream::restore(
            self.verifier.clone(),
            &self.archive,
            manifest.checkpoint,
            at,
        )?;
        let facts = restored.pin(at, manifest.facts_version)?;
        if facts.digest() != manifest.facts_digest || facts.version() != manifest.facts_version {
            return Err("execution replay facts mismatch".into());
        }
        let mut captured = HashMap::new();
        for entry in &manifest.identities {
            let envelope = self.archive.get(entry.envelope)?;
            let identity = self.verifier.open_identity(&envelope, at)?;
            if identity.scope != "transaction"
                || identity.binding_hash != format!("{:#x}", entry.transaction_hash)
            {
                return Err("execution replay identity mismatch".into());
            }
            captured.insert(
                ExecutionBinding::Transaction(entry.transaction_hash),
                CapturedIdentity { identity, envelope },
            );
        }
        ExecutionHandle::new(
            facts,
            at,
            block.network.clone(),
            RecordingResolver {
                source: None,
                at,
                captured: Mutex::new(captured),
                outcomes: Mutex::new(HashMap::new()),
                expected: Some(
                    manifest
                        .identities
                        .iter()
                        .map(|entry| {
                            (
                                ExecutionBinding::Transaction(entry.transaction_hash),
                                entry.outcome.clone(),
                            )
                        })
                        .collect(),
                ),
                archive: None,
                facts_version: manifest.facts_version,
            },
        )
    }
}

#[derive(Debug)]
pub struct ExecutionHandle {
    facts: Arc<AppliedFacts>,
    policy: Arc<PinnedPolicySnapshot>,
    identities: Arc<RecordingResolver>,
    network: Network,
    at: i64,
}

impl ExecutionHandle {
    fn new(
        facts: Arc<AppliedFacts>,
        at: i64,
        network: Network,
        identities: RecordingResolver,
    ) -> Result<Arc<Self>, String> {
        let adapter = FactsPolicy::new(facts.clone(), at)?;
        let policy = Arc::new(PinnedPolicySnapshot::new(
            facts.version(),
            facts.digest(),
            Arc::new(adapter),
        ));
        Ok(Arc::new(Self {
            facts,
            policy,
            identities: Arc::new(identities),
            network,
            at,
        }))
    }
    pub fn factory(&self) -> PolicyFactory {
        PolicyFactory::new(self.policy.clone(), self.identities.clone())
    }

    pub fn candidate_factory(
        &self,
        candidate: &PolicyArtifact,
        org: &str,
    ) -> Result<(PolicyFactory, Arc<DiagnosticReport>), String> {
        let adapter =
            FactsPolicy::new(self.facts.clone(), self.at)?.with_candidate(candidate, org)?;
        let snapshot = Arc::new(PinnedPolicySnapshot::new(
            self.facts.version(),
            self.facts.digest(),
            Arc::new(adapter),
        ));
        Ok(self.factory().candidate(snapshot))
    }

    pub fn candidate_set_factory(
        &self,
        candidates: &[PolicyArtifact],
        org: &str,
    ) -> Result<(PolicyFactory, Arc<DiagnosticReport>), String> {
        let adapter =
            FactsPolicy::new(self.facts.clone(), self.at)?.with_candidates(candidates, org)?;
        let snapshot = Arc::new(PinnedPolicySnapshot::new(
            self.facts.version(),
            self.facts.digest(),
            Arc::new(adapter),
        ));
        Ok(self.factory().candidate(snapshot))
    }

    pub fn persist(&self, archive: &ArtifactStore, block: &BlockDescriptor) -> Result<(), String> {
        if block.network != self.network || block.timestamp != self.at as u64 {
            return Err("produced block execution context mismatch".into());
        }
        let captured = self
            .identities
            .captured
            .lock()
            .map_err(|_| "execution identities unavailable")?;
        let outcomes = self
            .identities
            .outcomes
            .lock()
            .map_err(|_| "execution outcomes unavailable")?;
        let identities = block
            .transactions
            .iter()
            .map(|hash| {
                let identity = captured
                    .get(&ExecutionBinding::Transaction(*hash))
                    .ok_or("missing executed transaction identity")?;
                Ok(BoundIdentity {
                    transaction_hash: *hash,
                    envelope: archive.put(&identity.envelope)?,
                    outcome: outcomes
                        .get(&ExecutionBinding::Transaction(*hash))
                        .cloned()
                        .ok_or("missing executed transaction outcome")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let checkpoint = self.facts.checkpoint(archive)?;
        let manifest = BlockManifest {
            format_version: 1,
            block: block.clone(),
            facts_version: self.facts.version(),
            facts_digest: self.facts.digest(),
            checkpoint,
            identities,
        };
        archive.publish(&manifest)?;
        for entry in &manifest.identities {
            let status = TransactionStatus {
                status: "produced".into(),
                facts_version: self.facts.version(),
                block_hash: Some(block.hash),
                block_number: Some(block.number),
                reason_code: entry.outcome.reason_code.clone(),
                created: entry.outcome.created.clone(),
                finalized: false,
                finalized_block_hash: None,
                finalized_block_number: None,
            };
            let id = archive
                .put(&serde_json::to_vec(&status).map_err(|_| "invalid execution status")?)?;
            archive.set_pointer(
                &format!(
                    "included-{}-{}",
                    alloy_primitives::hex::encode(entry.transaction_hash),
                    alloy_primitives::hex::encode(block.hash)
                ),
                id,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RecordingResolver {
    source: Option<Arc<IdentityRegistry>>,
    at: i64,
    captured: Mutex<HashMap<ExecutionBinding, CapturedIdentity>>,
    outcomes: Mutex<HashMap<ExecutionBinding, ExecutionOutcome>>,
    expected: Option<HashMap<ExecutionBinding, ExecutionOutcome>>,
    archive: Option<Arc<ArtifactStore>>,
    facts_version: u64,
}
impl IdentityResolver for RecordingResolver {
    fn record(&self, binding: &ExecutionBinding, outcome: ExecutionOutcome) -> Result<(), String> {
        if let Some(expected) = &self.expected
            && expected.get(binding) != Some(&outcome)
        {
            return Err("replayed execution outcome differs from archive".into());
        }
        if let (Some(archive), ExecutionBinding::Transaction(hash)) = (&self.archive, binding) {
            {
                let status = TransactionStatus {
                    status: if outcome.denied { "denied" } else { "pending" }.into(),
                    facts_version: self.facts_version,
                    block_hash: None,
                    block_number: None,
                    reason_code: outcome.reason_code.clone(),
                    created: Vec::new(),
                    finalized: false,
                    finalized_block_hash: None,
                    finalized_block_number: None,
                };
                let id = archive
                    .put(&serde_json::to_vec(&status).map_err(|_| "invalid execution status")?)?;
                archive.set_pointer(
                    &format!("status-{}", alloy_primitives::hex::encode(hash)),
                    id,
                )?;
            }
        }
        self.outcomes
            .lock()
            .map_err(|_| "execution outcomes unavailable")?
            .insert(binding.clone(), outcome);
        Ok(())
    }
    fn resolve(
        &self,
        binding: &ExecutionBinding,
        transaction: &TxEnv,
    ) -> Result<ExecutionIdentity, String> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| "execution identities unavailable")?;
        if !captured.contains_key(binding) {
            let source = self
                .source
                .as_ref()
                .ok_or("missing archived execution identity")?;
            captured.insert(binding.clone(), source.capture(binding, self.at)?);
        }
        let identity = &captured
            .get(binding)
            .ok_or("missing execution identity")?
            .identity;
        let signer = identity
            .signer
            .parse::<Address>()
            .map_err(|_| "invalid execution signer")?;
        if signer != transaction.caller {
            return Err("execution signer mismatch".into());
        }
        Ok(ExecutionIdentity {
            principal_id: identity.principal_id.clone(),
            org_id: identity.org_id.clone(),
            context_id: identity.context_id.clone(),
            signer,
            binding: binding.clone(),
            min_snapshot_version: identity.min_snapshot_version,
        })
    }
}
