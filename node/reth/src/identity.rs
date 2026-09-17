//! Bounded authenticated identity ingestion. Transaction bindings survive ticket
//! expiry until trusted terminal reconciliation; expiry never permits rebinding.

use crate::{
    context::{ExecutionBinding, ExecutionIdentity, IdentityResolver},
    wire::{Identity, Verifier},
};
use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    Transaction(B256),
    Simulation(String),
}

#[derive(Clone, Debug)]
struct StoredIdentity {
    identity: Identity,
    envelope: Vec<u8>,
}

/// One atomic registry read. Record this envelope when this identity is used, so
/// a concurrent ticket renewal cannot substitute different replay evidence.
#[derive(Clone, Debug)]
pub struct CapturedIdentity {
    pub identity: Identity,
    pub envelope: Vec<u8>,
}

#[derive(Debug)]
pub struct IdentityRegistry {
    verifier: Verifier,
    capacity: usize,
    identities: Mutex<HashMap<Key, StoredIdentity>>,
}

impl IdentityRegistry {
    pub fn new(verifier: Verifier, capacity: usize) -> Self {
        Self {
            verifier,
            capacity: capacity.max(1),
            identities: Mutex::new(HashMap::new()),
        }
    }

    /// A successful result is the acknowledgement that the context is installed.
    pub fn accept(&self, envelope: &[u8], now: i64) -> Result<Identity, String> {
        let identity = self.verifier.open_identity(envelope, now)?;
        let key = key_for_identity(&identity)?;
        let mut store = self
            .identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?;
        if let Some(old) = store.get(&key) {
            let old = &old.identity;
            if old.principal_id != identity.principal_id
                || old.org_id != identity.org_id
                || old.signer != identity.signer
                || old.header.network != identity.header.network
                || old.binding_hash != identity.binding_hash
                || identity.header.issued_at < old.header.issued_at
                || identity.header.expires_at < old.header.expires_at
                || identity.min_snapshot_version < old.min_snapshot_version
            {
                return Err("execution binding conflict".into());
            }
        } else if store.len() >= self.capacity {
            return Err("execution identity capacity reached".into());
        }
        store.insert(
            key,
            StoredIdentity {
                identity: identity.clone(),
                envelope: envelope.to_vec(),
            },
        );
        Ok(identity)
    }

    pub fn lookup(&self, binding: &ExecutionBinding, at: i64) -> Result<Identity, String> {
        Ok(self.capture(binding, at)?.identity)
    }

    pub fn capture(&self, binding: &ExecutionBinding, at: i64) -> Result<CapturedIdentity, String> {
        let stored = self.get(binding)?;
        self.verifier.validate_header(&stored.identity.header, at)?;
        Ok(CapturedIdentity {
            identity: stored.identity,
            envelope: stored.envelope,
        })
    }

    fn get(&self, binding: &ExecutionBinding) -> Result<StoredIdentity, String> {
        let store = self
            .identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?;
        let stored = store
            .get(&key_for_binding(binding))
            .ok_or_else(|| "missing execution identity".to_owned())?;
        let expected = match binding {
            ExecutionBinding::Transaction(hash) => hash,
            ExecutionBinding::Simulation { digest, .. } => digest,
        };
        if stored.identity.binding_hash != format!("{expected:#x}") {
            return Err("execution identity binding mismatch".into());
        }
        Ok(stored.clone())
    }

    /// Only trusted terminal-status reconciliation may release pending bindings.
    pub fn finish(&self, binding: &ExecutionBinding) -> Result<(), String> {
        self.identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?
            .remove(&key_for_binding(binding));
        Ok(())
    }

    pub fn for_execution(self: &Arc<Self>, at: i64) -> Arc<RegistryView> {
        Arc::new(RegistryView {
            registry: self.clone(),
            at,
        })
    }

    /// The runtime may reclaim expired leases after persisting immutable
    /// transaction bindings. Standalone registries retain their original policy.
    pub(crate) fn release_expired(&self, now: i64) -> Result<(), String> {
        self.identities
            .lock()
            .map_err(|_| "identity registry unavailable")?
            .retain(|_, stored| stored.identity.header.expires_at > now);
        Ok(())
    }
}

#[derive(Debug)]
pub struct RegistryView {
    registry: Arc<IdentityRegistry>,
    at: i64,
}

impl IdentityResolver for RegistryView {
    fn resolve(
        &self,
        binding: &ExecutionBinding,
        transaction: &TxEnv,
    ) -> Result<ExecutionIdentity, String> {
        let identity = self.registry.lookup(binding, self.at)?;
        let signer = identity
            .signer
            .parse::<Address>()
            .map_err(|_| "invalid execution signer".to_owned())?;
        if signer != transaction.caller {
            return Err("execution signer mismatch".into());
        }
        Ok(ExecutionIdentity {
            principal_id: identity.principal_id,
            org_id: identity.org_id,
            context_id: identity.context_id,
            signer,
            binding: binding.clone(),
            min_snapshot_version: identity.min_snapshot_version,
        })
    }
}

fn key_for_identity(identity: &Identity) -> Result<Key, String> {
    match identity.scope.as_str() {
        "transaction" => Ok(Key::Transaction(
            identity
                .binding_hash
                .parse()
                .map_err(|_| "invalid transaction binding".to_owned())?,
        )),
        "simulation" => Ok(Key::Simulation(identity.context_id.clone())),
        _ => Err("invalid identity scope".into()),
    }
}

fn key_for_binding(binding: &ExecutionBinding) -> Key {
    match binding {
        ExecutionBinding::Transaction(hash) => Key::Transaction(*hash),
        ExecutionBinding::Simulation { context_id, .. } => Key::Simulation(context_id.clone()),
    }
}
