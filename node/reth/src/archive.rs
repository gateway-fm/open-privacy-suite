//! Durable local evidence for produced blocks. This layer authenticates content
//! addresses, not issuer signatures. Replay must also verify the retained signed
//! checkpoint and identities before constructing an execution handle.

use crate::wire::{Network, decode_strict, identifier};
use alloy_primitives::{B256, hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_OBJECT: usize = 64 << 20;
const MAX_MANIFEST: usize = 16 << 20;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(B256);
impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDescriptor {
    pub network: Network,
    pub hash: B256,
    pub parent_hash: B256,
    pub number: u64,
    pub timestamp: u64,
    pub transactions: Vec<B256>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundIdentity {
    pub transaction_hash: B256,
    pub envelope: ArtifactId,
    pub outcome: crate::context::ExecutionOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockManifest {
    pub format_version: u32,
    pub block: BlockDescriptor,
    pub facts_version: u64,
    /// Digest of the exact last applied snapshot/delta payload, not checkpoint JSON.
    pub facts_digest: B256,
    /// Immutable checkpoint document referencing retained signed stream artifacts.
    pub checkpoint: ArtifactId,
    pub identities: Vec<BoundIdentity>,
}

#[derive(Debug)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        private_directory(root.as_ref())?;
        private_directory(&root.as_ref().join("objects"))?;
        private_directory(&root.as_ref().join("blocks"))?;
        private_directory(&root.as_ref().join("pointers"))?;
        Ok(Self {
            root: root.as_ref().to_owned(),
        })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<ArtifactId, String> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT {
            return Err("invalid execution artifact size".into());
        }
        let id = ArtifactId(B256::from_slice(&Sha256::digest(bytes)));
        publish_immutable(&self.root.join("objects"), &id.to_string(), bytes)?;
        Ok(id)
    }

    pub fn get(&self, id: ArtifactId) -> Result<Vec<u8>, String> {
        let bytes = read_bounded(&self.root.join("objects").join(id.to_string()), MAX_OBJECT)?;
        if B256::from_slice(&Sha256::digest(&bytes)) != id.0 {
            return Err("execution artifact digest mismatch".into());
        }
        Ok(bytes)
    }

    /// Durable mutable index into immutable evidence. Keys are node-owned names,
    /// never paths supplied by API clients. The referenced object must exist.
    pub fn set_pointer(&self, key: &str, id: ArtifactId) -> Result<(), String> {
        pointer_key(key)?;
        self.get(id)?;
        let bytes = serde_json::to_vec(&id).map_err(|_| "invalid execution archive pointer")?;
        replace_atomic(&self.root.join("pointers"), key, &bytes)
    }

    pub fn pointer(&self, key: &str) -> Result<Option<ArtifactId>, String> {
        pointer_key(key)?;
        let path = self.root.join("pointers").join(key);
        match fs::symlink_metadata(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error(err)),
            Ok(_) => decode_strict(&read_bounded(&path, 256)?).map(Some),
        }
    }

    pub fn remove_pointer(&self, key: &str) -> Result<(), String> {
        pointer_key(key)?;
        let directory = self.root.join("pointers");
        match fs::remove_file(directory.join(key)) {
            Ok(()) => File::open(directory)
                .and_then(|file| file.sync_all())
                .map_err(io_error),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }

    pub fn pointers(&self, prefix: &str) -> Result<Vec<ArtifactId>, String> {
        pointer_key(prefix)?;
        let mut result = Vec::new();
        for entry in fs::read_dir(self.root.join("pointers")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid execution archive pointer")?;
            if name.starts_with(prefix) {
                result.push(
                    self.pointer(name)?
                        .ok_or("missing execution archive pointer")?,
                );
            }
        }
        Ok(result)
    }

    /// Call before publishing the assembled block. ACK requires durable artifacts
    /// and manifest. A retry is idempotent; an existing hash cannot be overwritten.
    pub fn publish(&self, manifest: &BlockManifest) -> Result<(), String> {
        self.validate(manifest)?;
        let bytes = serde_json::to_vec(manifest).map_err(|_| "invalid execution manifest")?;
        if bytes.len() > MAX_MANIFEST {
            return Err("execution manifest too large".into());
        }
        publish_immutable(
            &self.root.join("blocks"),
            &hex::encode(manifest.block.hash),
            &bytes,
        )
    }

    /// Reserved for block self-import and trusted forensic replay. Historical user
    /// RPC calls must choose current permissions instead of this archive.
    pub fn load_for_block(&self, expected: &BlockDescriptor) -> Result<BlockManifest, String> {
        let bytes = read_bounded(
            &self.root.join("blocks").join(hex::encode(expected.hash)),
            MAX_MANIFEST,
        )?;
        let manifest: BlockManifest = decode_strict(&bytes)?;
        if &manifest.block != expected {
            return Err("execution manifest block mismatch".into());
        }
        self.validate(&manifest)?;
        Ok(manifest)
    }

    fn validate(&self, manifest: &BlockManifest) -> Result<(), String> {
        if manifest.format_version != 1
            || manifest.block.network.chain_id == 0
            || !identifier(&manifest.block.network.deployment_id)
            || manifest.block.hash.is_zero()
            || manifest.facts_version == 0
            || manifest.facts_digest.is_zero()
            || manifest.identities.len() != manifest.block.transactions.len()
        {
            return Err("invalid execution manifest".into());
        }
        let mut unique = HashSet::new();
        for (hash, identity) in manifest.block.transactions.iter().zip(&manifest.identities) {
            if *hash != identity.transaction_hash || !unique.insert(*hash) {
                return Err("execution manifest transaction mismatch".into());
            }
            self.get(identity.envelope)?;
            if identity.outcome.denied
                || (!identity.outcome.success && !identity.outcome.created.is_empty())
            {
                return Err("invalid included execution outcome".into());
            }
        }
        self.get(manifest.checkpoint)?;
        Ok(())
    }
}

fn private_directory(path: &Path) -> Result<(), String> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(io_error)?;
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(io_error(err)),
    }
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err("execution archive requires a private directory".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > limit as u64 {
        return Err("invalid execution archive file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io_error)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("invalid execution archive file".into());
    }
    Ok(bytes)
}

fn publish_immutable(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let destination = directory.join(name);
    let temporary = directory.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(io_error)?;
        match fs::hard_link(&temporary, &destination) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_bounded(&destination, bytes.len())? != bytes {
                    return Err("conflicting immutable execution artifact".into());
                }
            }
            Err(err) => return Err(io_error(err)),
        }
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(io_error)
    })();
    drop(file);
    let cleanup = fs::remove_file(&temporary).map_err(io_error);
    result.and(cleanup)
}

fn io_error(_: std::io::Error) -> String {
    "execution archive unavailable".into()
}

fn pointer_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || key.len() > 192
        || !key.as_bytes()[0].is_ascii_alphanumeric()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("invalid execution archive pointer".into());
    }
    Ok(())
}

fn replace_atomic(directory: &Path, key: &str, bytes: &[u8]) -> Result<(), String> {
    let temporary = directory.join(format!(
        ".pending-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temporary, directory.join(key)).map_err(io_error)?;
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(io_error)
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
