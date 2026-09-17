//! Authenticated OPS_NODE_POLICY_V1 messages. Verification uses received payload
//! bytes, never a JSON reserialization. This module does not authorize execution.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
};

pub const MAX_ENVELOPE_BYTES: usize = 64 << 20;
pub const MAX_IDENTITY_BYTES: usize = 16 << 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub chain_id: u64,
    pub deployment_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub network: Network,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    #[serde(flatten)]
    pub header: Header,
    pub scope: String,
    pub context_id: String,
    pub principal_id: String,
    pub org_id: String,
    pub signer: String,
    pub binding_hash: String,
    pub min_snapshot_version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(flatten)]
    pub header: Header,
    pub version: u64,
    pub principals: Vec<Principal>,
    pub groups: Vec<Group>,
    pub contracts: Vec<Contract>,
    pub policies: Vec<PolicyArtifact>,
    pub sanctions: Vec<Sanction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    #[serde(flatten)]
    pub header: Header,
    pub previous_version: u64,
    pub previous_digest: String,
    pub version: u64,
    pub upserts: Upserts,
    pub deletes: Deletes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upserts {
    pub principals: Vec<Principal>,
    pub groups: Vec<Group>,
    pub contracts: Vec<Contract>,
    pub policies: Vec<PolicyArtifact>,
    pub sanctions: Vec<Sanction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deletes {
    pub principals: Vec<String>,
    pub groups: Vec<String>,
    pub contracts: Vec<String>,
    pub policies: Vec<String>,
    pub sanctions: Vec<Sanction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    #[serde(flatten)]
    pub header: Header,
    pub version: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub banned: bool,
    pub kyc: bool,
    pub linked_addresses: Vec<String>,
    pub memberships: Vec<Membership>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub group_id: String,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub org_id: String,
    pub claims: u8,
    pub org_admin: bool,
    pub contract_claims: Vec<ContractClaim>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractClaim {
    pub address: String,
    pub claims: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub address: String,
    pub org_id: String,
    pub shared_infrastructure: bool,
    pub code_hash: String,
    pub deployer_principal_id: String,
    pub pending: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sanction {
    pub org_id: String,
    pub address: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifact {
    pub org_id: String,
    pub revision: u64,
    pub policy_digest: String,
    pub runtime_digest: String,
    #[serde(with = "base64_bytes")]
    pub bytecode: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    kind: String,
    key_id: String,
    payload: String,
    signature: String,
}

#[derive(Clone, Debug)]
pub struct Verifier {
    network: Network,
    keys: BTreeMap<String, VerifyingKey>,
}

impl Verifier {
    pub fn new(network: Network, keys: BTreeMap<String, VerifyingKey>) -> Self {
        Self { network, keys }
    }
    pub fn network(&self) -> &Network {
        &self.network
    }

    pub fn open(&self, kind: &str, wire: &[u8]) -> Result<Vec<u8>, String> {
        if wire.is_empty()
            || wire.len() > MAX_ENVELOPE_BYTES
            || !matches!(kind, "identity" | "snapshot" | "delta" | "heartbeat")
        {
            return Err("invalid node policy envelope".into());
        }
        let envelope: Envelope = decode_strict(wire)?;
        if envelope.version != 1 || envelope.kind != kind || !identifier(&envelope.key_id) {
            return Err("invalid node policy envelope".into());
        }
        let payload = decode_base64(&envelope.payload)?;
        let signature = Signature::from_slice(&decode_base64(&envelope.signature)?)
            .map_err(|_| "untrusted node policy signature".to_owned())?;
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or_else(|| "untrusted node policy signature".to_owned())?;
        key.verify_strict(&signing_bytes(kind, &envelope.key_id, &payload), &signature)
            .map_err(|_| "untrusted node policy signature".to_owned())?;
        Ok(payload)
    }

    pub fn open_identity(&self, wire: &[u8], now: i64) -> Result<Identity, String> {
        if wire.len() > MAX_IDENTITY_BYTES {
            return Err("invalid node policy envelope".into());
        }
        let identity: Identity = decode_strict(&self.open("identity", wire)?)?;
        self.validate_header(&identity.header, now)?;
        if !matches!(identity.scope.as_str(), "transaction" | "simulation")
            || !identifier(&identity.context_id)
            || !identifier(&identity.principal_id)
            || !identifier(&identity.org_id)
            || !hex_field(&identity.signer, 20)
            || !hex_field(&identity.binding_hash, 32)
            || identity.min_snapshot_version == 0
        {
            return Err("invalid execution identity".into());
        }
        Ok(identity)
    }

    pub fn open_snapshot(&self, wire: &[u8], now: i64) -> Result<Snapshot, String> {
        let snapshot: Snapshot = decode_strict(&self.open("snapshot", wire)?)?;
        self.validate_header(&snapshot.header, now)?;
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    pub fn validate_header(&self, header: &Header, now: i64) -> Result<(), String> {
        if header.network != self.network
            || header.network.chain_id == 0
            || !identifier(&header.network.deployment_id)
        {
            return Err("node policy network mismatch".into());
        }
        if header.issued_at < 0
            || header.expires_at <= header.issued_at
            || header
                .expires_at
                .checked_sub(header.issued_at)
                .is_none_or(|v| v > 600)
            || header.issued_at > now.saturating_add(5)
            || header.expires_at <= now
        {
            return Err("node policy message outside validity window".into());
        }
        Ok(())
    }
}

fn signing_bytes(kind: &str, key_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [kind.as_bytes(), key_id.as_bytes(), payload] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

pub fn simulation_hash(request: &[u8]) -> Result<[u8; 32], String> {
    if request.is_empty() || request.len() > 1 << 20 {
        return Err("invalid simulation request".into());
    }
    let mut h = Sha256::new();
    h.update(b"OPS_SIMULATION_V1\0");
    h.update((request.len() as u32).to_be_bytes());
    h.update(request);
    Ok(h.finalize().into())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationRequest {
    pub method: String,
    pub params: Vec<serde_json::Value>,
    pub dry_run: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub candidate_policy: Option<PolicyArtifact>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PolicyArtifact>, D::Error> {
    Option::<PolicyArtifact>::deserialize(deserializer)
}

pub fn parse_simulation(
    request: &[u8],
    expected_hash: &[u8; 32],
) -> Result<SimulationRequest, String> {
    if &simulation_hash(request)? != expected_hash {
        return Err("simulation identity binding mismatch".into());
    }
    let parsed: SimulationRequest = decode_strict(request)?;
    if !matches!(
        parsed.method.as_str(),
        "eth_call" | "eth_estimateGas" | "debug_traceCall"
    ) || parsed.params.is_empty()
        || parsed.params.len() > 3
        || !parsed.params[0]
            .get("from")
            .and_then(|v| v.as_str())
            .is_some_and(|from| hex_field(from, 20))
    {
        return Err("invalid simulation request".into());
    }
    if let Some(candidate) = &parsed.candidate_policy {
        validate_artifact(candidate)?;
    }
    let empty_override = |value: &serde_json::Value| {
        value.is_null() || value.as_object().is_some_and(|fields| fields.is_empty())
    };
    if let Some(options) = parsed.params.get(2) {
        if parsed.method == "debug_traceCall" {
            if !options.is_null() && !options.is_object() {
                return Err("invalid tracing options".into());
            }
            for field in ["stateOverrides", "blockOverrides"] {
                if options
                    .get(field)
                    .is_some_and(|value| !empty_override(value))
                {
                    return Err("simulation state and block overrides are unsupported".into());
                }
            }
        } else if !empty_override(options) {
            return Err("simulation state and block overrides are unsupported".into());
        }
    }
    Ok(parsed)
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
}
pub(crate) fn hex_field(value: &str, size: usize) -> bool {
    value.len() == 2 + size * 2
        && value.starts_with("0x")
        && value.as_bytes()[2..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}
pub(crate) fn hex_digest(value: &str) -> bool {
    value.len() == 64 && hex_field(&format!("0x{value}"), 32)
}
pub(crate) fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| "noncanonical base64".to_owned())?;
    if STANDARD.encode(&bytes) != value {
        return Err("noncanonical base64".into());
    }
    Ok(bytes)
}

pub(crate) fn validate_snapshot(snapshot: &Snapshot) -> Result<(), String> {
    let invalid = || "invalid policy fact snapshot".to_owned();
    if snapshot.version == 0 {
        return Err(invalid());
    }
    let mut groups = HashSet::new();
    for group in &snapshot.groups {
        if !identifier(&group.id)
            || !identifier(&group.org_id)
            || group.claims & !7 != 0
            || !groups.insert(&group.id)
        {
            return Err(invalid());
        }
        let mut addresses = HashSet::new();
        for claim in &group.contract_claims {
            if !hex_field(&claim.address, 20)
                || claim.claims & !7 != 0
                || !addresses.insert(&claim.address)
            {
                return Err(invalid());
            }
        }
    }
    let mut principals = HashSet::new();
    for principal in &snapshot.principals {
        if !identifier(&principal.id) || !principals.insert(&principal.id) {
            return Err(invalid());
        }
        let mut addresses = HashSet::new();
        for address in &principal.linked_addresses {
            if !hex_field(address, 20) || !addresses.insert(address) {
                return Err(invalid());
            }
        }
        let mut memberships = HashSet::new();
        for membership in &principal.memberships {
            if !groups.contains(&membership.group_id)
                || !memberships.insert(&membership.group_id)
                || membership.expires_at < 0
            {
                return Err(invalid());
            }
        }
    }
    let mut contracts = HashSet::new();
    for contract in &snapshot.contracts {
        if !hex_field(&contract.address, 20)
            || !contracts.insert(&contract.address)
            || !(identifier(&contract.org_id)
                || contract.shared_infrastructure && contract.org_id.is_empty())
            || !(contract.code_hash.is_empty() || hex_field(&contract.code_hash, 32))
            || !(contract.deployer_principal_id.is_empty()
                || identifier(&contract.deployer_principal_id))
            || contract.pending
                && (contract.shared_infrastructure || !contract.deployer_principal_id.is_empty())
        {
            return Err(invalid());
        }
    }
    let mut policies = HashSet::new();
    for artifact in &snapshot.policies {
        if !policies.insert(&artifact.org_id) || validate_artifact(artifact).is_err() {
            return Err(invalid());
        }
    }
    let mut sanctions = HashSet::new();
    for sanction in &snapshot.sanctions {
        if !hex_field(&sanction.address, 20)
            || !(sanction.org_id.is_empty() || identifier(&sanction.org_id))
            || !sanctions.insert((&sanction.org_id, &sanction.address))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn validate_artifact(artifact: &PolicyArtifact) -> Result<(), String> {
    if !identifier(&artifact.org_id)
        || artifact.revision == 0
        || artifact.bytecode.is_empty()
        || artifact.bytecode.len() > 24576
        || !hex_digest(&artifact.policy_digest)
        || !hex_digest(&artifact.runtime_digest)
        || alloy_primitives::hex::encode(Sha256::digest(&artifact.bytecode))
            != artifact.runtime_digest
    {
        return Err("invalid policy artifact".into());
    }
    Ok(())
}

pub(crate) fn decode_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    Unique(0)
        .deserialize(&mut parser)
        .map_err(|_| "ambiguous node policy JSON".to_owned())?;
    parser
        .end()
        .map_err(|_| "trailing node policy JSON".to_owned())?;
    serde_json::from_slice(bytes).map_err(|_| "invalid node policy schema".into())
}

struct Unique(u8);
impl<'de> DeserializeSeed<'de> for Unique {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.0 > 32 {
            return Err(de::Error::custom("maximum JSON depth"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Unique {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unambiguous JSON")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Unique(self.0 + 1))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut names = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !names.insert(key) {
                return Err(de::Error::custom("duplicate key"));
            }
            map.next_value_seed(Unique(self.0 + 1))?;
        }
        Ok(())
    }
}

mod base64_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        decode_base64(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}
