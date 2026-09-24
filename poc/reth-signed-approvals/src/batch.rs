//! Signed approval batches; no transaction grouping or atomic EVM execution.
use crate::approvals::Approval;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAX_APPROVALS: usize = 32;
pub const MAX_FRAME: usize = 16_384;
pub const DOMAIN: &[u8] = b"OPS_APPROVAL_BATCH_V1\0";

// The binary frame carries the exact bytes OPS signed, followed by the raw
// signature. No JSON/hex decoding or reconstruction of the signed message.
pub enum Packet<'a> {
    Json(Incoming),
    Binary {
        message: &'a [u8],
        signature: Signature,
        approvals: Vec<Approval>,
    },
}
impl<'a> Packet<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() > MAX_FRAME {
            return Err("oversize frame".into());
        }
        if !bytes.starts_with(DOMAIN) {
            return serde_json::from_slice(bytes)
                .map(Self::Json)
                .map_err(|e| e.to_string());
        }
        let header = DOMAIN.len() + 4;
        if bytes.len() < header + 64 {
            return Err("truncated frame".into());
        }
        let count = u32::from_be_bytes(bytes[DOMAIN.len()..header].try_into().unwrap()) as usize;
        if !(1..=MAX_APPROVALS).contains(&count) || bytes.len() != header + count * 120 + 64 {
            return Err("invalid frame count or length".into());
        }
        let end = bytes.len() - 64;
        let signature = Signature::from_slice(&bytes[end..]).map_err(|e| e.to_string())?;
        let mut approvals = Vec::with_capacity(count);
        for a in bytes[header..end].as_chunks::<120>().0 {
            let hash_mode = match &a[..16] {
                b"OPS_APPROVAL_V1\0" => 0,
                b"OPS_APPROVAL_V3\0" => 3,
                _ => return Err("invalid member domain".into()),
            };
            approvals.push(Approval {
                hash_mode,
                chain_id: u64::from_be_bytes(a[16..24].try_into().unwrap()),
                tx_hash: alloy_primitives::B256::from_slice(&a[24..56]),
                fingerprint: alloy_primitives::B256::from_slice(&a[56..88]),
                principal: alloy_primitives::B256::from_slice(&a[88..120]),
                signature: String::new(),
            });
        }
        Ok(Self::Binary {
            message: &bytes[..end],
            signature,
            approvals,
        })
    }
    pub fn verify(self, key: &VerifyingKey, chain: u64) -> Result<Vec<Approval>, String> {
        match self {
            Self::Json(incoming) => incoming.verify(key, chain),
            Self::Binary {
                message,
                signature,
                approvals,
            } => {
                if approvals.iter().any(|a| a.chain_id != chain) {
                    return Err("wrong chain".into());
                }
                key.verify_strict(message, &signature)
                    .map_err(|e| e.to_string())?;
                Ok(approvals)
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub version: u32,
    pub approvals: Vec<Approval>,
    pub signature: String,
}
impl Batch {
    pub fn message(&self) -> Result<Vec<u8>, String> {
        if self.version != 1 || self.approvals.is_empty() || self.approvals.len() > MAX_APPROVALS {
            return Err("unsupported or invalid approval batch".into());
        }
        let mut message = b"OPS_APPROVAL_BATCH_V1\0".to_vec();
        message.extend_from_slice(&(self.approvals.len() as u32).to_be_bytes());
        for a in &self.approvals {
            if !a.valid_mode() {
                return Err("unknown approval hash mode".into());
            }
            if !a.signature.is_empty() {
                return Err("batch member has individual signature".into());
            }
            message.extend_from_slice(&a.message());
        }
        Ok(message)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Incoming {
    Single(Approval),
    Batch(Batch),
}
impl Incoming {
    pub fn verify(self, key: &VerifyingKey, chain: u64) -> Result<Vec<Approval>, String> {
        match self {
            Self::Single(a) => {
                a.verify(key, chain)?;
                Ok(vec![a])
            }
            Self::Batch(b) => {
                let message = b.message()?;
                if b.approvals.iter().any(|a| a.chain_id != chain) {
                    return Err("wrong chain".into());
                }
                let signature =
                    alloy_primitives::hex::decode(&b.signature).map_err(|e| e.to_string())?;
                let signature = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
                key.verify_strict(&message, &signature)
                    .map_err(|e| e.to_string())?;
                Ok(b.approvals)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    fn fixture() -> Batch {
        serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/batch.json"
        ))
        .unwrap()
    }
    pub fn golden_wire() -> Vec<u8> {
        let b = fixture();
        let mut wire = b.message().unwrap();
        wire.extend(alloy_primitives::hex::decode(&b.signature).unwrap());
        wire
    }
    #[test]
    fn binary_go_signature_rejects_tampering_truncation_and_trailing_data() {
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let wire = golden_wire();
        assert_eq!(
            Packet::decode(&wire)
                .unwrap()
                .verify(&key, 31337)
                .unwrap()
                .len(),
            3
        );
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 1;
            assert!(
                Packet::decode(&bad)
                    .and_then(|p| p.verify(&key, 31337))
                    .is_err(),
                "byte {i}"
            );
        }
        for size in 0..wire.len() {
            assert!(Packet::decode(&wire[..size]).is_err());
        }
        let mut trailing = wire;
        trailing.push(0);
        assert!(Packet::decode(&trailing).is_err());
    }
    #[test]
    fn go_signed_batch_and_all_tampering() {
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert_eq!(
            Incoming::Batch(fixture())
                .verify(&key, 31337)
                .unwrap()
                .len(),
            3
        );
        for member in 0..3 {
            for field in 0..4 {
                let mut b = fixture();
                let a = &mut b.approvals[member];
                match field {
                    0 => a.tx_hash = alloy_primitives::B256::ZERO,
                    1 => a.fingerprint = alloy_primitives::B256::ZERO,
                    2 => a.principal = alloy_primitives::B256::ZERO,
                    _ => a.chain_id = 1,
                }
                assert!(Incoming::Batch(b).verify(&key, 31337).is_err());
            }
        }
        for case in 0..7 {
            let mut b = fixture();
            match case {
                0 => b.approvals.swap(0, 1),
                1 => {
                    b.approvals.pop();
                }
                2 => b.approvals.clear(),
                3 => b.approvals = vec![b.approvals[0].clone(); 33],
                4 => b.version = 2,
                5 => b.signature = "00".repeat(64),
                _ => b.approvals[0].signature = "00".repeat(64),
            }
            assert!(Incoming::Batch(b).verify(&key, 31337).is_err());
        }
    }
    #[test]
    fn mixed_call_and_strict_modes_are_signed_in_json_and_binary() {
        let b: Batch = serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/call-batch.json"
        ))
        .unwrap();
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let mut wire = b.message().unwrap();
        wire.extend(alloy_primitives::hex::decode(&b.signature).unwrap());
        let decoded = Packet::decode(&wire).unwrap().verify(&key, 31337).unwrap();
        assert_eq!(
            decoded.iter().map(|a| a.hash_mode).collect::<Vec<_>>(),
            vec![3, 0]
        );
        assert_eq!(Incoming::Batch(b).verify(&key, 31337).unwrap().len(), 2);
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 1;
            assert!(
                Packet::decode(&bad)
                    .and_then(|p| p.verify(&key, 31337))
                    .is_err(),
                "byte {i}"
            );
        }
        for mode in [0, 1, 2, 4, 255] {
            let mut b: Batch = serde_json::from_str(include_str!(
                "../../../internal/nodeapproval/testdata/call-batch.json"
            ))
            .unwrap();
            b.approvals[0].hash_mode = mode;
            assert!(
                Incoming::Batch(b).verify(&key, 31337).is_err(),
                "mode {mode}"
            );
        }
    }
}
