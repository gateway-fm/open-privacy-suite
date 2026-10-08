//! The signed approval envelope `OPS_APPROVAL_BATCH_V2` and the receiver's checks 1–7
//! (docs/implementation/approvals-wire-contract.md §2, §3). The node verifies the exact bytes OPS
//! signed; nothing is re-encoded, and a batch either passes every check or contributes nothing.
use crate::approvals::Approval;
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeMap;

pub const DOMAIN: &[u8; 22] = b"OPS_APPROVAL_BATCH_V2\0";
pub const MAX_APPROVALS: usize = 32;
pub const MAX_KEY_ID: usize = 64;
/// Check 6: how far `issued_at` may run ahead of the receiver's clock.
pub const MAX_CLOCK_AHEAD_MS: u64 = 5_000;

/// Trusted OPS signing keys by the id a batch names. Rotation is add-then-switch.
pub type KeySet = BTreeMap<String, VerifyingKey>;

/// What the receiver accepts: its chain, its keys and the longest approval lifetime.
#[derive(Clone, Debug)]
pub struct Trust {
    pub chain: u64,
    pub keys: KeySet,
    pub max_ttl_ms: u64,
}

/// The first failing check of contract §3, in its order. Each maps to one gRPC status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// 1: not a well-formed envelope.
    Malformed(&'static str),
    /// 2: the key id is not in the trusted set.
    UntrustedKey,
    /// 3: the signature does not verify under the named key.
    BadSignature,
    /// 4: an approval names another chain.
    WrongChain,
    /// 5: `expires_at − issued_at` exceeds the maximum TTL.
    TtlTooLong,
    /// 6: `issued_at` is more than 5 s ahead of the receiver's clock.
    IssuedInFuture,
    /// 7: `expires_at` has passed.
    Expired,
    /// 8: the store has no room for every approval of the batch.
    StoreFull,
}

/// 1–64 characters of `[A-Za-z0-9._:-]`, like `nodeapproval.ValidKeyID`.
pub fn valid_key_id(id: &[u8]) -> bool {
    (1..=MAX_KEY_ID).contains(&id.len())
        && id
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// `id=hex[,id=hex...]`, the format of the Besu plugin's `--plugin-ops-approval-public-keys`.
pub fn parse_key_set(spec: &str) -> Result<KeySet, String> {
    let mut keys = KeySet::new();
    for entry in spec.split(',') {
        let (id, hex) = entry
            .split_once('=')
            .ok_or_else(|| format!("expected id=hex, got {entry:?}"))?;
        let id = id.trim();
        if !valid_key_id(id.as_bytes()) {
            return Err(format!("invalid key id {id:?}"));
        }
        let raw = alloy_primitives::hex::decode(hex.trim())
            .map_err(|_| format!("key {id:?} is not hex"))?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| format!("key {id:?} must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&raw)
            .map_err(|_| format!("key {id:?} is not an Ed25519 public key"))?;
        if keys.insert(id.to_string(), key).is_some() {
            return Err(format!("key id {id:?} is listed twice"));
        }
    }
    Ok(keys)
}

const APPROVAL_LEN: usize = 120;
const SIGNATURE_LEN: usize = 64;

fn hash_mode(domain: &[u8]) -> Option<u8> {
    match domain {
        b"OPS_APPROVAL_V1\0" => Some(0),
        b"OPS_APPROVAL_V3\0" => Some(3),
        _ => None,
    }
}

/// A decoded envelope that has passed check 1; the signature is not yet verified.
pub struct Envelope<'a> {
    key_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    members: &'a [u8],
    message: &'a [u8],
    signature: Signature,
}

impl<'a> Envelope<'a> {
    /// Check 1: known domain, lengths, count 1–32, known approval domains, `expires_at` >
    /// `issued_at`.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Refusal> {
        use Refusal::Malformed;
        let rest = bytes
            .strip_prefix(DOMAIN.as_slice())
            .ok_or(Malformed("unknown envelope version"))?;
        let (&k, rest) = rest.split_first().ok_or(Malformed("truncated"))?;
        let k = usize::from(k);
        if !(1..=MAX_KEY_ID).contains(&k) {
            return Err(Malformed("key id length out of range"));
        }
        if rest.len() < k + 20 {
            return Err(Malformed("truncated"));
        }
        let (key_id, rest) = rest.split_at(k);
        if !valid_key_id(key_id) {
            return Err(Malformed("invalid key id"));
        }
        let key_id = std::str::from_utf8(key_id).map_err(|_| Malformed("invalid key id"))?;
        let word = |at: usize| u64::from_be_bytes(rest[at..at + 8].try_into().unwrap());
        let (issued_at, expires_at) = (word(0), word(8));
        let count = u32::from_be_bytes(rest[16..20].try_into().unwrap()) as usize;
        let rest = &rest[20..];
        if !(1..=MAX_APPROVALS).contains(&count) {
            return Err(Malformed("approval count out of range"));
        }
        if rest.len() != count * APPROVAL_LEN + SIGNATURE_LEN {
            return Err(Malformed("length does not match the approval count"));
        }
        if expires_at <= issued_at {
            return Err(Malformed("expires_at is not after issued_at"));
        }
        let (members, signature) = rest.split_at(count * APPROVAL_LEN);
        if members
            .as_chunks::<APPROVAL_LEN>()
            .0
            .iter()
            .any(|m| hash_mode(&m[..16]).is_none())
        {
            return Err(Malformed("unknown approval domain"));
        }
        Ok(Self {
            key_id,
            issued_at,
            expires_at,
            members,
            message: &bytes[..bytes.len() - SIGNATURE_LEN],
            signature: Signature::from_bytes(signature.try_into().unwrap()),
        })
    }

    /// Checks 2–7. `now` is the receiver's clock in Unix milliseconds.
    pub fn verify(self, trust: &Trust, now: u64) -> Result<Vec<Approval>, Refusal> {
        let key = trust.keys.get(self.key_id).ok_or(Refusal::UntrustedKey)?;
        key.verify_strict(self.message, &self.signature)
            .map_err(|_| Refusal::BadSignature)?;
        let members = self.members.as_chunks::<APPROVAL_LEN>().0;
        let chain = |m: &[u8; APPROVAL_LEN]| u64::from_be_bytes(m[16..24].try_into().unwrap());
        if members.iter().any(|m| chain(m) != trust.chain) {
            return Err(Refusal::WrongChain);
        }
        if self.expires_at - self.issued_at > trust.max_ttl_ms {
            return Err(Refusal::TtlTooLong);
        }
        if self.issued_at > now.saturating_add(MAX_CLOCK_AHEAD_MS) {
            return Err(Refusal::IssuedInFuture);
        }
        if self.expires_at <= now {
            return Err(Refusal::Expired);
        }
        let key_id: std::sync::Arc<str> = self.key_id.into();
        Ok(members
            .iter()
            .map(|m| Approval {
                hash_mode: hash_mode(&m[..16]).expect("checked by decode"),
                chain_id: chain(m),
                tx_hash: alloy_primitives::B256::from_slice(&m[24..56]),
                fingerprint: alloy_primitives::B256::from_slice(&m[56..88]),
                key_id: key_id.clone(),
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            })
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy_primitives::B256;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;

    pub const CHAIN: u64 = 31337;
    pub const ISSUED: u64 = 1_790_000_000_000;
    pub const EXPIRES: u64 = 1_790_000_600_000;

    pub fn fixture_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    pub fn trust() -> Trust {
        Trust {
            chain: CHAIN,
            keys: KeySet::from([("default".to_string(), fixture_key().verifying_key())]),
            max_ttl_ms: 3_600_000,
        }
    }

    /// One 120-byte approval, encoded independently of the decoder (contract §2).
    pub fn member(mode: u8, chain: u64, tx: B256, fingerprint: B256) -> Vec<u8> {
        let mut m = if mode == 3 {
            b"OPS_APPROVAL_V3\0".to_vec()
        } else {
            b"OPS_APPROVAL_V1\0".to_vec()
        };
        m.extend(chain.to_be_bytes());
        m.extend(tx);
        m.extend(fingerprint);
        m.extend([0; 32]);
        m
    }

    pub fn message(key_id: &str, issued: u64, expires: u64, members: &[Vec<u8>]) -> Vec<u8> {
        let mut m = DOMAIN.to_vec();
        m.push(key_id.len() as u8);
        m.extend(key_id.as_bytes());
        m.extend(issued.to_be_bytes());
        m.extend(expires.to_be_bytes());
        m.extend((members.len() as u32).to_be_bytes());
        members.iter().for_each(|x| m.extend(x));
        m
    }

    pub fn envelope(
        signer: &SigningKey,
        key_id: &str,
        issued: u64,
        expires: u64,
        members: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut m = message(key_id, issued, expires, members);
        let signature = signer.sign(&m).to_bytes();
        m.extend(signature);
        m
    }

    /// A batch of `n` fixture approvals for distinct transactions, signed like OPS signs.
    pub fn signed(n: usize, issued: u64, expires: u64) -> Vec<u8> {
        let members: Vec<_> = (0..n)
            .map(|i| member(3, CHAIN, B256::with_last_byte(i as u8 + 1), B256::ZERO))
            .collect();
        envelope(&fixture_key(), "default", issued, expires, &members)
    }

    /// A shared golden vector as wire bytes: the fields re-encoded, then OPS's own signature.
    pub fn golden(json: &str) -> (Vec<u8>, Value) {
        let v: Value = serde_json::from_str(json).unwrap();
        let members: Vec<_> = v["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let hex = |k: &str| a[k].as_str().unwrap().parse::<B256>().unwrap();
                let mut m = member(
                    a["hash_mode"].as_u64().unwrap_or(0) as u8,
                    a["chain_id"].as_u64().unwrap(),
                    hex("tx_hash"),
                    hex("fingerprint"),
                );
                // The reserved field is signed but carries no meaning; the vectors fill it.
                m[88..].copy_from_slice(hex("principal").as_slice());
                m
            })
            .collect();
        let mut wire = message(
            v["key_id"].as_str().unwrap(),
            v["issued_at"].as_u64().unwrap(),
            v["expires_at"].as_u64().unwrap(),
            &members,
        );
        wire.extend(alloy_primitives::hex::decode(v["signature"].as_str().unwrap()).unwrap());
        (wire, v)
    }

    pub fn golden_batch() -> Vec<u8> {
        golden(include_str!(
            "../../../internal/nodeapproval/testdata/batch.json"
        ))
        .0
    }

    fn check(bytes: &[u8], trust: &Trust, now: u64) -> Result<Vec<Approval>, Refusal> {
        Envelope::decode(bytes)?.verify(trust, now)
    }

    #[test]
    fn go_signed_golden_batches_decode_and_verify() {
        for (json, modes) in [
            (
                include_str!("../../../internal/nodeapproval/testdata/batch.json"),
                vec![0, 0, 0],
            ),
            (
                include_str!("../../../internal/nodeapproval/testdata/call-batch.json"),
                vec![3, 0],
            ),
        ] {
            let (wire, v) = golden(json);
            let approvals = check(&wire, &trust(), ISSUED).unwrap();
            assert_eq!(
                approvals.iter().map(|a| a.hash_mode).collect::<Vec<_>>(),
                modes
            );
            for (a, j) in approvals.iter().zip(v["approvals"].as_array().unwrap()) {
                assert_eq!(a.chain_id, CHAIN);
                assert_eq!(a.tx_hash.to_string(), j["tx_hash"].as_str().unwrap());
                assert_eq!(
                    a.fingerprint.to_string(),
                    j["fingerprint"].as_str().unwrap()
                );
                assert_eq!(&*a.key_id, "default");
                assert_eq!((a.issued_at, a.expires_at), (ISSUED, EXPIRES));
            }
        }
    }

    #[test]
    fn any_flipped_bit_truncation_or_trailing_byte_is_refused() {
        for json in [
            include_str!("../../../internal/nodeapproval/testdata/batch.json"),
            include_str!("../../../internal/nodeapproval/testdata/call-batch.json"),
        ] {
            let (wire, _) = golden(json);
            for i in 0..wire.len() {
                for bit in 0..8 {
                    let mut bad = wire.clone();
                    bad[i] ^= 1 << bit;
                    assert!(check(&bad, &trust(), ISSUED).is_err(), "byte {i} bit {bit}");
                }
            }
            for size in 0..wire.len() {
                assert!(matches!(
                    Envelope::decode(&wire[..size]),
                    Err(Refusal::Malformed(_))
                ));
            }
            let mut trailing = wire;
            trailing.push(0);
            assert!(matches!(
                Envelope::decode(&trailing),
                Err(Refusal::Malformed(_))
            ));
        }
    }

    #[test]
    fn the_first_failing_check_in_contract_order_decides() {
        let now = ISSUED;
        let other = SigningKey::from_bytes(&[9; 32]);
        let foreign = member(3, 1, B256::with_last_byte(1), B256::ZERO);
        let local = member(3, CHAIN, B256::with_last_byte(1), B256::ZERO);
        let hour = 3_600_000;
        let cases: Vec<(&str, Vec<u8>, Refusal)> = vec![
            (
                "zero approvals and everything else wrong",
                envelope(&other, "other", now + 9_000, now + 3 * hour, &[]),
                Refusal::Malformed("approval count out of range"),
            ),
            (
                "untrusted key, bad signature, wrong chain, TTL and clock",
                envelope(
                    &other,
                    "other",
                    now + 9_000,
                    now + 3 * hour,
                    std::slice::from_ref(&foreign),
                ),
                Refusal::UntrustedKey,
            ),
            (
                "bad signature, wrong chain, TTL and clock",
                envelope(
                    &other,
                    "default",
                    now + 9_000,
                    now + 3 * hour,
                    std::slice::from_ref(&foreign),
                ),
                Refusal::BadSignature,
            ),
            (
                "wrong chain, TTL and clock",
                envelope(
                    &fixture_key(),
                    "default",
                    now + 9_000,
                    now + 3 * hour,
                    &[foreign],
                ),
                Refusal::WrongChain,
            ),
            (
                "TTL and clock",
                envelope(
                    &fixture_key(),
                    "default",
                    now + 9_000,
                    now + 3 * hour,
                    std::slice::from_ref(&local),
                ),
                Refusal::TtlTooLong,
            ),
            (
                "issued ahead of the clock",
                envelope(
                    &fixture_key(),
                    "default",
                    now + 9_000,
                    now + hour,
                    std::slice::from_ref(&local),
                ),
                Refusal::IssuedInFuture,
            ),
            (
                "expired",
                envelope(&fixture_key(), "default", now - hour, now, &[local]),
                Refusal::Expired,
            ),
        ];
        for (name, wire, expected) in cases {
            assert_eq!(check(&wire, &trust(), now).err(), Some(expected), "{name}");
        }
    }

    #[test]
    fn boundaries_of_every_check() {
        let now = ISSUED;
        let hour = 3_600_000;
        let ok = |wire: &[u8]| check(wire, &trust(), now).map(|a| a.len());
        let local = |mode| member(mode, CHAIN, B256::with_last_byte(1), B256::ZERO);
        let sign = |key_id: &str, issued, expires, members: &[Vec<u8>]| {
            envelope(&fixture_key(), key_id, issued, expires, members)
        };
        // TTL is expires_at − issued_at, no clock involved: exactly the maximum passes.
        assert_eq!(
            ok(&sign("default", now - 1, now - 1 + hour, &[local(3)])),
            Ok(1)
        );
        assert_eq!(
            ok(&sign("default", now - 1, now + hour, &[local(3)])),
            Err(Refusal::TtlTooLong)
        );
        // issued_at may run 5 s ahead of the receiver's clock, not more.
        assert_eq!(
            ok(&sign("default", now + 5_000, now + 6_000, &[local(3)])),
            Ok(1)
        );
        assert_eq!(
            ok(&sign("default", now + 5_001, now + 6_000, &[local(3)])),
            Err(Refusal::IssuedInFuture)
        );
        // Usable while now < expires_at.
        assert_eq!(ok(&sign("default", now - 10, now + 1, &[local(3)])), Ok(1));
        assert_eq!(
            ok(&sign("default", now - 10, now, &[local(3)])),
            Err(Refusal::Expired)
        );
        assert!(matches!(
            Envelope::decode(&sign("default", now, now, &[local(3)])),
            Err(Refusal::Malformed(_))
        ));
        // 1–32 approvals; strict and calls domains may be mixed.
        assert_eq!(
            ok(&sign("default", now, now + 1, &vec![local(0); 32])),
            Ok(32)
        );
        assert_eq!(
            ok(&sign("default", now, now + 1, &[local(0), local(3)])),
            Ok(2)
        );
        assert!(matches!(
            Envelope::decode(&sign("default", now, now + 1, &vec![local(0); 33])),
            Err(Refusal::Malformed(_))
        ));
        let mut unknown = local(3);
        unknown[14] = b'2';
        assert!(matches!(
            Envelope::decode(&sign("default", now, now + 1, &[unknown])),
            Err(Refusal::Malformed(_))
        ));
        // Key ids: 1–64 characters of [A-Za-z0-9._:-].
        let long = "k".repeat(64);
        let mut with_long = trust();
        with_long
            .keys
            .insert(long.clone(), fixture_key().verifying_key());
        assert_eq!(
            check(&sign(&long, now, now + 1, &[local(3)]), &with_long, now).map(|a| a.len()),
            Ok(1)
        );
        for id in ["", &"k".repeat(65), "a/b", "a b", "é"] {
            assert!(
                matches!(
                    Envelope::decode(&sign(id, now, now + 1, &[local(3)])),
                    Err(Refusal::Malformed(_))
                ),
                "{id:?}"
            );
        }
    }

    #[test]
    fn rotation_is_add_then_switch_and_the_key_id_is_signed() {
        let old = SigningKey::from_bytes(&[1; 32]);
        let new = SigningKey::from_bytes(&[2; 32]);
        let members = [member(3, CHAIN, B256::with_last_byte(1), B256::ZERO)];
        let mut trust = trust();
        trust.keys = KeySet::from([
            ("old".to_string(), old.verifying_key()),
            ("new".to_string(), new.verifying_key()),
        ]);
        let by = |key: &SigningKey, id: &str| envelope(key, id, ISSUED, ISSUED + 1, &members);
        assert!(check(&by(&old, "old"), &trust, ISSUED).is_ok());
        assert!(check(&by(&new, "new"), &trust, ISSUED).is_ok());
        // A batch cannot claim another trusted key's id.
        assert_eq!(
            check(&by(&new, "old"), &trust, ISSUED).err(),
            Some(Refusal::BadSignature)
        );
        trust.keys.remove("old");
        assert_eq!(
            check(&by(&old, "old"), &trust, ISSUED).err(),
            Some(Refusal::UntrustedKey)
        );
    }

    #[test]
    fn key_set_parses_like_the_plugin_option() {
        let a = alloy_primitives::hex::encode(SigningKey::from_bytes(&[1; 32]).verifying_key());
        let b = alloy_primitives::hex::encode(SigningKey::from_bytes(&[2; 32]).verifying_key());
        let keys = parse_key_set(&format!("default={a}, rotated.2026-09:b = 0x{b}")).unwrap();
        assert_eq!(
            keys.keys().collect::<Vec<_>>(),
            ["default", "rotated.2026-09:b"]
        );
        let not_a_point = (0..=255u8)
            .map(|b| [b; 32])
            .find(|k| VerifyingKey::from_bytes(k).is_err())
            .unwrap();
        for bad in [
            String::new(),
            a.clone(),
            format!("a/b={a}"),
            format!("default={}", &a[2..]),
            "default=zz".to_string(),
            format!("default={a},default={b}"),
            format!("default={}", alloy_primitives::hex::encode(not_a_point)),
        ] {
            assert!(parse_key_set(&bad).is_err(), "{bad:?}");
        }
    }
}
