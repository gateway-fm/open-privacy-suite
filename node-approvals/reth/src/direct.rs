//! Encode V2 directly from execution state; no JSON trees or repeated bytecode hashing.
//! CallFrame retains upstream Geth handling of reverted calls/logs and delegate calls.
use crate::{fingerprint::DOMAIN, profile};
use alloy_evm::{
    Database,
    revm::state::{AccountInfo, EvmState},
};
use alloy_primitives::{Address, B256, KECCAK256_EMPTY, U256, hex, keccak256};
use alloy_rpc_types_trace::geth::{CallFrame, CallLogFrame};
use std::collections::BTreeSet;
use std::io::Write;

const LIMIT: usize = 1_048_576;

/// Capture original metadata before commit, including native-value recipients.
pub fn code_hashes<DB: Database>(
    db: &mut DB,
    state: &EvmState,
) -> Result<Vec<(Address, AccountInfo)>, DB::Error> {
    let mut accounts = Vec::with_capacity(state.len());
    for address in state.keys() {
        accounts.push((*address, db.basic(*address)?.unwrap_or_default()));
    }
    accounts.sort_unstable_by_key(|(address, _)| *address);
    Ok(accounts)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Fees {
    pub sender: Address,
    pub beneficiary: Address,
    pub charge: U256,
    pub reward: U256,
}
impl Fees {
    pub fn balance(&self, address: Address, balance: U256, deleted: bool) -> Result<U256, String> {
        // A deleted beneficiary's post-execution reward does not survive commit.
        if deleted {
            return Ok(U256::ZERO);
        }
        if address == self.sender && address == self.beneficiary {
            let net = self
                .charge
                .checked_sub(self.reward)
                .ok_or("reward exceeds charge")?;
            return balance
                .checked_add(net)
                .ok_or("fee normalization overflow".into());
        }
        let balance = if address == self.sender {
            balance
                .checked_add(self.charge)
                .ok_or("fee normalization overflow")?
        } else {
            balance
        };
        if address == self.beneficiary {
            balance
                .checked_sub(self.reward)
                .ok_or("fee normalization underflow".into())
        } else {
            Ok(balance)
        }
    }
}
fn code_hash(info: &AccountInfo) -> B256 {
    if info.is_code_hash_empty_or_zero() {
        KECCAK256_EMPTY
    } else {
        info.code_hash
    }
}
fn creations(call: &CallFrame, out: &mut BTreeSet<Address>) {
    if matches!(call.typ.as_str(), "CREATE" | "CREATE2")
        && let Some(to) = call.to
    {
        out.insert(to);
    }
    for child in &call.calls {
        creations(child, out);
    }
}

struct Encoder<'a> {
    bytes: &'a mut Vec<u8>,
}
impl Encoder<'_> {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > LIMIT + DOMAIN.len() - self.bytes.len() {
            return Err("fingerprint exceeds 1 MiB".into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn hex(&mut self, bytes: &[u8]) -> Result<(), String> {
        let needed = bytes
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(4))
            .ok_or("hex length overflow")?;
        if needed > LIMIT + DOMAIN.len() - self.bytes.len() {
            return Err("fingerprint exceeds 1 MiB".into());
        }
        self.raw(b"\"0x")?;
        let start = self.bytes.len();
        self.bytes.resize(start + bytes.len() * 2, 0);
        hex::encode_to_slice(bytes, &mut self.bytes[start..]).expect("exact hex output size");
        self.raw(b"\"")
    }
    fn quantity(&mut self, n: u64) -> Result<(), String> {
        // Bounded stack buffer; preserve Geth's unpadded hex quantity encoding.
        let mut buf = [0u8; 20];
        let mut writer = &mut buf[..];
        write!(writer, "\"0x{n:x}\"").expect("u64 fits buffer");
        let length = 20 - writer.len();
        self.raw(&buf[..length])
    }
    fn log(&mut self, log: &CallLogFrame) -> Result<(), String> {
        self.raw(b"{")?;
        let mut comma = false;
        // Field order MUST match serde_json::Value's sorted map, including optional fields.
        if let Some(a) = log.address {
            self.raw(b"\"address\":")?;
            self.hex(a.as_slice())?;
            comma = true;
        }
        if let Some(data) = &log.data {
            if comma {
                self.raw(b",")?;
            }
            self.raw(b"\"data\":")?;
            self.hex(data)?;
            comma = true;
        }
        if let Some(index) = log.index {
            if comma {
                self.raw(b",")?;
            }
            self.raw(b"\"index\":")?;
            self.quantity(index)?;
            comma = true;
        }
        if let Some(position) = log.position {
            if comma {
                self.raw(b",")?;
            }
            self.raw(b"\"position\":")?;
            self.quantity(position)?;
            comma = true;
        }
        if let Some(topics) = &log.topics {
            if comma {
                self.raw(b",")?;
            }
            self.raw(b"\"topics\":[")?;
            for (i, topic) in topics.iter().enumerate() {
                if i != 0 {
                    self.raw(b",")?;
                }
                self.hex(topic.as_slice())?;
            }
            self.raw(b"]")?;
        }
        self.raw(b"}")
    }
    fn call(
        &mut self,
        call: &CallFrame,
        parent_storage: Option<Address>,
        count: &mut usize,
    ) -> Result<(), String> {
        *count += 1;
        if *count > 128 {
            return Err("more than 128 calls".into());
        }
        if ![
            "CALL",
            "STATICCALL",
            "DELEGATECALL",
            "CALLCODE",
            "CREATE",
            "CREATE2",
            "SELFDESTRUCT",
        ]
        .contains(&call.typ.as_str())
        {
            return Err(format!("unsupported call: {}", call.typ));
        }
        let failed_create =
            matches!(call.typ.as_str(), "CREATE" | "CREATE2") && call.error.is_some();
        let noop_self = call.typ == "SELFDESTRUCT"
            && call.to.is_none()
            && call.from == Address::ZERO
            && call.value.is_none_or(|v| v.is_zero())
            && call.error.is_none()
            && parent_storage.is_some();
        let destination = if noop_self { parent_storage } else { call.to };
        if destination.is_none() && !failed_create {
            return Err("missing call destination".into());
        }
        let to = destination.unwrap_or_default();
        let from = if noop_self { to } else { call.from };
        let storage = if call.typ == "DELEGATECALL" || call.typ == "CALLCODE" {
            parent_storage.ok_or("root delegate")?
        } else if call.typ == "SELFDESTRUCT" {
            from
        } else {
            to
        };
        self.raw(b"{\"calls\":[")?;
        for (i, child) in call.calls.iter().enumerate() {
            if i != 0 {
                self.raw(b",")?;
            }
            self.call(child, Some(storage), count)?;
        }
        self.raw(b"],\"failed\":")?;
        self.raw(if call.error.is_some() {
            b"true"
        } else {
            b"false"
        })?;
        self.raw(b",\"from\":")?;
        self.hex(from.as_slice())?;
        self.raw(b",\"input\":")?;
        self.hex(&call.input)?;
        self.raw(b",\"logs\":[")?;
        for (i, log) in call.logs.iter().enumerate() {
            if i != 0 {
                self.raw(b",")?;
            }
            self.log(log)?;
        }
        self.raw(b"],\"output\":")?;
        self.hex(call.output.as_ref().map(|b| b.as_ref()).unwrap_or_default())?;
        self.raw(b",\"storageAddress\":")?;
        if destination.is_none() {
            self.raw(b"\"\"")?;
        } else {
            self.hex(storage.as_slice())?;
        }
        self.raw(b",\"to\":")?;
        if destination.is_none() {
            self.raw(b"\"\"")?;
        } else {
            self.hex(to.as_slice())?;
        }
        self.raw(b",\"type\":\"")?;
        self.raw(call.typ.as_bytes())?;
        self.raw(b"\",\"value\":")?;
        self.hex(&call.value.unwrap_or_default().to_be_bytes::<32>())?;
        self.raw(b"}")
    }
}

pub fn fingerprint(
    calls: &CallFrame,
    state: &EvmState,
    codes: &[(Address, AccountInfo)],
    fees: Fees,
    scratch: &mut Vec<u8>,
    timer: &mut profile::Timer,
) -> Result<B256, String> {
    scratch.clear();
    scratch.extend_from_slice(DOMAIN);
    let mut out = Encoder { bytes: scratch };
    out.raw(b"{\"accounts\":[")?;
    let mut created = BTreeSet::new();
    creations(calls, &mut created);
    let mut emitted = false;
    for (address, before) in codes {
        let account = &state[address];
        let deleted = account.is_selfdestructed();
        let code_before = code_hash(before);
        let code_after = if deleted {
            KECCAK256_EMPTY
        } else {
            code_hash(&account.info)
        };
        let contract = code_before != KECCAK256_EMPTY
            || code_after != KECCAK256_EMPTY
            || !account.storage.is_empty()
            || created.contains(address);
        let balance = fees.balance(*address, account.info.balance, deleted)?;
        let delta = crate::fingerprint::balance_delta(before.balance, balance);
        if !contract && delta == "0" {
            continue;
        }
        if emitted {
            out.raw(b",")?;
        }
        emitted = true;
        out.raw(b"{\"address\":")?;
        out.hex(address.as_slice())?;
        out.raw(b",\"balanceDelta\":\"")?;
        out.raw(delta.as_bytes())?;
        out.raw(b"\",\"codeAfter\":")?;
        out.hex(code_after.as_slice())?;
        out.raw(b",\"codeBefore\":")?;
        out.hex(code_before.as_slice())?;
        out.raw(b",\"nonceAfter\":\"")?;
        out.raw(
            if contract && !deleted {
                account.info.nonce
            } else {
                0
            }
            .to_string()
            .as_bytes(),
        )?;
        out.raw(b"\",\"nonceBefore\":\"")?;
        out.raw(
            if contract { before.nonce } else { 0 }
                .to_string()
                .as_bytes(),
        )?;
        out.raw(b"\"")?;
        out.raw(b",\"storage\":[")?;
        let mut slots: Vec<_> = account.storage.iter().collect();
        slots.sort_unstable_by_key(|(slot, _)| **slot);
        for (j, (slot, value)) in slots.into_iter().enumerate() {
            if j != 0 {
                out.raw(b",")?;
            }
            out.raw(b"{\"after\":")?;
            out.hex(
                &if deleted {
                    U256::ZERO
                } else {
                    value.present_value
                }
                .to_be_bytes::<32>(),
            )?;
            out.raw(b",\"before\":")?;
            out.hex(&value.original_value.to_be_bytes::<32>())?;
            out.raw(b",\"slot\":")?;
            out.hex(&slot.to_be_bytes::<32>())?;
            out.raw(b"}")?;
        }
        out.raw(b"]}")?;
    }
    out.raw(b"],\"calls\":")?;
    out.call(calls, None, &mut 0)?;
    out.raw(b"}")?;
    timer.lap(10);
    let hash = keccak256(&*scratch);
    timer.lap(8);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::revm::{
        database::InMemoryDB,
        state::{Account, EvmStorageSlot},
    };
    use alloy_primitives::Bytes;
    use serde_json::{Value, json};

    #[test]
    fn fee_normalization_handles_sender_beneficiary_alias_at_uint256_limit() {
        let sender = Address::repeat_byte(1);
        let fees = Fees {
            sender,
            beneficiary: sender,
            charge: U256::from(20),
            reward: U256::from(15),
        };
        // The sender receives its own tip. Only the net fee was lost; adding the
        // full charge first would overflow even though the normalized value fits.
        assert_eq!(
            fees.balance(sender, U256::MAX - U256::from(5), false)
                .unwrap(),
            U256::MAX
        );
        assert_eq!(
            fees.balance(Address::repeat_byte(2), U256::from(7), false)
                .unwrap(),
            U256::from(7)
        );
    }

    #[test]
    fn fee_normalization_preserves_value_and_deleted_beneficiary_effects() {
        let fees = Fees {
            sender: Address::repeat_byte(1),
            beneficiary: Address::repeat_byte(2),
            charge: U256::from(20),
            reward: U256::from(15),
        };
        assert_eq!(
            fees.balance(fees.sender, U256::from(73), false).unwrap(),
            U256::from(93)
        );
        assert_eq!(
            fees.balance(fees.beneficiary, U256::from(22), false)
                .unwrap(),
            U256::from(7)
        );
        assert_eq!(
            fees.balance(fees.beneficiary, U256::from(15), true)
                .unwrap(),
            U256::ZERO
        );
        assert!(
            fees.balance(fees.beneficiary, U256::from(14), false)
                .is_err()
        );
    }

    /// Treat the existing Go/Rust golden and canonicalizer as the oracle. Check bytes,
    /// not just hashes, so field ordering, zero deletion and optional logs cannot drift.
    fn compare(calls: &Value, pre: &Value, diff: &Value) -> Result<B256, String> {
        let frame: CallFrame = serde_json::from_value(calls.clone()).unwrap();
        let mut state = EvmState::default();
        let mut db = InMemoryDB::default();
        for (address, item) in pre.as_object().unwrap() {
            let address: Address = address.parse().unwrap();
            let mut account = Account::default();
            account.info.code_hash =
                keccak256(hex::decode(item["code"].as_str().unwrap_or("0x")).unwrap());
            for (slot, before) in item
                .get("storage")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let changed = diff["pre"][address.to_string().to_lowercase()]["storage"]
                    .get(slot)
                    .is_some()
                    || diff["post"][address.to_string().to_lowercase()]["storage"]
                        .get(slot)
                        .is_some();
                let after = if changed {
                    diff["post"][address.to_string().to_lowercase()]["storage"].get(slot)
                } else {
                    Some(before)
                };
                let before = before.as_str().unwrap().parse::<U256>().unwrap();
                let after = after
                    .and_then(Value::as_str)
                    .unwrap_or("0x0")
                    .parse::<U256>()
                    .unwrap();
                account.storage.insert(
                    slot.parse().unwrap(),
                    EvmStorageSlot::new_changed(before, after, Default::default()),
                );
            }
            db.insert_account_info(address, account.info.clone());
            state.insert(address, account);
        }
        let codes = code_hashes(&mut db, &state).unwrap();
        let mut scratch = Vec::new();
        let actual = fingerprint(
            &frame,
            &state,
            &codes,
            Fees::default(),
            &mut scratch,
            &mut profile::Timer::new(false),
        );
        let expected = crate::fingerprint::fingerprint(calls, pre, diff);
        assert_eq!(actual.is_ok(), expected.is_ok());
        if let (Ok(a), Ok(b)) = (&actual, &expected) {
            assert_eq!(a, b);
            assert_eq!(
                &scratch[DOMAIN.len()..],
                serde_json::to_vec(&crate::fingerprint::canonical(calls, pre, diff).unwrap())
                    .unwrap()
            );
        }
        actual
    }

    #[test]
    fn golden_and_generated_storage_and_call_variants() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/fingerprint.json"
        ))
        .unwrap();
        assert_eq!(
            compare(&golden["calls"], &golden["pre"], &golden["diff"])
                .unwrap()
                .to_string(),
            golden["expected"]
        );
        for case in 0u64..128 {
            let mut calls = golden["calls"].clone();
            // Include every optional log field combination and multi-digit hex quantities.
            let log = CallLogFrame {
                address: (case & 1 != 0).then_some(Address::repeat_byte(0xab)),
                data: (case & 2 != 0).then_some(Bytes::from(vec![0, 128, 255])),
                index: (case & 4 != 0).then_some(case),
                position: (case & 8 != 0).then_some(case * 71),
                topics: (case & 16 != 0).then_some(vec![B256::repeat_byte(0xfe), B256::ZERO]),
            };
            calls["logs"] = json!([log]);
            let mut child = golden["calls"].clone();
            child["type"] = json!(
                [
                    "CALL",
                    "STATICCALL",
                    "DELEGATECALL",
                    "CALLCODE",
                    "CREATE",
                    "CREATE2",
                    "SELFDESTRUCT"
                ][(case % 4) as usize]
            );
            if case & 32 != 0 {
                child["error"] = json!("execution reverted");
                child["output"] = json!("0x00ff");
            }
            calls["calls"] = json!([child]);
            let mut pre = json!({});
            let mut diff = json!({"pre":{},"post":{}});
            for a in (1u8..=4).rev() {
                let address = format!("{:#x}", Address::repeat_byte(a));
                pre[&address] = json!({"code":if a==4 {"0x"} else {"0x6000"},"storage":{}});
                for k in (0u64..6).rev() {
                    let slot = format!(
                        "{:#x}",
                        B256::from(U256::from(k * 97 + case).to_be_bytes::<32>())
                    );
                    pre[&address]["storage"][&slot] = json!(format!("0x{:x}", case + k));
                    match k % 3 {
                        0 => {
                            diff["pre"][&address]["storage"][&slot] =
                                pre[&address]["storage"][&slot].clone();
                        } // deleted -> zero
                        1 => {
                            diff["post"][&address]["storage"][&slot] =
                                json!(format!("0x{:x}", case + 991));
                        }
                        _ => {} // unchanged reads
                    }
                }
            }
            compare(&calls, &pre, &diff).unwrap();
        }
    }

    #[test]
    fn cancun_noop_marker_preserves_parent_context() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/fingerprint.json"
        ))
        .unwrap();
        let mut calls = golden["calls"].clone();
        calls["calls"] = json!([{"type":"SELFDESTRUCT","from":Address::ZERO,"input":"0x","gas":"0x0","gasUsed":"0x0"}]);
        let noop = compare(&calls, &golden["pre"], &golden["diff"]).unwrap();
        calls["calls"][0]["from"] = calls["to"].clone();
        calls["calls"][0]["to"] = calls["to"].clone();
        calls["calls"][0]["value"] = json!("0x0");
        assert_eq!(
            compare(&calls, &golden["pre"], &golden["diff"]).unwrap(),
            noop
        );
        calls["calls"][0].as_object_mut().unwrap().remove("to");
        assert!(compare(&calls, &golden["pre"], &golden["diff"]).is_err());
    }

    #[test]
    fn unsupported_calls_and_bounds_remain_fail_closed() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/fingerprint.json"
        ))
        .unwrap();
        for kind in ["AUTHCALL", "UNKNOWN"] {
            let mut call = golden["calls"].clone();
            call["type"] = json!(kind);
            assert!(compare(&call, &golden["pre"], &golden["diff"]).is_err());
        }
        let mut call = golden["calls"].clone();
        call["value"] = json!("0x1");
        assert!(compare(&call, &golden["pre"], &golden["diff"]).is_ok());
        call = golden["calls"].clone();
        call["calls"] = json!(vec![golden["calls"].clone(); 128]);
        assert!(compare(&call, &golden["pre"], &golden["diff"]).is_err());
        call = golden["calls"].clone();
        call["input"] = json!(format!("0x{}", "00".repeat(LIMIT / 2)));
        assert!(compare(&call, &golden["pre"], &golden["diff"]).is_err());
    }
}
