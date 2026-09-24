//! V3: compact, versioned call identity/input fingerprint. No application state hash.
use crate::profile;
use alloy_primitives::{Address, B256, KECCAK256_EMPTY, U256, keccak256};
use alloy_rpc_types_trace::geth::CallFrame;

const DOMAIN: &[u8] = b"OPS_CALLS_V3\0";
const LIMIT: usize = 1_048_576;

pub fn fingerprint(
    call: &CallFrame,
    code: impl FnMut(Address) -> Result<B256, String>,
    scratch: &mut Vec<u8>,
    timer: &mut profile::Timer,
) -> Result<B256, String> {
    scratch.clear();
    scratch.extend_from_slice(DOMAIN);
    scratch.extend_from_slice(&0u32.to_be_bytes());
    let mut encoder = Encoder {
        bytes: scratch,
        code,
        count: 0,
    };
    encoder.call(call, u32::MAX, None)?;
    let count = encoder.count;
    scratch[DOMAIN.len()..DOMAIN.len() + 4].copy_from_slice(&count.to_be_bytes());
    timer.lap(10);
    let hash = keccak256(&*scratch);
    timer.lap(8);
    Ok(hash)
}

struct Encoder<'a, F> {
    bytes: &'a mut Vec<u8>,
    code: F,
    count: u32,
}
impl<F: FnMut(Address) -> Result<B256, String>> Encoder<'_, F> {
    fn call(
        &mut self,
        call: &CallFrame,
        parent: u32,
        parent_storage: Option<Address>,
    ) -> Result<(), String> {
        if self.count >= 128 {
            return Err("more than 128 calls".into());
        }
        let kind = match call.typ.as_str() {
            "CALL" => 1,
            "STATICCALL" => 2,
            "DELEGATECALL" => 3,
            "CALLCODE" => 4,
            _ => return Err("lifecycle/unknown operation under call-only approval".into()),
        };
        let to = call.to.ok_or("missing call destination")?;
        let storage = if kind == 3 || kind == 4 {
            parent_storage.ok_or("root delegate")?
        } else {
            to
        };
        if self
            .bytes
            .len()
            .checked_add(134)
            .and_then(|n| n.checked_add(call.input.len()))
            .is_none_or(|n| n > LIMIT)
        {
            return Err("call fingerprint exceeds 1 MiB".into());
        }
        let this = self.count;
        self.count += 1;
        self.bytes.extend_from_slice(&parent.to_be_bytes());
        self.bytes.push(kind);
        for address in [call.from, to, storage] {
            self.bytes.extend_from_slice(address.as_slice());
        }
        let mut code = (self.code)(to)?;
        if code == B256::ZERO {
            code = KECCAK256_EMPTY;
        }
        self.bytes.extend_from_slice(code.as_slice());
        self.bytes
            .extend_from_slice(&call.value.unwrap_or(U256::ZERO).to_be_bytes::<32>());
        self.bytes.push(u8::from(call.error.is_some()));
        self.bytes
            .extend_from_slice(&(call.input.len() as u32).to_be_bytes());
        self.bytes.extend_from_slice(&call.input);
        for child in &call.calls {
            self.call(child, this, Some(storage))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use serde_json::Value;
    use std::collections::HashMap;
    fn fixture() -> (CallFrame, HashMap<Address, B256>, B256) {
        let v: Value = serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/call-v3.json"
        ))
        .unwrap();
        let codes = v["pre"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(a, v)| {
                (
                    a.parse().unwrap(),
                    keccak256(hex::decode(v["code"].as_str().unwrap_or("0x")).unwrap()),
                )
            })
            .collect();
        (
            serde_json::from_value(v["calls"].clone()).unwrap(),
            codes,
            v["expected_calls"].as_str().unwrap().parse().unwrap(),
        )
    }
    fn hash(call: &CallFrame, codes: &HashMap<Address, B256>) -> Result<B256, String> {
        fingerprint(
            call,
            |a| codes.get(&a).copied().ok_or("missing code".into()),
            &mut Vec::new(),
            &mut profile::Timer::new(false),
        )
    }
    #[test]
    fn go_golden_and_deliberately_ignored_outputs() {
        let (mut call, codes, want) = fixture();
        assert_eq!(hash(&call, &codes), Ok(want));
        call.output = Some(vec![1, 2, 3].into());
        call.calls[0].output = Some(vec![9].into());
        assert_eq!(hash(&call, &codes), Ok(want));
    }
    #[test]
    fn call_boundaries_inputs_code_context_and_caught_reverts_are_bound() {
        for change in 0..9 {
            let (mut call, mut codes, want) = fixture();
            match change {
                0 => call.calls.swap(0, 1),
                1 => {
                    let nested = call.calls[0].calls.remove(0);
                    call.calls.push(nested);
                }
                2 => call.calls[0].calls[0].typ = "CALLCODE".into(),
                3 => call.calls[0].calls[0].input = vec![99].into(),
                4 => call.calls[0].calls[0].value = Some(U256::from(8)),
                5 => call.calls[0].calls[0].error = None,
                6 => call.calls.push(call.calls[0].clone()),
                7 => {
                    codes.insert(call.to.unwrap(), B256::repeat_byte(7));
                }
                _ => call.calls[0].calls[0].from = Address::repeat_byte(8),
            }
            assert_ne!(hash(&call, &codes), Ok(want), "change {change}");
        }
    }
    #[test]
    fn missing_code_limits_and_lifecycle_fail_closed() {
        let (call, codes, _) = fixture();
        assert!(hash(&call, &HashMap::new()).is_err());
        for kind in ["CREATE", "CREATE2", "SELFDESTRUCT", "AUTHCALL"] {
            let mut changed = call.clone();
            changed.calls[0].calls[0].typ = kind.into();
            assert!(hash(&changed, &codes).is_err());
        }
        let mut large = call.clone();
        large.input = vec![0; LIMIT].into();
        assert!(hash(&large, &codes).is_err());
        let mut many = call.clone();
        let mut leaf = call.clone();
        leaf.calls.clear();
        many.calls = vec![leaf; 128];
        assert!(hash(&many, &codes).is_err());
    }
}
