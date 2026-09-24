//! V2 reference encoder: call/value tree, code/storage/nonces and application balance deltas.
//! RPC preflight has no protocol fee charges on the pinned Reth version.
use alloy_primitives::{B256, U256, hex, keccak256};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const DOMAIN: &[u8] = b"OPS_EXECUTION_V2\0";

fn word(v: Option<&Value>) -> Result<String, String> {
    let s = v
        .and_then(Value::as_str)
        .unwrap_or("0x0")
        .trim_start_matches("0x");
    if s.len() > 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bad storage word".into());
    }
    Ok(format!("0x{:0>64}", s.to_lowercase()))
}

fn call(v: &Value, parent_storage: Option<&str>, count: &mut usize) -> Result<Value, String> {
    *count += 1;
    if *count > 128 {
        return Err("more than 128 calls".into());
    }
    let kind = v["type"].as_str().ok_or("missing call type")?;
    if ![
        "CALL",
        "STATICCALL",
        "DELEGATECALL",
        "CALLCODE",
        "CREATE",
        "CREATE2",
        "SELFDESTRUCT",
    ]
    .contains(&kind)
    {
        return Err(format!("unsupported call: {kind}"));
    }
    let failed_create =
        ["CREATE", "CREATE2"].contains(&kind) && v.get("error").is_some_and(|e| !e.is_null());
    let mut from = v["from"].as_str().ok_or("missing caller")?.to_lowercase();
    let noop_self = kind == "SELFDESTRUCT"
        && v["to"].is_null()
        && from == "0x0000000000000000000000000000000000000000"
        && word(v.get("value"))? == word(None)?
        && v["error"].is_null()
        && parent_storage.is_some();
    let to = if noop_self {
        from = parent_storage.unwrap().to_lowercase();
        from.clone()
    } else {
        v["to"]
            .as_str()
            .or(failed_create.then_some(""))
            .ok_or("missing call destination")?
            .to_lowercase()
    };
    let storage = if kind == "DELEGATECALL" || kind == "CALLCODE" {
        parent_storage.ok_or("root delegate")?
    } else if kind == "SELFDESTRUCT" {
        &from
    } else {
        &to
    };
    let children = v
        .get("calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|c| call(c, Some(storage), count))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"type":kind,"from":from,
        "to":to,"storageAddress":storage,"input":v["input"].as_str().unwrap_or("0x").to_lowercase(),
        "output":v["output"].as_str().unwrap_or("0x").to_lowercase(),
        "failed":v.get("error").is_some_and(|e| !e.is_null()),"value":word(v.get("value"))?,"calls":children,
        "logs":v.get("logs").cloned().unwrap_or(json!([]))}))
}

pub fn number(v: &Value) -> Result<U256, String> {
    match v {
        Value::Null => Ok(U256::ZERO),
        Value::String(s) => s.parse::<U256>().map_err(|e| e.to_string()),
        Value::Number(n) => n.as_u64().map(U256::from).ok_or("invalid uint64".into()),
        _ => Err("invalid integer".into()),
    }
}

pub fn balance_delta(before: U256, after: U256) -> String {
    if after >= before {
        (after - before).to_string()
    } else {
        format!("-{}", before - after)
    }
}

pub fn canonical(calls: &Value, pre: &Value, diff: &Value) -> Result<Value, String> {
    let calls = call(calls, None, &mut 0)?;
    let mut accounts = Vec::new();
    let mut created = BTreeSet::new();
    fn creations(v: &Value, addresses: &mut BTreeSet<String>) {
        if matches!(v["type"].as_str(), Some("CREATE" | "CREATE2"))
            && let Some(to) = v["to"].as_str()
        {
            addresses.insert(to.to_lowercase());
        }
        for child in v["calls"].as_array().into_iter().flatten() {
            creations(child, addresses);
        }
    }
    creations(&calls, &mut created);
    let mut addresses = BTreeSet::new();
    for map in [pre, &diff["pre"], &diff["post"]] {
        if let Some(map) = map.as_object() {
            addresses.extend(map.keys());
        }
    }
    for address in addresses {
        let account = &pre[address];
        let before_diff = &diff["pre"][address];
        let post = &diff["post"][address];
        let deleted = !before_diff.is_null() && post.is_null();
        let code_before = account["code"].as_str().unwrap_or("0x");
        let code_after = if deleted {
            "0x"
        } else {
            post["code"].as_str().unwrap_or(code_before)
        };
        let balance_before = number(&account["balance"])?;
        let balance_after = if deleted {
            U256::ZERO
        } else if post["balance"].is_null() {
            balance_before
        } else {
            number(&post["balance"])?
        };
        let delta = balance_delta(balance_before, balance_after);
        let mut slots = BTreeSet::new();
        for map in [
            &account["storage"],
            &before_diff["storage"],
            &post["storage"],
        ] {
            if let Some(map) = map.as_object() {
                slots.extend(map.keys());
            }
        }
        let contract = code_before != "0x"
            || code_after != "0x"
            || !slots.is_empty()
            || created.contains(&address.to_lowercase());
        if !contract && delta == "0" {
            continue;
        }
        let nonce_before = if contract {
            number(&account["nonce"])?
        } else {
            U256::ZERO
        };
        let nonce_after = if !contract || deleted {
            U256::ZERO
        } else if post["nonce"].is_null() {
            nonce_before
        } else {
            number(&post["nonce"])?
        };
        let mut storage = Vec::new();
        for slot in slots {
            let before = account["storage"].get(slot);
            let changed = deleted
                || before_diff["storage"].get(slot).is_some()
                || post["storage"].get(slot).is_some();
            let after = if changed {
                post["storage"].get(slot)
            } else {
                before
            };
            storage.push(json!({"slot":word(Some(&json!(slot)))?,"before":word(before)?,"after":word(after)?}));
        }
        storage.sort_by(|a, b| a["slot"].as_str().cmp(&b["slot"].as_str()));
        accounts.push(json!({"address":address.to_lowercase(),"codeBefore":keccak256(hex::decode(code_before).map_err(|e|e.to_string())?),"codeAfter":keccak256(hex::decode(code_after).map_err(|e|e.to_string())?),"nonceBefore":nonce_before.to_string(),"nonceAfter":nonce_after.to_string(),"balanceDelta":delta,"storage":storage}));
    }
    Ok(json!({"calls":calls,"accounts":accounts}))
}

pub fn fingerprint(calls: &Value, pre: &Value, diff: &Value) -> Result<B256, String> {
    profiled_fingerprint(calls, pre, diff, &mut crate::profile::Timer::new(false))
}

pub fn profiled_fingerprint(
    calls: &Value,
    pre: &Value,
    diff: &Value,
    timer: &mut crate::profile::Timer,
) -> Result<B256, String> {
    let canonical = canonical(calls, pre, diff)?;
    timer.lap(6);
    let bytes = serde_json::to_vec(&canonical).map_err(|e| e.to_string())?;
    drop(canonical);
    timer.lap(7);
    if bytes.len() > 1_048_576 {
        return Err("fingerprint exceeds 1 MiB".into());
    }
    let mut input = DOMAIN.to_vec();
    input.extend(bytes);
    let hash = keccak256(input);
    timer.lap(8);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_go_rust_golden() {
        let v: Value = serde_json::from_str(include_str!(
            "../../../internal/nodeapproval/testdata/fingerprint.json"
        ))
        .unwrap();
        assert_eq!(
            fingerprint(&v["calls"], &v["pre"], &v["diff"])
                .unwrap()
                .to_string(),
            v["expected"].as_str().unwrap()
        );
    }
}
