| Review item | Finding |
|---|---|
| Authentication | `hash_mode=3` changes the signed member domain to `OPS_APPROVAL_V3`. Both JSON and binary mixed-mode batches are tested. Mode downgrade, unknown mode and every mutated binary byte are rejected. |
| Encoding | Go and Rust share a binary fixture. Parent indices and ordered records preserve topology. Length-prefix calldata; fixed-width fields; limits of 128 frames/1 MiB. |
| Executed code | Every call target's code hash is bound. Delegate/callcode records bind the storage context. Actual code comes from the current pre-commit node state; storage changes earlier in a block do not cause stale code lookup. |
| Lifecycle | Any lifecycle frame in preflight, even reverted, selects strict V2. Such a frame encountered under a calls approval rejects the transaction; no runtime downgrade/retry using a weaker mode. |
| Commit | A match returns the original EVM result; a mismatch returns an error before commit. Real tests check receipts, storage, sender nonce and balance. |
| Intentional relaxation | Storage, output and log equality are removed. A regression explicitly demonstrates the resulting internal-accounting limitation. Full calldata stays exact; no inference from transaction history. |
| State-policy boundary | Existing OPS DB gates remain; a state-dependent business policy requiring extra predicates must use strict mode until those predicates exist. |
| Timing | Call records use a reused binary buffer and local code metadata. Signatures remain off the execution thread. Compare off/strict/calls on one binary; do not interpret producer timing as whole-stack TPS. |

[Plan and critique](CALL-HASH-PLAN.md) · [Brief results](CALL-HASH.md)
