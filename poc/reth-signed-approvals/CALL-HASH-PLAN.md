Implement a signed call-only fingerprint for ordinary transactions; preserve strict V2 for lifecycle operations and explicit strict mode.

| Step | Required evidence |
|---|---|
| Plan and critique | Define encoding and signed mode; identify protections intentionally removed. |
| TDD | Reproduce shared-state rejection; require matching Go/Rust bytes, sensitivity to call identity/inputs/code/context/order, and signed-mode tamper rejection. |
| Implementation | Binary V3 call records, existing async signatures/transport, one provisional execution. Full calldata stays exact. |
| Real execution | Concurrent counter writes and shared token balances succeed. Cross-org redirects, changed nested inputs/value/code and caught-revert calls fail before commit. Strict lifecycle tests still pass. |
| Performance | Same binary, off/strict/calls; identical warmed transactions and block hashes; rotated modes; separate concurrent-counter success counts. |
| Review | Check rollback, signed version, unknown modes, bounds and fallback; update brief usage/results and limitations. |

Critique: call-only equality does not prove identical financial outcomes inside a contract. Storage-only changes, returned values and logs may differ. Different call branches, variable internal arguments and lifecycle state contention remain constrained. No dynamic policy generation, parameter masks or arbitrary predicates are implemented. A transaction sender cannot opt out of the OPS-selected mode. No fallback from a mismatching calls approval to another mode at execution time.

Encoding: OPS_CALLS_V3 NUL, uint32 frame count, preorder records with uint32 parent index (root 0xffffffff), uint8 operation, caller/code/storage addresses, executed code hash, uint256 value, uint8 failed, uint32 calldata length and calldata. All integers big-endian; at most 128 frames and 1 MiB. Only CALL/STATICCALL/DELEGATECALL/CALLCODE participate. Any CREATE/CREATE2/SELFDESTRUCT anywhere, including reverted frames, selects strict V2 during preflight; encountering one under a call-only approval denies execution.

Authentication: hash_mode 0 retains legacy strict V2 and OPS_APPROVAL_V1 domain; hash_mode 3 selects calls V3 and OPS_APPROVAL_V3 domain. The mode is therefore signed, including in binary batches, without increasing the 120-byte approval member. Unknown modes/domains fail closed. Default OPS setting becomes calls; OPS_APPROVAL_HASH_MODE=strict retains the prior behavior.
