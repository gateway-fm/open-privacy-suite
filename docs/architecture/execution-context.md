# Authenticated execution identity and fact protocol

Status: implementation contract, 16 September 2026. Reth is the selected node.

## User-requested review reminder

**Review this change before accepting the finished implementation.** The user approved preserving shared signing addresses on 16 September and specifically asked that the implementation be documented for later inspection.

Migration 027 permits several OPS users to link the same Ethereum address. Recovering the transaction signer cannot identify which user's permissions apply. OPS therefore supplies the authenticated user's stable internal ID in a signed, transaction-bound identity context. It does not send a simulated allow decision or a predicted call tree. Reth evaluates actual frames using that identity and the current block-pinned facts and policy bytecode.

Required review evidence:

- Two users share one signing key but have different memberships; each receives only their own permissions.
- The same pending signed transaction cannot be rebound to another principal.
- A ticket minted before a ban, unlink or membership removal does not preserve revoked authority.
- Concurrent calls and gas estimates never share mutable principal context.
- Missing, forged, expired, wrong-network or conflicting context denies execution.
- Restart, ticket expiry and replacement have explicit status/recovery, without resubmitting a deployment accidentally.
- Historical user queries use current permissions; original execution facts are reserved for authorised forensic replay.

## Signed envelopes

The node accepts only version 1 envelopes from configured Ed25519 keys. JSON envelope fields are `version`, `kind`, `key_id`, `payload`, `signature`. Payload and signature are standard base64. Unknown/duplicate fields, oversized input and noncanonical field encodings are rejected. Every declared field is required. Null is allowed only for explicitly nullable candidate and status-evidence fields; fact fields reject it. Empty collections are encoded as [], and zero/false fields must be present explicitly.

The signed bytes are ASCII `OPS_NODE_POLICY_V1` followed by NUL, then three length-prefixed byte strings: kind, key ID, and the exact decoded payload. Each length is an unsigned 32-bit big-endian integer. Verifiers use the received payload bytes, not a JSON reserialization; struct ordering therefore does not depend on the verifier language. The payload is strictly decoded only after signature verification. Kind and key ID are authenticated so envelopes cannot be repurposed across message types or issuers.

Every payload contains `network` (`chain_id` and unique `deployment_id`), `issued_at`, `expires_at` in Unix seconds, and its type-specific data. Verifiers check the expected network, supported version, key, signature, validity interval and allowed clock skew. Validity windows are bounded. A signed heartbeat is necessary even without changes.

Kinds:

- `identity`: scope (`transaction` or `simulation`), context ID, principal ID, selected organisation ID, signer, exact transaction/request hash, required minimum snapshot version. No permission verdict or membership claims. The selected organisation preserves OPS's existing request organisation resolution; the principal must still hold a current membership there. Each registered frame selects its storage owner's policy and the principal's memberships in that organisation.
- `snapshot`: complete versioned facts and active policy artifacts; a coherent bootstrap/checkpoint.
- `delta`: previous/current version, previous payload digest, typed upserts and explicit deletes. A coherent export can coalesce several committed versions. Apply the entire final graph atomically; a missing predecessor requires resynchronisation.
- `heartbeat`: current committed/applied stream watermark and digest; does not advance facts itself.

Principal IDs are internal user IDs, not DIDs. Group and organisation IDs retain their stable database identities; policy ABI group words are `keccak256(group ID UTF-8)` as in the existing compiler. Addresses and hashes are lower-case `0x` hex of exact length. Compiled artifacts include SHA-256 bytecode digests and remain private to the node.

The installed digest is SHA-256 of the exact last applied snapshot or delta payload, including its original header, encoded as 64 lowercase hex characters without `0x`. A heartbeat references that same version and digest and extends a separate freshness lease. It never rewrites the snapshot header, facts, version or digest. A candidate execution pins both immutable facts and its verified lease. Same-version payload rewrites and backward leases are rejected; identical retries are idempotent. A newer full snapshot can resynchronise a receiver. Checkpoints retain the signed base snapshot and subsequent deltas plus the current signed lease so restart can verify the chain independently.

Delta `upserts` contains required arrays named `principals`, `groups`, `contracts`, `policies`, and `sanctions`, using the full snapshot entity schemas. `deletes` has the same required arrays: principal/group IDs, contract addresses, policy keys, and `{org_id,address}` sanctions. A grouped policy key is the organization ID, NUL, and group ID; a legacy single-artifact key is the organization ID alone. A key cannot repeat or appear in both sets. Missing deletion targets and invalid final references reject the entire update.

Current operational claim authority comes from `group_access.claims`. As in the existing RBAC resolver, a group's claims apply to a registered target only while that same group has a contract grant. The old physical `contract_grants.claims` column is not the current resolver's authority. Exported target masks preserve that behavior; one group's upgrade claim cannot authorize another group's rule. Sanctions retain their organisation scope (empty organisation means global), and shared infrastructure retains its optional code-hash pin.

## Binding and delivery

OPS verifies authentication, linked signer and admission gates before issuing identity context. Transaction context binds the signed raw transaction hash. Reth's selection boundary must retain that hash before converting the transaction to an EVM environment; signer/nonce alone is not the binding.

Simulation context binds the exact requested operation, call parameters, forced linked `from`, block reference and permitted overrides. The internal request carries base64 exact JSON bytes for `{method, params, dry_run, candidate_policy}` with optional `candidate_policies` for a complete group-artifact set; allowed methods are `eth_call`, `eth_estimateGas` and `debug_traceCall`. A non-null legacy `candidate_policy` and `candidate_policies` are mutually exclusive. An explicit empty candidate list replaces the selected organization's candidate set with no grants; absence does not request that replacement. The hash is SHA-256 of ASCII `OPS_SIMULATION_V1`, NUL, a uint32 big-endian byte length, and those exact decoded JSON bytes. The node hashes before strict parsing. It never reserializes equivalent JSON to compute the binding, so whitespace/ordering changes invalidate the hash. Privileged dry-run is explicit and authenticated; callers cannot supply it through ordinary user RPC parameters.

Group-artifact wire/storage compatibility and the all-or-none replacement rules
are specified in [Execution artifact granularity](../implementation/execution-artifact-granularity.md).
Each artifact carries an optional `group_id`; absence identifies a previously
approved organization-wide artifact. One organization's set cannot mix legacy
and grouped artifacts or different document digests/revisions. OPS and Reth must
be upgraded together before grouped revisions are activated.

Transaction bindings are indexed by signed transaction hash. Simulation bindings are indexed by context ID and must additionally match the request hash: different principals can simulate identical requests without sharing identity. Golden signatures, snapshot bytes and simulation hashes live in `internal/nodepolicy/testdata/envelopes-v1.json` and are consumed by both Go and Rust tests.

Ingestion is acknowledged and retried idempotently. OPS forwards a transaction only after its context is accepted, or records an explicit pending-context state. Reth resolves current memberships, links and bans from the immutable snapshot selected for that execution. A signed identity cannot freeze old permissions. Binding conflicts are errors, never last-writer-wins.

Snapshot version assignment is serialised in Postgres commit order. The fact mutation and outbox row are atomic. The node applies whole batches, pins immutable state per candidate block, and checkpoints acknowledged state. Lag beyond the hard validity bound prevents execution. Historical produced-block manifests retain the exact snapshot, policy revisions and principal contexts needed for self-import/replay; ordinary user queries still use current access rights.

## Implementation and evidence index

- Go protocol: `internal/nodepolicy/`.
- Reth private evaluator: `node/reth/`.
- Test evidence is recorded under `docs/implementation/evidence/` as each slice passes.
- End-to-end shared-signer and revocation evidence is required before marking this checklist complete.

This document describes the accepted contract. It does not claim all listed integration points are already implemented.

## Candidate privacy and finality

A candidate policy is optional, bound to the exact signed simulation and evaluated only in that request. Ordinary candidate previews still enforce active application permissions and cannot perform candidate live state/account reads; they return no output if the candidate attempts one. A named full human administrator may explicitly request audited diagnostics, with independent selected-organization isolation and code pins retained. Approved active policy record getters keep their reviewed authority.

Transaction status distinguishes canonical inclusion from finalized inclusion. OPS materializes successful contract ownership, deployment grants and visibility only after canonical finality evidence; provisional outcomes remain polled and can return to pending after reorganization. Signed identity renewal cannot change the original principal, organization, signer or visibility intent. No recovery path automatically resubmits a transaction.
