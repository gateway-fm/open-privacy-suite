# Redaction Engine — Developer Specification

**Status:** Living document. Update when adding new entity types, fixing gaps, or changing visibility semantics.

---

## Invariant: RPC access and explorer visibility must agree

For every (viewer, address) pair, the RPC access layer (`rbac.AccessController.CheckAccess`) and the explorer visibility layer (`db.GetBatchVisibility`) must return consistent outcomes. If CheckAccess allows a viewer to interact with an address, `GetBatchVisibility` must return `VisibilityFull` for that address for the same viewer. If CheckAccess denies, visibility must be `Hidden` or `Redacted` — never `Full`.

Any asymmetry is a bug. The historical failure mode (RD-849) was tier 3 admin-claim users getting RPC access to every contract in their org while the explorer correctly treated the same contracts as `[PRIVATE]`. The symmetry is enforced by `e2e/access_visibility_symmetry_test.go` — every change to either layer must keep that test green.

The rule also drives how admin and deploy claims are scoped: they grant bypass on **explicitly granted contracts only**, not org-wide access. Org-wide access is the exclusive privilege of `is_org_admin` groups (tier 2), materialized as explicit `ContractAccess` for every org contract.

---

## 1. Overview

The redaction engine enforces the privacy promise at two independent layers:

### Layer 1 — RPC Filter (`internal/rbac/response_filter.go`)

Runs on every JSON-RPC response **before** it is returned to the calling client. The caller is a raw JSON-RPC user (wallet, script, block explorer backend). Redaction here is binary: a non-participant receives `null` or has their entry removed entirely. There is no `[PRIVATE]` placeholder at this layer — the client simply sees no data.

Called by: `proxy.go` → `responseFilter.Filter(method, response, callerLinkedAddresses)`

### Layer 2 — Explorer API Redactor (`internal/explorer/redaction/`)

Runs on structured data objects before they are serialised and returned by the Explorer REST API (`/api/explorer/...`). The caller is a user with an authenticated session and a known visibility level for each address. At this layer redaction is graduated: addresses can be replaced with `[PRIVATE]`, values zeroed, or entries dropped, depending on their visibility level.

Called by: Explorer API handlers → `RedactionEngine.RedactTransaction(tx, viewerOrgID)` etc.

### Layer 2a — SQL-Level Visibility Filtering (`internal/explorer/visibility_filter.go`)

Runs **before** data is fetched from the explorer database. Where Layer 2 redacts individual fields on already-fetched rows, this layer prevents invisible rows from being fetched at all. This is critical for correct pagination and count totals — without it, a page of 25 items might contain only 3 visible rows after post-fetch redaction.

The filter is built by `buildVisibilityFilter()`:

1. `GetAllRegisteredAddresses()` loads every contract address from the RBAC database.
2. `GetBatchVisibility(addresses, viewerOrgID)` classifies each address as Full, Redacted, or Hidden for the current viewer.
3. Addresses classified as Hidden are collected into a set.
4. A `VisibilityFilter` struct is constructed containing the hidden address set.

The SQL `WHERE NOT(...)` clause excludes:

- **Contract creation transactions from hidden deployers**: `to_address IS NULL AND from_address IN (hidden set)` — deployment activity from other orgs is completely invisible.
- **Transactions where both from AND to are hidden**: neither party is visible to the viewer, so the transaction is dropped entirely.

**Count/Total Security:** All paginated endpoints return only the count of rows that pass the visibility filter, never the raw database total. This prevents information disclosure about private transaction volume. A viewer cannot determine how many transactions exist that they are not allowed to see.

**Block Transaction Counts:** Per-block transaction counts returned by the explorer API are adjusted per-viewer via `GetBlockTransactionCountFiltered`, which applies the same visibility filter. The `transaction_count` in block list responses reflects only the transactions visible to the current viewer.

**Chain Stats:** `TotalTransactions` and `TotalAddresses` in the `/api/explorer/stats` response are filtered for viewer visibility. The raw database totals are never exposed.

**Transaction History:** Daily and hourly transaction count charts (`/api/explorer/stats/charts/txs`) are filtered to exclude hidden transactions. A viewer's chart data reflects only transaction volume they are permitted to see.

**Contract Creation Redaction:** Contract deployments from non-identifiable deployers (Hidden visibility) are completely dropped at the SQL level, not just field-redacted. This is stronger than Layer 2's field-level redaction: the transaction never appears in any list, and is not counted in any total.

**Interaction with Layer 2:** SQL-level filtering handles row-level drops (entire transactions removed). Layer 2 (`RedactTransactions`) still runs on the surviving rows for field-level redaction: replacing addresses with `[PRIVATE]`, zeroing values, and applying the participant visibility override. The two layers are complementary and both are required.

---

## 2. Visibility Levels

These levels are computed per-address by the redaction engine based on the viewer's RBAC grants and the address's org membership.

| Level | Meaning | Viewer relationship |
|-------|---------|---------------------|
| **Full** | Address and all associated data shown without modification | Viewer owns the address, or holds an explicit grant to it |
| **Pseudonymous** | Address replaced with a stable, deterministic pseudonym (e.g. `0xPSEUDO…`) | Address is redacted but viewer holds a partial grant; not yet implemented for most entity types |
| **Redacted** | Address replaced with `[PRIVATE]`; value and calldata zeroed | Address belongs to another org; viewer has no grant |
| **Hidden** | Entry dropped entirely (address not disclosed even as `[PRIVATE]`) | Address belongs to another org and viewer has no right to see the tx at all |

**Drop rule:** A transaction/transfer/log is dropped if **both** sides are Hidden. If one side is Hidden or Redacted and the other is Full, the entry is kept with the private side masked.

**Nonce rule:** Nonce is tied to the sender. Strip nonce when `from` is Hidden or Redacted. Preserve nonce when only `to` is Hidden or Redacted (nonce belongs to the sender, who is visible).

**Unregistered addresses (private by default):** Addresses not present in the `contracts` or `preregistered_addresses` tables and not linked via `eth_address_links` are treated as **private** (`VisibilityHidden`). The only exception is EVM precompile addresses (0x01-0x09), which are always `VisibilityFull` since they are native EVM functions. Contracts deployed through the proxy are **never unregistered** — they are pre-registered to the deployer's org before the transaction is forwarded to the node.

### 2.1 Visibility Resolution by Address Type

`GetBatchVisibility` resolves each address independently based on what kind of address it is and the viewer's relationship to it:

| Address type | How identified | Anonymous viewer | Org admin viewer | Grant holder (any claim) | Standard org member (no grant) | Address owner |
|---|---|---|---|---|---|---|
| **Org contract** | In `contracts` table | Redacted | **Full** (if admin of owning org) | **Full** (group has contract_grant) | Redacted | N/A |
| **User EOA** | In `eth_address_links` | Hidden | **Hidden** | Hidden | Hidden | **Full** |
| **EVM Precompile** | Address 0x01-0x09 | Full | Full | Full | Full | Full |
| **Unregistered** | Not in contracts, eth_address_links, or precompiles | **Hidden** | **Hidden** | **Hidden** | **Hidden** | **Hidden** |

**Key implication for org admins:** An org admin has `VisibilityFull` on their org's **contracts** but NOT on individual **user EOAs**. User EOAs are personal wallets — they remain `VisibilityHidden` to everyone except the owner (and recipients of disclosure grants). This means:

- Contract calls (EOA → contract) are **visible** to org admin — the contract side is Full, so the tx survives the SQL filter. The EOA side is redacted as `[PRIVATE]`.
- Contract-to-contract interactions are **fully visible** to org admin.
- EOA-to-EOA transfers (e.g., ETH sent between two users) are **dropped** — both sides are Hidden.
- Contract deployments from user EOAs (`from=EOA, to=NULL`) are **dropped** — the deployer EOA is Hidden.

To see user EOA activity, an org admin would need a **disclosure grant** from each user, or the visibility model would need to be changed to treat user EOAs differently for org admins (design decision, see G11 below).

### 2.2 Full Access Criteria (3-Tier Admin Model)

`VisibilityFull` for org contracts is granted to viewers who are members of a group that meets one of:
1. `is_org_admin = true` on the group (**tier 2 — org admin** — sees ALL contracts in the org)
2. The group has a `contract_grant` linking it to the specific contract (any claims — `read`, `write`, `deploy`, `admin`)

**Tier 3 (contract admin):** Having `'admin' = ANY(group_access.claims)` without `is_org_admin = true` does **not** grant org-wide contract visibility. Contract admins see only contracts explicitly granted to their group via `contract_grant`. Their `admin` claim gives them RBAC bypass (event rule bypass, all functions allowed) on those granted contracts only — not org-wide visibility.

Path 1 grants visibility on ALL contracts in the org without needing explicit per-contract grants. This is the org admin (tier 2) privilege. Path 2 is for all grant holders (including contract admins): if a user can access a contract via their group's grant, the contract should not appear as `[PRIVATE]` in the explorer.

Users in the same org but in a group **without** a `contract_grant` and **without** `is_org_admin` still see `VisibilityRedacted`.

---

## 3. Entity Field Matrix

### 3.1 Transaction (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | Both-sides-hidden → drop entire tx (org admins keep it when `ORG_ADMIN_VIEW_USER_TXS=true`, address stays `[PRIVATE]` — see §3.8) |
| `to` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | Contract address if deploy; nil if null |
| `value` | 0 / nil | 0 / nil | 0 / nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted. **Exception:** preserved for org admins when `ORG_ADMIN_VIEW_USER_TXS=true` (§3.8) — resolves the tx-vs-log amount asymmetry |
| `inputData` | nil | nil | nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted. Stays stripped even under the §3.8 admin view (calldata embeds addresses) |
| `error` | nil | nil | nil | unchanged | Yes | Partial | Zeroed when either side hidden/redacted |
| `revertReason` | nil | nil | nil | unchanged | Yes | Partial | Zeroed when either side hidden/redacted |
| `nonce` | nil | nil | nil | unchanged | Yes | Yes | Nil only when FROM is hidden/redacted; not when only TO is |
| `gasUsed` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted: gas params are not identity-revealing in isolation; visible to all RPC participants |
| `gasPrice` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `maxFeePerGas` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `maxPriorityFeePerGas` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `gasLimit` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `contractAddress` | — (tx dropped)* | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | *Dropped by SQL visibility filter when deployer is hidden |
| `txCategories` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted: derived labels, not raw addresses |

### 3.2 InternalTransaction (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `to` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `value` | 0 / nil | 0 / nil | 0 / nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted |
| `input` | nil | nil | nil | unchanged | Yes | Yes | |
| `output` | nil | nil | nil | unchanged | Yes | Yes | |
| `error` | nil | nil | nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted (revert strings can embed the hidden counterparty's address/reason). **G4 resolved (RD-1177).** |
| `gas` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `gasUsed` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |

### 3.3 TokenTransfer (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `to` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `value` | 0 / nil | 0 / nil | 0 / nil | unchanged | Yes | Yes | |
| `tokenAddress` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted: the token contract is public infrastructure |

### 3.4 Log (Explorer API)

Log redaction depends on the visibility of the **emitting contract address**, not the transaction parties.

| Field | Emitter Hidden | Emitter Redacted | Emitter Full | Implemented | Tested | Notes |
|-------|---------------|-----------------|--------------|-------------|--------|-------|
| Entry | Dropped | Kept | Kept | Yes | Yes | When emitter is hidden, the entire log entry is removed |
| `address` (emitter) | — (entry dropped) | `[PRIVATE]` | unchanged | Yes | Yes | |
| `topics[0..3]` (when emitter hidden) | — (entry dropped) | all nil | — | Yes | Partial | |
| `topics[0..3]` (when emitter redacted) | — | all nil | — | Yes | Partial | |
| `topics[1..3]` (when emitter full) | — | — | Scanned for zero-padded embedded addresses; private ones zeroed | Yes | Yes | topics[0] is event signature hash for non-anonymous events; address pattern check skips it naturally |
| `data` (when emitter hidden) | — (entry dropped) | — | — | Yes | Partial | |
| `data` (when emitter redacted) | — | zeroed | — | Yes | Partial | |
| `data` (when emitter full + ABI registered) | — | — | Non-indexed address params decoded, private ones zeroed | Yes | Partial | |
| `data` (when emitter full + NO ABI) | Entire log denied at both layers (RPC and Explorer) | — | — | Yes | Yes | **G5 closed (RD-875 RPC + RD-889 explorer).** Without an ABI we can't decode non-indexed `address` params; both layers fail closed (drop the log) when no ABI is resolvable for the emitting contract. Admin bypass on the RPC layer (RD-751) still applies. Operator must register a custom ABI or set `metadata.token_type` to a built-in registry value (ERC-20 / ERC-721) before any event becomes visible. Grant save handler also rejects up-front. |
| `data` (when emitter visible + dynamic non-indexed params) | Entire log denied at both layers unless contract has `events_allow_dynamic_payload = true` | — | — | Yes | Yes | **M15 closed (security audit follow-up to RD-915).** Pre-M15 the static-slot scanner read only AddressTy + bytes32 slots; dynamic types (`bytes`, `string`, dynamic arrays, dynamic structs) passed through verbatim. Bridge / forwarder / smart-wallet contracts that embed foreign-org addresses inside a `bytes` payload leaked them to any reader. Both layers now drop the log when the matching event's ABI declares any dynamic non-indexed param, unless the operator has explicitly opted the contract out via `contracts.events_allow_dynamic_payload`. Admin viewers (RD-890) and visibleTo-unlock viewers (RD-874) bypass — they resolve before the gate. Opt-out is admin-only (super-admin via X-Admin-Token) via `PUT /orgs/:org_id/contracts/:address/events-allow-dynamic-payload`; default FALSE (close-by-default). |

### 3.4.1 RPC-Layer Log Filtering (Event Access Control)

In addition to Explorer API redaction, logs returned by `eth_getLogs` and `eth_getTransactionReceipt` are filtered at the RPC layer by `FilterEventLogs` (`internal/rbac/event_filter.go`). This is a separate layer from Explorer API redaction — it controls which log entries are visible at all, before any field-level redaction occurs.

**Admin bypass (RD-751):** Users with the `admin` claim on a contract see ALL logs from that contract, regardless of event rules or address-in-topic checks. This applies to:
- Per-contract admin (group has `admin` in `group_access.claims` + `contract_grant`)
- Org admin (`is_org_admin = true` group — resolver grants `admin` on all org contracts)

The bypass does NOT apply to users with `deploy`, `write`, `read`, or `upgrade` claims only.

**Participant/sender admission (RD-1162):** a viewer who is a **participant** of a log's transaction — their linked address is the tx `from` or `to` — sees that transaction's logs **on contracts they have a grant to**, even when the event is not in their `event_rules` allowlist and carries no address of theirs (e.g. `PaymentCompleted(bytes32 indexed key, string id)`, keyed by a business identifier). The viewer authored/participated in the tx and already knows its contents, so this reveals nothing new (same rationale as §G21). It is **bounded by contract-grant access** — logs from contracts the viewer has no grant on stay dropped, so a tx that internally touched a foreign-org contract never leaks that contract's logs (mirrors the explorer participant override, §3.7: Redacted→Full, Hidden stays dropped). Participation is threaded in via `TxVisibilityContext.ParticipantTxHashes`: the receipt path derives it from the receipt's `from`/`to`; the `eth_getLogs` path resolves each tx's sender via a batched upstream `eth_getTransactionByHash` (log entries do not carry the sender). It slots **after** the deny-when-no-ABI (RD-875) and M15 dynamic-payload gates — participation relaxes only the allowlist/param/self checks, never the embedded-address protections, so an event with a dynamic non-indexed payload still requires the operator's `events_allow_dynamic_payload` attestation before even its participants see it.

| Viewer | Event rules configured | Address in topics | Participant of tx | Log visible? |
|--------|----------------------|-------------------|-------------------|-------------|
| Admin on contract | Any | Any | Any | **Yes** (bypass) |
| Org admin | Any | Any | Any | **Yes** (bypass via admin claim) |
| Read user, grant on contract | `null` (default) | Yes | Any | Yes |
| Read user, grant on contract | `null` (default) | No | **Yes** | **Yes** (RD-1162; if it clears the no-ABI + M15 gates) |
| Read user, grant on contract | `null` (default) | No | No | No |
| Read user, grant on contract | `[Transfer]` | N/A | No | Only Transfer logs |
| Read user, grant on contract | `[]` (deny all) | Any | No | No |
| Read user, grant on contract | `[]` (deny all) | No | **Yes** | **Yes** (RD-1162) |
| No access to contract (Hidden emitter) | Any | Any | **Yes** | **No** (participation does not override the grant bound) |
| `perms == nil` | N/A | N/A | Any | No (fail-closed) |

### 3.5 TokenHolder (Explorer API)

| Field | Hidden | Redacted | Full | Implemented | Tested | Notes |
|-------|--------|----------|------|-------------|--------|-------|
| Entry | Dropped | Kept | Kept | Yes | Yes | When address is hidden, the entire holder entry is removed from the list |
| `address` | — (entry dropped) | `[PRIVATE]` | unchanged | Yes | Yes | |
| `balance` | — (entry dropped) | 0 / nil | unchanged | Yes | Partial | Zeroed when redacted |
| `percentage` | — (entry dropped) | 0 / nil | unchanged | Yes | Partial | Zeroed when redacted |

### 3.6 Block (Explorer API / RPC Layer)

| Field | Behavior | Implemented | Tested | Notes |
|-------|----------|-------------|--------|-------|
| `miner` | Not redacted | N/A | N/A | Accepted: block producer is consensus-layer infrastructure metadata, not user identity; no grant/visibility mechanism for blocks |
| `logsBloom` | All-zero (256 bytes) on every response, every viewer | Yes | Yes | **G6 closed (RD-873).** Bloom previously leaked address/topic membership in O(1) to anyone who already knew the target address. Now overwritten unconditionally on the way out — no per-block address scanning needed because the field carries no useful information for clients of a privacy proxy. |
| `number`, `hash`, `timestamp`, `gasUsed`, `gasLimit`, `difficulty`, `size`, `parentHash`, `nonce`, `extraData`, `baseFeePerGas`, `withdrawalsRoot` | Public; not redacted | N/A | N/A | Block header fields are consensus-layer public data |
| `transactions` (full objects, `fullTxObjects=true`) | Non-participant txs removed from array | Yes | Yes | Per-tx participant check; block-level fields preserved |
| `transactions` (hashes only, `fullTxObjects=false`) | Passed through | Yes | Yes | Tx hashes alone are not sensitive |

### 3.7 Explorer API — Participant Visibility Override

The visibility map (`GetBatchVisibility`) resolves each address independently: own address → Full, org contract grant holder → Full, org admin → Full (all org contracts), everything else → Hidden/Redacted.

However, **transaction participants must always see their counterparty** in their own transactions. A sender already knows the recipient (it's in their wallet history) and vice versa. Hiding it from them adds no privacy, only confusion.

This is implemented as a **per-transaction override** in `RedactTransactions` (`internal/explorer/redactor.go`):

1. The viewer's linked ETH addresses are fetched via `GetLinkedAddresses(ctx, viewerDID)`.
2. For each transaction, if any viewer address matches `from`, `to`, **or appears in calldata as an address parameter** (e.g., ERC20 `transfer(address,uint256)` recipient), both sides are overridden to `VisibilityFull` for that transaction only.
3. The shared visibility map is **never mutated** — the override uses local variables scoped to the current transaction.

**Calldata-level participant detection:** For contract calls, the tx-level `to` is the contract address, not the actual counterparty. The redactor also parses `inputData` for common function selectors to detect participants encoded in calldata:
- `0xa9059cbb` — `transfer(address to, uint256 amount)`: param 0 is recipient
- `0x23b872dd` — `transferFrom(address from, address to, uint256 amount)`: params 0 and 1
- `0x095ea7b3` — `approve(address spender, uint256 amount)`: param 0 is spender

| Scenario | Viewer is participant? | Counterparty visibility | Override |
|----------|----------------------|------------------------|----------|
| Viewer is sender (`from`) | Yes | Hidden → Full | Per-tx only |
| Viewer is receiver (`to`) | Yes | Hidden → Full | Per-tx only |
| Viewer is ERC20 transfer recipient (in calldata) | Yes | Hidden → Full | Per-tx only |
| Viewer is not involved | No | No override | Normal rules apply |
| Same tx, different viewer | — | Independent | Each viewer gets their own override |

**Log participant override:** `RedactLogs` accepts optional `participantAddrs` (the parent tx's `from` and `to`). When the viewer's linked address matches a participant address, Redacted emitting contracts are upgraded to Full for that log context — topics and data are preserved instead of stripped. Hidden emitting contracts remain dropped even with participant override. The API handler (`getExplorerTransactionLogs`) fetches the parent transaction and passes its `from`/`to` as participant context.

**Security invariant:** The override ONLY applies within `RedactTransactions`/`RedactLogs`/`RedactTransfers`/`RedactInternalTransactions`, which process a specific transaction's data. It does NOT affect `GetBatchVisibility` or `GetBatchVisibilityDetailed`. A counterparty address visible via participant override in a transaction list will still show as Hidden when queried via other visibility resolution paths.

### 3.7.1 Per-contract visibleTo unlock (RD-874)

By default `visibleTo` is **additive** — it widens an already-permitted viewer's response (e.g. param-rule fallback) but never grants new event-level access. The settlement-bank pattern (many participants, shifting per-event visibility) is awkward to express that way, so contracts can opt in to the **unlock semantic**: per-tx visibleTo lists become per-event opt-in unlocks.

**Opt-in switch:** `contracts.allow_visibleto_unlock` (boolean, default false). Flipped via the admin API:

```
PUT /api/orgs/:org_id/contracts/:address/visibleto-unlock
{"allow_visibleto_unlock": true}
```

Admin-only on the contract's owning org. Migration **045**.

**When the flag is true and a viewer is listed in a transaction's `visibleTo`, the viewer sees ALL event logs of that transaction** (per-tx, all-events) — bypassing the contract grant's `event_rules` allowlist, any `param_rules`, and the deny-when-no-ABI gate (RD-875/889). Field-level redaction of embedded private addresses in topics/data is also bypassed for that one tx — the contract owner has explicitly authorised tx senders to share full event payloads with their listed recipients.

**Eligibility gate** (`rbac.IsViewerEligibleForVisibleToUnlock`) — both must hold for any unlock:

1. The viewer resolves to a real `users` row (anonymous viewers — no DID account — are denied here).
2. The viewer is a member of at least one **non-system** group whose `org_id` equals the contract's owning `org_id`, AND that group has a `contract_grant` on this contract. The grant's `event_rules` may be deny-all — the unlock works *because of* the grant link, not its rule set.

Cross-org isolation: `GetEffectivePermissionsByIDs` resolves grants per-org, so a viewer who has access only in another org gets `HasContractAccess(addr) == false` here. Anonymous / system groups are excluded explicitly.

**Per-tx blast-radius cap:** `visibleTo` lists at `eth_sendTransaction` time are capped at **32 entries** (`server.visibleToMaxSize`). Larger lists are rejected with HTTP 400. Operators with legitimate >32-recipient flows should use a dedicated group + grant instead.

**Matrix:**

| Viewer in eligible group on contract? | Listed in tx's `visibleTo`? | `allow_visibleto_unlock` flag | Outcome on that tx's events |
|---------------------------------------|-----------------------------|-------------------------------|------------------------------|
| Yes | Yes | true | **All events visible**, no field redaction (unlock fires) |
| Yes | No | true | Existing event_rules apply (unchanged) |
| Yes | Yes | false | Existing additive widening (unchanged — RD-842 / param-rule fallback) |
| No (cross-org or no group) | Yes | true | Denied (eligibility gate fails) |
| Anonymous viewer | Yes | true | Denied (no `users` row) |
| Eligible but membership later revoked | Was previously listed | true | Denied at next request — eligibility is checked at request-time (`RedactionEngine.RedactLogs` runs per-request; cache invalidated on grant change via `InvalidateOrg`) |

**RPC and explorer use the same eligibility gate** — `rbac.IsViewerEligibleForVisibleToUnlock` is the single source of truth. RPC layer pre-resolves it via `processor_event_rules.go::buildVisibleToUnlockableMap`; explorer pre-resolves via `dbVisibleToUnlockResolver` wired through `wireExplorerRedactor`. Both feed an `UnlockableContracts map[string]bool` into the per-log decision so it stays O(1) per log.

**Auditability note:** with the flag on, the set of users who can see a contract's events grows beyond what `groups + grants` enumeration alone shows — the active set is `(groups + grants) ∪ (every DID listed in any tx's visibleTo)`. Operators who flip the flag should plan for that surface in access-review tooling. The flag itself is a single boolean per contract; flips go through the admin API and are subject to whatever audit log the API surface uses.

**Method-allowlist non-bypass (RPC layer):** the unlock relaxes *redaction*, never *method access*. Over RPC the group's `AllowedMethods` allowlist is enforced **first** (`rbac.access.go::HasMethod`), before contract-access and before any `visibleTo` / unlock / redaction logic. So an eligible, listed viewer whose group does not allow the method is denied at the allowlist gate — the unlock never adds a method to a viewer's allowlist. Which facet needs which method: tx object → `eth_getTransactionByHash` (or block-index variants); receipt + logs → `eth_getTransactionReceipt`; filtered logs → `eth_getLogs` (+ contract access). This non-bypass is intentional and test-locked by `TestCheckAccess_VisibleTo_DoesNotBypassMethodAllowlist` (RD-837). The **only** allowlist-exempt surface is the Explorer API (separate BFF/JWT auth, reads via `RedactionEngine`) — which is why "visible in the explorer" ≠ "can call `eth_getLogs`".

### 3.7.2 Disclosure-grant counterparty lens (RD-1079)

When a viewer is **not** a transaction participant (§3.7) but holds a **disclosure grant** on *one* side of a transfer/tx, the redactor renders the *other* side (the counterparty) through a per-grant-level "lens" (`counterpartyLensLevel`, `internal/explorer/redactor.go`). The lens result is the floor the counterparty renders at.

The disclosed party themselves always renders at their own grant level via the visibility map, carrying `addressMetadata` reason `disclosure_grant`. The table below is about the **counterparty** (the other side):

| Viewer's grant level on the disclosed party | Counterparty renders as | Counterparty `addressMetadata` reason | Drives the §G24 row-survival union? |
|---|---|---|---|
| **Full** | real address (regulatory reveal; audit-logged via `GrantFullReveals`) | `visible_to_grant` (revealed via the union override; the reveal is entitled) | **Yes** — viewer is entitled to counterparties |
| **Pseudonymous** | stable pseudonym (`Address-XXXX`), never real hex | the counterparty's own reason (e.g. `no_access`) — **never** `visible_to_grant` | **No** |
| **Redacted** | `[PRIVATE]` | the counterparty's own reason (e.g. `no_access`) — **never** `visible_to_grant` | **No** |
| (none — viewer not a participant, no grant) | Hidden → row dropped | — | No |

**Invariant (RD-1079):** the lens is only reached when the row is **not** force-revealed by a participant override or by `VisibleTxHashes`. Therefore the G24 transfer-participant row-survival union (which feeds `VisibleTxHashes`, a *full-reveal* override) MUST be driven only by **Full-visible** addresses (`fullVisible` in `buildVisibilityFilter`). Feeding it a pseudonymous/redacted disclosure-grant address would bypass this lens and leak the counterparty's real address (the G25/RD-1079 bug). For a non-Full grant the counterparty must render at the lens level (pseudonym / `[PRIVATE]`) and must **never** carry the `visible_to_grant`/"Shared" label — that label on a counterparty the viewer holds no per-tx `visibleTo` share for is the frontend-visible symptom of this leak.

**Under View-as (RD-1028):** this lens — like all visibility resolution — is governed by the **resolved (impersonated) viewer** from `getViewerDIDFromRequest`, which returns a single DID (the override target, else the JWT subject) and never a union. `buildVisibilityFilter`, the disclosure-grant resolution, the participant override, and `opts.ViewerIsAdmin = isViewerAdmin(resolvedDID)` are all keyed on that one DID. So an admin viewing-as a pseudonymous-grant holder sees the counterparty pseudonymised exactly as that holder would — the signed-in admin's own (broader) visibility does **not** bleed in. There is no admin+target mixing axis; the RD-1028 fail-open guard (`impersonation_viewer_resolution_test.go`) pins the contract-grant direction of the same property.

### 3.8 RPC Layer (`eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs`, `eth_getBlockByNumber`, `eth_getBlockReceipts`)

At the RPC layer, the tx envelope (`eth_getTransactionByHash` / `eth_getTransactionReceipt`) is binary on participation (one of the caller's linked addresses matches `from`/`to`); the **logs** inside a receipt, and `eth_getLogs`, are additionally RBAC/event-rule filtered by `FilterEventLogs` (§3.4.1).

| Method | Participant behavior | Non-participant behavior | Implemented | Tested |
|--------|---------------------|--------------------------|-------------|--------|
| `eth_getTransactionByHash` | Full transaction returned | `null` | Yes | Yes |
| `eth_getTransactionReceipt` | Receipt returned; logs event-rule filtered, **plus** the participant sees their own tx's logs on granted contracts even if address-less (RD-1162, §3.4.1) | `null` | Yes | Yes |
| `eth_getLogs` | Entries where a topic address matches a linked address, **or** (RD-1162) entries of a tx the caller participated in on a granted contract (bounded by grant + no-ABI/M15 gates) | Entry removed from array | Yes | Yes |
| `eth_getLogs` topics[0..3] | All 4 slots scanned for private addresses | Non-matching entries removed | Yes | Yes |
| `eth_getLogs` data field (no ABI) | Whole log denied at RPC layer regardless of event_rules; explorer layer also denies via the unified ABIResolver | — | Yes | Yes | G5 closed (RD-875 RPC + RD-889 explorer) — see §3.4 row for `data (when emitter full + NO ABI)` |
| `eth_getBlockByNumber` (`fullTxObjects=true`) | Full block; all txs | Non-participant txs removed | Yes | Yes |
| `eth_getBlockByNumber` (`fullTxObjects=false`) | Passes through | Passes through | Yes | Yes |
| `eth_getBlockReceipts` | Participant receipts kept; their logs still topic-address filtered by the *simple* path (`filterReceiptLogs`), so an address-less own-tx log is not yet admitted here | Non-participant receipts removed | Yes | Yes |
| `logsBloom` in blocks | All-zero (256 bytes) for every viewer | — | Yes | Yes | G6 closed (RD-873) |

**`eth_call` internal-call validation (RD-915).** The table above covers response-side filtering. `eth_call` has a separate gating layer at the *request* boundary: every call is traced via `debug_traceCall` and every internal `CALL`/`STATICCALL`/`DELEGATECALL` frame is checked against the caller's org membership (`internal/server/jsonrpc_processor.go` `validateEthCallWithTracing`). Without this, a same-org wrapper contract could STATICCALL into a foreign-org private contract and bubble up the result through the return value — defeating cross-org isolation on the read side even if the response itself contains no addresses to redact. Tracing is uncached on the read path because proxy-pattern contracts (EIP-1967, Diamond, Beacon, transparent upgradeable) can re-target their internal calls by rewriting a storage slot, so a `(from,to,data,value)` cache yields stale "allow" decisions after a cross-org upgrade. `from` is rebound to the JWT-bound EOA via `GetLinkedEthAddresses`; spoofed `from` is rejected (not silently rebound — preserves audit trail). See `docs/rd-915-design.md`.

**Intra-org grant scoping on internal frames (RD-1053).** The RD-915 frame check gates on the caller's *org membership* only: an internal frame into any contract owned by one of the caller's orgs is allowed, even when the caller's groups have no contract grant for it. This means grant-level scoping — which the grant-aware entry-point `CheckAccess` enforces on the directly-called `to` — does **not** hold transitively through internal calls by default. The optional `RUNTIME_TRACING_INTRA_ORG_GRANTS_ENABLED` flag (default OFF; super-admin runtime toggle at `POST /api/v1/admin/system/intra-org-grant-tracing`) tightens the same-org branch to additionally require a contract grant, mirroring the entry point. It governs both the read side (`eth_call` / `debug_traceCall`) and the send side (`eth_sendTransaction` / `eth_sendRawTransaction` / deploy constructor frames). Cross-org and unregistered-address denials are independent of this flag and always enforced. Plumbed via `rbac.WithIntraOrgGrantScoping`; the granted set mirrors `EffectivePermissions.ContractAccess` (explicit grants + org-admin materialization + deployer auto-grants). In-flight deployments (precomputed CREATE/CREATE2/CREATE3 addresses pre-registered but not yet mined, hence grant-less) are allowed through for deploy-claim callers via an `IsAddressPreregistered` fallback, mirroring the entry point — so strict mode does not break multi-contract / factory deploys that reference a precomputed sibling before it is mined.

### 3.9 Token (Explorer API)

Token visibility is determined by the token's contract address. If the address is registered as an org contract in the RBAC database, the token inherits that contract's visibility. Unregistered addresses default to `VisibilityHidden` (all contracts are private by default).

| Field | Hidden | Redacted | Full | Implemented | Tested | Notes |
|-------|--------|----------|------|-------------|--------|-------|
| Entry | Dropped from list | Kept | Kept | Yes | Yes | Hidden tokens never appear in `/tokens` list |
| `address` | — (dropped) | `[PRIVATE]` | unchanged | Yes | Yes | |
| `symbol` | — | empty string | unchanged | Yes | Yes | |
| `name` | — | nil | unchanged | Yes | Yes | |
| `decimals` | — | unchanged | unchanged | Yes | Yes | Non-identifying metadata |
| `tokenType` | — | unchanged | unchanged | Yes | Yes | Non-identifying metadata |
| `totalSupply` | — | nil | unchanged | Yes | Yes | |
| `holderCount` | — | 0 | unchanged | Yes | Yes | |
| `transferCount` | — | 0 | unchanged | Yes | Yes | |
| `creationTx` | — | nil | unchanged | Yes | Yes | |
| `l1Address` | — | nil | unchanged | Yes | Yes | |
| `usdPrice` | — | nil | unchanged | Yes | Yes | |
| `iconUrl` | — | nil | unchanged | Yes | Yes | |

**Single token endpoint** (`/tokens/:address`): Hidden returns 404. Redacted returns masked fields. Full returns as-is.

**Sub-endpoints** (`/tokens/:address/holders`, `/tokens/:address/transfers`): Hidden or Redacted returns 404. Full proceeds normally (holder/transfer redaction still applies to individual entries).

**Grant holder visibility:** Any user whose group has a `contract_grant` on a token's contract address sees the token with `VisibilityFull` — full name, symbol, supply, and holder count are visible. This aligns with RPC access: if you can call `balanceOf()` on the contract, hiding its name in the token list is security theater.

**List total:** The `total` field in `/tokens` reflects the count after filtering, never the raw database count.

### 3.8 Org-admin elevated transaction view (`ORG_ADMIN_VIEW_USER_TXS`)

A deployment-wide boolean flag (`ORG_ADMIN_VIEW_USER_TXS`, env var; `config.OrgAdminViewUserTxs`; default **false**). It is an interim control that exists until the dedicated compliance role lands (see G12). It does **not** change the default privacy posture — when unset, behaviour is byte-for-byte identical to strict privacy.

**What it grants when `true`, for viewers who are org admins (`is_org_admin` or `admin` claim):**

- **Row survival.** Transactions / token transfers / internal transactions where *both* sides are non-identifiable (user↔user activity, deploys from a private EOA) are **kept** instead of dropped. Without an admin + the flag, they are dropped as before.
- **Value preserved.** The `value` / transfer amount on those rows (and on one-side-hidden rows the admin already sees) is **not** zeroed. This resolves a real asymmetry: the amount of a Transfer is already readable by the admin via the event log (`RedactLogs`, admin bypass RD-751), while the matching transaction record showed `value = ""`. Under the flag both agree.

**What it does NOT grant:**

- **No real addresses, ever.** Counterparty addresses still render as `[PRIVATE]`. This is a volume/timing/amount audit view, not identity disclosure. Real-address visibility for AML/sanctions is the job of the planned compliance role (G12 option (c)), not this flag.
- **`inputData` / internal `input`/`output` stay stripped** (calldata embeds addresses) and `nonce` stays nil (it would link a private account's transactions). The view reveals volume and timing, never identity or cross-tx correlation.

**Scope of effect.** The flag acts at the redaction layer (`RedactTransactions` / `RedactTransfers` / `RedactInternalTransactions`). It therefore takes effect on endpoints that fetch by tx hash or by a contract/address the admin can already see (e.g. `/tokens/:address/transfers`, `/txs/:hash`, address-scoped lists), and on the value-asymmetry fix everywhere those rows surface. It deliberately does **not** alter the SQL-level `buildVisibilityFilter` allowlist used by the global recent-transactions list, so pure user↔user EOA activity that touches no org contract does not appear in the global feed under this flag — surfacing that safely requires org-scoped SQL filtering, which is scoped to the compliance-role work.

**Auditability (ISO 27001 A.8.15).** Every request that *actually* reveals ≥1 row under this flag writes one `rbac_audit_log` entry: actor = admin DID, `action = "access"`, `resource_type = "explorer_user_txs"`, the endpoint label and target, the count of rows revealed, and the client IP. Addresses are never written to the audit log (the view itself never exposes them). Audit-write failures are logged but do not fail the read. The flag is flipped via env + redeploy, i.e. the change-management-audited path (same posture as `RUNTIME_TRACING_ETH_CALL_ENABLED`).

---

## 4. Known Gaps

The following gaps are numbered. G1, G2, G3, G4, G5, G6, G7, G8, G9, G11, G14, G16, G20, G21, G22, G24 are resolved. G15, G23 are outstanding.

### Resolved

- **G1 (resolved):** Nonce not stripped when sender was hidden — now nil when `from` is Hidden/Redacted.
- **G2 (resolved):** `value` and `inputData` not zeroed for mixed-party txs (one side hidden) — now zeroed when either side is Hidden or Redacted.
- **G3 (resolved):** Log topics[1..3] not scanned for embedded address parameters — now scanned for all logs where emitter is Full; private addresses zeroed.
- **G5 (resolved, RD-875 + RD-889 + RD-890):** Log.data not scanned when no ABI registered — without an ABI neither layer could decode non-indexed `address`-typed parameters in event data, leaking private addresses verbatim. Both layers now fail closed when no ABI is resolvable for the emitting contract: RPC layer in `rbac.FilterEventLogs` (RD-875) — denies regardless of `event_rules`; explorer layer in `RedactionEngine.RedactLogs` (RD-889) via the unified `explorer.ABIResolver` (wired to `rbac.Store` + `rbac.ResolveContractABI`). RD-890 closed the admin-bypass asymmetry by adding `explorer.AdminContractsResolver`, wired to `rbac.AccessController`, which mirrors the RPC layer's per-contract `isAdminByContract` map — tier-2 (`is_org_admin`) and tier-3 (per-contract `admin` claim) viewers bypass the deny gate on both layers. Resolvable means a custom upload OR `metadata.token_type` matching the built-in registry (ERC-20 / ERC-721). Grant save handlers (create + update) reject non-deny `event_rules` up-front when no ABI is resolvable, so admins get a clear 400 instead of silently saving rules that won't fire. Closes `decisions.md` §2 G5.
- **G6 (resolved, RD-873):** Block-level `logsBloom` not zeroed — bloom filter contained hashed representations of addresses and event topics from every log in the block; a viewer who knew a target address could probe activity in O(1). Now overwritten with an all-zero 256-byte value on every block-returning RPC response (`eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBlockReceipts`) regardless of viewer or block shape. The previous "expensive per-block scanning" cost vanished once we accepted that clients of a privacy proxy can't usefully consume the bloom anyway — sanitisation is a single field overwrite.
- **G7 (resolved):** Transaction.contractAddress leaks deployed address — contract deployment transactions from hidden deployers are now dropped entirely via SQL-level visibility filtering.
- **G8 (resolved):** TokenHolder entries not dropped when address is Hidden — now dropped.
- **G9 (resolved):** Log entries not dropped when emitter is Hidden — now dropped entirely.
- **G14 (resolved):** Token endpoints (`/tokens`, `/tokens/:address`, `/tokens/:address/holders`, `/tokens/:address/transfers`) returned raw unredacted token data without any visibility checks. Now: Hidden tokens are dropped from lists and return 404 from single-token endpoints. Redacted tokens have sensitive fields masked (`[PRIVATE]`, nil names/symbols, zeroed counts). Sub-endpoints (holders, transfers) return 404 for Hidden or Redacted token addresses. List total reflects filtered count only.
- **G24 (resolved, RD-1009): Cross-redactor row-survival asymmetry — tx dropped while its derived token-transfer row survived**
  `RedactTransactions` and `RedactTransfers` apply the same drop predicate (`bothHidden → drop unless adminAuditView`), but they evaluate it on *different address sets*: `RedactTransactions` checks the EVM tx's `from` / `to` (typically the EOA caller and the token *contract address*), while `RedactTransfers` checks the ERC-20 event's `from` / `to` (the actual participants). For an admin viewing an org-mate's incoming USDC, the tx looked like `{from: hidden_user, to: hidden_token_contract}` → both hidden → tx dropped, while the transfer was `{from: hidden_user, to: visible_org_mate}` → kept. Result: `/transfers` surfaced the transfer (and via `TokenTransfer.TxHash`, the parent tx hash) while `/transactions` was missing the row — incoherent UX and an audit-trail gap. **Fix:** `buildVisibilityFilter` unions in the tx hashes returned by `ExplorerBackend.FindTransferParticipantTxs(fullVisibleAddrs, …)` — every tx whose token-transfer participants the viewer sees **at Full** is added to `VisibilityFilter.VisibleTxHashes`, so it survives both the SQL allowlist filter and `RedactTransactions`' `bothHidden` branch. `VisibleTxHashes` is a full-identity-reveal override in the redactor (it promotes both tx-level addresses to Full), so the union MUST be driven only by Full-visible addresses — see the RD-1079 correction below. Counter to the broader directions considered (drop the transfer instead, or render everything `[PRIVATE]` uniformly), this preserves the visibility the viewer already has on the transfer side. **Single-tx-by-hash path** (`getExplorerTransaction`) is out of scope here — it doesn't go through `buildVisibilityFilter`. If a viewer dereferences a tx hash they obtained via the transfer feed, the redactor still drops it under strict privacy; tracked as follow-up if symptom evidence justifies it.

- **G25 (resolved, RD-1079): the transfer-participant union must be driven by Full-visible addresses only, never by non-Full disclosure grants**
  The G24 union originally fed `VisibleTxHashes` from the *whole* `visible` set, which `buildVisibilityFilter` builds from (a) Full-visible addresses **and** (b) pseudonymous/redacted **disclosure-grant** addresses (added for SQL row-survival of the disclosed party in `/transfers`). Because `VisibleTxHashes` is a *full-reveal* override, a viewer holding a **pseudonymous** disclosure grant on a transfer participant (Eve) had every tx where Eve is a participant unioned in — and the override force-revealed Eve's **counterparty's** real address (Charlie) in full hex, bypassing the disclosure-grant counterparty lens (§3.7.2). The G24 "reveals nothing new" rationale was false here: on `/transfers` Eve renders as a pseudonym while Charlie was shown in full. **Fix:** the union is driven by `fullVisible` (only addresses where `GetBatchVisibility` returns `VisibilityFull` — RBAC-full contracts/admin, plus *full* disclosure grants), excluding pseudonymous/redacted grant addresses. Those addresses stay in `VisibleAddresses` (so the disclosed party's `/transfers` row still survives), but no longer drive the full-reveal union, so the counterparty lens runs and renders Charlie at Eve's grant level. **Trade-off:** for a pseudonymous/redacted-grant viewer the disclosed party's transfer still shows in `/transfers` (pseudonymised), but the parent tx no longer surfaces in `/transactions` — strictly more private than the leak it replaced. A Full-level viewer (admin, or a full disclosure grant) is entitled to see counterparties, so the G24 coherence behaviour is unchanged for them. Pinned by `TestBuildVisibilityFilter_DisclosureGrant_UnionDrivenByFullOnly_RD1079` (server) and `redactor_rd1079_test.go` (redactor).

- **G4 (resolved, RD-1177): InternalTransaction.error not stripped**
  Error strings returned from trace calls can contain raw revert messages or embedded addresses (e.g. `execution reverted: caller 0xABCD... not authorized`). `RedactInternalTransactions` masked From/To→`[PRIVATE]` and stripped Input/Output/Value on the one-side-hidden branch but left `error` unchanged, while the top-level `RedactTransactions` already nil'd it — an asymmetry that leaked the hidden counterparty's address/reason on `/transactions/:hash/internal`. Fixed: `redacted.Error = nil` on the one-side-hidden branch, mirroring `RedactTransactions`. Pinned by `TestRedactInternalTransactions_OneSideHidden_StripsError_RD1177`.

- **G22 (resolved): Address page transaction count not filtered**
  The `/addresses/:address/stats` endpoint returned the pre-computed `tx_count` from the `address_stats` table without applying visibility filtering. A viewer who could only see 2 of 12 transactions still saw "Transactions: 12", leaking the total activity volume of the address. Same class of issue as RD-758 (fixed for paginated list endpoints and block counts) but missed for address summary counts. Fixed: the handler now computes a live `COUNT(*)` from the `transactions` table with the SQL-level visibility filter applied via `GetAddressTransactionCountFiltered`, overriding the stale `address_stats.tx_count`. The filter is built per-viewer using `buildVisibilityFilter`, matching the pattern used by block transaction counts.

### Outstanding

- **G10: One-side-hidden transactions leak activity metadata**
  When only one party in a transaction/transfer is hidden and the other is public, the entry survives the SQL visibility filter. The hidden side is masked (`[PRIVATE]`), but the viewer still learns that *some* private party interacted with the visible address — including timing, block number, gas used, and transfer amounts. For example, a non-participant can see "someone private called [public contract]." On a private network this metadata may be sensitive. The stricter alternative — drop if ANY side is hidden unless viewer is a participant — would eliminate this leak but significantly reduce explorer utility for public addresses. **Decision pending**: track as a design tradeoff. If tightened, the participant override in `RedactTransactions`/`RedactTransfers`/`RedactInternalTransactions` ensures participants still see their own activity.

- **G11 (resolved, then redesigned): Visibility admin check — 3-tier model**
  Admin visibility on org contracts is now granted through two paths only: `is_org_admin = true` (tier 2, sees ALL org contracts) or any `contract_grant` on the specific contract (any claim including admin). The `'admin' = ANY(group_access.claims)` path was **removed** as part of the 3-tier admin model: contract admins (tier 3, admin claim without `is_org_admin`) now see only contracts explicitly granted to their group, not all org contracts. This is intentional — tier 3 is scoped to specific contracts. Any grant holder (regardless of claims) still sees their granted contracts as Full. **History:** Originally fixed in PR #84, regressed in PR #87, re-fixed, then redesigned with the 3-tier admin model.

- **G12: Org admin cannot see user EOA activity (contract deployments, EOA transfers)** — **partially addressed (interim), full fix pending**
  Org admins have `VisibilityFull` on org contracts but user EOAs remain `VisibilityHidden`. This means: EOA-to-EOA transfers are dropped, contract deployments from user EOAs are dropped, and the deployer's address shows as `[PRIVATE]` in surviving contract call txs. For an org admin auditing their network, not seeing who transferred how much is a significant gap. **Options:** (a) org admins automatically get visibility on all EOAs of users who are members of any group in that org, (b) require explicit disclosure grants from users, (c) add a new "audit" / compliance role that unlocks EOA visibility.
  **Interim step shipped:** the `ORG_ADMIN_VIEW_USER_TXS` flag (§3.8, default off) gives org admins a *volume/timing/amount* audit view — rows survive and `value` is preserved — while keeping addresses `[PRIVATE]` and auditing every reveal. It deliberately stops short of real-address visibility. **Still pending:** the full decision between (a)/(b)/(c) for *identity* disclosure. The leading direction is (c) — a dedicated compliance role with real-address visibility, its own audit trail, and separation of duties from the operations admin (so identity disclosure is never a property of the default admin role). Until that lands, identity stays hidden even with the interim flag on.

- **G13: Minting from zero address to private recipient visible to non-participants**
  Token mints (`from=0x0000...0000, to=private_address`) survive the SQL filter because the zero address is public (not in contracts or eth_address_links). Non-participants can see "someone private received a mint from [token contract]" — revealing that a private user received tokens, when they did, and from which contract. This is a specific case of G10 but worth calling out separately because mint events are particularly sensitive (they reveal token distribution to specific parties). **Options:** (a) treat zero address as neutral rather than public for visibility purposes, (b) handled by G10 if the stricter drop rule is adopted. **Decision pending.**

- **G15: Address parameters in URL paths leak real addresses**
  All `/addresses/:address/...` endpoints embed real addresses in URLs visible in server logs, network intermediaries, and browser history. An untrusted block explorer client that knows a private address can confirm its existence by requesting its sub-endpoints (even if the response is 404, the address appears in access logs). This is a design-level issue requiring API redesign (e.g., opaque address IDs instead of raw hex addresses in URL paths).

- **G16 (resolved): `check-address` enumeration vector closed**
  The `/check-address/:address` and `/check-addresses` endpoints were removed entirely. Address visibility is now communicated inline via `addressMetadata` fields in explorer API responses (PR #96), eliminating the enumeration oracle.

- **G17 (resolved): Disclosure grants now visible in regular explorer views**
  `GetBatchVisibility` and `GetBatchVisibilityDetailed` check active full-disclosure grants for the viewer. Disclosed addresses are upgraded to `VisibilityFull` with reason `"disclosure_grant"` in `addressMetadata`. The block explorer renders this as a "Disclosed" label (purple badge). This replaces the previous design where grants were hidden from regular views.

- **G18 (resolved): "Disclosed" label appears in regular pages for disclosure grant recipients**
  Disclosure grant recipients see disclosed addresses labeled "Disclosed" in regular Transactions, Token Transfers, and address pages. The `addressMetadata` includes `"disclosure_grant"` as the reason, which the frontend renders as a purple "Disclosed" badge.

- **G19: Grant page should show viewer's own address as "Mine" not External-XXXX**
  On the pseudonymous grant page, the viewer's own address is pseudonymized as `External-XXXX` like any other external address. The proxy should detect when an external address in a grant transaction matches the viewer's linked address and label it as "You" or "Mine" instead of generating a pseudonym.

- **G20 (resolved): Redacted disclosure level — proof of activity without correlation.**
  Earlier the `redacted` level short-circuited `/grant/:id/:addr/transactions` to an empty list, which contradicted the docs/UI promise of "proves activity exists." Resolved by giving Redacted a distinct semantic: txs are returned, but every address (disclosed and counterparty alike) renders as the uniform placeholder `[PRIVATE]`, `value` is `"hidden"`, no tx hash, no per-address labels. The auditor sees timing, direction, gas, and status — sufficient for a proof-of-activity audit — but cannot correlate counterparties across txs (no stable per-address pseudonym, unlike Pseudonymous). Three-level model now reads as: Full = identity + graph, Pseudonymous = graph without identity, Redacted = volume/timing without graph. Activity-log access remains orthogonal (gated by `Scope.Methods` containing `activity_logs`/`full_disclosure`).

- **G21 (resolved): Inbound transaction visibility — recipient sees sender.**
  Earlier framing labelled this a "probing" primitive, but no probing exists: the only information flow is sender → recipient (the sender reveals their own address by sending the tx). The recipient has no return channel to the sender, and learns one address per inbound tx with no visibility into the sender's other activity. Hiding sender from recipient would break legitimate audit/settlement use cases (knowing who paid you is a baseline requirement) without preventing any disclosure the sender had not already volunteered by sending. The symmetric participant override in `response_filter.go:104-110` (and equivalents in `FilterTransactionReceipt:153-160` and `RedactLogs` via `explorer_api.go:1556-1567`) is correct.

- **G23: Explorer log-data redaction does not cover cross-org-touched txs**
  RD-915 closes the `eth_call`-side cross-org leak at the proxy boundary, but the explorer-side log-data redaction (RD-875/RD-889) is keyed on the *emitting contract* of each log, not on whether the originating tx touched a foreign-org contract via internal calls. A tx authored by org A that internally STATICCALLs an org B contract may end up with org A logs whose `data` references org B state. The RPC-layer `eth_call` gate prevents the live-query angle; the indexed/historical explorer view is still open. Follow-up needed: extend `RedactLogs` (or add a tx-level pre-filter) so that any log of a tx whose trace touched a foreign-org address is treated as cross-org for the viewer. See `docs/rd-915-design.md` §KD-6.

---

## 5. Adding a New Entity Type

When adding a new entity to the Explorer API, a developer **must**:

1. **Identify all address fields** in the entity struct. Map each to a `from`/`to`/`emitter` role.
2. **Determine the drop condition**: define when an entry must be removed entirely (typically: all address fields are Hidden).
3. **Implement the redaction method** in `internal/explorer/redaction/` following the existing pattern (`RedactTransaction`, `RedactLog`, etc.). The method must:
   - Accept the entity and the viewer's org ID.
   - Call `resolveVisibility(address, viewerOrgID)` for each address field.
   - Apply the correct behavior per visibility level for every field in the entity.
4. **Handle cascading value fields**: any field whose value is only meaningful in combination with a private address (e.g. `value`, `input`, `nonce`) must be zeroed/nil when the associated address is Hidden or Redacted.
5. **Update this spec**: add the new entity to Section 3 with a complete field matrix.
6. **Write unit tests** covering all conditions listed in Section 6.
7. **Wire the redaction method** into the relevant API handler. Verify the handler calls the method before serialisation.
8. **Check for error/reason fields**: if the entity has any free-text error or reason field, treat it as potentially containing addresses and zero it when either party is hidden.

---

## 6. Test Coverage Requirements

Every redaction method must have unit tests covering the following scenarios. Tests that are missing are a bug.

### Required test cases per entity

| Scenario | Expected result |
|----------|----------------|
| Both sides Full | All fields unchanged |
| `from` Hidden, `to` Full | `from` → `[PRIVATE]`; value/input/nonce (if applicable) → nil; `to` unchanged |
| `from` Full, `to` Hidden | `to` → `[PRIVATE]`; value/input → nil; nonce preserved (belongs to sender) |
| Both sides Hidden | Entry dropped entirely |
| Both sides Redacted | `from` and `to` → `[PRIVATE]`; value/input/nonce → nil |
| Emitter Hidden (logs) | Entire log entry dropped |
| Emitter Redacted (logs) | Address → `[PRIVATE]`; all topics → nil; data → nil |
| Emitter Full, topic address is private | Topic address zeroed; other topics unchanged |
| Emitter Full, ABI registered, data has private address | Private address slot in data → zeroed |
| Deploy tx, sender Hidden | Entry dropped entirely (SQL-level) |
| Viewer is sender, counterparty Hidden | Counterparty → Full (participant override) |
| Viewer is receiver, counterparty Hidden | Counterparty → Full (participant override) |
| Viewer not a participant, both sides Hidden | Entry dropped (no override) |
| Two txs, viewer participates in one only | Override applies only to the participated tx |

### RD-1162 — participant sees own-tx logs (RPC layer, §3.4.1)

The participant/sender log admission requires the following cases. Adding the
"Participant of tx" column to the §3.4.1 matrix pulls in these tests
(`internal/rbac/event_filter_test.go` + `internal/server/*rd1162*_test.go`):

| Scenario | Expected result | Test |
|----------|-----------------|------|
| Participant of a tx, address-less event, **granted** emitter | Log admitted | `TestFilterEventLogs_ParticipantSeesOwnTxLog_RD1162` |
| Non-participant / non-matching tx, address-less event | Log dropped | `TestFilterEventLogs_ParticipantSeesOwnTxLog_RD1162` |
| Participant, but **no grant** on emitter (Hidden/foreign-org) | Log dropped — the grant bound holds | `TestFilterEventLogs_ParticipantBounds_RD1162` |
| Participant, granted emitter, but **no ABI** or **M15 dynamic payload** | Log dropped — participation slots AFTER those gates | `TestFilterEventLogs_ParticipantBounds_RD1162` |
| Receipt glue: participant's address-less own-tx log, granted emitter → visible; non-granted → hidden | As stated | `TestFilterReceiptLogsWithEventRules_ParticipantSeesAddresslessOwnTxLog_RD1162` |
| getLogs sender resolution (`buildParticipantTxHashes`): from-match, to-match, non-participant, unknown tx | Correct participant set | `TestBuildParticipantTxHashes_ResolvesParticipants_RD1162` |
| getLogs sender resolution fails closed: no linked addrs / upstream unreachable / unparseable response / over the 256-tx cap | Empty set (pre-RD-1162 behaviour) | `TestBuildParticipantTxHashes_FailClosed_RD1162` |
| Full getLogs path (resolve → filter): own-tx address-less log admitted, other-tx log dropped | 1 log (own tx only) | `TestGetLogsParticipantPath_AddresslessOwnTxLogAdmitted_RD1162` |

### Gap behavior must be explicitly asserted

Do not allow a gap to become invisible through test omission. For each known gap (e.g. G4, and the RD-1162 `eth_getBlockReceipts` gap below), write a test that:
1. Sets up the exact scenario that triggers the gap.
2. Asserts the **current (broken) behavior** with a comment: `// GAP <id>: <current vs desired> — fix before release`.

This makes gaps visible in CI output and prevents accidental regression to worse behavior.

- **RD-1162 `eth_getBlockReceipts` gap:** `eth_getBlockReceipts` still uses the simple topic-address `filterReceiptLogs`, so a participant's address-less own-tx log is **not** admitted there (unlike `eth_getLogs` / `eth_getTransactionReceipt`, §3.4.1). Pinned by `TestFilterBlockReceipts_ParticipantAddresslessOwnTxLog_GAP_RD1162`, which asserts the current (gap) behavior so the fix — migrating `eth_getBlockReceipts` to the event-rules path (`FilterReceiptLogsWithEventRules`) — cannot land silently.

### Cross-redactor consistency (RD-1009 / G24 + follow-up)

Single-entity matrices above test each redactor in isolation. Real bugs hide in the gaps *between* them. Every change touching `RedactTransactions`, `RedactTransfers`, `RedactInternalTransactions`, `RedactLogs`, the SQL pre-filter `buildVisibilityFilter`, or the by-hash helper `buildRedactOptsForViewer` MUST include at least one assertion that the surviving rows from a derived feed (transfers / internal txs / logs) imply the parent tx survives in the surrounding `/transactions` list and `GET /transactions/:hash` lookup.

Required scenarios (RD-1009 + follow-up):

| Fixture | Viewer | Expected |
|---------|--------|----------|
| EOA caller hidden, token contract hidden, transfer recipient admin-visible | Admin (flag off) | tx surfaces; transfer surfaces; internal tx for the same parent surfaces; Transfer log surfaces |
| Same fixture | Non-admin, non-participant | None of the above surface |
| Same fixture | Admin, by-hash (`GET /transactions/:hash`) | 200; matching `/internal`, `/transfers`, `/logs` all return rows |
| Counterparty (Charlie) hidden, token hidden, transfer recipient (Eve) visible via **Full** disclosure grant | Non-admin, non-participant, Full grant on Eve | tx surfaces (Full drives the union); counterparty Charlie rendered as real address (entitled) |
| Same fixture, **Pseudonymous** grant on Eve | Non-admin, non-participant | transfer surfaces with Eve as pseudonym and **counterparty Charlie as a pseudonym, never real hex** (`disclosure_grant` reason); parent tx does **not** surface in `/transactions` (RD-1079 — Full-only union) |
| Same fixture, **Redacted** grant on Eve | Non-admin, non-participant | transfer surfaces with Eve and counterparty Charlie as `[PRIVATE]`; parent tx does **not** surface in `/transactions` |
| Same fixture, any grant level | viewer listed in the parent tx's `tx_visible_to` | tx surfaces and counterparty revealed — but ONLY because of the genuine per-tx `visibleTo` share, not the transfer-participant union |

The bug class is invisible to per-entity matrices because each redactor passes its own assertions independently. The pinned invariants (`internal/server/explorer_coherence_e2e_test.go` drives all five surfaces against one fixture) catch divergence at PR time. Reviewers: a new explorer surface that derives rows from a parent tx MUST add a row to that coherence test before merge.

The unified opts contract for handler authors:

- **List handlers** call `s.buildVisibilityFilter(...)` then `redactOptsFromFilter(filter)` plus `ViewerIsAdmin` / `applyAdminTxView` wiring.
- **Single-item handlers** call `s.buildRedactOptsForViewer(...)` — internally identical, by design.

Constructing `explorer.RedactOpts{}` by hand silently skips the transfer-participant union, `visibleTo` shares, and the admin-flag wiring. PR review rejects hand-rolled opts.

#### Why `RedactLogs` is NOT in the same bug class

`RedactLogs` evaluates its drop predicate on the **emitting contract address** (`l.Address`), not on tx participants. It already honours `opts.VisibleTxHashes` through the `visibleTo` override (upgrades Hidden / Redacted emitter to Full when the parent tx is in the allowlist) and through the param-rule fallback. There is no related-feed redactor that surfaces "the same log row" at a different address set, so the RD-1009 asymmetry shape (two redactors evaluating `bothHidden` on different address sets) cannot apply. The log model has its own gating (deny-when-no-ABI, event_rules, dynamic-payload drop, M15) — orthogonal to row-survival coherence.


### Impersonation viewer-resolution (RD-1028)

Every explorer handler MUST resolve the viewer through **`getViewerDIDFromRequest`**, which honours the impersonation override (`viewerDIDOverrideContextKey`, set by `impersonationGateMiddleware`) before falling back to the JWT `subject`. Under View-as the authenticated `subject` is the **admin**, not the impersonated target — so a handler that reads `subject` directly (or `?wallet=`) resolves the **wrong viewer**.

History: a legacy `getViewerIdentity` (subject-only, override-blind) survived on 13 single-item handlers (token / address detail). Under View-as it resolved the admin or anonymous identity instead of the target, which:

- **failed closed** — a target with a contract grant got a wrong 404 (the GUSD/Bob report); and
- could **fail open** — when the admin had broader access than the target, the admin's view bled into the impersonated session.

`getViewerIdentity` is removed; there is exactly one viewer resolver. The `?wallet=` viewer path it carried (a viewer-impersonation oracle) is gone with it — `addressVisibleOrFullGrant` no longer takes a wallet argument.

Required scenarios — any change adding/altering an explorer handler or its viewer resolution MUST assert **both** directions (subject ≠ override):

| Fixture | subject (admin) | override (target) | Expected |
|---------|-----------------|-------------------|----------|
| Org contract; target has a group `contract_grant` (Full); admin is a non-member | admin (Redacted) | target (Full) | Handler serves the **target's Full** view (200) — not 404 |
| Org contract; admin has the grant (Full); target is a non-member (Redacted) | admin (Full) | target (Redacted) | Handler reflects the **target's** view (404/masked) — admin's Full must **NOT** bleed through |

Pinned in `internal/server/impersonation_viewer_resolution_test.go`. The per-entity redaction matrices above structurally cannot catch this class because they set viewer == `subject` (no override), so the override-blind path looks correct. Reviewers: a new explorer handler that gates on viewer visibility MUST resolve via `getViewerDIDFromRequest` and add a row to that test.


### Test structure

Follow the existing table-driven test pattern:

```go
tests := []struct {
    name     string
    from     VisibilityLevel
    to       VisibilityLevel
    wantDrop bool
    wantFrom string
    wantNonce *int
    // ...
}{
    // cases here
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // ...
    })
}
```

Tests live alongside the redaction code in `internal/explorer/redaction/*_test.go`.

---

## 7. visibleTo — Per-Transaction Visibility Grants

The `visibleTo` parameter lets a transaction sender grant full transaction and log visibility to specific recipients.

### Usage

**Recommended (RD-1163): a top-level `visibleTo` field on the JSON-RPC request** — a sibling of `params` — on either `eth_sendTransaction` or `eth_sendRawTransaction`. `privateFor` is accepted as an alias (Quorum/Tessera/Besu compatibility). Recipients may be **DIDs and/or ETH addresses**; addresses are resolved to their linked DID via `eth_address_links` — **fail-closed**: an address with no linked DID is dropped, never widening access.

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "eth_sendRawTransaction",
  "params": ["0xf86c..."],
  "visibleTo": ["did:privado:alice", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"]
}
```

`privateFor` alias (identical semantics):

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "eth_sendRawTransaction",
  "params": ["0xf86c..."],
  "privateFor": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"]
}
```

The top-level form is preferred: it works with standard Ethereum client libraries (which cannot express extra `params` on a standardized method) and matches the industry convention for per-tx privacy metadata.

**Back-compat (param-embedded, DIDs only)** — still supported. `eth_sendTransaction` inside the tx object (`params[0]`):

```json
{"method":"eth_sendTransaction","params":[{"from":"0x...","to":"0x...","data":"0x...","visibleTo":["did:privado:alice"]}]}
```

`eth_sendRawTransaction` as a second param (`params[1]`):

```json
{"method":"eth_sendRawTransaction","params":["0xf86c...",{"visibleTo":["did:privado:alice"]}]}
```

All present forms are **unioned and deduped**; the combined list is capped at 32 recipients (`server.visibleToMaxSize`).

### Behavior

- All `visibleTo`/`privateFor` fields (top-level and param-embedded) are stripped before forwarding to the node (never sent on-chain).
- Recipients are normalised to DIDs (ETH addresses resolved via `eth_address_links`, fail-closed) and the resulting DID list is stored in `tx_visible_to` with the resulting tx hash.
- **Explorer views**: Transactions with `visibleTo` grants appear in regular Transactions and Token Transfers pages for the listed DIDs. The `buildVisibilityFilter` includes these tx hashes as an override to address-based filtering.
- **JSON-RPC filtering**: Listed DIDs can see event logs from these transactions via `eth_getLogs`, even when `must_be=self` param rules would otherwise filter them. This extends (never restricts) existing access.
- **Transaction and receipt access**: `visibleTo` overrides participant checks for both `eth_getTransactionByHash` and `eth_getTransactionReceipt`. A listed DID receives the full transaction/receipt even if they are not a from/to participant — the sender explicitly chose to share this transaction.

### Storage

Table: `tx_visible_to` (migration 040, renamed from `tx_log_visible_to`)

| Column | Type | Description |
|--------|------|-------------|
| tx_hash | TEXT | Transaction hash (lowercase) |
| visible_to_dids | TEXT[] | Array of DIDs granted visibility |
| sender_did | TEXT | DID of the transaction sender |
| org_id | TEXT | Organization ID of the sender |
| created_at | TIMESTAMPTZ | When the rule was created |


---

## 8. Admin dry-run / impersonation (RD-872)

A tier-2 org admin can ask the proxy "what would user X see if they made this RPC call?" via `POST /api/orgs/:org_id/dry-run`. The endpoint is an *ergonomics* tool — it does NOT expand the admin's data reach.

### Why it's safe at this scope

- A tier-2 org admin already holds `AllClaims()` on every contract in their own org via `computeOrgAdminPermissions`. Any data the dry-run pipeline can reveal to them is already in their reach via direct RPC/explorer calls. Net new data: **zero**.
- The endpoint does no JWT minting at any point. The "impersonated user" is a synthetic principal constructed inside the request handler from `(user.ID, :org_id)`; it is never persisted, never returned, never auth-credentialed.
- Multi-org users are **structurally invisible across orgs**: `EffectivePermissions` are resolved scoped to admin's `:org_id` via `GetEffectivePermissionsByIDs(userID, :org_id)`. A user who is also in Org B has Org B's grants resolved to nothing in this context.

### Hard gates

| Gate | Enforcement | Failure |
|---|---|---|
| Super-admin token (`X-Admin-Token`) is **rejected** | `auth_method == "admin_token"` check at the top of `handleDryRun` | 403 with explicit reason. Super-admin's design role is admin-of-admins; impersonation would invent data-layer reach they don't have today. |
| Tier-2 admin of `:org_id` only | adminAuthMiddleware + orgScopingMiddleware enforce upstream; handler trusts `admin_subject` | tier-3 admins fail at orgScoping; non-admins fail at adminAuth. |
| Self-dry-run rejected | `req.UserDID == adminDID` check | 400 — would skew audit reasoning. |
| Method allowlist | `dryRunReadMethods` ∪ `dryRunTraceMethods` | 400 with the supported set listed. |
| Cross-org user invisible | `GetUserOrgIDs(user.ID)` must include `:org_id` | generic 404 "user not found" — identical to "user does not exist." |
| Same RBAC pipeline | `CheckAccess` runs as the impersonated user with their own `EffectivePermissions` | no parallel implementation that could diverge from real-request behaviour. |

### Write-method translation (`debug_traceCall`)

Both write-method shapes are rewritten to `debug_traceCall` against the upstream node — current state, no commit. The `callTracer` preset with `withLog: true` returns nested call frames + emitted logs; the handler walks the frames, extracts logs, and runs them through `rbac.FilterEventLogs` with the impersonated user's perms so the response includes both `logs_emitted` (full trace logs) and `logs_visible_to_user` (the subset they would actually see in `eth_getTransactionReceipt`).

`eth_sendRawTransaction` is RLP-decoded via the same production helper (`decodeRawTransaction` in `internal/server/jsonrpc_processor.go`) used by the real-call path. Sender is recovered from the signature using the chain-id-aware signer; the trace then runs against `(from, to, data, value)` exactly as a real raw-tx call would. A malformed signed blob returns a clean decode error rather than a silent pass.

If the upstream node doesn't expose `debug_*`, write-method dry-run returns "node does not support debug_traceCall — dry-run for write methods unavailable." Read-method dry-run continues to work.

### Audit log (`impersonation_log`)

Migration **046** adds the dedicated table. Every dry-run writes one row with:

- `actor_did` — the calling admin's DID (from JWT)
- `impersonated_did` — the user being dry-run-as
- `org_id`, `method`, `params_hash` (sha256, never raw params), `decision`, `reason`, `correlation_id`, `created_at`

The hash means private addresses or signed-tx blobs in params never persist; reviewers correlate against external request logs. Retention is operator-side; SIEM forwarding (`internal/audit/siem.go`) handles tamper evidence.

### Out of scope

- Dashboard "View as user" / browse-as flow — Phase 2, deferred (see RD-872).
- Tier-3 admin / Read-Only Admin / super-admin dry-run — explicit NO. Each adds real attack surface that the tier-2-only argument doesn't cover.
- JWT minting / impersonation tokens — never. The synthetic principal is a per-request struct; if it leaked, it would be a bug.

## 9. Method access policies (RD-1206)

Per-record access control for record-reader `eth_call`s (e.g.
`getPaymentInfo(id)`). A contract grant authorizes a function all-or-nothing;
this layer binds the *call* to the *record*, so only a record's stakeholders may
read it. Operator-facing docs: `site/.../docs/security/method-policies`.

**Where it runs.** The read gate is `applyMethodPolicyGate`
(`internal/server/method_policy_gate.go`), invoked from `applyResponseFilter`
for `eth_call` — i.e. **post-forward**. It decodes the caller's OWN
already-fetched response; it never issues a second upstream call, so allow and
deny share the timing profile (no per-record existence oracle). The engine is
`internal/rbac/method_policy.go` (`Validate`, `DecodeCaptures`, `EvaluateReader`,
`EvaluateAccess`, `DecodeReturnAddresses`).

**Model.** Per contract, `contracts.method_policies` (JSONB, nullable). Two
halves, both validated against the registered ABI at write time:

- **capture** (writer methods): remember `param(i)` / `sender` / `visibleTo`
  under a record key, written via the receipt-confirmed outbox
  (`pending_record_captures` → `contract_record_captures`, promoted by the
  visibility reconciler only when the source tx's receipt is status 1).
- **access** (reader methods): allow when the authenticated caller matches the
  record's captured fields/audience, OR an address decoded from the reader's
  return. Union of the two resolvers.

**Fail-closed, everywhere.** No policy → passthrough (unchanged). Policy but a
DB/parse/decode error, owner-org mismatch, missing capture, or set-once poison
→ opaque deny. Zero/empty values never match a caller. Keys canonicalize on the
decoded typed value; capture and access key types must agree. Only narrows —
the method allowlist / grant / claims / function-selector list / RD-915 tracing
all run first and unchanged.

**Admin.** `GET`/`PUT /api/v1/admin/orgs/{org}/contracts/{address}/method-policies`.
PUT is **super-admin only** (same tier as `events-allow-dynamic-payload`: it is
the whole per-record read-enforcement surface, not a per-grant decision), ABI-
validated, audit-logged before/after.

### Surface asymmetry — what a method policy does NOT cover

A method policy gates the **getter** (`eth_call`) only. The *same record's data
reachable by other means* — the writer transaction's emitted **event logs**
(`eth_getLogs`, receipt logs) — is governed by the event-rule engine (§3.4.1)
and `visibleTo` (§3.7.1, §7), **not** by the method policy. An operator who
locks `getPaymentInfo` but whose `createPayment` emits a stakeholder-bearing
event must gate that event separately (per-record `param_rules`), or the record
is still observable via logs. This is not an RPC/explorer invariant violation:
`eth_call` has no explorer counterpart, and the policy only *narrows* an
already-`CheckAccess`-allowed call — it never touches `GetBatchVisibility`.

**Gating scope (aliases):** the gate fires for `eth_call` (and any method alias
that `ResolveMethodAlias` maps to `eth_call`). A chain-specific read method
exposed via a wildcard namespace that is NOT aliased to `eth_call` bypasses the
gate, like every other response filter — if an operator adds a `*_call`-style
method, it must be aliased to `eth_call` to inherit method-policy gating.
