# Redaction Engine — Developer Specification

**Status:** Living document. Update when adding new entity types, fixing gaps, or changing visibility semantics.

---

## Invariant: RPC access and explorer visibility must agree

For every (viewer, address) pair, the RPC access layer (`rbac.AccessController.CheckAccess`) and the explorer visibility layer (`db.GetBatchVisibility`) must return consistent outcomes. If CheckAccess allows a viewer to interact with an address, `GetBatchVisibility` must return `VisibilityFull` for that address for the same viewer. If CheckAccess denies, visibility must be `Hidden` or `Redacted` — never `Full`.

Any asymmetry is a bug. The historical failure mode (RD-849) was tier 3 admin-claim users getting RPC access to every contract in their org while the explorer correctly treated the same contracts as `[PRIVATE]`. The symmetry is enforced by `e2e/access_visibility_symmetry_test.go` — every change to either layer must keep that test green.

The rule also drives how admin and deploy claims are scoped: they grant bypass on **explicitly granted contracts only**, not org-wide access. Org-wide access is the exclusive privilege of `is_org_admin` groups (tier 2), materialized as explicit `ContractAccess` for every org contract.

**Log redaction uses shared decisions across RPC and Explorer (RD-1214, RD-1300).** `rbac.DecideLogEmitter` returns a `LogDecision{Admit, Payload}` for each log. Both layers render ordinary admissions with `LogPayloadMasked`, using the shared `explorer.RedactLogAddressFields` primitive and `db.GetBatchVisibilityDetailed` for embedded addresses. Only the per-contract `visibleTo` unlock (§3.7.1) produces `LogPayloadFull`, returning the log exactly as emitted. A `Pseudonymous` embedded address is rendered as a pseudonym in Explorer and zeroed in RPC; both apply the same real-address visibility decision. Parity is covered by `internal/server/rpc_explorer_log_parity_test.go`, `TestVisibleToUnlockFullPayload_CrossLayer_RD1300`, and `TestExplorerRedactorWiring_FullStack`.

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
- Exception (G27): a tx kept because one of its token transfers involves an org contract survives, with the user EOA still `[PRIVATE]`.

To see user EOA activity, an org admin would need a **disclosure grant** from each user, or the visibility model would need to be changed to treat user EOAs differently for org admins (design decision, see G11 below).

### 2.2 Full Access Criteria (3-Tier Admin Model)

`VisibilityFull` for org contracts is granted to viewers who are members of a group that meets one of:
1. `is_org_admin = true` on the group (**tier 2 — org admin** — sees ALL contracts in the org)
2. The group has a `contract_grant` linking it to the specific contract (any claims, or none — a grant alone confers visibility; the operational claims are `admin`, `upgrade`, `deploy`)

**Tier 3 (contract admin):** Having `'admin' = ANY(group_access.claims)` without `is_org_admin = true` does **not** grant org-wide contract visibility. Contract admins see only contracts explicitly granted to their group via `contract_grant`. Their `admin` claim gives them RBAC bypass (event rule bypass, all functions allowed) on those granted contracts only — not org-wide visibility.

Path 1 grants visibility on ALL contracts in the org without needing explicit per-contract grants. This is the org admin (tier 2) privilege. Path 2 is for all grant holders (including contract admins): if a user can access a contract via their group's grant, the contract should not appear as `[PRIVATE]` in the explorer.

Users in the same org but in a group **without** a `contract_grant` and **without** `is_org_admin` still see `VisibilityRedacted`.

---

## 3. Entity Field Matrix

### 3.1 Transaction (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | Both-sides-hidden → drop entire tx (org admins keep it when `ORG_ADMIN_VIEW_USER_TXS=true`, address stays `[PRIVATE]` — see §3.8), except union-kept rows (G27), which survive with both sides `[PRIVATE]` |
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
| `contractAddress` | `[PRIVATE]` / tx dropped* | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | *A deploy from a hidden deployer is dropped, except a union-kept row (G27) or under the §3.8 admin view; the row then survives and `contractAddress` renders at the viewer's own level of the deployed contract |
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
| Entry | Dropped | Dropped | Kept | Yes | Yes | A no-grant emitter (Redacted/`ReasonNoAccess`) is now **dropped**, matching the RPC (`access == nil`) — RD-1208/RD-1214. Only a Full emitter (grant / admin / visibleTo-unlock) is kept. Pre-RD-1214 a Redacted emitter was kept with topics/data stripped; that "kept stub" is gone. |
| `address` (emitter) | — (entry dropped) | — (entry dropped) | unchanged | Yes | Yes | Rendered only when the viewer holds a grant (Full); otherwise the whole entry is dropped |
| `topics[1..3]` (emitter Full) | — | — | Scanned for zero-padded embedded addresses; ones not visible to the viewer are zeroed via the shared `RedactLogAddressFields` (RD-1214). **Exception:** a log admitted by the `visibleTo` unlock (§3.7.1) is returned exactly as emitted (`LogPayloadFull`) | Yes | Yes | topics[0] is the event signature hash; the address-pattern check skips it naturally. Cross-layer parity: `TestRPCExplorerLogParity_RD1214`, `TestRPCExplorerLogParity_VisibleToUnlock_RD1300` |
| `data` (emitter Full + ABI registered) | — | — | Non-indexed address params decoded, ones not visible to the viewer zeroed (same shared primitive). Same unlock exception as `topics` | Yes | Yes | Parity + edge cases: `TestRPCExplorerLogParity_RD1214`, `TestRPCFieldRedaction_DataFieldNonIndexedAddress`, `TestRPCExplorerLogParity_VisibleToUnlock_RD1300` |
| `addressMetadata` (explorer only) | — (entry dropped) | — (entry dropped) | reason emitted ONLY for addresses that stay visible (Full); empty for a `visibleTo`-unlocked log | Yes | Yes | Masked embedded addresses are omitted from metadata keys. Test: `TestRedactLogs_EmbeddedAddressMetadata_NoLeak_RD1214` |
| `data` (when emitter full + NO ABI) | Entire log denied at both layers (RPC and Explorer) | — | — | Yes | Yes | **G5 closed (RD-875 RPC + RD-889 explorer).** Without an ABI we can't decode non-indexed `address` params; both layers fail closed (drop the log) when no ABI is resolvable for the emitting contract. Admin bypass on the RPC layer (RD-751) still applies. Operator must register a custom ABI or set `metadata.token_type` to a built-in registry value (ERC-20 / ERC-721) before any event becomes visible. Grant save handler also rejects up-front. |
| `data` (when emitter visible + dynamic non-indexed params) | Entire log denied at both layers unless contract has `events_allow_dynamic_payload = true` | — | — | Yes | Yes | **M15 closed (security audit follow-up to RD-915).** Pre-M15 the static-slot scanner read only AddressTy + bytes32 slots; dynamic types (`bytes`, `string`, dynamic arrays, dynamic structs) passed through verbatim. Bridge / forwarder / smart-wallet contracts that embed foreign-org addresses inside a `bytes` payload leaked them to any reader. Both layers now drop the log when the matching event's ABI declares any dynamic non-indexed param, unless the operator has explicitly opted the contract out via `contracts.events_allow_dynamic_payload`. Admin viewers (RD-890) and visibleTo-unlock viewers (RD-874) bypass — they resolve before the gate. Opt-out is admin-only (super-admin via X-Admin-Token) via `PUT /orgs/:org_id/contracts/:address/events-allow-dynamic-payload`; default FALSE (close-by-default). |

### 3.4.1 RPC-Layer Log Filtering (Event Access Control)

Logs returned by `eth_getLogs` and `eth_getTransactionReceipt` are redacted at the RPC layer in **two steps**, mirroring the explorer:

1. **Entry admission** — `FilterEventLogs` (`internal/rbac/event_filter.go`) decides which log entries are visible at all, via the shared `rbac.DecideLogEmitter` (the SAME decision the explorer's `RedactLogs` uses — RD-1214).
2. **Payload rendering** — each admitted entry carries the payload policy the shared decision attached to it (`rbac.FilterEventLogsDetailed` → `rbac.AdmittedLog{Raw, Payload}`), and `JSONRPCProcessor.redactAdmittedLogs` (`internal/server/rpc_log_field_redaction.go`) renders it in the same in-memory pass — the policy is never re-derived or serialised between the two steps (RD-1300):
   - `LogPayloadMasked` (every ordinary, participant and admin admission): every embedded address (indexed topics + ABI-decoded non-indexed `data`) the viewer is not entitled to see is zeroed. It resolves per-address visibility through the SAME `db.GetBatchVisibilityDetailed` and applies the SAME `explorer.RedactLogAddressFields` primitive as the explorer, so the two layers hide identical addresses for a given (viewer, log). Fail-closed: a resolver error zeroes every embedded address, and a log that cannot be parsed or re-encoded is dropped, never returned raw.
   - `LogPayloadFull` (the per-contract `visibleTo` unlock for this exact viewer, emitting contract and transaction, §3.7.1): the log is returned exactly as emitted — the same full reveal the explorer renders.

Both entry admission and per-address payload rendering are covered by `TestRPCExplorerLogParity_RD1214` (`internal/server/rpc_explorer_log_parity_test.go`) and the RD-1300 unlock parity tests. A `Pseudonymous` embedded address renders as a stable pseudonym in Explorer and is zeroed in RPC because a 32-byte log topic cannot carry a pseudonym string.

**Admin bypass (RD-751):** Users with the `admin` claim on a contract see ALL logs from that contract, regardless of event rules or address-in-topic checks. This applies to:
- Per-contract admin (group has `admin` in `group_access.claims` + `contract_grant`)
- Org admin (`is_org_admin = true` group — resolver grants `admin` on all org contracts)

The bypass does NOT apply to users with `deploy` or `upgrade` claims only — those are operational claims (contract creation / proxy upgrade), not log-visibility grants.

**Participant/sender admission (RD-1162):** a viewer who is a **participant** of a log's transaction — their linked address is the tx `from` or `to` — sees that transaction's logs **on contracts they have a grant to**, even when the event is not in their `event_rules` allowlist and carries no address of theirs (e.g. `PaymentCompleted(bytes32 indexed key, string id)`, keyed by a business identifier). The viewer authored/participated in the tx and already knows its contents, so this reveals nothing new (same rationale as §G21). It is **bounded by contract-grant access** — logs from contracts the viewer has no grant on stay dropped, so a tx that internally touched a foreign-org contract never leaks that contract's logs. The explorer applies the **same grant bound** (§3.7): participation does not upgrade a no-grant emitter. Participation is threaded in via `TxVisibilityContext.ParticipantTxHashes`: the receipt path derives it from the receipt's `from`/`to`; the `eth_getLogs` path resolves each tx's sender via a batched upstream `eth_getTransactionByHash` (log entries do not carry the sender). It slots **after** the deny-when-no-ABI (RD-875) and M15 dynamic-payload gates — participation relaxes only the allowlist/param/self checks, never the embedded-address protections, so an event with a dynamic non-indexed payload still requires the operator's `events_allow_dynamic_payload` attestation before even its participants see it.

**Ordinary `visibleTo` is grant-bounded (RD-1208):** a viewer listed in a transaction's `visibleTo` set sees that tx's logs **only on contracts they already hold a grant to**. Ordinary (non-unlock) `visibleTo` is *additive* — it widens an already-permitted viewer's response (the param-rule fallback: an allowlisted `topic0` whose `param_rules` failed, or `must_be=self` did not match) but never grants **new** contract-level event access. A log emitted by a contract the viewer has **no** grant on (`access == nil`) is dropped even when the viewer is in that tx's `visibleTo` — a transaction *sender* cannot unilaterally expose a contract's event logs to a DID the contract *owner* never granted. This keeps grant eligibility load-bearing (RD-874 / §3.7.1); the only standalone-grant path is the per-contract `allow_visibleto_unlock` semantic (§3.7.1). The explorer layer agrees: a **registered contract with no grant** resolves to `VisibilityRedacted`/`ReasonNoAccess` (grant holders resolve to `VisibilityFull`; `VisibilityHidden` is an unregistered address / EOA), ordinary `visibleTo` does **not** upgrade that emitter's visibility, and the no-grant log is denied by the explorer's event-rule deny-all gate — the same grant boundary as the RPC `access == nil` deny. "Listed" means the same thing on both layers: the transaction's own `tx_visible_to` row names the viewer. The explorer reads it from `RedactOpts.ListedTxHashes`, not from `VisibleTxHashes`, which also carries the G24 transfer-participant union for row survival (RD-1307).

| Viewer | Event rules configured | Address in topics | Participant / visibleTo of tx | Log visible? |
|--------|----------------------|-------------------|-------------------|-------------|
| Admin on contract | Any | Any | Any | **Yes** (bypass) |
| Org admin | Any | Any | Any | **Yes** (bypass via admin claim) |
| Read user, grant on contract | `null` (default) | Yes | Any | Yes |
| Read user, grant on contract | `null` (default) | No | **Participant** | **Yes** (RD-1162; if it clears the no-ABI + M15 gates) |
| Read user, grant on contract | `null` (default) | No | No | No |
| Read user, grant on contract | `[Transfer]` | N/A | No | Only Transfer logs |
| Read user, grant on contract | `[Transfer]`, param `self` | not self | in tx `visibleTo` | **Yes** (additive param-rule fallback; topic0 allowlisted) |
| Read user, grant on contract | `[]` (deny all) | Any | No | No |
| Read user, grant on contract | `[]` (deny all) | No | **Participant** | **Yes** (RD-1162) |
| No grant on contract (`access == nil`) | Any | Any | **Participant** | **No** (participation does not override the grant bound) |
| No grant on contract (`access == nil`) | Any | Any | in tx `visibleTo`, no unlock | **No** (RD-1208; ordinary visibleTo does not override the grant bound) |
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
| `logsBloom` | All-zero (256 bytes) on every response, every viewer | Yes | Yes | **G6 closed (RD-873).** Bloom previously leaked address/topic membership in O(1) to anyone who already knew the target address. Now overwritten unconditionally on the way out — no per-block address scanning needed because the field carries no useful information for clients of the Open Privacy Suite. |
| `gasUsed`, `blobGasUsed` | All-zero (`0x0`) on every block response, every viewer | Yes | Yes | **RD-929.** Block-aggregate gas is the sum over every tx in the block, including ones hidden by the transactions[] filter — passing it through leaks the presence/weight of other-org activity. Per-tx gas is still available via the caller's own receipts. |
| `size` | RPC: zeroed (`0x0`) on every block response, every viewer. Explorer API: field omitted entirely. | Yes | Yes | **RD-1052.** Block serialized byte-length is a per-block aggregate over every tx (including hidden ones), leaking other-org block volume — same class as `gasUsed`. `0x0` is never a real block size, so it carries no information. |
| `number`, `hash`, `timestamp`, `gasLimit`, `difficulty`, `parentHash`, `nonce`, `extraData`, `baseFeePerGas`, `withdrawalsRoot` | Public; not redacted | N/A | N/A | Block header fields are consensus-layer public data |
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

**Log participant override is grant-bounded (RD-1208 / RD-1162):** `RedactLogs` accepts optional `participantAddrs` (the parent tx's `from`/`to`), but participation does **not** upgrade the emitting contract's visibility. A viewer holding a grant on the emitting contract already resolves to `Full`, so they see their own tx's logs there (RD-1162); a viewer with **no** grant sees a `Redacted`/`ReasonNoAccess` emitter's log stay redacted and a `Hidden` (unregistered/EOA) emitter's log dropped — regardless of participation, because a tx that internally touched a contract the viewer has no grant on must not leak its event payload. This mirrors `rbac.FilterEventLogs`, whose participant bypass is bounded by `access != nil`. The counterparty EOA the viewer transacted with is still revealed by the transaction-level participant override (from/to) above; this concerns only the emitting contract's log payload. (RPC/explorer unification into one decision engine: RD-1214.)

**Security invariant:** The override ONLY applies within `RedactTransactions`/`RedactLogs`/`RedactTransfers`/`RedactInternalTransactions`, which process a specific transaction's data. It does NOT affect `GetBatchVisibility` or `GetBatchVisibilityDetailed`. A counterparty address visible via participant override in a transaction list will still show as Hidden when queried via other visibility resolution paths.

### 3.7.1 Per-contract visibleTo unlock (RD-874)

By default `visibleTo` is **additive** — it widens an already-permitted viewer's response (e.g. param-rule fallback) but never grants new event-level access. The settlement-bank pattern (many participants, shifting per-event visibility) is awkward to express that way, so contracts can opt in to the **unlock semantic**: per-tx visibleTo lists become per-event opt-in unlocks.

**Opt-in switch:** `contracts.allow_visibleto_unlock` (boolean, default false). Flipped via the admin API:

```
PUT /api/orgs/:org_id/contracts/:address/visibleto-unlock
{"allow_visibleto_unlock": true}
```

Admin-only on the contract's owning org. Migration **045**.

**When the flag is true and an eligible viewer is listed in a transaction's `visibleTo`, the viewer receives every log emitted by this flagged contract in that transaction, with its full event payload.** This policy applies independently of the contract grant's `event_rules`, `param_rules`, ABI availability, the M15 dynamic-payload gate, and embedded-address masking. `eth_getLogs`, receipt logs, and Explorer `/transactions/:hash/logs` apply the same policy. Explorer `/logs` and `/addresses/:address/logs` currently use ordinary rules without `visibleTo` (RD-1309). The decision is per log for the exact (viewer, emitting contract, transaction) tuple: another emitter uses its own flag and eligibility, and a later transaction needs its own listing. Receipt logs use the receipt's own transaction listing. In Explorer, genuine listings come from `RedactOpts.ListedTxHashes`, built only from `GetVisibleTxHashesForDID`; the transfer-participant union in `VisibleTxHashes` controls row survival and does not establish a listing (RD-1307).

**Eligibility gate** (`rbac.UnlockableContracts`, which adds the flag check; `rbac.IsViewerEligibleForVisibleToUnlock` is the same boundary without it) — both must hold for any unlock:

1. The viewer resolves to a real `users` row (anonymous viewers — no DID account — are denied here).
2. In the contract's owning org, the viewer is either:
   - a member of an **org-admin** group (`is_org_admin`) — the contract owner's own authority, which already reaches every org contract, so no `contract_grant` row is needed; or
   - a member of an **eligible** group that has a `contract_grant` on this contract. The seeded **default** group (`rbac.DefaultGroupID`) and **system** groups (`is_system`) are excluded (RD-1306). An operator-configured automatic group for an identity-provider tenant (Azure AD `default_group_id`) is treated like any other group unless it is the seeded default or a system group. Granting that group a flagged contract makes its members eligible. Eligibility depends on the grant link, including when its `event_rules` are deny-all.

Cross-org isolation: only memberships in the contract's owning org are considered, so a viewer who has access only in another org is never eligible. Memberships (expired ones excluded) and grants are read per request, and any lookup error fails closed.

**Per-tx blast-radius cap:** `visibleTo` lists at `eth_sendTransaction` time are capped at **32 entries** (`server.visibleToMaxSize`). Larger lists are rejected with HTTP 400. Operators with legitimate >32-recipient flows should use a dedicated group + grant instead.

**Matrix:**

| Viewer in eligible group on contract? | Listed in tx's `visibleTo`? | `allow_visibleto_unlock` flag | Outcome on that tx's events |
|---------------------------------------|-----------------------------|-------------------------------|------------------------------|
| Yes | Yes | true | **All of this contract's events in this tx visible, full payload** on `eth_getLogs`, receipt logs and the explorer's transaction logs (unlock fires) |
| Yes | No | true | Existing event_rules apply (unchanged) |
| Yes | Yes | false | Existing additive widening (unchanged — RD-842 / param-rule fallback) |
| No (cross-org or no group) | Yes | true | Denied (eligibility gate fails) |
| Grant only via the default group or a system group | Yes | true | Denied (eligibility gate fails) |
| Org admin of the owning org (no grant row needed) | Yes | true | **All of this contract's events in this tx visible, full payload** |
| Anonymous viewer | Yes | true | Denied (no `users` row) |
| Eligible but membership later revoked | Was previously listed | true | Denied at next request — eligibility reads memberships and grants at request time on both layers |

**RPC and explorer use the same eligibility gate** — `rbac.UnlockableContracts` (flag + eligibility) is the single source of truth. The RPC layer pre-resolves it via `processor_event_rules.go::buildVisibleToUnlockableMap`; the explorer via `dbVisibleToUnlockResolver` wired through `wireExplorerRedactor` — both are thin wrappers over the same helper. Both feed an `UnlockableContracts map[string]bool` into the per-log decision so it stays O(1) per log, and both render from the decision's `Payload` (`rbac.LogPayloadFull` only for an unlocked log), so the payload a listed viewer receives is identical on the two layers.

**Org admins and self-listing:** an eligible sender can list their own DID, and an org admin is eligible on every contract of their org. A listed org admin therefore receives the flagged contract's full payloads for that tx — including user EOAs embedded in the events, which G12 and the `ORG_ADMIN_VIEW_USER_TXS` audit view otherwise keep hidden from admins. This is the contract owner's opt-in (the flag) combined with the sender's disclosure (the listing); operators should enable the flag only on contracts whose events may be shared in full with any eligible, listed participant.

**Auditability note:** the eligible population is the owning org's org admins plus the members of eligible (non-system, non-default) groups holding a grant on the flagged contract. The viewers who actually receive a particular unlocked event are the eligible DIDs named in **that transaction's** `visibleTo`; neither a grant list nor a `visibleTo` list alone describes that set, so access reviews for a flagged contract must join the two. Eligibility is checked at read time, so revocation changes future reads. The flag itself is a single boolean per contract; flips go through the admin API and are subject to whatever audit log the API surface uses.

**Method-allowlist non-bypass (RPC layer):** the unlock relaxes *redaction*, never *method access*. Over RPC the group's `AllowedMethods` allowlist is enforced **first** (`rbac.access.go::HasMethod`), before contract-access and before any `visibleTo` / unlock / redaction logic. So an eligible, listed viewer whose group does not allow the method is denied at the allowlist gate — the unlock never adds a method to a viewer's allowlist. Which facet needs which method: tx object → `eth_getTransactionByHash` (or block-index variants); receipt + logs → `eth_getTransactionReceipt`; filtered logs → `eth_getLogs` (+ contract access). This non-bypass is intentional and test-locked by `TestCheckAccess_VisibleTo_DoesNotBypassMethodAllowlist` (RD-837). The **only** allowlist-exempt surface is the Explorer API (separate BFF/JWT auth, reads via `RedactionEngine`) — which is why "visible in the explorer" ≠ "can call `eth_getLogs`".

### 3.7.2 Disclosure-grant counterparty lens (RD-1079)

When a viewer is **not** a transaction participant (§3.7) but holds a **disclosure grant** on *one* side of a transfer/tx, the redactor renders the *other* side (the counterparty) through a per-grant-level "lens" (`counterpartyLensLevel`, `internal/explorer/redactor.go`). The lens result is the floor the counterparty renders at.

The disclosed party themselves always renders at their own grant level via the visibility map, carrying `addressMetadata` reason `disclosure_grant`. The table below is about the **counterparty** (the other side):

| Viewer's grant level on the disclosed party | Counterparty renders as | Counterparty `addressMetadata` reason | Drives the §G24 row-survival union? |
|---|---|---|---|
| **Full** | real address (regulatory reveal by the lens; audit-logged via `GrantFullReveals`) | the counterparty's own reason (e.g. `no_access`) — never `visible_to_grant` | **Yes** — but the union only keeps the row (G27); the reveal is the lens's |
| **Pseudonymous** | stable pseudonym (`Address-XXXX`), never real hex | the counterparty's own reason (e.g. `no_access`) — **never** `visible_to_grant` | **No** |
| **Redacted** | `[PRIVATE]` | the counterparty's own reason (e.g. `no_access`) — **never** `visible_to_grant` | **No** |
| (none — viewer not a participant, no grant) | Hidden → row dropped | — | No |

**Invariant (RD-1079, RD-1316):** only the participant override, a genuine `visibleTo` listing (`ListedTxHashes`) and this lens may reveal an address the viewer does not already see. The transfer-participant union (`VisibleTxHashes`, G24/G27) MUST only keep rows and MUST NOT change how any address renders, so this lens still runs on union-kept rows. The union MUST be driven only by Full-visible addresses (`fullVisible` in `buildVisibilityFilter`) and, for the G27 both-sides class, the public zero address and precompiles — never by a pseudonymous/redacted grant subject (G25). A non-Full grant's counterparty MUST render at the lens level (pseudonym / `[PRIVATE]`) and MUST never carry the `visible_to_grant`/"Shared" label — that label on a counterparty the viewer holds no per-tx `visibleTo` share for is the frontend-visible symptom of the RD-1079 leak.

**Under View-as (RD-1028):** this lens — like all visibility resolution — is governed by the **resolved (impersonated) viewer** from `getViewerDIDFromRequest`, which returns a single DID (the override target, else the JWT subject) and never a union. `buildVisibilityFilter`, the disclosure-grant resolution, the participant override, and `opts.ViewerIsAdmin = isViewerAdmin(resolvedDID)` are all keyed on that one DID. So an admin viewing-as a pseudonymous-grant holder sees the counterparty pseudonymised exactly as that holder would — the signed-in admin's own (broader) visibility does **not** bleed in. There is no admin+target mixing axis; the RD-1028 fail-open guard (`impersonation_viewer_resolution_test.go`) pins the contract-grant direction of the same property.

### 3.8 RPC Layer (`eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs`, `eth_getBlockByNumber`, `eth_getBlockReceipts`)

At the RPC layer, the tx envelope (`eth_getTransactionByHash` / `eth_getTransactionReceipt`) is gated on participation (one of the caller's linked addresses matches `from`/`to`) plus `visibleTo`/admin; the **logs** inside a receipt, and `eth_getLogs`, are additionally RBAC/event-rule filtered by `FilterEventLogs` (§3.4.1). As of RD-1183 the **receipt** envelope is additionally admitted to a viewer entitled to ≥1 of the tx's logs under their event rules (see below).

| Method | Participant behavior | Non-participant behavior | Implemented | Tested |
|--------|---------------------|--------------------------|-------------|--------|
| `eth_getTransactionByHash` | Full transaction returned | `null` (tx-by-hash log-entitlement admission is a documented gap, below) | Yes | Yes |
| `eth_getTransactionReceipt` | Receipt returned; logs event-rule filtered, **plus** the participant sees their own tx's logs on granted contracts even if address-less (RD-1162, §3.4.1) | Receipt returned (logs filtered to the entitled set, `logsBloom` zeroed) when the viewer is entitled to ≥1 of the tx's logs under their event rules (RD-1183); `null` otherwise. Contract-deployment receipts (`to == null`) stay participant/`visibleTo`/admin-only. | Yes | Yes |
| `eth_getLogs` | Entries where a topic address matches a linked address, **or** (RD-1162) entries of a tx the caller participated in on a granted contract (bounded by grant + no-ABI/M15 gates) | Entry removed from array | Yes | Yes |
| `eth_getLogs` embedded addresses (admitted entry) | topics[1..3] + ABI-decoded non-indexed `data` scanned; addresses not visible to the viewer are **zeroed** (RD-1214), identical to the explorer. A log admitted by the `visibleTo` unlock (§3.7.1) is returned with its full payload (RD-1300), identical to the explorer | Entry already removed by admission | Yes | Yes |
| `eth_getLogs` data field (no ABI) | Whole log denied at RPC layer regardless of event_rules; explorer layer also denies via the unified ABIResolver | — | Yes | Yes | G5 closed (RD-875 RPC + RD-889 explorer) — see §3.4 row for `data (when emitter full + NO ABI)` |
| `eth_getBlockByNumber` (`fullTxObjects=true`) | Full block; all txs | Non-participant txs removed | Yes | Yes |
| `eth_getBlockByNumber` (`fullTxObjects=false`) | Passes through | Passes through | Yes | Yes |
| `eth_getBlockReceipts` | Participant receipts kept; their logs still topic-address filtered by the *simple* path (`filterReceiptLogs`), so an address-less own-tx log is not yet admitted here | Non-participant receipts removed | Yes | Yes |
| `logsBloom` in blocks | All-zero (256 bytes) for every viewer | — | Yes | Yes | G6 closed (RD-873) |

**`eth_call` internal-call validation (RD-915).** The table above covers response-side filtering. `eth_call` has a separate gating layer at the *request* boundary: every call is traced via `debug_traceCall` and every internal `CALL`/`STATICCALL`/`DELEGATECALL` frame is checked against the caller's org membership (`internal/server/jsonrpc_processor.go` `validateEthCallWithTracing`). Without this, a same-org wrapper contract could STATICCALL into a foreign-org private contract and bubble up the result through the return value — defeating cross-org isolation on the read side even if the response itself contains no addresses to redact. Tracing is uncached on the read path because proxy-pattern contracts (EIP-1967, Diamond, Beacon, transparent upgradeable) can re-target their internal calls by rewriting a storage slot, so a `(from,to,data,value)` cache yields stale "allow" decisions after a cross-org upgrade. `from` is rebound to the JWT-bound EOA via `GetLinkedEthAddresses`; spoofed `from` is rejected (not silently rebound — preserves audit trail). See `docs/rd-915-design.md`.

**Creation-shaped calls (RD-1323).** An `eth_call`, `eth_estimateGas` or `eth_createAccessList` whose call object has no `to` (missing, `null`, `""` or `"0x"`) makes the node execute `data` as contract-creation code, which can `CALL`/`STATICCALL` any contract and return what it reads (directly, through revert data, or as touched addresses/slots). Such a call is classified as a deployment (`rbac.IsContractDeployment`, via the shape classifier `rbac.ClassifyCallShape` that target extraction and the trace also use): it requires an authenticated caller holding the `deploy` claim, exactly like `eth_sendTransaction` without `to`, and past that gate it is traced with an empty `to` so every internal call frame is validated as above. The creation frame itself has no registered owner and is not a target; contracts the creation code deploys (successful `CREATE`/`CREATE2` frames in the same trace) are not refused as unregistered when it then calls them (`rbac.WithCreatedContractsAsOwn`, read side only), and their own frames are validated in turn. A failed `CREATE` (address collision) does not qualify. A creation-shaped read requires a working runtime tracer (a missing, disabled or unavailable tracer refuses the call) and preserves the complete call object, including gas, fees, nonce and access lists, instead of projecting it onto four fields — `RUNTIME_TRACING_ETH_CALL_ENABLED` (and its runtime override) only switches tracing of *targeted* reads, which keep their entry-point gate when it is off — and a trace that cannot be obtained (node without `debug_traceCall`, timeout, depth) refuses the call. A `from`, if given, must be one of the caller's linked addresses, as for targeted reads. The trace's creation rule uses the deploy claim of the org the request was authorised in, resolved as `CheckAccess` resolves it (`EffectivePermissions`: org-admin members hold every claim), and expired memberships count for nothing in the `eth_call` trace — neither as an org for the cross-org rule nor as a claim (the send-side and `debug_traceCall` traces are tracked in RD-1342). A trace refused because it creates a contract without the claim answers with the same message as a cross-org denial (`deploy_claim_required` is recorded in the access log only).

Malformed call objects are refused for `eth_call`, `eth_estimateGas`, `eth_createAccessList` and `eth_sendTransaction` (and operator aliases of them), targeted or not, because the node would read them differently from the proxy: a call object that is not an object, a `to` that is not a string or `null`, a key that differs from `to`/`from`/`data`/`input`/`value` only in letter case (Geth matches field names case-insensitively, last match wins — `{"to": X, "To": null}` runs as a creation), or `data` and `input` with different contents (Anvil executes `input`, Geth rejects the pair).

The classification runs inside `CheckAccess`, so `/rpc`, the View-as mirror, admin dry-run, `/admin/access/check` and `/admin/test-request` agree, with operator aliases resolved on each; `/rpc`, View-as, `/admin/test-request` and dry-run (`eth_call`) also run the trace. No `(viewer, address)` pair exists for a call without a target, so the explorer visibility layer has no counterpart to keep symmetric. As for targeted reads, the frames validated are `CALL`/`STATICCALL`/`DELEGATECALL`/`CREATE`/`CREATE2`.

**Client state / code / block overrides are unsupported (RD-1305).** Override sets are optional arguments on call/simulation methods such as `eth_call`; the exact options a node supports vary by implementation. OPS applies the following incoming-request policy before access checks, tracing, or forwarding, for every caller including admins. Ordinary calls continue to run against the configured node's state at the requested block, subject to the normal method, contract, block-reference, and tracing rules.

| Method | Rejected by the option policy | Passes this check |
|---|---|---|
| `eth_call` / `eth_estimateGas` / `eth_createAccessList`, including mapped equivalents | non-empty or malformed override values at `params[2]` or `params[3]`; anything at `params[1]` other than a string, `null`, or an object whose keys are all `blockNumber` / `blockHash` / `requireCanonical`; more than four parameters | omitted, `null`, or `{}` positional overrides; supported block references; a boolean optimization argument at `params[2]` for `eth_createAccessList` |
| `debug_traceCall` | config keys matching `stateOverrides` / `stateOverride` / `blockOverrides` / `blockOverride` / `txIndex`, including case-equivalent spellings and keys with empty values | a config omitting those keys, subject to the normal trace checks |

Bundled simulation methods `eth_simulateV1`, `eth_simulate`, `eth_multicallV1`, `eth_callMany`, and `eth_callBundle` are globally blocked. `rbac.DetectStateOverride` judges both the raw method and its alias target, and is enforced at three points: `Process` (before RBAC, for every method outside the trace and raw-send paths), the top of `processDebugTrace` (after the catalog gate), and `CheckAccess` (`checkStateOverrides`, which also covers admin dry-run and test-request). Incoming RPC denials use the opaque `method not found` (404) and log `state_override_not_allowed`. The `Process` and `processDebugTrace` checks run before org resolution, so their access-log rows carry no org and are visible only in the fleet-wide (super-admin) view. Passthrough methods are not classified: their params, overrides included, are forwarded as sent. The same keys in a `debug_traceTransaction` config are refused by the trace config check with a 400 (see the RD-1304 table below).

**Intra-org grant scoping on internal frames (RD-1053).** The RD-915 frame check gates on the caller's *org membership* only: an internal frame into any contract owned by one of the caller's orgs is allowed, even when the caller's groups have no contract grant for it. This means grant-level scoping — which the grant-aware entry-point `CheckAccess` enforces on the directly-called `to` — does **not** hold transitively through internal calls by default. The optional `RUNTIME_TRACING_INTRA_ORG_GRANTS_ENABLED` flag (default OFF; super-admin runtime toggle at `POST /api/v1/admin/system/intra-org-grant-tracing`) tightens the same-org branch to additionally require a contract grant, mirroring the entry point. It governs both the read side (`eth_call`; the client `debug_traceCall` / `debug_traceTransaction` path applies grant scoping **always**, regardless of this flag — see below) and the send side (`eth_sendTransaction` / `eth_sendRawTransaction` / deploy constructor frames). Cross-org and unregistered-address denials are independent of this flag and always enforced. Plumbed via `rbac.WithIntraOrgGrantScoping`; the granted set mirrors `EffectivePermissions.ContractAccess` (explicit grants + org-admin materialization + deployer auto-grants). In-flight deployments (precomputed CREATE/CREATE2/CREATE3 addresses pre-registered but not yet mined, hence grant-less) are allowed through for deploy-claim callers via an `IsAddressPreregistered` fallback, mirroring the entry point — so strict mode does not break multi-contract / factory deploys that reference a precomputed sibling before it is mined.

**Client `debug_traceCall` / `debug_traceTransaction` (RD-1304).** The supported format is a validated `callTracer` tree. Other tracer formats, `withLog`, state/block overrides and replay-position options are unsupported.

The invariant now enforced: a client trace returns only call-tree frames (`callTracer`), with no storage dump, memory or raw logs, and each value inside them only to a viewer who may read the storage of the contract that produced it (see *Value visibility* below). It returns the frames only to a viewer who passes the read twin's access check. Each frame must be a precompile, tagged shared infrastructure, or a contract in the request's org with the required viewer access. Function and argument rules also apply to returned nested calls, using the frame's storage contract for delegated execution. `processDebugTrace` (`internal/server/jsonrpc_trace.go`) enforces, in order:

| Step | `debug_traceCall` | `debug_traceTransaction` |
|------|-------------------|--------------------------|
| Allowlist | `HasMethod` (RD-1121) | same |
| Shape / config | One canonical call object: `from`/`to` as addresses, `value` as a hex quantity (at most 256 bits), `data`/`input` as hex bytes, and `data`/`input` must agree. Any tracer other than plain `callTracer` is rejected, as are `withLog`, struct-logger options, state/block overrides (`stateOverride[s]`, `blockOverride[s]`, `txIndex`, matched case-insensitively), case-colliding keys, extra positional args and malformed config. Unsupported trace shape/config returns 400; state/block override and replay-position options use the shared opaque 404 option denial. Both are refused before any upstream call. | Tx hash must be `0x` + 64 hex; same config rules, except that override and replay-position keys get a 400 from the config check (the simulation-option check classifies `debug_traceCall` only). |
| Rate / concurrency | Before any upstream call (RD-915 F5). | Same. |
| Access | eth_call-equivalent `CheckAccess` (`Method=debug_traceCall`, `AccessMethod=eth_call`) on the canonical call: ban/KYC, path-org resolution, contract grant, function selector, and the historical-state guard (admin-exempt, like eth_call). The Multicall guard is applied explicitly. `from` must be a linked EOA (RD-915 KD-2). | `CheckAccess` (`Method=debug_traceTransaction`, `AccessMethod=eth_getTransactionByHash`): ban/KYC, path-org or single-org resolution (a multi-org caller must name the org), and the allowlist in that org. Then a cheap `eth_getTransactionByHash`. The viewer must be a participant (linked address = `from`/`to`), admin of `to` in that org, or a `visibleTo` recipient. A `to` registered to another org is refused before the trace. A missing tx and a non-visible tx return the **same** opaque 403. |
| Trace | The proxy **builds** a `callTracer` request from the canonical call and the validated, rebuilt block param. The caller's body is never forwarded. | The proxy builds `debug_traceTransaction(hash, callTracer)`. |
| Validate | `tracer.ParseStrictCallTrace` accepts only a well-formed callTracer tree (known frame types, valid `to`). `CALLCODE` is validated as `DELEGATECALL` and a `SELFDESTRUCT` beneficiary as a `CALL` target. Then `ValidateTrace` runs on those frames, pinned to the CheckAccess-resolved org, with the real deploy status and client-trace grant scoping **always on**. Delegated frames use the parent storage context while implementation ownership remains checked; registered created contracts require a grant. Each granted organization-owned nested frame also passes the existing eth_call-equivalent function and argument checks with its actual calldata and original viewer; precompile, shared-infrastructure and creation frames retain their specific validation rules. | Same, pinned to the resolved org; client-trace grant scoping always on. The top-level `to` and actual calldata must pass the eth_call contract-access check in that org (grant or deployer fallback, cross-org isolation) and is then an authorized frame. |
| Redact values | `tracer.RedactStrictCallTrace`: a nested frame's `input` and `value` are kept only if the viewer may read the private storage of the parent frame's storage context, and its `output` and `revertReason` only for its own storage context. The decision is `AccessController.CanReadPrivateStorage`: the `eth_getStorageAt` check for a non-infrastructure slot (method allowlist, contract access, storage-slot tier) in the pinned org. The top frame is never redacted. | Same. |
| Return | The re-marshaled sanitized tree (known callTracer fields only, values redacted per viewer), re-wrapped with the caller's JSON-RPC `id`. | Same. |

Notes on these choices:

- **No TOCTOU.** There is one upstream trace, and its strictly parsed, re-marshaled payload is both what is validated and what is returned, so nothing the node adds (logs, vendor fields, a different tracer's body) passes through.
- **Why only `callTracer`, even for admins.** `callTracer` reveals only call frames, and every frame is validated. `prestateTracer` also dumps accounts reached only through `BALANCE` / `EXTCODE*`, which create no frame. Frame validation therefore cannot bound it.
- **Value visibility.** Frame validation limits which contracts appear in a trace, not which values do: a contract can read its own private storage and pass the value on (Payroll reads a private salary and calls `Token.transfer(employee, salary)`), or return data only its caller may see. Each value is therefore shown only to a viewer who could already read the producing contract's storage directly, so the trace applies the storage-slot tier to the values each contract produces: a contract grant lets a viewer call a contract, not read its private data. The rule follows the contract that produced a value, not where that contract's inputs came from.

  | Part of the trace | Produced by | Shown when |
  |---|---|---|
  | Top frame `input`, `value` | the caller | always |
  | Top frame `output`, `revertReason` | the `to` contract | always (`eth_call` returns it anyway) |
  | Nested frame `input`, `value` | the parent frame's storage context (for a DELEGATECALL parent, the contract whose storage runs) | the viewer may read that contract's private storage |
  | Nested frame `output`, `revertReason` | the frame's own storage context | the viewer may read that contract's private storage |
  | `type`, `from`, `to`, `gas`, `gasUsed`, `error`, tree shape | — | always |

  "May read private storage" is exactly the `eth_getStorageAt` decision for a slot outside the EIP-1967/EIP-2535 allowlist, at `latest`, in the pinned org: the method allowlist (so `eth_getStorageAt` must be allowed), contract access, and the storage-slot tier (the `admin` claim on the contract, which org admins hold on every org contract). Org contracts the viewer has no access to are refused, as before; precompile and shared-infrastructure frames follow their frame rules and are redacted as above. A hidden field is omitted and named in the frame's `redacted` array, one of `["input","value"]`, `["output","revertReason"]` or all four in that order. The array depends only on the viewer's access, never on whether the hidden field had data or its length. View-as judges values as the impersonated user. A replay, or a trace at a past block, shows values as they were at that block, judged by the viewer's current storage access; the historical-state rule that `eth_getStorageAt` applies to past blocks is not applied to those values. A nested precompile frame's output is never shown, since no viewer holds the `admin` claim on a precompile. A shared-infrastructure contract's output is shown only to viewers with the `admin` claim on it in the pinned org, which requires the contract to be registered to that org.
- **Why grant scoping is forced here.** The RD-1053 knob governs eth_call/send, where only the final result leaves the proxy. A trace exposes every same-org frame (and, to a viewer who may read that contract's storage, its values), and the explorer shows an ungranted same-org contract as private to the same viewer.
- **Pinning to one org.** A trace is pinned to one org: the CheckAccess-resolved org, which is the path org or the org the view-as gate pins. A multi-org trace across a caller's orgs is therefore denied, which is stricter than eth_call's union-of-memberships frame check on the plain path.
- **Opaque denials.** All deny messages are opaque constants. The validator `Reason`, `DenialKind` and `DeniedTarget` go to slog only (KD-3). Every denial raised by an internal frame of the returned trace (ownership, grant, deploy claim, depth, function or argument rules) returns the same message, because the caller can steer which frames run; the access log keeps a finer reason code (`cross_org`, `deploy_claim_required`, `trace_depth_exceeded`, `trace_access_denied`).
- **Residual timing difference.** Missing-tx and non-visible-tx denials differ only in timing (the visible-tx path runs the participant lookups). The same residual exists on `eth_getTransactionByHash`. Likewise, a function or argument denial on a nested frame is decided after the validator has passed and one access check per frame has run, so it takes longer than an ownership or grant denial; the response itself is identical.
- **Other paths.** The admin `POST /api/v1/admin/test-request` diagnostic refuses trace methods and points to `/rpc`, which serves them (dry-run rejects them). The View-as RPC surface takes the same trace path, pinned to the org named in its URL. Operator aliases to trace methods are not supported by the exact method catalog. The internal tracer paths (eth_call RD-915, send-side, deploy, dry-run) call the tracer directly and are unaffected.

**Related:** the shared incoming simulation-option policy is described above (RD-1305). A stricter participant-only profile for `debug_traceTransaction` is not part of this design (RD-1299).


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

The following gaps are numbered. G1, G2, G3, G4, G5, G6, G7, G8, G9, G11, G14, G16, G20, G21, G22, G24, G25, G27 are resolved. G15, G23 are outstanding.

### Resolved

- **G1 (resolved):** Nonce not stripped when sender was hidden — now nil when `from` is Hidden/Redacted.
- **G2 (resolved):** `value` and `inputData` not zeroed for mixed-party txs (one side hidden) — now zeroed when either side is Hidden or Redacted.
- **G3 (resolved):** Log topics[1..3] not scanned for embedded address parameters — now scanned for all logs where emitter is Full; private addresses zeroed.
- **G5 (resolved, RD-875 + RD-889 + RD-890):** Log.data not scanned when no ABI registered — without an ABI neither layer could decode non-indexed `address`-typed parameters in event data, leaking private addresses verbatim. Both layers now fail closed when no ABI is resolvable for the emitting contract: RPC layer in `rbac.FilterEventLogs` (RD-875) — denies regardless of `event_rules`; explorer layer in `RedactionEngine.RedactLogs` (RD-889) via the unified `explorer.ABIResolver` (wired to `rbac.Store` + `rbac.ResolveContractABI`). RD-890 closed the admin-bypass asymmetry by adding `explorer.AdminContractsResolver`, wired to `rbac.AccessController`, which mirrors the RPC layer's per-contract `isAdminByContract` map — tier-2 (`is_org_admin`) and tier-3 (per-contract `admin` claim) viewers bypass the deny gate on both layers. Resolvable means a custom upload OR `metadata.token_type` matching the built-in registry (ERC-20 / ERC-721). Grant save handlers (create + update) reject non-deny `event_rules` up-front when no ABI is resolvable, so admins get a clear 400 instead of silently saving rules that won't fire. Closes `decisions.md` §2 G5.
- **G6 (resolved, RD-873):** Block-level `logsBloom` not zeroed — bloom filter contained hashed representations of addresses and event topics from every log in the block; a viewer who knew a target address could probe activity in O(1). Now overwritten with an all-zero 256-byte value on every block-returning RPC response (`eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBlockReceipts`) regardless of viewer or block shape. The previous "expensive per-block scanning" cost vanished once we accepted that clients of the Open Privacy Suite can't usefully consume the bloom anyway — sanitisation is a single field overwrite.
- **G7 (resolved):** Transaction.contractAddress leaks deployed address — contract deployment transactions from hidden deployers are now dropped entirely via SQL-level visibility filtering (union-kept rows excepted: they survive with `contractAddress` at the viewer's own level, G27).
- **G8 (resolved):** TokenHolder entries not dropped when address is Hidden — now dropped.
- **G9 (resolved):** Log entries not dropped when emitter is Hidden — now dropped entirely.
- **G14 (resolved):** Token endpoints (`/tokens`, `/tokens/:address`, `/tokens/:address/holders`, `/tokens/:address/transfers`) returned raw unredacted token data without any visibility checks. Now: Hidden tokens are dropped from lists and return 404 from single-token endpoints. Redacted tokens have sensitive fields masked (`[PRIVATE]`, nil names/symbols, zeroed counts). Sub-endpoints (holders, transfers) return 404 for Hidden or Redacted token addresses. List total reflects filtered count only.
- **G24 (resolved, RD-1009): Cross-redactor row-survival asymmetry — tx dropped while its derived token-transfer row survived**
  `RedactTransactions` and `RedactTransfers` apply the same drop predicate (`bothHidden → drop unless adminAuditView`), but they evaluate it on *different address sets*: `RedactTransactions` checks the EVM tx's `from` / `to` (typically the EOA caller and the token *contract address*), while `RedactTransfers` checks the ERC-20 event's `from` / `to` (the actual participants). For an admin viewing an org-mate's incoming USDC, the tx looked like `{from: hidden_user, to: hidden_token_contract}` → both hidden → tx dropped, while the transfer was `{from: hidden_user, to: visible_org_mate}` → kept. Result: `/transfers` surfaced the transfer (and via `TokenTransfer.TxHash`, the parent tx hash) while `/transactions` was missing the row — incoherent UX and an audit-trail gap. **Fix:** `buildVisibilityFilter` adds to `VisibilityFilter.VisibleTxHashes` the parent tx hashes of token transfers that involve the viewer (their own address, a Full disclosure-grant subject) or that the viewer can see, so the parent survives both the SQL allowlist filter and `RedactTransactions`' drop predicates. Which transfers drive it depends on the viewer (G27): for an admin (`isViewerAdmin`, exempt from the G10 drop), any transfer with a Full-visible party (`FindTransferParticipantTxs`); for anyone else, transfers with one of their own addresses or a Full disclosure-grant subject as a party, and transfers whose two sides are both Full or public on a token they have event access to (`FindTransferTxsBetween`). The union keeps rows only (G27, RD-1316): a union hash survives the SQL filter and the redactors' drop predicates, but its addresses render at the viewer's own visibility; only a genuine `tx_visible_to` listing (`ListedTxHashes`) reveals. It is still driven only by Full-visible (or, for the G27 both-sides class, public) addresses — never by a pseudonymous/redacted grant subject; see the RD-1079 correction below. The union is a row-survival override only: it is never a `visibleTo` listing, so the log decisions that require one (the §3.7.1 unlock and the §3.4.1 param-rule fallback) read `ListedTxHashes`, which excludes it (RD-1307). Counter to the broader directions considered (drop the transfer instead, or render everything `[PRIVATE]` uniformly), this preserves the visibility the viewer already has on the transfer side. The single-tx-by-hash path (`getExplorerTransaction`) uses the same filter through `buildRedactOptsForViewer` (RD-1009 follow-up).

- **G25 (resolved, RD-1079): only Full disclosure grants drive the parent-row union**
  The G24 union was first driven from every address in `VisibleAddresses`, which also holds pseudonymous/redacted disclosure-grant subjects (kept there so the subject's own `/transfers` rows survive the SQL filter). At the time the union also revealed the tx-level parties, so a pseudonymous grant on Eve exposed her counterparty Charlie in full hex, bypassing the §3.7.2 lens. **Fix:** only Full-visible addresses drive the union; non-Full grant subjects stay in `VisibleAddresses`, and their counterparties render at the lens level. **Trade-off:** for a pseudonymous/redacted-grant viewer the subject's transfer shows in `/transfers` but its parent tx does not surface in `/transactions` — a documented exception to the §6 coherence invariant. Since RD-1316 the union no longer reveals (G27), so the exclusion is a scope rule rather than a leak fix: a non-Full grant authorises the subject's own rows under its lens, while the parent tx of a transfer the subject merely took part in belongs to its sender (wallet, gas, timing), which that grant does not cover. Pinned by `TestBuildVisibilityFilter_DisclosureGrant_UnionDrivenByFullOnly_RD1079` (server) and `redactor_rd1079_test.go` (redactor).

- **G4 (resolved, RD-1177): InternalTransaction.error not stripped**
  Error strings returned from trace calls can contain raw revert messages or embedded addresses (e.g. `execution reverted: caller 0xABCD... not authorized`). `RedactInternalTransactions` masked From/To→`[PRIVATE]` and stripped Input/Output/Value on the one-side-hidden branch but left `error` unchanged, while the top-level `RedactTransactions` already nil'd it — an asymmetry that leaked the hidden counterparty's address/reason on `/transactions/:hash/internal`. Fixed: `redacted.Error = nil` on the one-side-hidden branch, mirroring `RedactTransactions`. Pinned by `TestRedactInternalTransactions_OneSideHidden_StripsError_RD1177`.

- **G27 (resolved, RD-1316): transfer-participant parent-row visibility**
  The G24 union keeps rows; it never reveals. A union-kept parent tx renders every address at the viewer's own visibility: another user's wallet stays `[PRIVATE]`, calldata and nonce are cleared, and value is cleared unless the §3.8 admin audit view (counted in `AdminUserTxsRevealed`) or a disclosure-grant lens applies. Only the viewer's own participation, a genuine `visibleTo` listing (`ListedTxHashes`, carried apart from the union) or the disclosure-grant lens reveals an address.
  - **Drivers.** Admins (`isViewerAdmin`, exempt from G10): any Full-visible transfer party. Everyone else, whose `/transfers` applies G10 and the event-access strip: (1) their own addresses — the parent is the viewer's own activity — and (2) Full disclosure-grant subjects — a Full grant covers the subject's transfer-linked txs (G25 limits this to Full) — kept whether or not the transfer row survives the event-access strip; (3) for coherence only, and so bounded by the transfer rows the viewer actually sees: transfers whose two sides are both Full or public (the zero address, a precompile) on a token they have event access to — mints and burns of a visible contract's tokens, and transfers between two visible contracts. A plain contract grant does not keep another user's tx whose transfer has a hidden side: G10 drops both rows, matching the RPC.
  - **Derived rows.** The union is keyed on the parent hash and keeps only the parent. Sibling transfers follow their own participant, grant, G10 and admin rules. The parent's internal frames follow the ordinary frame rules: a frame with at least one side the viewer can see survives with the other side `[PRIVATE]`; a frame with both sides private (another org's call tree) is dropped unless the §3.8 admin audit view keeps it (counted). Only a genuine listing of the parent reveals its frames.
  - **RPC.** Union-kept rows show public activity fields (existence, block, timing, gas); the RPC may return `null` for the same tx under its participant rules. Addresses agree: neither layer reveals the private party.
  - **RD-1079 scope correction.** RD-1079 kept the union's reveal for "a Full-level viewer (admin, or a full grant), entitled to see counterparties". That entitlement covers only the Full-grant lens: the disclosed party's counterparty on rows where the disclosed party is a party, audited via `GrantFullReveals` (§3.7.2). It never covered an org admin's view of user wallets (§2.1, G12), tx-level parties that are not the row's counterparty (the token contract, a relayer), calldata/nonce/value, or internal frames (RD-1122 / RD-1223). Before RD-1316 the union acted as an unaudited full reveal for admins and contract-grant holders; it now only keeps rows.
  Tests: `redactor_union_row_survival_rd1316_test.go`, `explorer_transfer_union_no_reveal_rd1316_test.go`, `store_transfer_txs_between_rd1316_test.go`.

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

- **G28: Derived rows that can survive without their parent tx**
  Two exceptions to the §6 coherence invariant (a surviving derived row implies its parent tx survives):
  1. **Internal frames have no G10 drop.** `RedactInternalTransactions` drops a frame only when both sides are private. A frame with one identifiable side — e.g. `[PRIVATE]` token → the viewer's vault — surfaces on `/transactions/:hash/internal` (and the address/block internal lists) for a non-admin whose `GET /transactions/:hash` is 404 under G10. This predates RD-1316 for txs with no visible transfer party; RD-1316's narrower non-admin union (G27) extends it to the transfer-linked txs of contract-grant holders, whose parent the union used to keep.
  2. **Admin mints and burns of other orgs' tokens** (predates RD-1316). An admin's `/transfers` keeps a mint or burn with a private counterparty on any token (the zero address is public; admins skip G10 and the event-access strip — G13), but the zero address does not drive the admin union (G27), so the parent tx — a private wallet calling another org's token — is dropped.
  Options: apply G10 to frames for non-admins (as for transfers); for (2) either restrict admin mints/burns to tokens the admin can see (G13) or let public addresses drive the admin union. Pinned by `TestExplorer_DerivedRowWithoutParent_GAP_G28`.

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
- **RD-1183 `eth_getTransactionByHash` log-entitlement gap:** the RD-1183 receipt admission (a log-entitled non-participant gets `eth_getTransactionReceipt`) is **not** mirrored on `eth_getTransactionByHash` / the block-index variants, which stay binary on participation/`visibleTo`/admin. The tx envelope carries no logs, so deciding entitlement there requires an out-of-band lookup (fetch the receipt, or query the indexer's log store) — deferred to keep this change self-contained and off the hot path. The interim state is strictly *more* restrictive on tx-by-hash than on the receipt (benign over-restriction, no leak). Follow-up: RD-1191.

### Cross-redactor consistency (RD-1009 / G24 + follow-up)

Single-entity matrices above test each redactor in isolation. Real bugs hide in the gaps *between* them. Every change touching `RedactTransactions`, `RedactTransfers`, `RedactInternalTransactions`, `RedactLogs`, the SQL pre-filter `buildVisibilityFilter`, or the by-hash helper `buildRedactOptsForViewer` MUST include at least one assertion that the surviving rows from a derived feed (transfers / internal txs / logs) imply the parent tx survives in the surrounding `/transactions` list and `GET /transactions/:hash` lookup.

Required scenarios (RD-1009 + follow-up):

| Fixture | Viewer | Expected |
|---------|--------|----------|
| EOA caller hidden, token contract hidden, transfer recipient admin-visible | Admin (flag off) | tx surfaces; transfer surfaces; internal frames of the parent surface only where the admin sees a side (a frame with both sides private is dropped; the §3.8 audit view keeps and counts it); the Transfer log surfaces only if the admin can see the emitting token (§3.4) — every row with the caller EOA and the tx-level token `[PRIVATE]`, calldata/nonce/value stripped (the union keeps rows, it never reveals — G27; the transfer row's `tokenAddress` stays as §3.3 accepts) |
| Same fixture | Non-admin, non-participant | None of the above surface |
| Same fixture | Admin, by-hash (`GET /transactions/:hash`) | 200; matching `/transfers` returns rows; `/internal` and `/logs` follow row 1 |
| Counterparty (Charlie) hidden, token hidden, transfer recipient (Eve) visible via **Full** disclosure grant | Non-admin, non-participant, Full grant on Eve | tx surfaces (Full drives the union; tx-level parties at the viewer's own level); on the transfer row counterparty Charlie is rendered as real address by the Full lens (entitled, counted in `GrantFullReveals`) |
| Same fixture, **Pseudonymous** grant on Eve | Non-admin, non-participant | transfer surfaces with Eve as pseudonym and **counterparty Charlie as a pseudonym, never real hex** (`disclosure_grant` reason); parent tx does **not** surface in `/transactions` (RD-1079 — Full-only union) |
| Same fixture, **Redacted** grant on Eve | Non-admin, non-participant | transfer surfaces with Eve and counterparty Charlie as `[PRIVATE]`; parent tx does **not** surface in `/transactions` |
| Same fixture, any grant level | viewer listed in the parent tx's `tx_visible_to` | tx surfaces and counterparty revealed — but ONLY because of the genuine per-tx `visibleTo` share, not the transfer-participant union |
| Hidden EOA calls a token; the tx mints to (or burns from) a contract the viewer sees, or moves tokens between two contracts the viewer sees; the viewer's grant on the token has event rules | Non-admin, non-participant | transfer surfaces with its amount; tx surfaces (third driver class, G27) with the caller `[PRIVATE]`, calldata/nonce/value stripped |
| Same fixture, token grant without event rules | Non-admin, non-participant | transfer stripped (no event access); tx does not surface |

Known exceptions to the invariant are G25 (a pseudonymous/redacted grant shows the subject's transfer without its parent) and G28 (derived rows that can survive without their parent); each is pinned by a test.

The bug class is invisible to per-entity matrices because each redactor passes its own assertions independently. The pinned invariants (`internal/server/explorer_coherence_e2e_test.go` drives all five surfaces against one fixture) catch divergence at PR time. Reviewers: a new explorer surface that derives rows from a parent tx MUST add a row to that coherence test before merge.

The unified opts contract for handler authors:

- **List handlers** compute `isViewerAdmin` once, call `s.buildVisibilityFilter(ctx, viewerDID, isAdmin)`, then `redactOptsFromFilter(filter)` with the same value as `ViewerIsAdmin`, plus `applyAdminTxView`.
- **Single-item handlers** call `s.buildRedactOptsForViewer(...)` — internally identical, by design.

Constructing `explorer.RedactOpts{}` by hand silently skips the transfer-participant union, `visibleTo` shares, and the admin-flag wiring. PR review rejects hand-rolled opts.

#### Why `RedactLogs` is NOT in the same bug class

`RedactLogs` evaluates its drop predicate on the **emitting contract address** (`l.Address`), not on tx participants. Its `visibleTo` decisions — the §3.7.1 unlock and the param-rule fallback — read the genuine listings (`opts.ListedTxHashes`), never the transfer-participant union (RD-1307, G27). There is no related-feed redactor that surfaces "the same log row" at a different address set, so the RD-1009 asymmetry shape (two redactors evaluating `bothHidden` on different address sets) cannot apply. The log model has its own gating (deny-when-no-ABI, event_rules, dynamic-payload drop, M15) — orthogonal to row-survival coherence.


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

The `visibleTo` parameter lets a transaction sender **share a transaction** with specific recipients: the listed DIDs receive the full **transaction/receipt envelope** (§3.8) even if they are not a `from`/`to` participant. It is **not** a contract-level event-access grant. The **event logs** inside that transaction stay gated by each emitting contract's grant (§3.4.1): ordinary (non-unlock) `visibleTo` is *additive* — it widens an already-permitted viewer's log access but never admits logs from a contract the viewer holds **no** grant on (RD-1208). A contract owner who wants `visibleTo` to confer standalone event access opts in per-contract via `allow_visibleto_unlock` (§3.7.1).

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
- **JSON-RPC log filtering**: on contracts the listed DID **already holds a grant to**, `visibleTo` widens their event-log access via `eth_getLogs` / `eth_getTransactionReceipt` — e.g. an allowlisted event whose `must_be=self` param rule would otherwise filter it passes for a listed DID (the param-rule fallback, §3.4.1). This is purely additive (never restricts). It does **not** admit logs from a contract the viewer has **no** grant on: grant eligibility is load-bearing (RD-874 / §3.7.1), so ordinary `visibleTo` never grants new contract-level event access (RD-1208). The `allow_visibleto_unlock` semantic (§3.7.1) is the only opt-in that turns `visibleTo` into a standalone event grant: if **that emitting contract** enables it, an eligible listed viewer sees every log it emitted **in that transaction**, with the full payload, regardless of their grant's event allowlist/parameter rules. Other emitters and later transactions are evaluated separately.
- **Transaction and receipt access**: `visibleTo` overrides participant checks for both `eth_getTransactionByHash` and `eth_getTransactionReceipt`. A listed DID receives the full transaction/receipt **envelope** even if they are not a from/to participant — the sender explicitly chose to share this transaction. The **logs inside** a shared receipt remain event-filtered per §3.4.1: the envelope is shared, but a no-grant emitter's logs are still dropped (RD-1208).

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

---

## 9. Raw storage reads — `eth_getStorageAt`, `eth_getProof` (RD-805, RD-1301)

Raw storage methods use contract access and storage-slot permissions at the **request** boundary (`rbac.validateStorageReadAccess`, called from `validateContractAccess`). Admitted responses are forwarded unchanged; denied requests receive the opaque `method not found` before they reach the node.

| Method | What the response carries | Non-admin on the contract | `admin` claim on the contract |
|---|---|---|---|
| `eth_getStorageAt(addr, slot, block)` | the slot's value | slot must be a well-known infrastructure slot | any slot |
| `eth_getProof(addr, keys[], block)` | balance, nonce, `codeHash`, `storageHash`, `accountProof`, and for **every** key its `storageProof[].value` + trie path | every key must be a well-known slot; an empty `keys` list (account-only proof) is allowed; a missing, `null` or non-array `keys`, or any non-string key, is denied | any keys (not inspected) |

- **Well-known slots** are hardcoded in `internal/rbac/storage_slots.go`: EIP-1967 implementation / admin / beacon and the EIP-2535 Diamond slot. They hold infrastructure addresses only. A key matches only in its full 32-byte form (case-insensitive, `0x` optional); short-form spellings never match, so they are denied.
- **Admin** means `admin` in the per-contract `ContractAccess` claims resolved for the request: tier 2 (`is_org_admin`, all claims on every org contract) or tier 3 (a group holding the `admin` claim *and* a grant on this contract). Deployer auto-grant, pre-registration (`deploy` claim), precompiles and plain grants are non-admin.
- **Order of gates (authenticated):** global blocklist + multicall detection → user gates (existence, ban, KYC) → historical-state guard (only `is_org_admin` is exempt) → org resolution → method allowlist → value-transfer / basic-address-query carve-outs (neither covers a storage read) → contract access + cross-org isolation → storage-slot tier. A storage read whose target address is missing or not a string is denied instead of being forwarded without the contract and slot checks.
- **Anonymous callers** get no contract-level check at all, so the tier cannot apply to them: a storage read is denied (`AuthRequired`) on the anonymous path even if a super admin adds the method, or an alias of it, to the anonymous group's allowlist.
- **Aliases** are judged on their access-control target (`AccessCheckRequest.EffectiveMethod`; targets are trimmed, validated against standard methods and stored in canonical spelling at startup): an operator alias such as `linea_getProof → eth_getProof` gets the same slot tier **and** the same historical-state guard as its target. No built-in standard method (`rbac.IsStandardMethod`, which covers every method a check or response filter keys on through the alias target) can be an alias key — config loading rejects it (`config.parseExplicitMethods`), because the node executes the raw method while many access decisions key on the alias target. As defence in depth, the Multicall check, the slot tier, the historical guards, the missing-target deny, the basic-address carve-out's storage-read exclusion and the anonymous floors also judge the raw method (`methodsToJudge`). A **passthrough** method has no alias target and is forwarded without these checks, so a chain-specific proof method must be declared as an alias of `eth_getProof`, not as passthrough (see the configuration docs).
- The same `CheckAccess` pipeline serves `/rpc`, the impersonation surface (view-as-user) and the admin `test-request` diagnostic, which resolves aliases the same way.

### Proof response metadata

The per-key allowlist controls which slot **values** a non-admin may request. An allowed Merkle-Patricia proof also includes account metadata, the storage root (`storageHash`), and account/storage trie proof nodes. This metadata is forwarded unchanged; the slot allowlist does not filter it. Empty-key account proofs remain supported under the same contract and method permissions.

Grant `eth_getProof` only to groups that need state proofs. Details: RD-1301. Broader account-metadata policy is tracked separately in RD-1270.

Tests: `internal/server/getproof_slot_access_rd1301_test.go` (full `Process()` path against a counting upstream — every denial asserts the node was never called; aliases, historical blocks, cross-org, every non-admin access path, malformed params, `test-request`), `internal/rbac/storage_read_access_test.go`, `e2e/storage_access_test.go`.
