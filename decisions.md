# Decisions, Limitations & Open Items

Last updated: 2026-04-21

Compiled for team review. Each item describes the current state, the decision made (or deferred), and whether action is needed. Items that have been fully resolved are removed — see `docs/OPEN_ITEMS.md` and git history for the cleanup log.

---

## 1. Privacy Model: Private by Default

**Decision:** Addresses/contracts are private by default. They only become accessible when registered to an organization and granted to users.

- Unregistered contracts (not owned by any org) are **denied by default**. Only EVM precompiles (0x01-0x09) are publicly accessible.
- Once a contract is registered to an org, only members with explicit grants (or implicit access via `deploy`/`admin` claims) can access it.
- The proxy is the sole gateway — if the proxy denies access, there is no alternative path.
- Access is gated by the method allowlist (`AllowedMethods`), not by claims.

**Implication:** Anything deployed through the proxy is automatically registered to the deployer's org (private). Anything deployed outside the proxy is unregistered and denied by default — it must be claimed via the admin API to become accessible.

### Anonymous (unauthenticated) access

Users without a JWT can only call claim-free methods: `eth_blockNumber`, `eth_chainId`, `eth_gasPrice`, `net_version`, etc. These return chain metadata only — no user data, no transactions, no contract state. All other methods (`eth_call`, `eth_getLogs`, `eth_getBalance`, `eth_getCode`, etc.) are denied.

- ***Impact on block explorer:*** An unauthenticated visitor to the block explorer sees essentially nothing useful — no transactions, no addresses, no contract data. The explorer's `ProxyDataProvider` calls the privacy proxy's Explorer API endpoints, which require authentication to return redacted data. Without a JWT, the explorer can show chain liveness (block number, chain ID) but no blockchain content.
- ***Discuss:*** Is this the intended UX for the block explorer? Should there be a "public view" that shows redacted transactions (all addresses as `[PRIVATE]`) to unauthenticated users, or should login be required to see anything?

---

## 2. Redaction Gaps (Known, Documented)

Remaining privacy leaks documented in `REDACTION_SPEC.md` with explicit test coverage asserting the *broken* behavior so they don't become invisible.

### G5: Log.data not scanned when no ABI registered — **CLOSED (RD-875)**

- With a registered ABI: non-indexed `address` params in `data` are decoded and private addresses zeroed
- Without ABI: raw ABI-encoded `data` blob returned unmodified — private addresses embedded as non-indexed params will leak
- **Decision:** Reversed for audit. Without an ABI we can't decode non-indexed address params — instead of accepting the leak, the RPC layer (`FilterEventLogs`) now denies all logs from a contract that has no resolvable ABI, regardless of `event_rules` (admin viewers excepted). Grant create/update handlers also reject non-deny `event_rules` up-front when no ABI is resolvable. ABI is resolvable when either a custom ABI is uploaded or `metadata.token_type` matches the built-in registry (ERC-20 / ERC-721).
- **Status:** Closed by RD-875 (PR #187).

### G6: Block.logsBloom not zeroed — **CLOSED (RD-873)**

- Bloom filter contains hashed representations of addresses — a viewer who knows a target address can probe whether it has activity in a block in O(1)
- Zeroing the bloom for all blocks requires expensive per-block address scanning
- **Decision:** Reversed for audit. The "low practical risk because attacker must already know the address" framing didn't hold in a private-by-default model — out-of-band leakage of addresses is exactly what we can't rule out. The bloom is now overwritten with all-zero (256 bytes) on every block-returning RPC response, every viewer. Mitigation cost turned out trivial — a single field overwrite, no DB lookups — once we accepted that clients of a privacy proxy can't usefully consume the bloom anyway.
- **Status:** Closed by RD-873 (PR #181).

---

## 3. Fields Accepted as Public (Not Redacted)

These fields are intentionally NOT redacted per design decision:

| **Field** | **Rationale** |
| --- | --- |
| `gasUsed`, `gasPrice`, `maxFeePerGas`, `gasLimit` | Gas params not identity-revealing in isolation |
| `txCategories` | Derived labels, not raw addresses |
| `miner` | Block producer is consensus-layer infrastructure, not user identity |
| Block header fields (`number`, `hash`, `timestamp`, etc.) | Consensus-layer public data |
| InternalTransaction `gas`, `gasUsed` | Not identity-revealing |

**Discuss:** Any of these a concern for the use case?

---

## 4. TODOs: Privacy Features Not Yet Built

### 4a. ~~Multi-party event stakeholder whitelists~~ — **RESOLVED**

`internal/server/response_filter.go:3` (stale TODO, predates `visibleTo` + EventRules)

**Status: not a real gap.** The original concern was: events whose indexed parameters are business identifiers (e.g., `event PaymentInitiated(string indexed paymentIdentifier)`) rather than addresses can't be matched to a viewer via `must_be=self`, so how does a multi-party set of stakeholders (debtor bank, settlement bank, creditor bank) each see the events for *their* payment?

**How it's actually covered today:**

1. **EventRules** — admins can allow an event for a group with: no `param_rules` (group sees all instances of the event), `must_be=self` (only events where an indexed address param matches the viewer), or `must_be=<hex>` (only events where an indexed param equals a fixed value).
2. **`visibleTo`** — the tx sender passes a DID list with `eth_sendTransaction`. Event logs from that tx become visible to listed DIDs even when `must_be=self` would otherwise filter them. This is the per-payment stakeholder mechanism: the submitting bank names the other stakeholders at send time.

Together these cover the multi-party-per-payment case at submit time.

**What remains out of scope (by design, not a bug):**

Granting visibility to a third party (e.g., an auditor) *after* a transaction is already mined, on a tx that has no common identifier (no shared from/to/topic) with other txs, requires disclosing those txs one-by-one. That's inherent to any system — you can't scale "give auditor access to these N arbitrary txs" without enumerating them. For that case the product has the **disclosure feature**: the auditor requests access, the sender approves, access is granted per-tx. MVP intentionally does not try to automate this beyond the disclosure flow.

**Discuss:** Sanity-check this framing with the team — is there a scenario where neither `visibleTo` (at submit time) nor disclosure (post-mine) is sufficient? If not, 4a can be closed and the `response_filter.go:3` TODO removed.

### 4b. eth_call response ABI decoding

`internal/server/response_filter.go:9`

`eth_call` returns raw ABI-encoded bytes. For field-level privacy (e.g., hiding `amount` in `getPaymentInfo` unless user is a party), the proxy needs to decode the response and selectively redact fields. Requires contract ABI registration + per-function redaction rules.

- **Current behavior:** Full `eth_call` response returned unfiltered to any user with read access.
- **Not resolved by `visibleTo`.** `visibleTo` is only extracted from `eth_sendTransaction` and does not apply to `eth_call` responses. eth_call responses remain unfiltered.

### 4c. Traffic analysis via block-level metadata

`internal/server/response_filter.go:287` (`FilterBlockTransactions`)

**Correction:** `eth_getBlockTransactionCountByHash/Number` does **not** leak the real block tx count — it's rewritten into a full-block fetch and returns only the count of the viewer's own transactions (`jsonrpc_processor.go:459-465`, `FilterBlockTransactionCount`). The earlier concern here was stated incorrectly.

**The actual leak:** `eth_getBlockByHash/Number` returns a block object where the `transactions` array is filtered to the viewer's own txs and `logsBloom` is zeroed — but block-level aggregate fields pass through untouched:

- `gasUsed` (total gas consumed by ALL txs in the block, including other orgs') — strongest signal; can estimate overall activity and, combined with the viewer's own gas usage, indirectly the number/weight of other txs in the block.
- `gasLimit`, `size`, `baseFeePerGas`, `timestamp`, `difficulty`, `number`, `hash`, `parentHash`, `miner`, etc.

These are consensus-layer data: they're identical across every RPC node on the network and can't be hidden without breaking chain integrity for the viewer. §3 already accepts `miner` and block header fields as public for this reason.

**Discuss:** Is block-level `gasUsed` a concern? It's the one field where "public by consensus" and "leaks aggregate other-org activity" overlap most clearly. Options: (a) accept as inherent to the chain, (b) zero it in responses (breaks any legitimate consumer that relies on gas-used for their own txs), (c) partially obscure (e.g., round to nearest bucket).

**Discuss:** Are 4b and 4c blocking for MVP? 4a is resolved above. 4b means `eth_call` responses are unfiltered. 4c is block-level aggregate gas/size metadata.

---

## 5. KYC / Billions Credential Gap

`docs/PRODUCTION_READINESS.md` section 1

**Problem:** After ZK proof verification succeeds, `kyc` is set to `false`. An admin must manually set `kyc=true` via the dashboard. This doesn't scale.

**Recommended fix:** Auto-set `kyc=true` when `ProofOfHumanity` verification succeeds.

### Making the credential check configurable

**Background.** Login has two paths:
- **Path A** — prove DID ownership only. No credential required.
- **Path B** — Path A + present a specific credential from a specific issuer containing a specific claim.

Path B currently has five values hardcoded in `internal/auth/privado.go`: the on-chain state contract, the ZK circuit ID, the credential schema URL, the credential type name, and the claim predicate (`isHuman == 1`). Four are strings; the claim is a structured iden3 query (supports multiple fields and operators like `$eq`, `$in`, `$lt`, …).

**Plan (approved).**

1. Expose four string values as env vars with current-as-defaults:
    - `PRIVADO_STATE_CONTRACT`
    - `PRIVADO_CIRCUIT_ID`
    - `BILLIONS_CREDENTIAL_SCHEMA_URL`
    - `BILLIONS_CREDENTIAL_TYPE`
2. Expose the claim as a JSON file (not flat env vars — an iden3 query can be multi-field):
    - `BILLIONS_CREDENTIAL_QUERY_FILE=/path/to/query.json`
    - File content example: `{"credentialSubject":{"isHuman":{"$eq":1}}}`
3. Change Path B to **opt-in by default** in every environment. Today prod defaults `RequireProofOfHumanity=true`, which means a prod deploy would ship with the hardcoded PolygonID-tutorial values — guaranteed to mismatch real Billions credentials. New behaviour: Path B runs only when explicitly enforced.
4. When Path B is enforced, validate at startup: all four env vars non-empty, query file exists, parses as JSON, contains `credentialSubject`. Otherwise the process refuses to start. This prevents a silent "prod boots but every login fails" outage.

**External dependency — input needed from Billions.**

Before Path B can be enabled in production, we need the following from Billions:

- Their real issuer DID
- Schema URL + credential type
- Circuit ID they sign with (MTP vs Sig vs V3)
- The field / operator / value that encodes "this person is KYC'd"

The plumbing can ship independently, but Path B stays off until these values are confirmed. Worth aligning on who owns the conversation with Billions.

**Action required before enabling Path B in prod:**

1. Get real values from Billions (schema URL, credential type, circuit ID, issuer DID, claim predicate).
2. Populate the four env vars + the query JSON file.
3. Set the enforce flag.
4. Smoke-test login end-to-end with a real Privado wallet holding a real Billions credential.

**Discuss:**
- Auto-set `kyc=true` on successful Path B, or keep manual admin approval?
- Anyone we can assign to own the Billions conversation?

---

## 6. Accepted Security Risks

From `docs/PRODUCTION_READINESS.md`:

| **Issue** | **Severity** | **Rationale** |
| --- | --- | --- |
| User JWTs in sessionStorage; admin API token in localStorage | High | User access/refresh tokens live in `sessionStorage` (per-tab, cleared on tab close — `AuthContext.tsx:31`). Admin API token lives in `localStorage` (`adminClient.ts:5-15`). Any XSS payload on the page can read both; `sessionStorage` only limits persistence, not readability. Mitigated by CSP. Proper fix is httpOnly cookies + CSRF protection — needs auth rework. |
| `/me/admin-status` externally accessible | High | Frontend needs it. Read-only, JWT-protected, returns boolean only. |
| No PKCE on Azure OAuth | Medium | Backend uses client secret (not a public client). |
| No rate limiting on admin endpoints | Medium | Protected by network isolation + token auth. |
| Wide private CIDR allowlist | Medium | `ADMIN_API_TOKEN` required in prod — network check is defense-in-depth. |

**Discuss:** Are these acceptable for production? The token-storage one is the most impactful — any XSS on the admin UI can read both user JWTs and the admin API token.

---

## 7. Audit Log Sensitivity

`internal/audit/redact.go`

Two explicit warnings in code:

1. Enabling `AUDIT_LOG_PARAMS` logs params for **all** methods verbatim — sensitive arguments for unlisted methods will appear in audit logs
2. Unknown methods are passed through and logged verbatim (intentional design, not a bug)

**Discuss:** Review which methods are enabled before turning on `AUDIT_LOG_PARAMS` in production. Ensure the audit log destination is appropriately secured.

---

## 8. Contract Access Within Your Own Org

`internal/rbac/access.go`, `internal/rbac/org_context.go`

When a contract is registered to an org, member access depends on their group configuration. After RD-849, the rule is uniform across the RPC access layer and the explorer visibility layer:

| **User's group** | **Explicit contract grant?** | **Can access own-org contract?** |
| --- | --- | --- |
| Group with `is_org_admin = true` (tier 2 org admin) | N/A — grants are materialized automatically | **Yes** — all org contracts (both RPC and explorer) |
| Group with `admin` or `deploy` claim (tier 3) | Yes | **Yes** — only for contracts their group has been granted |
| Group with `admin` or `deploy` claim (tier 3) | No | **No** — claim alone does not unlock contracts |
| Group with only method allowlist | Yes (via group) | **Yes** |
| Group with only method allowlist | No | **No** — denied |
| Any group, deployer of a specific contract | Auto-grant on deploy | **Yes** — only for contracts the user deployed |

Tier 3 admins were previously given implicit access to all own-org contracts at the RPC layer only — an asymmetry with the explorer. RD-849 fixed this; `CheckDefaultClaimsAllowed` no longer falls through for admin/deploy claim. The invariant "RPC access and explorer visibility must agree" is enforced by `e2e/access_visibility_symmetry_test.go`.

**Discuss:** New org members without explicit grants can't access their own org's contracts until an admin either (a) creates a contract grant for their group, (b) promotes them to an `is_org_admin` group, or (c) they themselves deploy a contract (auto-grant). Is that the intended UX, or should the default group get some form of baseline grant?

---

## 9. SIEM Webhook — Privacy Disclosure

The SIEM forwarder (`internal/audit/siem.go`) sends batched events to an external webhook. This is an intentional data export — but it means user-identifying information leaves the system.

### What's sent in every access event

| **Field** | **Content** | **Privacy Impact** |
| --- | --- | --- |
| `ActorID` | User's DID (e.g., `did:privado:...`) | **High** — personally identifiable |
| `SourceIP` | Client IP address | **High** — location tracking |
| `Action` | RPC method name (`eth_call`, `eth_sendTransaction`, etc.) | Medium — activity profiling |
| `Outcome` | `success`/`denied`/`error` | Medium — reveals access attempts on private contracts |
| `EntryHash` | SHA-256 of the full audit log entry | Low — hash only |

### Ethereum address linking events

When a user links an ETH address, the SIEM event's `Details` field contains `address=0x...` — the **raw Ethereum address in plaintext**. This directly ties a user's DID to their wallet address in the external SIEM system.

The code is aware of this sensitivity: when an address collision is detected (same address linked by multiple DIDs), the full DID list is intentionally NOT sent to SIEM ("full DID list is PII and must not leave the system in forwarded events" — `eth_link.go:269-270`). But the address itself still goes out.

### AUDIT_LOG_PARAMS flag

When `AUDIT_LOG_PARAMS=true`, request parameters are included:

- `eth_sendRawTransaction`: raw tx hex truncated to 20 chars
- `eth_sendTransaction`: `from/to/value/gas` kept, `data` truncated
- `eth_call`, `eth_estimateGas`: `from/to/value` kept, `data` truncated
- **All other methods: params logged VERBATIM** — the code has explicit warnings about this

Default is `false` (params not logged).

### Security controls

- HTTPS-only (non-HTTPS rejected)
- SSRF protection: blocks private/loopback/metadata IP ranges
- No redirects allowed
- 10s timeout, 3 retries with exponential backoff
- Fallback: failed batches written to local file (0600 permissions)

**Discuss:**

- Is sending raw DIDs and IP addresses to an external SIEM acceptable? Should they be hashed/anonymized?
- Is sending raw ETH addresses in address-link events acceptable?
- If `AUDIT_LOG_PARAMS` will be enabled, which methods are safe to log verbatim?

---

## 10. What the Proxy Does NOT Protect Against

This section describes scenarios where users can leak data despite the proxy's protections. These are architectural limitations, not bugs.

### 10a. Public view functions can return anything

If a contract has a `public view` function that returns sensitive data, anyone with `read` access can call it via `eth_call` and see the full return value.

**Why:** The proxy validates who can call which contract but cannot inspect or redact return values from `eth_call`. Response data is raw ABI-encoded bytes.

**Example:** A contract with `function getCounterparties() view returns (address[])` — any org member with read access sees the full list, even if addresses belong to other orgs.

**Bottom line:** Contract authors are responsible for not exposing sensitive data through public view functions. The proxy can't fix bad contract design.

### 10b. Contract bytecode visibility is a per-group configuration choice

`eth_getCode` is gated by the group's `AllowedMethods` list (method allowlist). There is no claim requirement — if the method is in the allowlist and the user has contract access, `eth_getCode` is allowed. Cross-org `eth_getCode` is denied. An org admin can remove `eth_getCode` from a group's allowed methods to prevent members from reading bytecode, while still allowing `eth_call` and other read operations.

If `eth_getCode` IS allowed for a group, members can read deployed bytecode of contracts they have access to. Hardcoded addresses, constants, or business logic in bytecode will be visible. Source code on verified contracts (via the explorer) is also returned without redaction.

**Note:** This is not a gap — it's a configuration decision per group. Org admins should be aware that including `eth_getCode` in allowed methods exposes bytecode to group members.

### 10c. Events can leak data

Event visibility is controlled by the **EventRules** model on contract grants:
- `null` / empty event rules = **deny all events** (fail-closed default)
- `"*"` wildcard = all events visible
- Explicit allowlist: only listed events (by topic0) are visible, with optional `param_rules` (`self` or custom hex constraints)
- Cross-org custom hex addresses in param rules are rejected at grant creation time (RD-796, RD-797)

Without a registered ABI, non-indexed params aren't scanned (G5 — accepted limitation). Non-address data (amounts, strings, identifiers) is never redacted — the proxy doesn't know which fields are sensitive.

**Bottom line:** The proxy controls which events are visible via EventRules and redacts addresses in event parameters, but does not redact business data in event params. Contract authors must avoid putting sensitive information in event parameters.

### 10d. Gas usage and transaction ordering reveal patterns

Even with full address redaction, the following metadata is public:

- **Gas used** per transaction — unusual patterns can fingerprint specific contract interactions
- **Transaction position** within blocks — ordering can reveal MEV or priority relationships
- **Block transaction count** — reveals overall network activity levels
- **Timing** of transactions — temporal patterns can correlate with off-chain events

The proxy does not attempt to obscure these metadata signals — they are inherent to how blockchains work.

### 10e. Users can deploy "leaker" contracts within their org

Nothing prevents an org member with `deploy` claim from deploying a contract that:

- Stores private data in public storage (readable via view functions by other org members)
- Emits events containing confidential data
- Hardcodes addresses of other orgs' contracts in bytecode

**Key distinction:** The proxy enforces inter-org boundaries (Org A can't read Org B's contracts) but does NOT enforce intra-org data hygiene.

**Bottom line:** The proxy is an access control layer, not a data classification layer. It controls who can interact with which contracts, not what data contracts choose to expose.

### 10f. eth_getStorageAt uses tiered access

`eth_getStorageAt` uses **tiered access** based on the `admin` claim:

| **User** | **Access** |
| --- | --- |
| `admin` claim (tier 2 org admin, tier 3 contract admin on granted contracts) | All storage slots |
| Any other user with `eth_getStorageAt` in AllowedMethods | EIP-1967 and EIP-2535 well-known proxy infrastructure slots only |
| User without `eth_getStorageAt` in AllowedMethods | Blocked entirely |

However, a contract's public view functions can read and return the same storage data. The tiered access only prevents reading storage of contracts without view functions.

### 10g. Pseudonymous addresses can be correlated

When addresses are shown as pseudonyms (`Address-ABCD`, `Address-EFGH`), the pseudonyms are deterministic per viewer. Observers can track:

- Transaction frequency between pseudonyms
- Amounts flowing between them
- Timing patterns

Over time, this can de-anonymize pseudonymous addresses, especially with off-chain knowledge.

**Open question:** Is amount redaction needed for pseudonymous-to-pseudonymous transfers?

### 10h. `eth_call` internal cross-contract reads are not traced

*Related to §10a but distinct: §10a is a contract-author problem (over-sharing to authorized readers) and the proxy cannot fix it. §10h is a proxy-layer access-control bypass — the attacker has no grant on the target contract at all and reaches it transitively through a contract they control. This one the proxy can fix (below). Defensive coding per §10a also mitigates §10h as a side effect, but they are separate gaps.*

RPC-level access control validates the **direct** target of a call. Internal `STATICCALL` / `CALL` / `DELEGATECALL` hops that happen inside the EVM during an `eth_call` execution are invisible to the proxy — `debug_traceCall` is not invoked on reads.

**Concrete attack (validated):** User2 in Org B learns the address of Org A's `0xSecretBalance`, deploys their own `0xPeekBalance` that internally calls `0xSecretBalance.getBalance(targetAddr)`, and reads any address's balance via `eth_call` on their own contract. The proxy allows it because the direct target (`0xPeekBalance`) is Org B-owned. See the `peekBalance` example from the Slack thread.

**Preconditions the attack requires:**

1. Attacker knows the target contract's address (proxy redacts contract addresses from non-participants — out-of-band leakage is the usual vector).
2. Target contract has a `public view` function returning data for caller-controlled address arguments.
3. Target contract does not self-authorize (e.g., lacks `require(msg.sender == ...)` check inside the view function).

**Why this is not "useless":** address secrecy (redaction) + contract-level authorization cover most cases — every ERC-20 that checks `msg.sender` in sensitive reads is immune, as is every contract whose address never leaks to other orgs. But "contracts that follow defensive patterns + addresses never leak" is not a property we can rely on at scale.

**Fix (proposed, ~1 week engineering):**

1. Invoke `debug_traceCall` on every `eth_call` via the existing `internal/tracer` infrastructure (already built for write-path CREATE/CREATE2 detection). Anvil, geth, erigon, reth all support `debug_traceCall` with `callTracer` — verified against the running Anvil. STATICCALL / CALL / DELEGATECALL frames are all emitted with target addresses.
2. Walk the returned call tree; for each internal `to`, re-run the proxy's normal access check against the caller's grants. Deny the whole `eth_call` if any internal target is cross-org and not grantable.
3. Add a trace cache keyed on `(to, data, block_hash)` so repeated reads don't re-trace.

**Deploy-time optimizations to limit trace cost:**

- **Tier 1 — Pure contracts**: scan bytecode at deployment. If it contains no `CALL` / `CALLCODE` / `DELEGATECALL` / `STATICCALL` / `CREATE` / `CREATE2` opcodes, the contract cannot make any external call. Mark `is_pure=true` on the contract table; `eth_call` fast-path skips tracing. Catches basic OZ ERC-20 (without permit), registries, getter-only contracts.
- **Tier 1+ — Precompile allowlist**: extend "pure" to include contracts whose only call targets are precompiles (`0x01-0x09`). Catches OZ ERC-20 with `permit` (uses `ecrecover` = STATICCALL to `0x01`).
- **Tier 2 — Static call-target analysis**: for contracts with calls to hardcoded addresses (PUSH20 immediates), extract the target set at deploy time. At call time, check the caller has grants on the whole set; skip tracing. Catches the `peekBalance` pattern with one static check.
- **Tier 3 — Dynamic targets**: must trace every call. Examples: proxies (DELEGATECALL), ERC-721 `safeTransferFrom` hooks, DeFi routers.
- **Tier 0 — Bytecode-hash allowlist**: for contracts deployed from proxy-blessed templates (or verified well-known bytecode), skip analysis entirely.

**Critical safety property for implementation:** default is "trace unless proven safe." Any bug in the deploy-time analyzer that incorrectly marks a contract as pure → silent privacy breach. Every fast-path skip must be logged and counted.

**Caveats:**

- True per-selector (function-level) reachability analysis — where e.g. ERC-721 `ownerOf` skips trace but `safeTransferFrom` traces — requires dataflow analysis on the bytecode. Tools like Slither / Mythril do this. Can be a Phase 2 refinement; initial rollout can apply tiering at contract level only.
- Contract upgrades (UUPS / Transparent proxies) invalidate deploy-time decisions — tier must be recomputed on `upgradeTo` or equivalent.

**Discuss:**

- Is this blocking MVP? In its current form, the system's cross-org privacy guarantee has a gap that defensive contract-authoring practices can close but cannot be enforced by the proxy.
- Strict default (deny any cross-org internal read with no grant) vs. allowlist pattern for known-safe cross-org reads (e.g., a shared compliance oracle)?

---

## 11. Post-MVP Improvements (Not Blocking)

| **Item** | **What it adds** | **Priority** |
| --- | --- | --- |
| Auto-set KYC from ProofOfHumanity | Currently an admin manually sets `kyc=true` in the DB after login succeeds. This would flip the flag automatically on successful Path B verification, removing manual toil. Overlaps with the §5 discussion item. | Short-term |
| Dynamic issuer registry (DB, hot-reload) | Today `BILLIONS_ISSUER_DID` is a single env value — one issuer per deployment, requires a restart to change. A DB-backed registry would let an admin add/remove accepted issuers at runtime (useful if we ever support multiple KYC providers or need to rotate an issuer DID). | Medium-term |
| Multi-credential support (AND/OR logic) | Today Path B checks exactly one credential. Multi-cred means login could require e.g. "PoH **AND** jurisdiction credential" or "PoH **OR** corporate-issuer-credential". Needs a query-language extension and UI. | Medium-term |
| Credential expiry tracking + re-auth prompts | iden3 credentials have an `expiration` field in the VC schema. The proxy could extract it from the verified presentation on login, stamp it into the JWT, and prompt re-auth before expiry. **Caveat:** not all issuers populate `expiration`; if Billions doesn't, the feature degrades to a fixed re-auth interval. Needs verification with Billions once they're engaged. | Medium-term |
| Log aggregation / SIEM wiring | A SIEM webhook forwarder already exists (`internal/audit/siem.go` — batches access events, sends with SSRF protection). This item refers to ops-side work: pointing the webhook at a real SIEM (Datadog / Elastic / Splunk), parsing/routing rules, retention dashboards. Product code already supports it; deployment side doesn't. | Medium-term |
| RPC token auth (long-lived tokens for MetaMask) | Today auth issues short-lived JWTs (30 min) that need refresh. MetaMask and similar wallet integrations want long-lived API-key-style tokens they can paste into an RPC config. Needs a new admin-managed token type scoped per user/org with revocation. | Planned |

---

## Summary: Items Requiring Team Decision

| **§** | **Item** | **Question** |
| --- | --- | --- |
| 1 | Anonymous users see only chain metadata | Should explorer have a public redacted view, or require login? |
| 2 | Gaps G5, G6 | Team confirms acceptance? |
| 4a | ~~Multi-party event whitelists~~ | Resolved — `visibleTo` + EventRules cover it; post-mine sharing served by disclosure feature |
| 4b | eth_call unfiltered responses | Blocking for MVP? |
| 4c | Block-level `gasUsed` / size aggregates leak cross-org activity | Accept as consensus-layer, or obscure? |
| 5 | KYC auto-set | Auto or manual approval? |
| 6 | User JWTs in sessionStorage; admin token in localStorage | Accept (XSS = stolen tokens) or move to httpOnly cookies? |
| 8 | New members without explicit grants can't access any own-org contract (tier 3 admin/deploy claim no longer grants blanket access after RD-849) | Intended? Should default group get a baseline grant? |
| 9 | SIEM sends DIDs, IPs, ETH addresses externally | Acceptable disclosure? Hash/anonymize? |
| 10a | View functions return unfiltered data | Acceptable? Document for contract authors? |
| 10g | Pseudonymous address correlation via amounts | Amount redaction needed? |
| 10h | `eth_call` internal reads not traced | Implement Phase 1 (deploy-time bytecode analysis + trace dynamic-target contracts) before MVP? |
| 12 | Should `visibleTo` bypass RBAC? | Keep additive (current) or change to bypass semantics? |
| 13 | Audit log integrity incomplete | Only `access_logs` hash-chained; `rbac_audit_log` + `compliance_logs` unprotected; no verifier/anchor/signing. Which gaps block the compliance bar? |

---

## 12. Evaluated: should `visibleTo` bypass RBAC?

Raised question: should the `visibleTo` list (attached per-transaction via `eth_sendTransaction`) **override** org / group / contract restrictions — i.e., make the tx and its logs visible to the listed DIDs regardless of whether those DIDs have RBAC access?

### Current behavior (additive)

`visibleTo` is **additive on top of RBAC**, never a substitute. Concretely:

- A viewer listed in `visibleTo` must still have the method in their group's `AllowedMethods` — `visibleTo` does **not** widen the method allowlist (`TestCheckAccess_VisibleTo_DoesNotBypassMethodAllowlist`).
- A viewer listed in `visibleTo` must still have a grant (direct or via `is_org_admin`) on the contract whose logs they're trying to read — `visibleTo` does **not** cross org boundaries (`TestCheckAccess_VisibleTo_GetLogs_DoesNotBypassCrossOrgContract`).
- `visibleTo` only widens behavior at the **response-filter stage**: when a viewer already has RBAC access to `eth_getLogs` on a contract but would otherwise be filtered out because `param_rules` say `must_be=self` (i.e., the viewer isn't the indexed sender/recipient), `visibleTo` lets those specific logs through.

In short: `visibleTo` is a **scoped exception within an already-authorized query**, not a grant of access.

### Proposed alternative (bypass)

Make `visibleTo` a full grant: if the sender of a tx lists a DID, that DID can see the tx and its logs even without RBAC access to the method, the group's allowlist, or the contract's grants.

### Security implications of the bypass model

**1. Privilege escalation from end users to admin.** Admins configure RBAC; end users pick `visibleTo` at tx time. Under bypass, any tx sender can unilaterally grant visibility that the admin never approved — including to users the admin deliberately excluded from that contract or method. RBAC stops being the ceiling; it becomes suggestive.

**2. Cross-org leakage without Org B's consent.** A user in Org A sends a tx with `visibleTo: [did:userInOrgB]`. Under bypass, that Org B user now sees a tx involving Org A's contracts — but Org B's admin had no opportunity to vet this. One-sided grants across org boundaries undermine the "each org controls its members' visibility surface" property.

**3. Contract-author intent broken.** When a tx touches Contract X, its logs include events from X. If X belongs to Org C, Org C has carefully configured `EventRules` on grants to limit which events are visible and to whom. Under bypass, any tx-sender interacting with X (including Org A/B users, or even X's own users) can leak X's events to arbitrary DIDs via `visibleTo`. Org C loses control over its contract's privacy surface. This is particularly bad for "shared infrastructure" contracts (compliance oracles, cross-org routers, Travel Rule contracts) that multiple orgs touch.

**4. Method allowlist bypass.** Admins set `AllowedMethods` on groups for reasons — sometimes operational (avoid noisy methods), sometimes privacy (block log queries for certain roles). Bypass semantics let any tx sender hand out the equivalent of a method grant, per-tx, invisible to the admin.

**5. Centralized audit collapses.** Under additive semantics, "who has access to what" is a query over RBAC tables (groups + grants + memberships). Under bypass, visibility becomes the union of RBAC access AND every `visibleTo` entry ever attached to any tx — thousands of ad-hoc end-user decisions, not centrally auditable. ISO 27001 / SOC 2 "access review" controls become much harder to satisfy.

**6. No revocation.** `visibleTo` is written into historical tx data. Once a tx is submitted with `visibleTo: [attacker]`, that attacker has visibility into that tx forever — you cannot "unshare." RBAC revocation (remove membership, delete grant) is instant; `visibleTo` under bypass is immutable grants sprayed across block history.

**7. Compromised end-user = cross-org data exfiltration path.** Today, compromising a low-privilege user in Org A exposes only what that user can see. Under bypass, the attacker can send arbitrary txs with `visibleTo: [attacker-controlled DID in any org]` and progressively leak data from every contract Org A's user interacts with.

**8. Incident response loss.** If an admin notices a compromise and tries to restrict a user, they can revoke RBAC — but any `visibleTo` bypass grants issued before revocation remain. The blast radius of a compromised account grows over time rather than being immediately containable.

### Potential benefits of the bypass model

- **Simpler mental model for end users.** "I send a tx, I decide who sees it" — like sending a DM.
- **Ad-hoc sharing without admin involvement.** Useful for auditor/regulator handoff or one-off business cases.
- **Less friction.** End users don't need to ask admins to create grants for every sharing need.

### Why the additive model is the right default

Each of the benefits above has a safer alternative that preserves RBAC as the ceiling:

- **Auditor/regulator ad-hoc sharing** → the existing **disclosure flow** (`/disclosure` endpoints): auditor requests access, sender approves, scope is logged. Revocable, auditable, two-sided-consent-friendly.
- **One-off sharing with a known DID already in the system** → admin creates a group with appropriately narrow access and adds the recipient. Still two-sided.
- **Cross-org visibility by design** → explicit `contract_grants` targeting the cross-org group, reviewed by both orgs' admins.

The current additive `visibleTo` already covers the most-common legitimate case: a tx sender wants to ensure co-participants (who already have access to the contract but wouldn't pass a `must_be=self` filter) see the event. Anything beyond that is either a disclosure-flow case or a group-grant case.

### Recommendation

**Keep the additive model.** Do not flip `visibleTo` to bypass semantics. The benefits are already covered by other mechanisms (disclosure, grants); the costs (7-8 distinct privacy-and-compliance regressions above) are severe and architecture-shaping — hard to undo once end users start relying on the bypass behavior.

If a specific use case emerges that isn't served by disclosure/grants, prefer introducing a **new, narrower, revocable, audited** mechanism rather than widening `visibleTo`.

**Discuss:** Is there a concrete use case where neither additive `visibleTo`, nor the disclosure flow, nor explicit cross-org grants is sufficient? If yes, that use case is the design input; we can propose a specific mechanism instead of a blanket bypass.

---

## 13. Audit Log Integrity (Hash Chain)

Auditor-relevant concern: can anyone with DB access quietly rewrite historical audit logs to hide their actions? Partial answer — depends on which log.

### What IS hash-chained

**`access_logs` table only** — every JSON-RPC call routed through the proxy.

- Algorithm (`internal/audit/hashchain.go`): `entry_hash = SHA-256(previous_entry_hash || entry_content)`
- `entry_content = "v2|{id}|{user_did}|{method}|{ip}|{req_status}|{resp_status}|{timestamp}|{correlation_id}|{params_digest}"`
- Chain is seeded at server startup from the last persisted `entry_hash` in the DB
- Tampering with any historical row invalidates every subsequent hash
- Covered fields: caller DID, method called, client IP, req/resp status, timestamp, correlation ID, (optionally) redacted params
- Migration: 017 (`entry_hash` column) + 031 (`request_params` stored as TEXT to preserve exact bytes for verification)

### What is NOT hash-chained

- **`rbac_audit_log`** — every admin action on RBAC (create/edit/delete groups, grants, memberships). Plain timestamped rows, no integrity protection.
- **`compliance_logs`** — travel-rule decisions, sanction hits, threshold overrides.
- **Auth events** — login success/failure, token refresh, revocation, Azure AD callbacks. Not persisted to a dedicated integrity-protected table.
- **Generic admin API actions** — no audit table beyond `rbac_audit_log` for RBAC-specific ops; other admin endpoints (compliance config, contract claim, disclosure decisions) are not chained.

For an auditor who cares about admin-action tampering — a standard SOC 2 / ISO 27001 CC7 control — the current coverage is incomplete. An attacker with DB write access can rewrite `rbac_audit_log` to hide a malicious grant creation and it's undetectable.

### Other gaps in the existing chain

1. **No verifier yet — but the chain is now recoverable across pruning.** The chain is still write-only at runtime: there is no CLI, admin endpoint, or scheduled job that recomputes `SHA-256(prev || content)` row-by-row. An auditor wanting an integrity attestation still has to write ad-hoc SQL. *What changed (RD-871):* every prune (the existing time-based TTL prune **and** the new FIFO row cap from `MAX_ACCESS_LOG_ROWS`) now writes the `(id, entry_hash)` of the last deleted row to a new `audit_chain_anchor` table inside the same transaction as the DELETE. The hash-chain seeder on startup falls back to that anchor when no surviving rows are present. A future verifier (RD-858) can therefore walk forward from the anchor without losing the seed. The anchor is the prerequisite, not the verifier itself — building the verifier remains short-term work.

2. **Two-step write race.** `LogAccessEnhanced` inserts the row, `UpdateAccessLogHash` writes the hash in a separate statement (`jsonrpc_processor.go:166-188`). If the process crashes in between, the row exists with `entry_hash = NULL`. A future verifier cannot distinguish crash from tampering without additional signals.

3. **Optional params.** `params_digest` in `entry_content` is only populated when `AUDIT_LOG_PARAMS=true`. When false, the chain integrity still holds, but the record cannot answer "what parameters did this caller send" — only "they called this method." May be fine for privacy reasons, but auditors should know.

4. **No external anchoring / signing.** An attacker with DB write access can rewrite the whole chain from any point and recompute forward hashes. Integrity is only as strong as the DB access controls. Mitigations not implemented:
    - Periodic tail-hash anchor to an external system (S3 WORM bucket, on-chain commit, hashed into nightly SIEM batch, etc.)
    - HSM signature per entry (or per N-entry block)
    - Append-only table constraints (Postgres `INSERT`-only role for the app; separate admin role required for `DELETE`/`UPDATE`)

### What we should do

| Gap | Action | Priority |
| --- | --- | --- |
| No verifier | Add `privacy-cli audit verify` subcommand (or admin endpoint) that walks the chain and reports integrity | Short-term (simple to build, enables auditor attestation) |
| `rbac_audit_log` not chained | Extend `HashChain` to cover this table. Same algorithm, separate chain. | Short-term (admin-action integrity is what auditors really want) |
| `compliance_logs` not chained | Same pattern as RBAC | Medium-term |
| Two-step write race | Compute hash in the insert statement itself (single TX, reserve ID via sequence first), or migrate to an append-only table pattern where `entry_hash` is `NOT NULL` from the start | Medium-term |
| No external anchor | Periodic tail-hash SIEM forward (piggyback on existing SIEM webhook) or on-chain commit | Medium-term |
| No signing | Sign entries or tail hashes with a dedicated audit key (HSM if available). Lift integrity from "DB-level" to "whoever holds the key" | Long-term / post-MVP |

**Discuss:**

- Which tables beyond `access_logs` need integrity protection to pass the compliance bar? At minimum `rbac_audit_log` and `compliance_logs`. Others?
- Is "DB-level integrity only" (current state) acceptable if we pair it with strict DB access controls, or do auditors specifically require a verifier + external anchor?
- Should the verifier be a CLI (run manually on demand) or a scheduled job (run every N minutes and alert on mismatch)?
