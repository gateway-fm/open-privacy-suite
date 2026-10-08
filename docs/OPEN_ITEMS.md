# Decisions, Limitations & Open Items

Last updated: 2026-04-21

Each item describes the current state, the decision made (or deferred), and whether action is needed. Items that have been fully resolved are removed — see the git history for the cleanup log. Ongoing security hardening work is tracked in the project's issue tracker (`RD-XXXX` identifiers throughout the codebase refer to those tickets); this doc is for items that need a maintainer decision before implementation.

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

- ***Impact on block explorer:*** An unauthenticated visitor to the block explorer sees essentially nothing useful — no transactions, no addresses, no contract data. The explorer's `ProxyDataProvider` calls the Open Privacy Suite's Explorer API endpoints, which require authentication to return redacted data. Without a JWT, the explorer can show chain liveness (block number, chain ID) but no blockchain content.
- ***Discuss:*** Is this the intended UX for the block explorer? Should there be a "public view" that shows redacted transactions (all addresses as `[PRIVATE]`) to unauthenticated users, or should login be required to see anything?

---

## 2. Redaction Gaps (Known, Documented)

Remaining privacy leaks documented in `REDACTION_SPEC.md` with explicit test coverage asserting the *broken* behavior so they don't become invisible.

### G5: Log.data not scanned when no ABI registered

- With a registered ABI: non-indexed `address` params in `data` are decoded and private addresses zeroed
- Without ABI: raw ABI-encoded `data` blob returned unmodified — private addresses embedded as non-indexed params will leak
- **Decision:** Accepted as limitation — no fix planned until heuristic ABI scanning is feasible
- **Status:** Accepted, not fixed

### G6: Block.logsBloom not zeroed

- Bloom filter contains hashed representations of addresses — a viewer who knows a target address can probe whether it has activity in a block in O(1)
- Zeroing the bloom for all blocks requires expensive per-block address scanning
- **Decision:** Accepted — probabilistic membership test only, requires knowing the target address already
- **Status:** Accepted, tracked as future hardening

**Discuss:** G5 and G6 were explicitly accepted — confirm the team agrees.

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

### 4d. eth_call internal-call tracing for cross-org isolation — **RESOLVED** (RD-915)

`internal/server/jsonrpc_processor.go` `validateEthCallWithTracing`

Pre-RD-915, `eth_call` was gated only on the entry-point `to` address. A same-org wrapper that internally STATICCALL/DELEGATECALL/CALLs into a foreign-org private contract would bubble up state through the return value, defeating cross-org isolation on the read side. Sends were already protected by `validateWithTracing`; reads were not.

RD-915 closes the read side:
- Every `eth_call` is traced with `debug_traceCall` (uncached — proxy-pattern contracts can re-target their internal calls via storage rewrites, see `runtime_tracer.go` docstring on `TraceTransactionUncached`).
- All internal call frames are passed through `TraceValidator.ValidateTrace` for the same cross-org check the send path uses.
- `from` is rebound to the JWT-bound EOA via `GetLinkedEthAddresses`; user-supplied `from` that doesn't match a linked address is rejected (preserves the audit trail of spoof attempts).
- A distinct 5s per-call timeout (`ETH_CALL_TRACE_TIMEOUT`), separate from the 30s send-side timeout, caps individual trace duration on the read path. *Note:* this does not cap how many concurrent traces a single JWT may issue — the concurrency limiter is acquired after the trace runs. Tracked separately as RD-923.
- Default-on; the `RUNTIME_TRACING_ETH_CALL_ENABLED=false` env flag exists for change-management rollback only (ISO 27001 A.8.32). See `docs/rd-915-design.md` §KD-5.

Open follow-up: `pure_helpers` skip-list (KD-1) to avoid tracing well-known stateless utility contracts; `access_logs.denial_reason` enum (KD-4); read-side access/visibility symmetry test (KD-6) — explorer log-data redaction for cross-org-touched txs is still a gap; per-user concurrency / RPS gate before the tracer (RD-923); apply the same cross-org tracing to `eth_estimateGas` (RD-924).

---

## 5. KYC / Billions Credential Gap

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

| **Issue** | **Severity** | **Rationale** |
| --- | --- | --- |
| ~~User JWTs in sessionStorage~~ → HttpOnly cookie (RD-1008); admin API token in localStorage | High | **PP access JWT now mirrored into an HttpOnly `pp_access` cookie (RD-1008, May 2026).** Middleware (`internal/auth/middleware.go:extractAccessToken`) reads the cookie when the `Authorization: Bearer` header is absent, so browser navigations to server-side endpoints (`/oauth/authorize`) capture `initiatorDID` correctly — unblocking silent SSO across same-eTLD+1 subdomains. XSS can no longer lift the access token from storage. The JSON response body still carries the token for backward compatibility with existing API clients; frontend follow-up to drop the sessionStorage mirror is optional cleanup. Admin API token (super-admin `X-Admin-Token`) stays in `localStorage` — different threat model (operator-pasted bootstrap credential), left as a separate decision. |
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

### 10f. eth_getStorageAt and eth_getProof use tiered access

`eth_getStorageAt` and `eth_getProof` (and aliases of them) use **tiered access** based on the `admin` claim. For `eth_getProof` the tier applies to every requested storage key; an empty key list (account-only proof) is allowed. See REDACTION_SPEC.md §9 for the accepted residuals of allowed proofs.

| **User** | **Access** |
| --- | --- |
| `admin` claim (tier 2 org admin, tier 3 contract admin on granted contracts) | All storage slots |
| Any other user with the method in AllowedMethods | EIP-1967 and EIP-2535 well-known proxy infrastructure slots only |
| User without the method in AllowedMethods | Blocked entirely |

However, a contract's public view functions can read and return the same storage data. The tiered access only prevents reading storage of contracts without view functions.

### 10g. Pseudonymous addresses can be correlated

When addresses are shown as pseudonyms (`Address-ABCD`, `Address-EFGH`), the pseudonyms are deterministic per viewer. Observers can track:

- Transaction frequency between pseudonyms
- Amounts flowing between them
- Timing patterns

Over time, this can de-anonymize pseudonymous addresses, especially with off-chain knowledge.

**Open question:** Is amount redaction needed for pseudonymous-to-pseudonymous transfers?

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
| 6 | ~~User JWTs in sessionStorage~~ | Resolved (RD-1008): moved to HttpOnly `pp_access` cookie, unblocked silent SSO across same-eTLD+1 subdomains. |
| 8 | New members without explicit grants can't access any own-org contract (tier 3 admin/deploy claim no longer grants blanket access after RD-849) | Intended? Should default group get a baseline grant? |
| 9 | SIEM sends DIDs, IPs, ETH addresses externally | Acceptable disclosure? Hash/anonymize? |
| 10a | View functions return unfiltered data | Acceptable? Document for contract authors? |
| 10g | Pseudonymous address correlation via amounts | Amount redaction needed? |
