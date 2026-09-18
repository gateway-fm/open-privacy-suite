# API migration map: what moved to the DSL, what stayed an operation, what an agent sees

Companion to [DECISION.md §3.5](../research/dsl-policy-and-node-enforcement/DECISION.md)
(the model) and `API_ENDPOINTS.md` (the generated inventory, 173 canonical
operations on `feat/ops-dsl-reth`, of which ~50 are admin impersonation mirrors
of explorer/RPC reads). This document is the endpoint-level answer to three
questions: which endpoints the DSL replaced, which stayed and why, and what
changed for a headless client. Everything below is verified against the
registered routes and the guards in `internal/server/admin_rbac.go`,
`admin_compliance.go`, `admin_shared_infra.go`, `admin_configuration.go`.

**The rule that sorted every endpoint.** Something is authored as a *declarative
document* (one revision per `(organisation, kind)`, re-applied, reviewed,
activated by a second person) only when a snapshot is enough: one owner,
reproducible result, absence means safe deletion, reviewable size, no dependency
on another party's future answer. Everything else stays an *operation* on its
existing REST endpoint, because a snapshot would either undo another writer's
work (bans, memberships from an IdP), cannot be authored (a signature proof),
or is inherently a request/answer between parties (disclosure).

## 1. Migrated to the DSL: 32 legacy write operations → 8 uniform revision operations × 6 streams

Each stream is edited through the same eight calls:
`GET …/{kind}/context`, `GET/POST …/{kind}/revisions`, `GET …/revisions/{id}`,
`POST …/revisions/{id}/simulate`, `POST …/revisions/{id}/activate`,
`POST …/revisions/{id}/activate-ci`, `POST …/revisions/{id}/withdraw`
(organisation streams under `/api/v1/admin/orgs/{org_id}/configuration/{kind}/…`,
platform under `/api/v1/admin/configuration/platform/…`, no `activate-ci`).
Once a stream has an active revision, the legacy writers below answer **409
"use a configuration revision"** and the database triggers refuse a direct
write; their `GET`s keep working as reads of the projection.

| Stream (`kind`) | What the document holds | Legacy write endpoints it replaces (now 409 when active) | Why a snapshot suffices |
|---|---|---|---|
| `groups` | group definitions: slug, name, admin flags, RPC method allowlist, claims, verbose errors | `POST /orgs/{o}/groups`, `PUT/DELETE /orgs/{o}/groups/{g}`, `PUT /orgs/{o}/groups/{g}/access`, `POST /orgs/{o}/groups/batch-delete` | one owner (org admin), reproducible; deleting a group with live members requires the exact member count in the document, so it cannot silently drop other writers' memberships |
| `contract-registry` | contracts (address, name, ABI, visibility flags) and their read grants (claims metadata, event rules) | `POST /orgs/{o}/contracts`, `PUT/DELETE /orgs/{o}/contracts/{a}`, `PUT …/{a}/abi`, `PUT …/{a}/visibleto-unlock`, `PUT …/{a}/events-allow-dynamic-payload`, `POST /orgs/{o}/contracts/claim`, `POST …/contracts/sync-delete`, `POST …/contracts/batch-move`, `POST/PUT/DELETE …/contracts/{a}/grants[/{g}]` (claims / event-rules part) | configuration, not observation: pipeline-registered contracts are *adopted* as drift into the next revision, never deleted by re-applying |
| `execution-rules` | the policy: which group may call which function with which argument bounds, nested-call / delegatecall rules, deployment rights — compiled to Solidity and executed by the node on every frame | `contract_grants.functions` (the function part of `POST/PUT/DELETE …/grants`), and the RD-1287 `POST /orgs/{o}/execution-policy/revisions`, `…/{id}/activate`, `…/{id}/withdraw` | the single statement of what may execute; anything else would be a second writer of the same permission |
| `compliance` | org settings (enabled, threshold, currency, unknown-price policy, enforce/monitor), per-address thresholds, manual token prices | `PUT /orgs/{o}/compliance/config`, `PUT/DELETE …/compliance/tokens/{t}`, `PUT/DELETE …/compliance/address-thresholds/{a}` | settings, not observations: fetched rates, sanctions hits, travel-rule records stay operational |
| `approvers` | which admin groups may activate revisions; trusted CI issuers/keys | — (new) | it is the authority configuration itself; human-only, activated by a different human |
| `platform` | shared infrastructure (address, codehash pin), tenants (default org/group, auto-provision) | `POST/PUT/DELETE /admin/azure-tenants[/{id}]`, `POST/PUT/DELETE /admin/shared-infrastructure[/{a}]`, `POST …/shared-infrastructure/{a}/refresh-codehash` | platform-owned, human-only, activated by a different allowlisted human |

Import: an organisation's first `execution-rules` revision is generated from
its existing grants (`legacyExecution` in the registry context keeps the
null-means-all vs empty-means-none distinction); `contract_grants.functions`
stays as a dormant column under the expand-only migration policy.

## 2. New endpoints (not replacements)

| Endpoint | Purpose |
|---|---|
| `…/configuration/{kind}/context` | complete editable source + live projection + `viewer` (can this principal activate?) + `capabilities` (API version, kinds, human-only kinds, approval modes, size limit, compiler version and availability) |
| `…/revisions/{id}/simulate` | review without mutation: diffs (create/update/delete/adopt), preserved drift, projected result, compiled digests |
| `…/revisions/{id}/activate` | atomic activation of one draft plus named siblings (ABI + dependent rules together); author ≠ activator; authority re-checked in the transaction |
| `…/revisions/{id}/activate-ci` | same, with an externally signed approval manifest instead of a second human (trusted issuer/key configured in `approvers`) |
| `POST /orgs/{o}/execution/simulate` | preview an `eth_call` / `eth_estimateGas` / `debug_traceCall` against a candidate policy on the node, without activating it |
| `GET /ready` | node-mode readiness: desired vs applied fact version, staleness, publication pending |
| `GET /me/transactions/{hash}/execution` | the submitter's own transaction lifecycle: queued → accepted → included / reverted / denied (`POLICY_DENIED`) / expired, with finality |

## 3. Kept as operations — and why each is not a document

| Group | Endpoints | Why it stays an operation |
|---|---|---|
| Users, bans, KYC | `GET /admin/users`, `GET/PUT/DELETE /admin/users/{u}`, `GET …/{u}/effective-permissions`, `GET …/{u}/linked-addresses` | user rows are created by login; bans/KYC are also set by compliance automation — a re-applied document with `banned: false` would undo an incident ban |
| Memberships | `GET/POST /admin/users/{u}/memberships`, `DELETE …/memberships/{m}`, `POST/DELETE /orgs/{o}/memberships/by-did` | several writers (admin, HR/IdP sync, ZK self-service, expiry) at people scale; a snapshot would fight them |
| Address links | `POST /eth/link/challenge`, `POST /eth/link/verify`, `GET /eth/addresses`, `DELETE /eth/addresses/{a}`, `POST …/refresh-ens`, `GET /admin/eth-addresses/collisions` | the link *is* a signature by the user's key; nobody can author it for them |
| Organisation lifecycle | `GET/POST /admin/orgs`, `GET/PUT/DELETE /admin/orgs/{o}` | **decided 2026-09-17 to move into the `platform` document** (see §6) — kept as an operation only until that is built |
| Disclosure | `GET/POST /admin/disclosure/requests`, `GET/DELETE …/requests/{r}`, `GET /admin/disclosure/grants`, `…/{g}/revoke`, `…/{g}/summary|events|logs|report`, `GET …/check-access`; `GET /me/disclosure/*`, `POST /me/disclosure/requests/{r}/approve|reject|revoke` | a request needs the other organisation's answer; state machine between parties, not desired state |
| Compliance operations | `GET/POST /admin/compliance/sanctions`, `DELETE …/sanctions/{id}`, `GET/POST /orgs/{o}/compliance/travel-rule-records`, `DELETE …/{id}`, `GET …/compliance/logs`, `GET/PUT /admin/compliance/currency`, `GET /admin/compliance/system-token-prices` | feeds and evidence (sanctions lists, travel-rule records, logs); the system currency is a one-off platform runtime setting |
| Upstream credential | `PUT /orgs/{o}/groups/{g}/rpc-credential` | a secret; never source text, never in a diff or audit value |
| Sessions and tokens | `POST /auth/request|verify|callback`, `/auth/azure/*`, `/auth/azure/service-principal`, `POST /refresh`, `/revoke`, `/introspect`, `GET /admin/sessions`, `DELETE /admin/sessions/{s}`, `/oauth/*` | runtime authentication, no desired state |
| Diagnostics and reads | `POST /orgs/{o}/dry-run`, `POST /admin/access/check`, `POST …/contracts/sync-check`, `POST …/groups/batch-delete-preview`, `GET …/contracts/grant-summary`, `GET …/contracts/{a}/events`, `GET /admin/contracts/by-address/{a}`, `GET /admin/audit-logs`, `GET /admin/logs`, `GET /admin/cache/stats`, `GET /admin/status`, `GET /admin/system/version`, `GET/POST /admin/system/eth-call-tracing`, `GET/POST /admin/system/intra-org-grant-tracing` | reads, previews and runtime switches |
| Chain reads and RPC | `GET /explorer/*` (~40 reads), `POST /rpc`, `POST /rpc/{org}` | the product's read side; visibility is decided per viewer at read time |
| Explorer ABI upload | `POST /explorer/addresses/{a}/abi`, `POST /explorer/index/block/{n}` | **known defect, parked by decision**: this writes a separate explorer store, not the registry the node and redaction read; it must close or route into the registry stream before `contract-registry` is the single ABI writer |
| Development only | `GET /dev/test-identities`, `POST /admin/dev/deploy-demo-erc20`, `POST /admin/test-request`, `/oauth/session/{id}/mock-complete` | mock-auth builds |

Reads of every migrated class (`GET /orgs/{o}/groups`, `GET …/contracts`,
`GET …/grants`, `GET …/compliance/config|tokens|address-thresholds`,
`GET /admin/azure-tenants`, `GET /admin/shared-infrastructure`, RD-1287
`GET …/execution-policy/context|revisions`) stay as they are: they read the
projection the activation wrote.

## 4. What changed for a headless client or an AI agent

Delivered on this branch (REST + SDK; no MCP):

| Before | Now |
|---|---|
| ~32 different setters, each with its own body shape and ordering constraints, the model deciding the order | one shape for all six streams: read context → edit the complete source → `POST revisions` → `simulate` → `activate` by someone else; the server reports diffs, deletions and drift; no planner, no change-set API |
| no way to know what the deployment supports | `capabilities` in every context: kinds, human-only kinds, approval modes (`human`, `trusted-ci`), document size limit, pinned compiler version and whether it is installed |
| a returned tx hash meant "sent" and nothing more | `GET /me/transactions/{hash}/execution`: queued / accepted / included / reverted / `POLICY_DENIED` / expired, with finality; `POST /orgs/{o}/execution/simulate` previews against a candidate policy |
| only a human login or the full admin token | Azure service-principal login (RD-1120) yields a scoped org-admin or read-only-admin JWT; a read-only principal can draft and simulate but not activate; approval is either a different human or a signed CI manifest |
| hand-written clients | `sdk/` — TypeScript client generated from the OpenAPI document with examples for login/refresh, prepare/review, activate (human or CI), operations, RPC and status tracking |

Deferred by decision (MCP out of this delivery), recorded here so it is not
lost. The 4 September research and DECISION §3.5 fixed the target shape:

| Today (`mcp/`) | Planned |
|---|---|
| 94 flat tools, one per endpoint, ordering left to the model | 6 revision tools parametrised by `(org, kind)` (`context`, `draft`, `simulate`, `get`, `activate`, `withdraw`) replacing ~40 setter tools; composite read tools per scope; operation tools grouped by role |
| server holds the full `PRIVACY_ADMIN_TOKEN` | server runs as a service principal with a scoped JWT; per-principal tool lists via the SDK's per-request server factory |
| workflows implicit | workflows published as MCP prompts plus preconditions in tool descriptions |
| stdio only | streamable HTTP for hosted agents |
| confirm token returned to the model | approval is the revision lifecycle itself (human `activate` or trusted CI) |

## 5. Questions this map leaves for the CTO

1. When does Reth policy mode become the default? Until then the legacy
   writers stay open for organisations without active streams, and the old
   preflight gate still decides access in legacy mode.
2. The explorer ABI upload writes a store nobody enforces from. Close it, or
   route it into the registry stream?
3. Scoped admin roles and quotas for standing agent automation ("add up to N
   members a day") — an RBAC extension, not a DSL question; not built.
4. MCP rebuild timing (table above).

## 6. Decided follow-up: organisations become part of the platform document

Decided 2026-09-17. Organisation lifecycle passes the snapshot test — one
writer (the platform), reproducible, no dependency on another party — and its
administrative trust roots have the platform as their only writer too, so
both belong in the `platform` stream rather than in three bootstrap operations:

```json
"organizations": [{
  "id": "…", "slug": "acme", "name": "ACME",
  "adminGroup": {"slug": "reviewers", "name": "Reviewers"},
  "administrators": ["did:…author", "did:…reviewer"]
}]
```

| Effect | Detail |
|---|---|
| Closes | `POST/PUT/DELETE /admin/orgs[/{o}]` and the bootstrap use of `POST /orgs/{o}/memberships/by-did` for administrators, once the platform stream is active |
| Stays an operation | everything about people and external events: login, address links, ordinary memberships, bans/KYC, disclosure, deployment discovery (adopted as drift) |
| Must be decided in the spec | which fields the platform owns (id, slug, administrators) versus the organisation itself (display name, compliance defaults — can stay in its own streams); deletion semantics (explicit `deletions` with acknowledged cascade counts for members, contracts and revisions; audit untouched) |
| Must be built with it | last-administrator lockout protection (the current code permits removing the last org admin); import of existing organisations into the first platform revision |
| Sequence | after the identity-admission durability fix (`evidence/reth-runtime.md`), before the MCP rebuild; estimate 1–2 days |

Two further follow-ups recorded on the same day, from the review of §7:

| Follow-up | Why | Size |
|---|---|---|
| Convert the legacy admin screens (groups, contracts, grants, compliance forms) into document views: read-only from the active revision, "edit" opens the Configuration screen | today they still call the legacy endpoints and, once a stream is active, receive 409 with no path forward — the UI is not yet uniformly a viewer/editor of the documents (plan Stage 3, not done) | 2–3 days |
| Separate chain observations from configuration in `contracts` (and the auto-grant rows in `contract_grants`): observations in their own facts table, configuration only in the `contract-registry` document, drift adoption as the bridge; then treat the remaining projection tables explicitly as caches rebuilt on activation | the mix is what makes the projections look like a second configuration store; without it only the explorer's SQL visibility filter still needs a materialised form | 2–3 days |

## 7. Why the document, why Postgres — one table

Every piece of data in the product was sorted with the same four questions:
**who writes it** (one owner, or several writers and automation), **what it is**
(a decision someone can review, or an observation / proof that can only be
recorded), **when it must take effect** (after a review, or in the next block),
and **whether it changes on its own** (expiry, chain events). The answers put
each class into one of four homes. The last column is the part that matters in
a discussion: what the world looks like if that class lived in the other home —
a document class left in tables, or a fact authored in a document.

**"Document" here always means the JSON configuration document** —
`ops.configuration/v1`, written by a person or an agent, stored in OPS as a
revision row and reviewed there. It is not a smart contract and nothing about it
is on chain. One stream goes further: the server compiles `execution-rules` into
EVM bytecode, and the node loads that artifact **privately, from the signed fact
snapshot**, to run it inside the call frame — the policy is never deployed to a
chain address and never visible to anyone reading the chain.

| Data | Stored in | What it is, and why there | If it lived elsewhere |
|---|---|---|---|
| **[Execution rules](#execution-rules)**<br><sub>what a group may call: contract, function, argument limits</sub> | OPS document `execution-rules`<br><sub>compiled artifact in Postgres, copy in node memory</sub> | **Decision.** one owner, reviewed before it decides anything, reproducible; the node executes the compiled artifact | In tables: a row is not executable — the node runs compiled policy code inside the call frame, so enforcement falls back to the proxy, which cannot see nested calls (the reason for the whole design, §2 of DECISION). On top of that a grant takes effect the moment the API call returns, with no review and no reproducible history — the state before RD-1287 |
| **[Group definitions](#group-definitions)**<br><sub>the groups of an organisation and what RPC they may use</sub> | OPS document `groups` | **Decision.** the org admin chooses the structure; deleting a group with live members needs explicit acknowledgement | In tables: structure changes with no review, and membership cascades nobody sees |
| **[Contract configuration](#contract-configuration)**<br><sub>which contracts the org owns, their ABI and visibility</sub> | OPS document `contract-registry` | **Decision.** pipeline-registered contracts are adopted as drift, never swept | In tables: several places set the same thing — the explorer's separate ABI writer problem, generalised |
| **[Compliance settings](#compliance-settings)**<br><sub>thresholds, currency, enforce or monitor</sub> | OPS document `compliance` | **Decision.** settings with one owner | In tables: "enforce" can be flipped to "monitor" without a second person |
| **[Approvers, trusted CI](#approvers-trusted-ci)**<br><sub>who may activate a revision, and which CI is trusted</sub> | OPS document `approvers`<br><sub>human-authored only</sub> | **Decision about authority itself.** who may approve cannot be set by an unreviewed call | As an operation: whoever can call the endpoint widens who may approve — the authority would guard itself |
| **[Platform](#platform)**<br><sub>shared contracts, tenants, organisations (§6)</sub> | OPS document `platform`<br><sub>human-authored only</sub> | **Decision, platform-owned.** chosen by the deployment operator, not by a tenant | As operations: a customer is bootstrapped by API calls nobody reviews |
| **[Users](#facts-about-people)**<br><sub>a person exists in OPS, identified by DID</sub> | Postgres `users`<br><sub>copy in node memory</sub> | **Event, not an authored line.** the row appears when someone logs in; nobody authors a user | In the document: a user exists only once an author types them in; login waits for a revision |
| **[Memberships](#facts-about-people)**<br><sub>who is in which group, until when</sub> | Postgres `user_memberships`<br><sub>copy in node memory</sub> | **Relationship with several writers.** several writers (admin, IdP/HR sync, ZK self-service, expiry); per-person cadence | In the document: every join and leave is a reviewed revision; a re-applied document overwrites what another writer changed; each expiry needs its own revision |
| **[Address links](#facts-about-people)**<br><sub>this wallet belongs to this person, proven by signature</sub> | Postgres `eth_address_links`<br><sub>copy in node memory</sub> | **Proof.** a link exists only because the user signed a challenge with that key (`eth/link/verify`; the demo bypass `MOCK_SIGNATURES` is force-disabled when `ENVIRONMENT=production`, `config.go:475`) — it is a **proof** | In the document: the link is an author's assertion, not the user's signature — whoever writes the document binds someone else's address to a principal and authorises its transactions |
| **[Bans, KYC, sanctions](#facts-about-people)**<br><sub>who is blocked or verified right now</sub> | Postgres `users`, `sanctioned_addresses`<br><sub>copy in node memory</sub> | **Safety flag, written by people and automation.** also written by compliance automation and feeds; an incident ban must reach the node in the next block | In the document: a ban waits for review instead of reaching the next block, and the next re-applied document lifts it silently |
| **[Deployment observations](#deployment-observations)**<br><sub>who deployed which contract, from which transaction</sub> | Postgres `contracts`<br><sub>to be split out — §6</sub> | **Observation.** recorded by the reconciler from a finalized receipt plus the identity binding; the chain alone shows the signer, not the principal or organisation (several principals may share a signer) | In the document: an author's claim, not an observation. From the chain alone: the receipt shows the signer, not the principal or the organisation |
| **[Disclosure](#disclosure-lifecycle)**<br><sub>one org asks another to reveal data; approve, reject, revoke</sub> | Postgres `disclosure_*` | **Exchange between two parties.** a state machine between two organisations; each step is an answer | In the document: one organisation authors the other's consent |
| **[The record](#the-record)**<br><sub>which document took effect, when, approved by whom</sub> | Postgres `configuration_revisions` + audit chain | **The record.** written in the same transaction as the change taking effect, with the hash-chained audit entry — the only place that can say *what was in force at T* (DECISION §3.1) | In Git: only what was merged, not what took effect or when. In the document: a configuration cannot carry the history of its own activation. On chain: public, and a transaction per review step |
| **[Execution bookkeeping](#execution-bookkeeping)**<br><sub>each submitted transaction, its principal and outcome</sub> | Postgres `node_submissions`, `tx_visible_to` | **Record of execution.** only OPS knows which principal, which `visibleTo`, which receipt | Anywhere else: nothing holds the join between a transaction, its principal and its `visibleTo` recipients |
| **[Fact stream](#fact-stream-to-the-node)**<br><sub>the versioned facts the node evaluates policy against</sub> | Postgres `node_policy_clock`, `outbox`, `cursors` | **Bookkeeping of the push.** the version bump commits in the same transaction as the fact change; the cursor is the restart point | Anywhere else: a fact could be durable in Postgres without the node ever learning of it |
| **[Group RPC credential](#group-rpc-credential)**<br><sub>the group's upstream API key</sub> | Postgres `group_access.rpc_api_key` | **Secret.** a secret is never source text | In the document: the secret appears in every diff, review and export |
| **[Projections](#projections-and-runtime)**<br><sub>tables rebuilt from the active documents</sub> | Postgres tables today<br><sub>target: in-memory document — §9</sub> | **Derived.** rebuilt from the document; they exist only because readers join configuration with facts | Nothing changes — they are rebuilt from the document; using them as a source is the transition artefact |
| **[Runtime state](#projections-and-runtime)**<br><sub>resolved permissions, sessions, challenges</sub> | Redis or replica memory<br><sub>§9</sub> | **Derived or short-lived.** recomputed on demand or expires on its own | Nothing durable — recomputed or re-issued |
The middle column says **where the bytes live**; the kind in bold says **why
there**. Four kinds, and each one decides its own storage:

| Kind | Meaning | Therefore stored | How it changes |
|---|---|---|---|
| Decision | someone chose it and someone else can review it before it takes effect | in an OPS document (`ops.configuration/v1`), one per `(organisation, kind)` | draft → simulate → activate by a second person or a signed CI manifest; the old write endpoints return 409 |
| Fact — event, proof, observation | it happened, or someone proved it; it cannot be authored, and it has several writers | in Postgres, written by the operations; copied to the node as a signed snapshot | one endpoint call, audited, in force at once |
| Record | the history of what took effect, when and by whose approval | in Postgres, written in the same transaction as the change | append-only, hash-chained |
| Derived | recomputable from a decision or a fact | Postgres tables, Redis or memory — wherever it is fastest | rebuilt, invalidated or expired; never a source |

Why the record is not in Git, on chain or in the node is spelled out in DECISION
§3.1 ("Why Postgres is the governance record"); why six documents rather than one
is §8; what must stay in Postgres if configuration leaves its tables entirely,
and what Redis is for, is §9.

## 8. Why six streams and not one organisation document

The revision mechanics would work for a single "organisation configuration"
document. The split into streams per `(organisation, kind)` is a deliberate
choice about review, blast radius and ownership, not a limitation of the
mechanics.

| Concern | Six streams (built) | One document per organisation |
|---|---|---|
| **Different approval rules per part** | each stream has its own rules today: `approvers` and `platform` may be drafted and activated only by humans; the other four may be drafted by a service or agent and activated by a different human (or by a trusted-CI manifest). Per-stream approval *policies* — one approval for group changes, three for execution rules — are the natural extension of the `approvers` stream, not built yet | one rule set for the whole document, or section-level rules hidden inside it — the same split, harder to see and to audit |
| **Blast radius of a mistake** | a wrong revision changes one stream; activation, rollback (a new revision of that stream) and the review diff are scoped to it; a broken execution-rules compile cannot block a compliance threshold change | every change re-applies and re-reviews everything; a mistake in one section is a revision of the whole organisation; rollback rewinds unrelated parts too |
| **Ownership and cadence** | execution rules change with every contract deployment; groups and compliance rarely; approvers almost never — each on its owner's cadence | one owner set and one cadence for all |
| **Parallel work** | a compliance officer and a rule author draft at the same time without touching each other's base revision | both drafts conflict on `baseRevision`; one redoes the work |
| **Cost of activation** | the Solidity compile runs only when `execution-rules` changes | compile on every activation, or track per-section digests — the streams again, internally |
| **Review size** | each diff is one class of objects | a diff across ~1 MB of ABIs and rules for a one-line threshold change |
| **Cross-references** | pinned by digest between streams (`abiDigest` from registry into rules); `activate` co-activates named siblings atomically | implicit inside the document |
| **Agent ergonomics** | one uniform API shape, six contexts | one context — genuinely simpler |

The ergonomics argument is the only one that favours a single document, and
it can be served without giving up the rest: a read of all contexts in one call
and a "bundle" submission that fans one organisation-wide document out into
per-stream drafts and co-activates them. That is a convenience layer over the
streams (about a day), not a change of storage or approval model.

## 9. Middle ground: if configuration lives only in documents, what must still be in Postgres

Asked on 2026-09-17 while looking for the position between "keep the tables" and
"nothing but the config". Checked against the readers in the code, not argued
from the current implementation.

**Per consumer — what it computes, which part is facts (stays SQL), which part is configuration (a document lookup), and the cost of switching.**

| Consumer — what it computes | Facts it needs (stays SQL) | Configuration it needs (document lookup) | Cost of switching |
|---|---|---|---|
| Explorer visibility (`GetBatchVisibility`, `explorer_redaction.go`)<br><sub>for viewer V and a page of N addresses: which are visible</sub> | V's linked addresses, memberships, disclosure grants (2–3 queries) | contracts of V's organisations and their grants → map lookup per address | one SQL statement becomes "facts query + in-memory lookups"; ~µs per address at 1 000 contracts; semantics guarded by the existing access/visibility symmetry tests |
| Effective permissions / access checks (`rbac_store_*`, `rbac/resolver.go`)<br><sub>user → allowed methods, contracts, claims</sub> | the user's memberships (1 query) | groups, allowlists, grants → lookups | the per-user result stays a computed cache of the hot set, never "all users in memory" |
| Fact export to the node (`node_policy_export.go`)<br><sub>the signed fact snapshot</sub> | users, memberships, links — the whole cost (1 M rows) | groups, contracts — microseconds | ≈ 0 |
| Deployment reconciliation (`node_submission.go`)<br><sub>records an observation</sub> | writes facts | — | untouched |
| Disclosure, address and tx helpers<br><sub>"is V an org admin", group by id</sub> | memberships | one flag lookup | trivial |
| Group upstream credential (`group_credentials.go`)<br><sub>the secret RPC key of a group</sub> | — | **not a document** | one small operational table stays |
Document cost: the size limit is 1 MiB; parsing that in Go takes milliseconds
**once per activation**, into maps keyed by id and address. The "join" is a
facts query followed by map lookups — the pattern the node already runs in Rust
(1.9 µs per frame for the whole fact preparation, `evidence/reth-runtime.md`).
Not measured: the explorer filter on an organisation with thousands of contracts
and hundreds of disclosure grants; the row above is arithmetic, not a benchmark.

**Redis** holds no configuration, but removing it is not free — checked in
`server.go:560-581`, `rbac/access.go`, `rbac/resolver.go`:

| In Redis today | What it actually does | To remove it |
|---|---|---|
| `PermissionCache` — resolved permissions, TTL 5 min (`RBACCacheTTL`) | **correctness, not just sharing**: `InvalidateUser/InvalidateOrg` deletes the shared row in `effective_permissions_cache` *and* the upper cache entry. With Redis that deletion reaches every replica. Without it each replica keeps its own in-memory copy, so a grant revoked on replica B stays usable on replica A for up to 5 minutes. The `rbac_cache_generation` counter (RD-1267) guards *publication* races, not cross-replica invalidation, and the read path does not revalidate it | change the cache, do not just drop it: either serve only from the shared SQL `effective_permissions_cache` (one DB round trip per resolution, invalidation already correct), or have each replica compare `rbac_cache_generation` before serving from memory (one cheap read, itself cacheable for about a second) |
| OAuth sessions, auth sessions, Azure OAuth state, link challenges | shared short-lived state; the in-memory fallback today is **single-replica only** — a login started on one replica cannot complete on another | Postgres tables with TTL cleanup (as `refresh_tokens` already is), or sticky sessions |
| upstream circuit breaker | per-replica view of the upstream | nothing to do — per-replica memory is correct |

**The middle ground**

| Stays in Postgres | Goes |
|---|---|
| facts about people and chain observations (single writer = the operations); the records (revisions, compiled artifacts, audit chain); `node_submissions`, outbox and clock; group secrets; short-lived runtime state (replacing Redis) | the ten projection tables as a *source* of configuration → an indexed in-memory document per organisation; the 075 trigger layer and the 32 legacy writers; Redis |

Cost: rewrite ~15 readers (mostly `rbac_store_*`, `explorer_redaction.go`, the
export), split observations out of `contracts`, keep the symmetry tests green.
Estimate 1–2 weeks. Not started; recorded so the position is explicit.

## 10. Appendix — the 47 tables of the live database, verified against the code

The per-table evidence behind §7, kept separate so the summary stays readable.
Verified against the live stack database after the 12-scenario acceptance
(47 tables in `privacy_proxy`; writers found by grepping `INSERT/UPDATE/DELETE`
in `internal/db` and the trigger functions in the migrations).

| Role, tables, written by | Why it stays in Postgres — and not on chain, not in a document |
|---|---|
| **Configuration record**<br>`configuration_revisions`<br>`execution_policy_revisions` (compiled artifacts)<br>*Written by:* revision lifecycle only | the reviewed document *is* the authoritative record (DECISION §3.1, "Why Postgres is the governance record": only Postgres writes the record in the same transaction as the change taking effect; Git knows what was merged — not what took effect, nor when). The compiled artifact is stored **next to** the revision, not inside the document: a document must contain only what a human reviews, and bytecode inside it would let an author ship code the reviewer cannot read — so uploaded policy bytecode is refused by design, the server compiles the approved source with the pinned compiler, and records source and artifact digests so every byte the node runs traces back to the reviewed text. The node receives the artifact and its digest, never the source |
|   **Projections**<br>`organizations`, `groups`, `group_access`<br>`contracts`, `contract_grants`, `compliance_config`<br>`address_threshold_overrides`, `token_prices`, `shared_infrastructure`<br>`allowed_azure_tenants`<br>*Written by:* activation tx (`configuration_revision_*.go`); legacy stores until a stream is active; `node_submission.go` for discovered contracts; triggers 075 refuse the rest | a **materialised cache of the active documents, not a second store of configuration** — and, checked consumer by consumer (§9), not one of them needs configuration in SQL. The UI reads the document from `context`. The server-side readers (`explorer_redaction.go`, `rbac_store_*`, `node_policy_export.go`, `node_submission.go`, disclosure and address helpers) all join *facts* (memberships, links, disclosure grants — which stay in SQL) with *configuration* (groups, grants, contracts), and the configuration half is a map lookup against an indexed in-memory copy of the document, parsed once per activation (≤ 1 MiB, milliseconds). What keeps these tables today is transition cost, plus two things that are not configuration and need a home: chain observations mixed into `contracts` (`deployed_by_user_id`, `deployed_at`, `metadata`) and the group upstream credential in `group_access` (a secret) |
| **Facts about people**<br>`users`, `user_memberships`, `eth_address_links`<br>`preregistered_addresses`<br>*Written by:* login, onboarding, `memberships/by-did`, `eth/link/*`, ban/KYC handlers; `tx_rbac.go` bootstrap | several writers and per-person cadence; a link is a signature the user produced; a re-applied document would overwrite bans or memberships written by someone else. The node needs these as facts and receives them from wherever their single writer is — today Postgres, because that is where the operations write. Putting them in the document instead loses concrete things, listed in §9 |
| **Fact stream**<br>`node_policy_clock` (version)<br>`node_policy_outbox` (what changed per version)<br>`node_policy_cursors` (what the node acknowledged)<br>*Written by:* AFTER triggers → `node_policy_mark_dirty` (073); pusher writes the cursor | the clock bump commits with the change or not at all — that is what "durable in Postgres, then pushed" rests on. The pusher exports the **full fact set at the clock version** in one repeatable-read transaction and sends a delta diffed against the last acknowledged generation (a full snapshot on first publish, when accumulated deltas exceed the checkpoint budget, or when the node asks to resync). The outbox markers are not consumed by Go code today; they are the audit of what each version changed |
| **Execution**<br>`node_submissions`<br>`pending_tx_visibility`, `tx_visible_to`<br>*Written by:* admission + reconciler (`node_submission.go`); send path enqueues visibility (`jsonrpc_processor.go`), worker promotes | the node knows the decision; only OPS knows which principal, which `visibleTo` recipients and which receipt it belongs to — that join is the product's read side |
| **Audit**<br>`rbac_audit_log` + `audit_chain_anchor/checkpoint/reanchor` (main DB), `access_logs` + anchors in the separate `privacy_proxy_audit` database<br>*Written by:* mutating transactions (append); request path for `access_logs` | tamper-evident hash chain verified on a schedule; a separate database with a separate role so the application role cannot rewrite history |
| **Compliance evidence**<br>`sanctioned_addresses`, `travel_rule_records`, `compliance_logs`<br>`system_token_prices`, `system_settings`<br>*Written by:* sanctions / travel-rule handlers, price fetcher, system setting | observations and evidence arrive from outside and are not anyone's desired state; the manual overrides that *are* desired state moved to the `compliance` document |
| **Disclosure**<br>`disclosure_requests`, `disclosure_grants`, `disclosure_events`<br>`disclosure_reports`<br>*Written by:* request / approve / reject / revoke handlers | a state machine between two organisations; each step is an answer, not configuration |
| **Runtime**<br>`refresh_tokens`, `revoked_tokens`, `oauth_silent_sso_log`<br>`impersonation_log`, `effective_permissions_cache`, `rbac_cache_generation`<br>`schema_version`<br>*Written by:* auth handlers, cache, tern | runtime state and caches; the permission cache is derivable and is invalidated, never authored |
| **Dormant / legacy**<br>`access_policies` (read once by the fact export for legacy flags; no writer), `api_keys`, `managed_proxies`<br>`price_change_log`, `tx_log_visible_to` (no reader or writer in Go)<br>*Written by:* nobody | cannot be dropped in production by policy; candidates for a documented forward migration that marks them retired |

Two honest qualifications. The projection tables are the largest group and
the least fundamental: they exist so that a hundred existing readers did not
have to change in this delivery, not because the data must live twice. And
`contract_grants.functions` still has writers in the code — the legacy grant
endpoints (`rbac_store_contract.go`) and the bootstrap helper (`tx_rbac.go`) —
but both the route guard and the `contract_grants` trigger refuse them once the
organisation's `execution-rules` stream is active, and the activation
projection never writes the column; it is dormant by design, not retired, for
the same expand-only reason.

Critic pass (2026-09-17): every writer set above was re-derived from
`INSERT/UPDATE/DELETE` sites in `internal/**/*.go` and the trigger functions in
migrations 073/075; the five dormant tables were confirmed to have no Go reader
or writer except the single `LEFT JOIN access_policies` in the fact export;
the audit separation was confirmed in migration 058 and `audit_chain.go`. Three
rows were corrected as a result (fact stream, execution bookkeeping, the
`functions` column).

## 11. How the claims here were checked

Written down because a claim in this document is only useful if it survives
being questioned. Checked on 2026-09-18 against the branch, not against memory.

| Claim | How it was checked | Result |
|---|---|---|
| "32 legacy write operations move to the streams" | counted the routes carrying a stream guard in `admin_rbac.go`, `admin_compliance.go`, `admin_shared_infra.go` | exactly 32 |
| "their `GET`s keep working" | no `GET` route of a migrated class carries a guard | confirmed |
| "the database triggers refuse a direct write" | `configuration_guard_projection` and its eight triggers, migration 075 | confirmed, including the `contract_grants` split between registry and execution-rules |
| every endpoint named in §3 exists | each path matched against the generated `API_ENDPOINTS.md` | all found |
| "`approvers` and `platform` are human-only" | `configuration.RequiresHumanAuthor`, enforced on submit and on activate | confirmed |
| "a link is a signature, not an assertion" | `eth_link.go` verification path; `MOCK_SIGNATURES` force-disabled in production (`config.go:475`) | confirmed |
| "a ban reaches the node in the next block" | AFTER trigger on `users` → `node_policy_mark_dirty` → clock bump in the same transaction (migration 073) | confirmed |
| "a group secret is never desired state" | the 075 trigger ignores `rpc_api_key` changes; the credential has its own route | confirmed |
| "94 flat MCP tools today" | `AddTool` call sites in `mcp/` | 94 |
| "≈18 µs and 6 436 gas per policy check" | `node/reth/tests/frame_cost.rs`, release build, 2 000 transactions per configuration | measured, `evidence/reth-runtime.md` |

Three claims were found wrong while checking and are corrected above:

| Was written | What the code shows |
|---|---|
| "Redis is needed only for sharing, not correctness" | it carries correctness for the permission cache: invalidation reaches other replicas only because that cache is shared; with the in-memory fallback a revoked grant survives on another replica for the 5-minute TTL (§9) |
| execution rules in tables give "two writers again" | in that hypothetical there is one writer; what is actually lost is executability — the node runs compiled code inside the call frame, so enforcement falls back to the proxy, which cannot see nested calls (§7) |
| "the outbox is what makes the push transactional"; "projections exist only for legacy readers"; "`contract_grants.functions` is written only during import" | the *clock* bump is the transactional part and the outbox rows are the per-version audit; the projections are also the source of the node's fact export; the `functions` column still has legacy writers, refused by the route guard and the trigger once the stream is active (§10) |

What in this document is **judgement, not verified fact**, and should be argued
as such: the effort estimates (§6, §9); that the projection tables could be
replaced by an in-memory document without a performance regression — the
explorer visibility filter on a large organisation was not benchmarked (§9);
that organisations belong in the platform document (§6) — a decision, with
self-service organisation creation named as the case that would reopen it;
and the shape of the deferred MCP surface (§4).

## 12. What each class looks like — one example each

Taken from the live acceptance stack, trimmed. Organisation
`12dac85b-227f-4e46-9716-be769e87f21a`.

### Execution rules

The policy inside the `execution-rules` document — JSON, stored in OPS. Each
binding is one group and what it may execute. The **server** compiles it to EVM
bytecode; the node receives that artifact in the signed fact snapshot and
executes it inside the call frame. Nothing is deployed on chain.

```json
{"kind": "execution-rules", "scope": {"kind": "organization", "id": "12dac85b…"},
 "baseRevision": 2,
 "spec": {"policy": {
   "kind": "ContractExecutionPolicy", "nestedCalls": "requireOwnRule",
   "bindings": [
     {"group": "operators", "allow": [
        {"targetClass": "contract", "storageAddress": "0xf2e246…95b",
         "selector": "0x9f0a7e8f", "abiDigest": "a71a173c…"},
        {"targetClass": "eoa", "selector": "0x"}]},
     {"group": "observers", "allow": []}]}}}
```

Reads as: the `operators` group may call one function (by selector, pinned to the
ABI it was reviewed against) on that contract and may send plain transfers;
`observers` may execute nothing. Rules can also bound arguments
("amount ≤ 1000") and name classes instead of addresses (`deployer` — anything
this principal deployed, `shared` — shared infrastructure, `precompile`).

### Group definitions

```json
{"kind": "groups", "spec": {"groups": [
  {"id": "ef205082…", "slug": "reviewers", "name": "Reviewers",
   "isOrgAdmin": true, "isOrgReadonlyAdmin": false,
   "allowedMethods": ["eth_call", "eth_sendRawTransaction", "eth_getLogs", "…"],
   "claims": [], "verboseErrors": true}]}}
```

The group's structure and which RPC methods it may use at all — a different
question from *what it may execute*, which is the policy above. Membership of
people is **not** here: that is a fact (below).

### Contract configuration

```json
{"kind": "contract-registry", "spec": {"contracts": [
  {"id": "df21d559…", "address": "0xf2e246…95b", "name": "Acceptance Counter",
   "abi": [{"name": "complete", "type": "function", "inputs": [{"type": "uint256"}]},
           {"name": "Changed", "type": "event", "inputs": [
              {"name": "actor", "type": "address", "indexed": true}]}],
   "allowVisibleToUnlock": false, "eventsAllowDynamicPayload": false,
   "readGrants": [{"groupId": "ef205082…", "eventRules": {"mode": "allowlist",
      "rules": [{"name": "Changed", "paramRules": [{"index": 0, "must_be": "self"}]}]}}]}]}}
```

Which contracts the organisation owns, the ABI rules are pinned to, and who may
see which events — the read side. A contract deployed by a pipeline appears here
as drift and is adopted by the next revision, never deleted by re-applying.

### Compliance settings

```json
{"kind": "compliance", "spec": {
  "settings": {"enabled": true, "thresholdFiat": 10000, "currency": "usd",
               "unknownPricePolicy": "forbidden", "enforcementMode": "enforce"},
  "addressThresholds": [{"address": "0x…", "thresholdFiat": 500, "note": "vendor"}],
  "tokenPrices": [{"tokenAddress": "0x…", "symbol": "ACME", "decimals": 18,
                   "pricesByCurrency": {"usd": "1.25"}, "coingeckoId": ""}]}}
```

Settings and manual prices. Fetched rates, sanctions hits and travel-rule
records are observations and stay operational.

### Approvers, trusted CI

```json
{"kind": "approvers", "spec": {
  "groupIds": ["ef205082…"],
  "trustedCI": [{"id": "…", "issuer": "customer-review-service",
                 "audience": "privacy-proxy", "subject": "ops-ci",
                 "repository": "customer/ops", "ref": "refs/heads/main",
                 "publicKey": "base64-ed25519"}]}}
```

Which admin groups may activate revisions, and whose signed approval manifest
CI activation will accept. Human-authored and human-activated only.

### Platform

```json
{"kind": "platform", "spec": {
  "sharedInfrastructure": [{"address": "0x…", "name": "Multicall3",
                            "codehash": "a1b2…"}],
  "tenants": [{"tenantId": "…", "label": "ACME", "defaultOrgId": "12dac85b…",
               "defaultGroupId": "…", "autoProvision": true}]}}
```

Deployment-wide items. Organisations join this document (§6).

### Facts about people

Not authored — produced by operations, each its own endpoint:

```
POST /api/v1/auth/verify                     → the user row exists (login)
POST /api/v1/admin/orgs/{org}/memberships/by-did
     {"did": "did:test:…user", "group_id": "0670f22a…", "expires_at": null}
POST /api/v1/eth/link/challenge → wallet signs → POST /api/v1/eth/link/verify
     {"address": "0x7e5f…bdf", "signature": "0x…"}     ← the proof
PUT  /api/v1/admin/users/{id}   {"banned": true}       ← reaches the node's next block
```

What the node then receives as facts:

```json
{"principals": [{"id": "user-a", "banned": false,
                 "linked_addresses": ["0x7e5f…bdf"],
                 "memberships": [{"group_id": "0670f22a…", "expires_at": 0}]}],
 "groups":     [{"id": "0670f22a…", "org_id": "12dac85b…", "claims": 4}],
 "contracts":  [{"address": "0xf2e246…95b", "org_id": "12dac85b…"}]}
```

### Deployment observations

Written by the reconciler after a finalized receipt, not by an author:

```
contracts.deployed_by_user_id = 6d382311…   (the principal, not just the signer)
contracts.deployed_at         = 2026-09-17T10:30:12Z
contracts.metadata            = {"deployment_tx": "0x03e987…", "block": 12}
```

The chain shows the signer; several principals may share one signer, so only
OPS knows which principal deployed it.

### Disclosure lifecycle

```
POST /api/v1/admin/disclosure/requests        org A asks to see org B's user data
POST /api/v1/me/disclosure/requests/{id}/approve   the subject answers
POST /api/v1/admin/disclosure/grants/{id}/revoke   either side ends it
```

Each step is an answer from another party, so it cannot be a document.

### The record

One row per reviewed revision — this is what answers "what was in force at T":

```
kind=execution-rules  revision=3  status=active   base=2
digest=sha256:172c3970494…      source=<the exact submitted text>
created_by=2775b9e3… (author, human)   activated_by=b522a114… (a different human)
activated_at=2026-09-17T10:30:05Z      compiled_artifact={bytecode, digests}
```

Plus the hash-chained audit entry written in the same transaction.

### Execution bookkeeping

```
node_submissions: tx 0x59988c…  principal 6d382311…  org 12dac85b…
                  state=expired  outcome=POLICY_DENIED  (the revoked-rule case)
                  tx 0xf5c2e3…  state=included  reconciled_at=…
```

The node knows the verdict; only OPS knows whose transaction it was and who may
see it.

### Fact stream to the node

```
node_policy_clock   version = 27                    ← bumped in the same transaction as the fact change
node_policy_outbox  27 → {"policy": {"12dac85b…": true}}   ← what changed in that version
node_policy_cursors producer → version 27, digest 82adb36e…, expires 1789646009
```

### Group RPC credential

```
PUT /api/v1/admin/orgs/{org}/groups/{group}/rpc-credential
    {"rpc_api_key": "<secret>"}        ← never source text, never in a diff or audit value
```

### Projections and runtime

Not authored and not a source: `groups`, `contracts`, `contract_grants` and the
other projection tables are rewritten by activation from the document;
`effective_permissions_cache`, sessions and challenges are recomputed or expire.
Both are rebuilt if lost.

