# Details and evidence behind the API migration map

The short version is [api-migration-map.md](api-migration-map.md) — read that
first. This document holds what did not belong in it: the per-endpoint lists,
an example of every configuration document taken from the running stack, the
reasoning behind each placement decision with its evidence, the full table
inventory of the live database, and a log of which claims were checked how and
which of them turned out wrong.

Companion to DECISION.md §3.5 (`docs/research/dsl-policy-and-node-enforcement/DECISION.md`, untracked; it lives in the main checkout and is not on this branch)
and `API_ENDPOINTS.md` (the generated inventory: 173 canonical operations on
`feat/ops-dsl-reth`, about 50 of them admin impersonation mirrors of explorer
and RPC reads). Everything here is verified against the registered routes and
the guards in `internal/server/admin_rbac.go`, `admin_compliance.go`,
`admin_shared_infra.go` and `admin_configuration.go`.

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
| `contract-registry` | contracts (address, name, ABI, visibility flags) and their read grants (claims metadata, event rules) | `POST /orgs/{o}/contracts`, `PUT/DELETE /orgs/{o}/contracts/{a}`, `PUT …/{a}/abi`, `PUT …/{a}/visibleto-unlock`, `PUT …/{a}/events-allow-dynamic-payload`, `POST /orgs/{o}/contracts/claim`, `POST …/contracts/sync-delete`, `POST …/contracts/batch-move`, `POST/PUT/DELETE …/contracts/{a}/grants[/{g}]` (claims / event-rules part — the route closes when either this stream or `execution-rules` is active; the column-level split is the database trigger's) | configuration, not observation: pipeline-registered contracts are *adopted* as drift into the next revision, never deleted by re-applying |
| `execution-rules` | the policy: which group may call which function with which argument bounds, nested-call / delegatecall rules, deployment rights — compiled to Solidity and executed by the node on every frame | `contract_grants.functions` (the function part of `POST/PUT/DELETE …/grants`), and the RD-1287 `POST /orgs/{o}/execution-policy/revisions`, `…/{id}/activate`, `…/{id}/withdraw` | the single statement of what may execute; anything else would be a second writer of the same permission |
| `compliance` | org settings (enabled, threshold, currency, unknown-price policy, enforce/monitor), per-address thresholds, and each token's entry: symbol, decimals, and either a price-feed id or a fixed price | `PUT /orgs/{o}/compliance/config`, `PUT/DELETE …/compliance/tokens/{t}`, `PUT/DELETE …/compliance/address-thresholds/{a}` | settings, not observations. **Live rates are not in the document**: the fetcher writes `system_token_prices` on a timer and the checker resolves a per-org entry with a feed id to that live price (`compliance/checker.go:262`); sanctions hits and travel-rule records stay operational too |
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
| Memberships | `GET/POST /admin/users/{u}/memberships`, `DELETE …/memberships/{m}`, `POST/DELETE /orgs/{o}/memberships/by-did` | three writers at people scale — the admin API, Azure auto-provision, ZK roles — producing instances of rules that are reviewed elsewhere; a re-applied snapshot would revert the machine-written ones |
| Address links | `POST /eth/link/challenge`, `POST /eth/link/verify`, `GET /eth/addresses`, `DELETE /eth/addresses/{a}`, `POST …/refresh-ens`, `GET /admin/eth-addresses/collisions` | the link *is* a signature by the user's key; nobody can author it for them |
| Organisation lifecycle | `GET/POST /admin/orgs`, `GET/PUT/DELETE /admin/orgs/{o}` | **decided 2026-09-17 to move into the `platform` document** (see §6) — kept as an operation only until that is built |
| Disclosure | `GET/POST /admin/disclosure/requests`, `GET/DELETE …/requests/{r}`, `GET /admin/disclosure/grants`, `…/{g}/revoke`, `…/{g}/summary|events|logs|report`, `GET …/check-access`; `GET /me/disclosure/*`, `POST /me/disclosure/requests/{r}/approve|reject|revoke` | a request needs the other organisation's answer; state machine between parties, not desired state |
| Compliance operations | `GET/POST /admin/compliance/sanctions`, `DELETE …/sanctions/{id}`, `GET/POST /orgs/{o}/compliance/travel-rule-records`, `DELETE …/{id}`, `GET …/compliance/logs`, `GET/PUT /admin/compliance/currency`, `GET /admin/compliance/system-token-prices` | feeds and evidence (sanctions lists, travel-rule records, logs); the system currency is a one-off platform runtime setting |
| Upstream credential | `PUT /orgs/{o}/groups/{g}/rpc-credential` | a secret; never source text, never in a diff or audit value |
| Sessions and tokens | `POST /auth/request|verify|callback`, `/auth/azure/*`, `/auth/azure/service-principal`, `POST /refresh`, `/revoke`, `/introspect`, `GET /admin/sessions`, `DELETE /admin/sessions/{s}`, `/oauth/*` | runtime authentication, no desired state |
| Diagnostics and reads | `POST /orgs/{o}/dry-run`, `POST /admin/access/check`, `POST …/contracts/sync-check`, `POST …/groups/batch-delete-preview`, `GET …/contracts/grant-summary`, `GET …/contracts/{a}/events`, `GET /admin/contracts/by-address/{a}`, `GET /admin/audit-logs`, `GET /admin/logs`, `GET /admin/cache/stats`, `GET /admin/status`, `GET /admin/system/version`, `GET/POST /admin/system/eth-call-tracing`, `GET/POST /admin/system/intra-org-grant-tracing` | reads, previews and runtime switches |
| Chain reads and RPC | `GET /explorer/*` (~40 reads), `POST /rpc`, `POST /rpc/{org}` | the product's read side; visibility is decided per viewer at read time |
| Explorer reindex | `POST /explorer/index/block/{n}` | an operator command against the read side; re-reads a block that the indexer already owns |
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

1. When does Reth policy mode become the default? The legacy writers close
   per stream as soon as that stream has an active revision, in either mode;
   only the preflight gate is tied to the mode, and in legacy mode it still
   decides access.
2. Scoped admin roles and quotas for standing agent automation ("add up to N
   members a day") — an RBAC extension, not a DSL question; not built.
3. MCP rebuild timing (table above).
4. **Where the configuration text is authored.** The recommendation is the
   customer's Git with CI or an ArgoCD-style agent pushing it in (§7). The
   decision to confirm is the layout — one file per `(organisation, stream)` is
   recommended — and whether OPS keeps a copy of the applied text. Keeping it is
   what lets the operator answer "what was in force at T" without the customer's
   repository; dropping it is a data-sovereignty choice, and a deliberate loss of
   that answer.

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

## 7. Where each class of data should live

The question this section answers: **for each kind of data, where should it
live, and when is an OPS-held document the wrong home?** Two axes, independent
of each other:

- **Form** — a reviewed document, or ordinary Postgres table rows written by an API call, or a record of what happened, or something derived.
- **Location of a document's text** — the customer's Git repository, or OPS. A document can be authored in Git and pushed in; nothing in the design requires OPS to be the authoring home.

One assumption, stated so it can be overruled: **the operator must be able to
answer "what was in force at T" without access to the customer's repository.**
That is what keeps a copy of an applied document in OPS. Decide otherwise and
exactly one row below changes.

Each row carries **one** argument — the one that decides it. The type column
says what kind of claim it is, so you know which ones survive a challenge:
*principle* (true of any system built this way), *verified* (checked in this
codebase, with the reference), *measured* (a number), *judgement* (mine).

| Data | Should live as | The argument that decides it | Type |
|---|---|---|---|
| **[Execution rules](#execution-rules)** | reviewed document; text in Git or OPS | what the node enforces must be derived from a text a human approved, byte for byte — the server compiles with a pinned compiler and records both digests | principle; verified (`policydsl`, digests on the revision) |
| **[Group definitions](#group-definitions)** | reviewed document; text in Git or OPS | a group is a bundle of powers (`isOrgAdmin`, `claims`, `allowedMethods`), so editing one changes what people may do | principle |
| **[Contract configuration](#contract-configuration)** | reviewed document; text in Git or OPS | it decides what other organisations can see (event rules, visibility flags) and what the execution rules are pinned to (`abiDigest`) — a security decision, not an observation | principle |
| **[Compliance settings](#compliance-settings)** | reviewed document; text in Git or OPS | a threshold or an enforce/monitor switch is something a reviewer can actually judge, and it changes rarely | judgement |
| **[Approvers, trusted CI](#approvers-trusted-ci)** | reviewed document, human-authored only | it decides who may approve; eligibility for an activation is read from the **active** approvers revision, so a document cannot widen the set that approves it | verified (`ConfigurationActorIsApprover`) |
| **[Platform](#platform)** | reviewed document, human-authored only | it is the deployment operator's decision, never a tenant's | principle |
| **[Users](#facts-about-people)** | Postgres rows in `users`, written at login | identity comes from the identity provider at login; the product does not decide who exists | verified (`EnsureUserExists`) |
| **[Memberships](#facts-about-people)** | Postgres rows in `user_memberships`, written by the API and by login | what is reviewed is the **rule**, not the row: the tenant mapping (`tenants[]` in the platform document) for Azure auto-provision, and the issuer's own process for ZK credentials, which name a group by slug and are honoured if it exists (`auth/zk_roles.go:83-124`). The row is the instance, written by three writers at per-person cadence | verified (`auth_azure.go:298`, `auth.go:603`) |
| **[Address links](#facts-about-people)** | Postgres rows in `eth_address_links`, written after the signature is verified | the link is the user's signature; in a document an author would assert someone else's address and authorise its transactions | principle; verified (`eth_link.go`) |
| **[Bans](#facts-about-people)** | a column of `users`, set by an admin call | it must take effect before anyone can review it, and the review would have nothing to decide | principle |
| **[KYC](#facts-about-people)** | a column of `users`, set at login | it is set by the credential the user logged in with | verified (`auth.go:571`) |
| **[Sanctions](#facts-about-people)** | Postgres rows in `sanctioned_addresses`, fed externally | a revision per feed update is a control with nothing for the reviewer to decide | principle |
| **[Deployment observations](#deployment-observations)** | columns of `contracts`, written by the reconciler | it is an observation, and only OPS can bind a receipt to a principal — the chain shows the signer, and several principals may share one | verified (`node_submission.go`) |
| **[Disclosure](#disclosure-lifecycle)** | Postgres rows in `disclosure_*`, written by both parties' actions | each step is the other organisation's answer | principle |
| **[The record: what was applied, when, by whom](#the-record)** | Postgres rows in `configuration_revisions` and `rbac_audit_log`, written with the activation | only the system that applied a change knows when it took effect; Git knows the merge | principle (rests on the assumption above) |
| **[Execution bookkeeping](#execution-bookkeeping)** | Postgres rows in `node_submissions`, `tx_visible_to` | only OPS holds the join between a transaction, its principal and its `visibleTo` recipients | verified |
| **[Fact version pin and cursor](#fact-stream-to-the-node)** | Postgres rows in `node_policy_clock`, `node_policy_cursors` | the version the node switches to must commit in the same transaction as the change it carries | principle; verified (`node_policy_mark_dirty`) |
| **[Group RPC credential](#group-rpc-credential)** | a secret store | a credential must never appear in a text that is diffed, reviewed and exported. Today it is encrypted in Postgres; an external secrets manager with only a reference in the database is the stronger design and an open gap | principle |
| **[Projections](#projections-and-runtime)** | derived tables, rebuilt on activation | they are recomputable from the document and are never a source; the target is to drop them (§9) | verified |
| **[Runtime state](#projections-and-runtime)** | memory or Redis | sessions are re-issued and permissions recomputed; losing them logs people out, it does not corrupt anything — with one exception, the permission cache needs a shared invalidation (§9) | measured (§9) |

### Why not a plain DSL file in Git?

You can, for all six configuration streams, and it is the better authoring
model. The recommendation:

- **Git holds the text and its history.** Review is the pull request. This is already supported: `activate-ci` accepts a signed manifest binding `repository`, `ref`, `commit`, the candidate digests and the reviewer subjects (`configuration/ci_approval.go:19`).
- **CI, or an ArgoCD-style agent, pushes it in.** Push rather than pull: no read credentials into the customer's repository, and enforcement never waits on Git being reachable. An external agent watching Git and calling the API gives the same GitOps loop.
- **OPS writes three things at that moment**, and these are the only reasons the database is involved at all: the version pin the node switches to, the activation record (who, when, which digest), and the projection tables for as long as they exist (§9 proposes removing them).
- **Facts never come from Git.** People, memberships, address links, bans. A reconcile loop over them would delete memberships the identity provider created and lift bans set during an incident.

The comparison people reach for is ArgoCD, and it supports this split rather
than contradicting it: in GitOps, Git holds desired state, the **target system**
holds applied state (Kubernetes in etcd, OPS in Postgres), and the agent syncs
between them. Nobody keeps applied state only in Git.

### If the text lives in Git, in how many files?

| Layout | Blast radius of a bad merge | Review ownership | Tenant isolation | Compile cost |
|---|---|---|---|---|
| **A. One global file** | every tenant at once | everyone reviews everything | none — one repository exposes every customer's configuration to every reviewer | every merge recompiles unless digests are compared |
| **B. One file per `(organisation, stream)`** | one stream of one tenant | natural: compliance owners review compliance, rule authors review rules, `approvers`/`platform` stay human-only | a repository per customer is possible | only the rules file triggers a compile |
| **C. One file per organisation** | one tenant | one owner set for everything in that tenant | a repository per customer is possible | needs digest comparison to skip unchanged streams |

Recommendation: **B**, with C acceptable for a small single-tenant deployment.
Two reasons. Review ownership genuinely differs per stream — `approvers` and
`platform` may only be authored by humans, while rules and registry may be
drafted by a service. And B maps one-to-one onto the activation unit, so a
change to one stream cannot force a review of the others. Cross-stream changes
(an ABI and the rules that pin it) stay one pull request and one activation:
the API already co-activates named sibling drafts.

A is disqualified for a multi-tenant deployment: one repository would put every
customer's configuration in front of every reviewer.

### The four tests behind the table

Each is an argument, then questioned: is it logical, is it a principle or only
how this build works, could it be designed otherwise, what is the evidence.
Two of the four were narrowed by that questioning.

**Test 1 — the document is not the only writer.** Several writers disqualify a
document **unless they write different kinds of thing that history merged into
one table** — then the fix is to separate them, not to tolerate drift. Drift
adoption today covers exactly two such cases: a chain observation stored in the
`contracts` table alongside decisions, and the legacy deploy auto-grant. Both
enter through the authorised registration transaction — the Reth reconciler
and, since this branch, the legacy plain-CREATE path too — so the next registry
revision adopts them as drift instead of the guard refusing them. Whether the
auto-grant should exist at all once the rules express it (`targetClass:
deployer`) is open. For memberships separation does not help: three writers
produce the same row for the same person.

**Test 2 — it must take effect before anyone can review it.** The latency of a
document is our four-eyes rule (`configuration_revision_store.go:442`). The part
that is not ours: an approver has no independent basis to judge an incident ban,
so the second signature adds delay without adding safety. A stream could allow
self-activation, but then that class has no review left, which is the reason to
make it a document at all.

**Test 3 — it is a proof or an observation someone else produced.** "A proof
cannot be authored" is too strong: a document could carry each signature and the
server could verify it. It fails on scale, not on principle — the facts for a
million users are about 85 MB against a 1 MiB document limit, and a reviewer
reading signatures approves nothing.

**Test 4 — it changes without anyone writing it.** Expiry is *not* an example:
a static `expiresAt` is evaluated dynamically by the node against the block it
is building (`facts.rs:254`). What survives is external feeds — sanctions,
prices — where each update would become a revision with nothing to decide.

## 8. Why six streams and not one organisation document

The revision mechanics would work for a single "organisation configuration"
document. The split into streams per `(organisation, kind)` is a deliberate
choice about review, blast radius and ownership, not a limitation of the
mechanics. (This is about the **activation unit**. How many *files* the text is
kept in is a separate question, answered in §7 — the recommendation there is one
file per stream, which lines up with this split.)

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

## 11. How the claims here were checked, and where the checking stopped

Checked on 2026-09-18 against the branch. Read the second table first: the first
pass verified the **mechanical** claims and left the **reasoning** cells
unverified, which is exactly where the errors were.

**Verified by reading the code or running it:**

| Claim | How | Result |
|---|---|---|
| "32 legacy write operations move to the streams" | counted routes carrying a stream guard in `admin_rbac.go`, `admin_compliance.go`, `admin_shared_infra.go` | exactly 32 |
| "their `GET`s keep working" | no `GET` of a migrated class carries a guard | confirmed |
| "the database triggers refuse a direct write" | `configuration_guard_projection` and its nine triggers (075) | confirmed, including the `contract_grants` split between registry and execution-rules |
| every endpoint named in §3 exists | matched against the generated `API_ENDPOINTS.md` | all found |
| "`approvers` and `platform` are human-only" | `configuration.RequiresHumanAuthor`, enforced on submit and activate | confirmed |
| "a link is a signature, not an assertion" | `eth_link.go`; `MOCK_SIGNATURES` force-disabled in production (`config.go:475`) | confirmed |
| "a ban reaches the node at the next block" | AFTER trigger on `users` → clock bump in the same transaction (073) | confirmed |
| "a group secret is never desired state" | the 075 trigger ignores `rpc_api_key`; the credential has its own route | confirmed |
| "a user row appears at login" | `EnsureUserExists` in `auth.go`, `auth_azure.go` | confirmed |
| "memberships have several writers" | admin API, Azure auto-provision (`auth_azure.go:298`), ZK roles (`auth.go:603`) | confirmed — three, now named |
| "deleting a group with live members needs the exact count" | `groups.go:80-86` | confirmed |
| "pipeline-registered resources are adopted, not swept" | `PreservedDrift` in the groups, registry, compliance and platform diffs; `ExecutionDiff` has none, because a deployment cannot create a rule | confirmed, with that limit |
| "the compiled policy is never on chain" | `known_bytecode` from the snapshot; `private_policy.rs` — no state entry, chain code at the same address does not override it, the application cannot observe it | confirmed |
| "94 flat MCP tools today" | `AddTool` call sites | 94 |
| "≈18 µs and 6 436 gas per policy check" | `tests/frame_cost.rs`, release, 2 000 transactions per configuration | measured |

**Found wrong while being questioned, and corrected.** Every one of them was a
reasoning or a storage cell, not a mechanical fact — the first pass did not
check those, and the section above overstated what "verified" meant:

| Was written | What the code shows |
|---|---|
| "Redis is needed only for sharing, not correctness" | it carries correctness for the permission cache: with the in-memory fallback a grant revoked on one replica survives on another for the 5-minute TTL (§9) |
| execution rules in tables give "two writers again" | in that hypothetical there is one writer; what is lost is executability — the node runs compiled code inside the frame, so enforcement falls back to the proxy, which cannot see nested calls |
| an on-chain policy would expose "group names, contracts, limits" | no names and no people: groups are `keccak256(group id)`; what it exposes is structure — governed addresses, per-group selectors, numeric bounds. Privacy is the weakest argument; the operational ones are decisive (§12) |
| bans are "also written by compliance automation and feeds" | `users.banned` is written only by the admin handler; KYC comes from the login credential; sanctions are a separate per-organisation address list checked at transaction time and never touch the user row |
| "the outbox makes the push transactional"; "projections exist only for legacy readers"; "`functions` is written only during import" | the *clock* bump is the transactional part; the projections are also the source of the node's fact export; the `functions` column still has legacy writers, refused by the guard and the trigger once the stream is active (§10) |
| "`execution-rules` has no projection table" | it projects into `execution_policy_revisions` — the RD-1287 table, with the previous revision marked `superseded` in the same transaction (`configuration_revision_execution.go:485`) |
| the record and the execution bookkeeping are "append-only rows" | only `rbac_audit_log` is. `configuration_revisions` freezes `source` and `digest` by trigger but sets `status`, `activated_by`, `activated_at` on activation; `node_submissions` rows are updated repeatedly until the transaction reaches an end state |
| the table's column read "Stored in", with "OPS document" beside "Postgres" | a document *is* a Postgres row (`configuration_revisions.source`); the column now says the **form** the data is written in, and the section leads with the four tests that decide that form |

Verified while rebuilding §7 on 2026-09-18: the CI approval manifest binds
`repository`, `ref`, `commit`, `candidateDigests` and `reviewerSubjects`
(`configuration/ci_approval.go:19`), so a Git pull request can carry the
approval; approver eligibility is read from the **active** approvers revision,
so a document cannot widen the set that approves it
(`ConfigurationActorIsApprover`); there is no Git client anywhere in the product
or in `go.mod`, so any Git-authored flow today is push, not pull.

The comparison with ArgoCD in §7 is design knowledge, not a claim about this
codebase: nothing here integrates with it.

**One standing assumption**, stated in §7 and reversible: the operator must be
able to answer "what was in force at T" without the customer's repository. It is
the only reason a copy of an applied document stays in OPS.

**Judgement, not verified fact** — argue these as opinions: the effort estimates
(§6, §9); that the projection tables can be replaced by an in-memory document
without a performance regression (the explorer visibility filter on a large
organisation was not benchmarked); that organisations belong in the platform
document (§6), with self-service organisation creation named as the case that
would reopen it; the shape of the deferred MCP surface (§4); and every sentence
of the form "a document would be the wrong tool for X" in §7 — those are design
arguments supported by the code's current writers, not measurements.

## 12. What each class looks like — one example each

Taken from the live acceptance stack, trimmed. Organisation
`12dac85b-227f-4e46-9716-be769e87f21a`.

### Execution rules

The policy inside the `execution-rules` document — JSON, stored in OPS. Each
binding is one group and what it may execute. The **server** compiles it to EVM
bytecode; the node receives that artifact in the signed fact snapshot and
executes it inside the call frame. Nothing is deployed on chain.

The artifact is not a separate store and not part of the authored text: both are
columns of one row in Postgres — `configuration_revisions.source` (what the
person wrote and reviewed, digest-pinned and immutable) and
`configuration_revisions.compiled_artifact` beside it (what the server produced
from that source with the pinned compiler; migration 075). They are split because the source is
**input** and the artifact is **evidence** derived from it: bytecode inside the
authored text would be code the reviewer cannot read and the author could
choose — so the schema refuses it, the server compiles, and both digests are
recorded. Recompiling the same source with the same compiler must reproduce the
same artifact; that is what makes "the node runs what was reviewed" checkable.

**Why the artifact is not deployed on chain.** It is a compiled contract, but it
is never *called* like one: the node's inspector builds a private static frame
with the bytecode supplied directly from the signed snapshot
(`known_bytecode`, address `0x…0900`, 100 k gas, reverted afterwards). Three
tests pin that this is deliberate — the policy account never appears in the
state result, code deployed at that address on chain does **not** override the
private policy, and the application cannot observe the code or its gas
(`node/reth/tests/private_policy.rs`). Deploying it would mean:

| | On chain | As today, in the signed snapshot |
|---|---|---|
| Who can read the organisation's access rules | everyone with chain access. Note what that is and is not: the artifact holds **no names and no people** — groups appear as `keccak256(group id)`, and without the facts (who is in which group) the code authorises nobody. What it does expose is the structure: which contract addresses are governed, which selectors each group may call, and the numeric bounds written into rules (`UintAtMost`, address equality). Moderate, not catastrophic — this is the weakest of the arguments below | only OPS and the node |
| Activation | a transaction: gas, inclusion latency, and the deployment itself is gated by the policy that governs deployments | one database transaction, then a versioned push; the node pins one version per candidate block |
| A reorg that drops the deploying block | the active policy disappears and enforcement flips | nothing changes: the version is pinned, not chain state |
| Emergency revocation | a transaction, subject to the chain's ordering | the next block after the push |
| Cost | a transaction per activation | none |
| Does it remove a moving part? | no — facts (people, memberships, bans) can never be on chain, so the signed channel exists anyway; the policy rides on it | — |

The decisive arguments are the operational rows, not the privacy one: putting
the artifact on chain turns activation and revocation into transactions whose
timing the chain decides, and makes the active policy a function of chain state
that a reorg can change. The one thing on-chain storage would add is
third-party verifiability of which policy is active. That is already covered without publishing the rules: the
revision row records the source and artifact digests, the signed snapshot
carries the artifact digest, and the node reports the digest it applied — an
auditor recompiles the reviewed source and compares.

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

## 13. Field-by-field sweep: who sets each field, and how often

Run on 2026-09-18 after a claim in the summary ("manually authored prices") was
true but misleading. For every field of every stream: **how is it set, who sets
it, how often.** Two findings came out of it; both are listed under the tables.

**`groups`**

| Field | Set by | How often |
|---|---|---|
| `slug`, `name`, `description` | an admin, in the document | rarely |
| `isOrgAdmin`, `isOrgReadonlyAdmin` | an admin, in the document; the **platform token** is additionally required to touch an org-admin group (`denyJWTAdminTouchOrgAdminGroup`) | rarely, and it is a privilege change |
| `allowedMethods`, `claims`, `verboseErrors` | an admin, in the document | rarely |
| *membership of people* | **not in this document** — the admin API, directory auto-provision and ZK roles | continuously |

**`contract-registry`**

| Field | Set by | How often |
|---|---|---|
| `address`, `name` | an admin, in the document; a deployment creates the row as drift, adopted by the next revision | per contract |
| `abi` | an admin, in the document — single writer since the explorer's own ABI endpoint was removed (§16) | on deployment or upgrade |
| `allowVisibleToUnlock`, `eventsAllowDynamicPayload`, `readGrants`, `eventRules` | an admin, in the document | rarely |
| `deployed_by_user_id`, `deployed_at`, `metadata` | **not configuration** — the reconciler, from a finalized receipt | per deployment |

**`compliance`**

| Field | Set by | How often |
|---|---|---|
| `enabled`, `thresholdFiat`, `currency`, `unknownPricePolicy`, `enforcementMode` | an admin, in the document | rarely |
| `addressThresholds[]` | an admin, in the document | rarely |
| `tokenPrices[]` — `symbol`, `decimals`, `coingeckoId` **or** a fixed price | an admin, in the document. This is the token's *entry*, not its price | when a token is added or corrected |
| the live rate | **not in any document** — the price fetcher writes `system_token_prices` on a timer; the checker resolves an entry that carries a feed id to that live price (`compliance/checker.go:262`) | every interval |
| the deployment-wide `base_currency` | a super admin, `PUT /admin/compliance/currency`; used only as a fallback when an org has no compliance config (`admin_compliance.go:91`) | almost never |

**`approvers`**

| Field | Set by | How often |
|---|---|---|
| `groupIds` | a human admin, in the document; eligibility for an activation is read from the **active** revision, so a document cannot widen its own approvers | rarely |
| `trustedCI[]` — issuer, audience, subject, repository, ref, public key | a human admin, in the document | on key rotation |

**`platform`**

| Field | Set by | How often |
|---|---|---|
| `tenants[]` | an allowlisted human, in the document | rarely |
| `sharedInfrastructure[].address`, `.name`, `.description` | an allowlisted human, in the document | rarely |
| `sharedInfrastructure[].codehash` | **an observation**: `refresh-codehash` reads `eth_getCode` at latest and stores its keccak256 | whenever a tracked upstream contract is upgraded |

**`execution-rules`**

| Field | Set by | How often |
|---|---|---|
| `policy` (bindings, selectors, argument bounds, target classes) | an admin or a service, in the document | with application changes |
| `artifact` | **the server**, by compiling the approved source; never accepted from a caller | on every submission |
| the compiler contract (version, optimizer runs, EVM version) | the deployment's pinned build | on a compiler upgrade |

### Two findings

**1. `refresh-codehash` is an observation writing into a decision field, and the
guard closed it completely.** The endpoint reads the chain and stores the hash
in a field the platform document owns. With the platform stream active it
returns 409 — which is right for the *write* (new bytecode should not be trusted
without review) and wrong for the *read*, because it was the only way to compute
the hash. After an upstream upgrade the operator now has to derive keccak256 by
hand before editing the document. It should become a read that returns the
observed codehash for pasting into the document.

**2. A compiler upgrade invalidates open drafts.** Activation re-verifies the
artifact against the currently pinned `SolidityVersion`, optimizer runs and EVM
version (`verifyExecutionArtifact`). An already-active revision is unaffected —
the node holds its artifact — but a draft compiled before the upgrade is refused
with "approved execution artifact differs from its source or compiler contract"
and must be resubmitted. Correct behaviour; it needs to be in the operator
documentation, which it is not.

## 14. Two kinds of concurrency, and why only one of them is a problem

**Two people or agents editing the same document.** Detected and recoverable.
A submission must name the currently active revision as its `baseRevision`; a
stale one is rejected with 409 (`configuration_revision_store.go:107`), and
activation re-checks the base inside the transaction under a scope lock
(`pg_advisory_xact_lock` for platform, `SELECT … FOR UPDATE` on the
organisation row, migration 076), so simultaneous activations serialise instead
of interleaving. The loser re-reads the context, re-applies the change and
resubmits — the same loop as a rejected `git push`.

Two caveats. There is no three-way merge: the loser redoes the edit by hand,
which is trivial for a one-line change and tedious for two large ones. And this
is why per-stream documents matter: a compliance edit and a rules edit never
collide, because they are different documents.

**A document and an operational writer touching the same data.** Not detected,
and that is inherent. The document declares the complete desired state, so
re-applying it removes anything the other writer did — no stale base, no
conflict, no error. A membership the directory created between two revisions
simply disappears at the next activation.

The difference decides where a class belongs. Concurrency between document
authors is a detected collision with a known recovery. Concurrency between a
document and an operation is silent data loss, unless the rows carry provenance
and the document owns only its own share (as `sanctioned_addresses.source` and
`user_memberships.source` already allow, and `users.banned` does not).

**Then why keep the mix at all — why not make every writer a document writer?**
Because no two *decision* writers coexist by design; that is precisely what
closing the thirty-two endpoints achieved. What remains are **event** writers,
machines reacting in the request path: login creating the user row, directory
auto-provision and ZK roles creating memberships, the reconciler recording a
finalized deployment, the price fetcher, the sanctions feed. Converting them
would mean either a human approval inside the login path, which stops the system
working, or machines self-activating their own revisions — which removes the
review that justified documents and **does not remove the conflict**: two
documents each declaring a complete desired set overwrite each other exactly the
same way, so ownership by provenance would still be required.

The rule that follows: a writer that makes a decision must be the document and
nothing else. Two places still break it and are on the list to fix — the
deployment auto-grant the policy can express with `targetClass: deployer`, and
`refresh-codehash` writing an observed value into a document-owned field.

## 15. Two findings from the membership path (2026-09-18)

**A ZK credential can grant membership in a privileged group.**
`ProcessZKMemberships` resolves the group by slug and creates the membership
with no check on `is_org_admin` (`auth/zk_roles.go:96-124`). The admin API
deliberately reserves org-admin membership to the platform token
(`denyJWTAdminTouchOrgAdminGroup`), so the two paths disagree: what a tier-2
admin may not do, an accepted credential may. Whether that is acceptable
depends on how far the credential issuer is trusted — it is the customer's own
authority — but it should be a stated decision rather than an accident.

**The ZK path rewrites provenance.** When a membership already exists it sets
`Source = zk_attested` on it (`auth/zk_roles.go:110`). An admin-created
membership therefore becomes credential-owned the first time a credential
mentions the same group. That matters for any design where a document owns
`source=admin` rows: a credential could move a row out of the document's
ownership without anyone noticing.

## 16. Two endpoint defects: one removed, one open

**Removed: the endpoint that wrote a dead column in another product's
database.** `POST /api/v1/explorer/addresses/{address}/abi` lived in OPS and
ran `UPDATE contracts SET abi` against the **indexer's** database — OPS
connects to it read-only for explorer pages, and this was the single place
where it wrote there.

The column was used by nobody. The indexer never reads or writes it: its own
interface says so ("NOT INCLUDED here and never served by the indexer: ABI,
source code, verification status… privacy mode does not expose contract
verification"), and there was no call site for its `UpdateContractABI`. The
standalone explorer does have source verification, but it keeps it in its own
table in its own database, and those routes are compiled out of the privacy
build. Nothing called the endpoint: not the frontend, not the end-to-end
tests, only the generated SDK types listed it.

Meanwhile the ABI that decides anything is ours: `privacy_proxy.contracts.abi`,
owned by the `contract-registry` document and read by the policy compiler, by
log redaction and by the admin screens.

The endpoint, its handler, the response model and `Store.SetContractABI` are
deleted. If verified ABIs for display are wanted later, that is the standalone
explorer's own feature in its own database, and a properly designed
verification feature belongs in the registry document (see the note below).

**5. `refresh-codehash`: we closed the write and lost the read with it.**

A shared-infrastructure entry carries a `codehash` pin. The address counts as
trusted shared infrastructure only while the bytecode living there hashes to
that value. It exists because of a real bypass: before the pin, an operator
could tag any address, and if a proxy contract sat behind it, an upgrade
rotated the bytecode while the trust stayed (migration 052).

Both the old trace validator and the node read it. The node receives the pin
with the facts and only sets the "shared infrastructure" fact when the actual
code in the frame hashes to it, which is what a `targetClass: shared` rule
depends on.

Until now the workflow after an upstream upgrade was one click:
`POST /admin/shared-infrastructure/{address}/refresh-codehash` fetched
`eth_getCode`, hashed it, stored it. That endpoint writes a field the platform
document owns, so the stream guard now answers 409 for the whole call.

Refusing the **write** is correct: a freshly observed hash must not become a
trust anchor without review, or a hostile upgrade is trusted automatically.
Refusing the **read** is the mistake: that call was the only thing that
produced the value. The operator now has to fetch the code and hash it exactly
the way we do — raw `eth_getCode` output, not deployment bytecode, not the
metadata-stripped variant — and a wrong guess silently drops the address out of
shared infrastructure.

Fix: keep the endpoint as a read that returns the observed codehash for pasting
into the document, and drop the write.

## 17. What an agent or a headless client sees

- One shape for all six streams instead of thirty-two setters: read context, edit the whole document, submit, simulate, and have someone else activate.
- Every context reports the deployment's capabilities: the streams, which are human-only, the approval modes, the document size limit, and whether the pinned compiler is installed.
- A returned transaction hash is no longer the end: `GET /me/transactions/{hash}/execution` reports queued, accepted, included, reverted, denied by policy, or expired, with finality.
- A TypeScript SDK generated from the OpenAPI document covers login and refresh, prepare and review, activation by a human or by CI, operations, RPC and status tracking. MCP is deferred; the planned shape is in the details document.
