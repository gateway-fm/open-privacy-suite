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

## 7. What stays in Postgres, table by table, and why

Verified against the live stack database after the 12-scenario acceptance
(47 tables in `privacy_proxy`; writers found by grepping `INSERT/UPDATE/DELETE`
in `internal/db` and the trigger functions in the migrations). "Why Postgres"
answers two questions at once: why not on chain, and why not inside a
declarative document.

| Role, tables, written by | Why it stays in Postgres — and not on chain, not in a document |
|---|---|
| **Configuration record**<br>`configuration_revisions`<br>`execution_policy_revisions` (compiled artifacts)<br>*Written by:* revision lifecycle only | the reviewed document *is* the authoritative record (DECISION §3.1, "Why Postgres is the governance record": only Postgres writes the record in the same transaction as the change taking effect; Git knows what was merged — not what took effect, nor when). The compiled artifact is stored **next to** the revision, not inside the document: a document must contain only what a human reviews, and bytecode inside it would let an author ship code the reviewer cannot read — so uploaded policy bytecode is refused by design, the server compiles the approved source with the pinned compiler, and records source and artifact digests so every byte the node runs traces back to the reviewed text. The node receives the artifact and its digest, never the source |
|  **Projections**<br>`organizations`, `groups`, `group_access`<br>`contracts`, `contract_grants`, `compliance_config`<br>`address_threshold_overrides`, `token_prices`, `shared_infrastructure`<br>`allowed_azure_tenants`<br>*Written by:* activation tx (`configuration_revision_*.go`); legacy stores until a stream is active; `node_submission.go` for discovered contracts; triggers 075 refuse the rest | a **materialised cache of the active documents, not a second store of configuration**. The UI does not need them: the Configuration screen renders and edits the document from `context`. What needs configuration in a joinable form next to the facts is SQL: the explorer visibility filter (`explorer_redaction.go`, transactions × grants × memberships over large row sets), effective-permission computation (`rbac_store_*`), the fact export (`node_policy_export.go`) and deployment reconciliation (`node_submission.go`). Only the explorer filter needs it in SQL; the others could read the document in memory. Two things about them are transition convenience, not design: they are still the *legacy tables with legacy writers* (refused by the 075 triggers once a stream is active), and `contracts` mixes chain observations (`deployed_by_user_id`, `deployed_at`, `metadata`) with configuration (`name`, `abi`, flags) — the observations are facts and belong in their own table, bridged to the document by drift adoption. Target: caches explicitly rebuilt from the documents on activation, kept only where SQL needs them |
| **Facts about people**<br>`users`, `user_memberships`, `eth_address_links`<br>`preregistered_addresses`<br>*Written by:* login, onboarding, `memberships/by-did`, `eth/link/*`, ban/KYC handlers; `tx_rbac.go` bootstrap | several writers and per-person cadence; a link is a signature the user produced; a re-applied document would overwrite bans or memberships written by someone else. Sent to the node as facts through the outbox — the node holds a copy, Postgres stays the only writer |
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

