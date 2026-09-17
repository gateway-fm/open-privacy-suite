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

## 7. What stays in Postgres, table by table, and why

Verified against the live stack database after the 12-scenario acceptance
(47 tables in `privacy_proxy`; writers found by grepping `INSERT/UPDATE/DELETE`
in `internal/db` and the trigger functions in the migrations). "Why Postgres"
answers two questions at once: why not on chain, and why not inside a
declarative document.

**Configuration — the record**

- Tables: `configuration_revisions`; `execution_policy_revisions` (compiled artifact per execution-rules revision)
- Written by: the revision lifecycle only
- Why Postgres: the reviewed document *is* the authoritative record (DECISION §3.1: the database is the governance record); the node receives the compiled policy, never the source; on chain it would be public and cost a transaction per review step

**Projections of activated configuration**

- Tables: `organizations`, `groups`, `group_access`, `contracts`, `contract_grants`, `compliance_config`, `address_threshold_overrides`, `token_prices`, `shared_infrastructure`, `allowed_azure_tenants`
- Written by: activation transaction (`configuration_revision_*.go`); legacy writers only while a stream is not yet active (`rbac_store_*.go`, `compliance_store.go`, `azure_tenant_store.go`); deployment reconciliation for discovered contracts (`node_submission.go`); triggers (075) refuse anything else
- Why Postgres: two kinds of readers depend on them: the existing product paths (RBAC checks in `rbac_store_*`, explorer redaction in `explorer_redaction.go`, UI lists) **and the fact export to the node** (`node_policy_export.go` reads `groups`, `group_access`, `contracts`, `contract_grants`, `shared_infrastructure`, `preregistered_addresses`). So they are not only a legacy convenience: today they are the source the node's facts are built from. Derivable, and could be replaced by reading the documents directly later

**Facts about people — operational, never a document**

- Tables: `users`, `user_memberships`, `eth_address_links`, `preregistered_addresses`
- Written by: login, onboarding, `memberships/by-did`, `eth/link/*`, ban/KYC handlers; `tx_rbac.go` for atomic bootstrap
- Why Postgres: several writers and per-person cadence; a link is a signature the user produced; a re-applied document would overwrite bans or memberships written by someone else. Sent to the node as facts through the outbox — the node holds a copy, Postgres stays the only writer

**Fact stream to the node**

- Tables: `node_policy_clock` (one version counter), `node_policy_outbox` (per version: which principals/groups/contracts/policies changed), `node_policy_cursors` (what the node acknowledged: version, digest, expiry)
- Written by: AFTER triggers on the fact and projection tables call `node_policy_mark_dirty` (migration 073), which bumps the clock **in the same transaction** as the change and records the markers; the pusher writes the cursor
- Why Postgres: the clock bump commits with the change or not at all — that is what "durable in Postgres, then pushed" rests on. The pusher exports the **full fact set at the clock version** in one repeatable-read transaction and sends a delta diffed against the last acknowledged generation (a full snapshot on first publish, when accumulated deltas exceed the checkpoint budget, or when the node asks to resync). The outbox markers are not consumed by Go code today; they are the audit of what each version changed

**Execution bookkeeping**

- Tables: `node_submissions` (raw tx, identity envelope, principal, outcome, reconciliation), `pending_tx_visibility`, `tx_visible_to`
- Written by: `node_submissions`: admission and the reconciler (`node_submission.go`); visibility: the send path enqueues `pending_tx_visibility` (`jsonrpc_processor.go`), a worker promotes rows to `tx_visible_to` once the transaction is included; in node mode the reconciler enqueues from the submission record
- Why Postgres: the node knows the decision; only OPS knows which principal, which `visibleTo` recipients and which receipt it belongs to — that join is the product's read side

**Audit**

- Tables: `rbac_audit_log` + `audit_chain_anchor/checkpoint/reanchor` (main DB); `access_logs` + anchors in the separate `privacy_proxy_audit` database
- Written by: append-only from the mutating transactions; the access log from the request path
- Why Postgres: tamper-evident hash chain verified on a schedule; a separate database with a separate role so the application role cannot rewrite history

**Compliance evidence and feeds**

- Tables: `sanctioned_addresses`, `travel_rule_records`, `compliance_logs`, `system_token_prices`, `system_settings`
- Written by: sanctions/travel-rule handlers, price fetcher, system currency setting
- Why Postgres: observations and evidence arrive from outside and are not anyone's desired state; the manual overrides that *are* desired state moved to the `compliance` document

**Disclosure**

- Tables: `disclosure_requests`, `disclosure_grants`, `disclosure_events`, `disclosure_reports`
- Written by: the request/approve/reject/revoke handlers
- Why Postgres: a state machine between two organisations; each step is an answer, not configuration

**Sessions and runtime**

- Tables: `refresh_tokens`, `revoked_tokens`, `oauth_silent_sso_log`, `impersonation_log`, `effective_permissions_cache`, `rbac_cache_generation`, `schema_version`
- Written by: auth handlers, cache, tern
- Why Postgres: runtime state and caches; the permission cache is derivable and is invalidated, never authored

**Dormant / legacy — kept only because production migrations are expand-only**

- Tables: `access_policies` (read once by the fact export for legacy flags; no writer), `api_keys`, `managed_proxies`, `price_change_log`, `tx_log_visible_to` (no reader or writer in Go)
- Written by: nobody
- Why Postgres: cannot be dropped in production by policy; candidates for a documented forward migration that marks them retired

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

