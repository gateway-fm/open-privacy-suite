# What moved to the DSL, what did not, and where the configuration should live

Three pages, for the decision. Everything behind it — per-endpoint lists,
examples of every document, the evidence for each argument, the table inventory
and the log of what was checked — is in
[api-migration-details.md](api-migration-details.md).

## 1. In one paragraph

Six classes of configuration are now authored as **reviewed documents** instead
of direct API calls: execution rules, group definitions, the contract registry,
compliance settings, approvers, and platform items. Thirty-two write endpoints
close behind them: once a stream has an active revision they answer 409, and a
database trigger refuses a direct write. Each stream is edited through the same
eight calls — read context, list revisions, submit, read one, simulate,
activate, activate through CI, withdraw. Everything about **people** stays an
operation on its existing endpoint: accounts, memberships, address links, bans,
KYC. Those are produced by events and proofs, not authored by anyone.

## 2. What moved

| Stream | What the document holds | Endpoints it replaces |
|---|---|---|
| `execution-rules` | which group may call which function, argument bounds, nested-call rules, deploy rights — compiled and enforced by the node on every call frame | the function half of contract grants, plus the three RD-1287 policy endpoints |
| `groups` | group definitions: admin flags, RPC method allowlist, claims | create, update, delete, group access, batch delete |
| `contract-registry` | contracts, ABI, visibility flags, read grants and event rules | contract create/update/delete, ABI, visibility, claim, sync-delete, batch-move, grants |
| `compliance` | thresholds, currency, enforce or monitor, and each token's entry — symbol, decimals, and either the price-feed id to use or a fixed price | compliance config, token entries, address thresholds |
| `approvers` | which admin groups may activate a revision, and which CI is trusted | none — new |
| `platform` | shared infrastructure, tenants (organisations to follow) | Azure tenants, shared infrastructure |

Thirty-two write endpoints in total. Their `GET`s keep working, as reads of the
projection.

## 3. What did not move, and why

One reason each. The full argument and its evidence are in the details
document.

| Class | Why it is not a document |
|---|---|
| Accounts | created at login; the identity provider decides who exists, not us |
| Memberships | three writers produce the same row for the same person — admin API, directory auto-provision, ZK roles — and none of it is a decision anyone reviews |
| Address links | the link is the user's own signature; in a document an author would be asserting someone else's address and authorising its transactions |
| Bans | must take effect before anyone can review it, and a reviewer has no basis to judge an incident |
| KYC | set by the credential the user logged in with |
| Sanctions, and live exchange rates | external feeds. Rates land in `system_token_prices` on a timer and are resolved at check time; the document only says which feed a token uses. A revision per rate update would be a control with nothing to decide |
| Deployment records | an observation: only OPS can bind a finalized receipt to a principal, because several principals may share one signer |
| Disclosure | every step is the other organisation's answer |
| Secrets (group RPC credential) | must never appear in a text that is diffed, reviewed and exported |
| Caches, sessions, permission results | recomputed or re-issued; never a source |

## 4. Where the document text should live

**Recommendation: the customer's Git.** The pull request is the review. This
already works: `activate-ci` accepts a signed manifest binding the repository,
ref, commit, the exact candidate digests and the reviewers who approved.

- **Push, not pull.** CI or an ArgoCD-style agent calls the API. No read credentials into the customer's repository, and enforcement never waits for Git to be reachable.
- **OPS writes three things at activation**, and they are the only reason the database is involved: the fact-version pin the node switches to, the activation record (who, when, which digest), and the projection tables for as long as they exist.
- **Facts never come from Git.** A reconcile loop over people would delete memberships the directory created and lift bans set during an incident.

This is the split GitOps already uses: Git holds desired state, the target
system holds applied state. Kubernetes keeps it in etcd; OPS keeps it in
Postgres.

**File layout: one file per `(organisation, stream)`.** It matches the
activation unit, keeps review ownership where it belongs (approvers and
platform are human-only, rules and registry may be drafted by a service), and a
change to one stream does not force a review of the others. A single global
file is disqualified for a multi-tenant deployment: one repository would put
every customer's configuration in front of every reviewer. One file per
organisation is acceptable for a small single-tenant deployment.

## 5. What an agent or a headless client sees

- One shape for all six streams instead of thirty-two setters: read context, edit the whole document, submit, simulate, and have someone else activate.
- Every context reports the deployment's capabilities: the streams, which are human-only, the approval modes, the document size limit, and whether the pinned compiler is installed.
- A returned transaction hash is no longer the end: `GET /me/transactions/{hash}/execution` reports queued, accepted, included, reverted, denied by policy, or expired, with finality.
- A TypeScript SDK generated from the OpenAPI document covers login and refresh, prepare and review, activation by a human or by CI, operations, RPC and status tracking. MCP is deferred; the planned shape is in the details document.

## 6. Decisions this needs

1. **Git as the authoring home, and the file layout.** Recommended above.
2. **Does OPS keep a copy of the applied text?** Assumed yes. It is the only way the operator can answer "what was in force at T" without the customer's repository, and the only way projections can be rebuilt from history. Saying no is a data-sovereignty choice with those two consequences.
3. **When does Reth policy mode become the default?** Until it does, legacy writers stay open for organisations without an active stream, and the old preflight gate still decides access.
4. **Organisations into the platform document.** Decided in principle; needs the deletion semantics and last-administrator protection.
5. **The explorer's separate ABI writer.** It writes a store nobody enforces from. Close it or route it through the registry.
6. **`refresh-codehash`.** It observes the chain and writes a field the platform document owns, so the guard now closes it entirely. Turn it into a read that returns the observed codehash; keep the write under review.
7. **MCP rebuild timing.** Six revision tools and role-grouped operations instead of 94 flat ones.
