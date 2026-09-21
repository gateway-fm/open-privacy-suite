# What moved to the DSL, what did not, and where the configuration should live

Three pages, for the decision. Everything behind it — per-endpoint lists,
examples of every document, the evidence for each argument, the table inventory
and the log of what was checked — is in
[api-migration-details.md](api-migration-details.md).

One word used throughout: a **principal** is the authenticated OPS identity that
acts — a person (their DID) or a service account. It is not a wallet address:
two principals may link the same Ethereum key, and the chain cannot tell them
apart.

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

One principle first, because it cuts across several rows: **for a control that
blocks someone — a ban, a sanctions entry — the data class does not decide the
approval mode, the situation does.** A curated list or a planned offboarding
can be reviewed, because a second person can check the basis. An incident
cannot wait for one. Both modes are legitimate and an organisation should be
able to choose. The design consequence is the same either way: a class that
supports both needs provenance on its rows, so re-applying a reviewed document
never undoes what an operator did immediately. Sanctions already carry that
field; bans do not.

| Class | Why it is not a document |
|---|---|
| Accounts | created at login; the identity provider decides who exists, not us |
| Memberships | what is reviewed is the **rule** that produces them, not the row: for directory auto-provision that rule is the tenant mapping in the platform document. The membership row is an instance of it, written by three writers at per-person cadence. (The ZK credential path is meant to rest on the issuer's process, but today it acts on claims the proof never covers — RD-1291) |
| Address links | the link is the user's own signature; in a document an author would be asserting someone else's address and authorising its transactions |
| Bans on a principal | an incident ban must take effect before anyone can review it. A *planned* deactivation could be reviewed, but `users.banned` has no provenance field today, so a re-applied document would lift an incident ban — see the decision below |
| KYC | set by the credential the user logged in with |
| Live exchange rates | a feed: rates land in `system_token_prices` on a timer and are resolved at check time; the document only says which feed a token uses |
| Sanctions list | operational **today**, but this depends on who produces it: a list the customer curates from OFAC designations is a decision and belongs in a document; a vendor feed is not. `sanctioned_addresses` already records `source`, so both can coexist — see the decision below |
| Deployment records | an observation: the receipt names the signing address, and two principals may share one. Only OPS knows which of them submitted the transaction, because the submission carried its authenticated identity |
| Disclosure | every step is the other organisation's answer |
| Secrets (group RPC credential) | must never appear in a text that is diffed, reviewed and exported |
| Caches, sessions, permission results | recomputed or re-issued; never a source |

The rule behind the table: **anything that makes a decision must be the document
and nothing else** — that is what closing thirty-two endpoints achieved. What
stays an operation is written by *events*: a login, a directory, a finalized
receipt, a price feed. Making those documents too would either put an approval
inside the login path or have machines self-activate revisions, which removes
the review and keeps the conflict, since two documents declaring a complete
state overwrite each other exactly as a document overwrites a row. Three places
still break the rule and are on the list below: the explorer's ABI writer, the
deployment auto-grant, and `refresh-codehash`.

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

**Where each piece physically sits.** The document text is
`configuration_revisions.source` in the `privacy_proxy` database, with its
`digest` in the column beside it; a trigger forbids changing either after the
row is created. What the server derives from that text — for execution rules,
the generated contract, its bytecode and hashes — goes into
`compiled_artifact`, another column of the same row. Nothing derived is ever
written back into the document text, and nothing is ever pushed back to Git.
The reviewed text and the derived evidence sit side by side and are
re-checked against each other at activation.

**A document can pin an observed value, but something must produce it.** This
is the real limit of "put everything in the configuration", and we already have
it in three places. A rule pins `abiDigest`, the sha256 of the exact registered
ABI text — and no endpoint returns that digest, so the author computes it by
hand and gets "re-derive the policy against the current ABI" when it is wrong.
A platform entry pins `codehash`, and the endpoint that computed it is now
closed by the stream guard (below). By contrast `legacyRestrictionDigest` is
done correctly: the context hands the author the value to paste
(`migration.legacyRestriction.policyDigest`).

The rule to follow when moving anything else into a document: **moving a field
into a document does not remove the observation, it moves the duty to the
author.** If the API does not publish the observed value, configuration-first
turns into hand-computed hashes and silent mismatches.

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

**1. Git as the authoring home, and the file layout.** Recommended above: the
text in the customer's Git, pushed in by CI, one file per
`(organisation, stream)`.

**2. Does OPS keep a copy of the applied text?** Assumed yes. It is the only
way the operator can answer "what was in force at T" without the customer's
repository, and the only way projections can be rebuilt from history. Saying no
is a data-sovereignty choice with those two consequences.

**3. Organisations into the platform document.** Decided in principle; needs
the deletion semantics and last-administrator protection.

**4. One endpoint writes a dead column in another product's database.**

`POST /api/v1/explorer/addresses/{address}/abi` lives in OPS and runs
`UPDATE contracts SET abi` against the **indexer's** database — OPS connects to
it read-only for explorer pages, and this is the single place where it writes
there.

That column is used by nobody. The indexer never reads or writes it: its own
interface says so ("NOT INCLUDED here and never served by the indexer: ABI,
source code, verification status… privacy mode does not expose contract
verification"), and there is no call site for its `UpdateContractABI`. The
standalone explorer does have source verification, but it keeps it in its own
table in its own database, and those routes are compiled out of the privacy
build.

Meanwhile the ABI that decides anything is ours:
`privacy_proxy.contracts.abi`, owned by the `contract-registry` document and
read by the policy compiler, by log redaction and by the admin screens.

So an operator who uploads an ABI through that endpoint changes nothing at all
— not access, not what the explorer shows — while the call is named as if it
registered the contract's ABI. Nothing in the product calls it: not the
frontend, not the end-to-end tests, only the generated SDK types list it.

Remove it. If verified ABIs for display are wanted later, that is the
standalone explorer's own feature in its own database, and a properly designed
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

**6. Should a curated sanctions list be a document?** It depends on who
produces it. A list the customer's compliance team maintains from OFAC
designations is a decision, and Git review fits it; a vendor feed is not, and a
revision per update would be theatre. Both can coexist —
`sanctioned_addresses` already records `source` — with two caveats: a document
is capped at 1 MiB, about ten thousand addresses with reasons, and
`users.banned` has no provenance field, so reviewed deactivations cannot be
separated from incident bans until it does.
