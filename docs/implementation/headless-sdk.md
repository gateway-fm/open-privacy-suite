# Headless OPS SDK

The TypeScript SDK in `sdk/` uses the same named-principal REST and JSON-RPC
interfaces as the dashboard. MCP is not required. It has no runtime dependency;
Node 22+ supplies `fetch`. The checked-in component and operation types are
generated from the repository's OpenAPI 3.1 artifact.

```sh
cd sdk
npm ci
npm test
```

After `make api-spec`, run `npm run generate` in `sdk/`. `npm run check:generated`
fails on drift. The generator retains required/optional properties, references,
arrays, enums, unions, intersections and typed dictionaries; unconstrained
OpenAPI objects remain `unknown` dictionaries. It does not infer stricter types
than the server specification. Exact authored configuration text has a dedicated
submission helper so duplicate keys and malformed source reach the strict
server parser intact.

## Named service workflow

First provision the service principal through the configured Azure tenant and
grant its OPS organization roles/methods. Exchange an Azure client-credentials
access token with `loginServicePrincipal`, or initialize a client with its OPS
access/refresh session. Tokens stay in memory; the SDK has no operator-token
fallback, browser cookie session or token logging. Use HTTPS outside local tests.
Refresh is explicit and concurrent refresh calls share one rotation. A failed
mutation is never automatically retried. Session changes and newer login
attempts invalidate pending authentication responses, so a slow earlier response
cannot switch the client back to an older principal.

```sh
export OPS_URL=http://localhost:8080
export OPS_ORG_ID=<organization-uuid>
export OPS_AZURE_ACCESS_TOKEN=<provider-access-token>
node examples/operate.mjs readiness
node examples/prepare.mjs > context.json
```

Copy the complete `source` object from context into a new JSON file and edit it.
Context includes current source, catalogs, viewer eligibility and migration
diagnostics. Omission is not a deletion request; managed resources require
explicit deletions. Set `OPS_CONFIGURATION_KIND` to `groups`,
`contract-registry`, `execution-rules`, `compliance`, `approvers` or `platform`.
Platform documents require separately configured named human platform authority;
that authority does not confer tenant access.

```sh
node examples/prepare.mjs execution-rules.json > review.json
```

`OPS_COACTIVATE` supplies comma-separated sibling revision IDs. Declare their
digests in source dependencies before submitting. Draft compilation retains the
immutable artifact, review uses the full projected catalog, and activation
rechecks the current base, authors, independent approver and exact bundle.
Legacy restriction migration additionally requires `legacyRestrictionDigest`;
ordinary proxy relationships need reviewed `proxyPairs` or explicit pair rules.

Set `OPS_PREVIEW_FILE` to a JSON request with `method` and `params` to preview the
new execution candidate. Supported methods are `eth_call`, `eth_estimateGas`
and `debug_traceCall`. Supply a linked `from`; it may be omitted only when the
principal has exactly one active linked address. Current active permissions
remain mandatory and a candidate cannot authorize the application call itself.

Ordinary previews cannot execute candidate live state/account reads. A policy
with `recordParty` returns HTTP 403 with code
`candidate_state_reads_require_diagnostics`. An audited full human organization
administrator can explicitly use `preview(..., {dryRun:true,...})` to diagnose a
current member under mandatory organization isolation. A service cannot promote
itself by setting this field. An explicitly granted `debug_traceCall` method
exposes application execution internals; private policy frames remain hidden.

## Approval is a separate operation

The preparation example stops at the review boundary. Run activation with a
different eligible human's `OPS_ACCESS_TOKEN`, or supply a signed manifest from
an independently configured CI approval system:

When switching credential sources, unset `OPS_AZURE_ACCESS_TOKEN` before setting
`OPS_ACCESS_TOKEN`. The examples reject ambiguous simultaneous credentials.

```sh
node examples/activate.mjs <revision-id>
node examples/activate.mjs <revision-id> signed-ci-approval.json
```

The SDK first reviews and captures the exact candidate IDs and document digests.
CI `candidateDigests` is keyed by configuration kind, not revision ID. The SDK
checks the captured digests before sending; the server independently verifies
scope, trusted issuer/key, repository/ref/commit, service subject, independent
human reviewers, expiry and single-use nonce. The SDK does not mint approval
claims or hold the external approval signing key. CI cannot replace approver
trust policy or platform configuration. Changed/stale bases require a new draft
and review, never silent source rewriting.

## Operations, RPC and status

Generated `client.request(operation, input)` provides typed access to the full
OpenAPI routes, including operational memberships, bans, linking and disclosure.
The convenience examples include onboarding via the existing by-DID operation:

```sh
node examples/operate.mjs onboard membership.json
node examples/operate.mjs rpc call.json
node examples/operate.mjs submit signed-transaction.txt
node examples/operate.mjs status <transaction-hash>
```

`membership.json` follows the generated `MembershipByDIDRequest` schema.
`call.json` contains `method`, `params`, and optional `visibleTo`. Deployment and
ordinary transactions must be signed locally and sent with
`eth_sendRawTransaction`; node mode does not support unlocked-account
`eth_sendTransaction`. Shared signers retain the current named principal's
identity and cannot read each other's transaction status.

Acceptance is not inclusion or finality. `waitForFinality` waits for an
`included` or `reverted` outcome with `execution.finalized` and completed OPS
reconciliation. Reverts are returned as finalized failed outcomes for the caller
to handle. Pending, denied and expired tickets remain nonterminal because an
already started execution may settle later. The helper has a bounded timeout and
accepts an `AbortSignal`; HTTP/authentication errors are returned to the caller.
Permanent ownership, deployment grants and visibility records are reconciled
only from finalized node evidence. A status response never exposes raw
transactions, execution identity envelopes or visibility recipients.

## Verification

Tests were added before the client; the first run failed on the missing client
module. The initial seven behavior tests passed, then a CI regression exposed
incorrect digest keys (revision IDs instead of configuration kinds). The fix
passes the CI regression. Independent review then identified stale login
responses replacing newer sessions. Three failing race tests reproduced slow
login versus `setSession`, out-of-order logins, and refresh superseded by a new
login. A session epoch now rejects those responses; all eleven tests pass.
Tests cover exact source, named credentials, service
exchange, refresh serialization, no mutation retries, captured review bundles,
external CI digest binding, explicit diagnostics, RPC errors, finality polling
and encoded route parameters. Compile-time negative cases reject unknown paths,
missing path parameters and unsupported stream names. Live OPS stack behavior is
covered by the separate integration harness; these SDK tests do not claim a
live identity-provider login.

The SDK also passed five checks against isolated stack
`ops-reth-6fe399425e`: generated-route named human mockauth login and real refresh,
live readiness/current execution context, an explicit audited human candidate
diagnostic on Reth, revoked-rule RPC denial, and finalized own status with a
shared-signer peer denied status access. The reproducible smoke command is:

```sh
node test/stack-smoke.mjs <OPS_ORIGIN> <stack/acceptance.json> <stack/sdk-acceptance.json>
```

This command uses that harness's development mockauth identities. It never
synthesizes production credentials and does not claim an Azure provider test.
The result file contains only stack/organization identifiers and check names.
