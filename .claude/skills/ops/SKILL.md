---
name: ops
description: Operate an Open Privacy Suite deployment — create organizations and groups, grant RPC access, onboard users by DID, choose between the admin and operator tokens, connect MetaMask through the JWT injector, and drive the admin API from an agent via the bundled MCP server. Use when the user asks how to set up a tenant, why a user cannot call anything, which token to use, how to connect a wallet, or how to configure the MCP server.
---

# Operating Open Privacy Suite

This skill is a **map, not a manual**. The reference documentation is already in
the repo and on the docs site; what follows is the order operations must happen
in, which credential each step needs, and the traps that produce a working-looking
deployment nobody can actually use.

Everything here is behaviour of the code in this repository. When an answer is not
covered below, read the source rather than guessing — the admin handlers live in
`internal/server/` and the access engine in `internal/rbac/`.

## Where the detail lives

| Topic | Read |
|---|---|
| Day-1 runbook, personas, first tenant | `ONBOARDING.md` |
| Full onboarding walkthrough with `curl` | `site/src/app/docs/operator-onboarding/page.mdx` |
| Permission model, claims, group rules | `site/src/app/docs/rbac/page.mdx` |
| Login flows, tokens, denial semantics | `site/src/app/docs/authentication/page.mdx` |
| Environment variables and secrets | `site/src/app/docs/configuration/page.mdx` |
| Why a call was denied | `site/src/app/docs/troubleshooting/page.mdx` |
| Every MCP tool, with arguments | `docs/mcp.md` |

## 1. Standing up a tenant — the order matters

Four steps, in this sequence. Skipping the third is the single most common way a
new tenant ends up unusable.

1. **Create the organization.** It starts with **no groups at all**.
2. **Create a group.** For the tenant's own administrators set `is_org_admin`.
3. **Set that group's access.** This is a separate call and it is *not* optional.
4. **Add members.**

### The trap: an admin group that can call nothing

Creating a group does **not** create its access settings. Until you set them, an
`is_org_admin` group grants every claim on every contract in the org and **zero
callable methods** — so its members authenticate successfully, appear correctly
configured in the dashboard, and every RPC call they make is denied.

This is deliberate fail-closed behaviour: the method allowlist is the source of
truth for method gating even for administrators, so the system refuses to guess a
set of methods rather than over-granting.

Two rules the API enforces when you set access on an `is_org_admin` group:

- `allowed_methods` must be **non-empty** — an empty list is rejected.
- `claims` must be **empty** — org admins receive all claims automatically, so a
  stored value there would be misleading. Sending claims is rejected.

A group cannot be both `is_org_admin` and `is_org_readonly_admin`; that is
rejected by the API and by a database constraint.

### Onboarding a user who has never logged in

Adding a member normally requires a user that already exists. To onboard a DID the
system has never seen, use the by-DID endpoint, which provisions the user and
places them in the group in one call:

```
POST /api/v1/admin/orgs/{org_id}/memberships/by-did
{ "did": "did:...", "group_id": "..." }
```

Note this has no MCP equivalent — the `add_membership` tool needs an existing
`user_id`, so for a brand-new DID use the REST endpoint above, or have the person
log in once first and then find them with `resolve_user`.

## 2. Which token to use

Both tier-1 credentials are sent in the `X-Admin-Token` header; which value you
send decides what you may do.

**Full admin token** (`ADMIN_API_TOKEN`) — unrestricted across the admin plane:
it reads and writes every tenant's configuration through the admin API. Hold it
only inside your own trust boundary. It is not a blanket override, though — the
dry-run endpoint rejects **both** tier-1 tokens, because evaluating a request as
a user means reading tenant data as that user, which neither may do. That needs
a tier-2 org-admin JWT.

**Operator token** (`OPERATOR_API_TOKEN`) — a restricted onboarder. It can run the
whole of section 1: create and delete organizations, create admin-tier groups, set
their access, and add their first members. It **cannot** read or modify tenant
data — regular groups, members, contracts, grants, audit logs and per-org
compliance all return `403`.

**If a third party performs onboarding, give them the operator token.** It does
everything the bootstrap needs while remaining unable to read the tenants it
creates. Handing over the full admin token grants far more than the job requires.

Tenant administrators do not use either. They log in and act with a session JWT,
which is scoped to the organizations they administer.

## 3. Connecting a wallet

Requests carry `Authorization: Bearer <JWT>`. Anything that can set an HTTP header
— `curl`, ethers.js, web3.js, backend SDKs — works unchanged.

**Browser wallets cannot set headers.** MetaMask therefore needs a JWT-injecting
reverse proxy such as [`gateway-fm/jwt-injector`](https://github.com/gateway-fm/jwt-injector)
between it and the proxy: point the wallet's RPC endpoint at the injector, which
stamps the user's token onto every request. JWTs are short-lived, and keeping that
token file fresh is your deployment's responsibility, not the injector's —
`ONBOARDING.md` covers the mechanics.

### The trap: MetaMask still fails for ordinary users

Once the injector is wired correctly, MetaMask can still fail for authenticated
**non-administrator** users, with state reads returning an opaque
`method not found`.

This is intended behaviour, not a misconfiguration. MetaMask issues state reads at
**concrete block numbers** while simulating transactions, and the proxy denies
historical state queries to non-admin users: per-address visibility is evaluated
against *current* ownership, so answering a query at a past block could disclose
state from a time when the contract belonged to a different organization.

- Affected methods: `eth_call`, `eth_getStorageAt`, `eth_getBalance`,
  `eth_getCode`, `eth_getTransactionCount`, `eth_getProof`.
- A query counts as historical when its block parameter is a concrete block number
  or hash. The named tags — `latest`, `pending`, `safe`, `finalized`, `earliest` —
  are not historical and are allowed.
- Organization administrators are exempt.

Denials on the RPC data path are deliberately opaque, so the client is told only
`method not found`; the real reason is in the access log. Check there first when a
call fails for a reason the caller cannot see.

## 4. Driving it from an agent

The repo ships an MCP server exposing the admin and explorer APIs as tools, so an
agent can operate the deployment directly. Copy `.mcp.json.example` to `.mcp.json`
and fill in `PRIVACY_ADMIN_TOKEN` and `PRIVACY_URL`; the proxy must be running.

Tools are grouped by domain: organizations, groups, users and memberships,
contracts and grants, disclosure, explorer reads, compliance, sessions and audit,
and system health. The setup in section 1 maps to `create_org`, `create_group`,
`set_group_access` and `add_membership`.

For diagnosis, three tools answer most questions without reading logs by hand:
`check_access` for whether a specific call would be allowed, `effective_permissions`
for what a user actually has in an organization, and `access_logs` for what was
denied and why. `docs/mcp.md` lists every tool and its arguments.

Destructive tools require an explicit confirmation step before they act.
