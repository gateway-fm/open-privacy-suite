# Evaluating the Open Privacy Suite — Start Here

This is the guided tour for someone seeing the product for the first time.
In ten minutes you'll have a running stack, five identities with different
privacy views, and answers to "so what does it actually do?".

> **Using an AI coding agent?** (Claude Code, Cursor, …) Point it at this
> repository and ask it anything — this file, [`docs/mcp.md`](docs/mcp.md),
> and the docs site are written so agents can answer accurately and drive
> the demo for you. Try: *"Run the quickstart and show me what Bob can see."*

## What is this?

A privacy-preserving gateway that sits between users and a shared EVM
blockchain. It enforces **who may see and do what** — so multiple
organizations (say, two banks and their regulator) can transact on one chain
without seeing each other's business. Plain-language capability summary:
[What It Does](https://gateway-fm.github.io/open-privacy-suite/docs/what-it-does/)
(or `site/src/app/docs/what-it-does/page.mdx` in this repo).

## Five-minute demo

Requirements: Docker (compose v2), make, curl, jq.

```bash
git clone https://github.com/gateway-fm/open-privacy-suite.git
cd open-privacy-suite
make quickstart
```

First run builds the images (a few minutes). At the end you get a seeded
scenario and **ready-to-use tokens printed to your terminal**:

| Persona | Identity (DID) | Role |
|---------|----------------|------|
| Alice | `did:test:alice` | Meridian Bank — payment operations (can deploy) |
| Carol | `did:test:carol` | Meridian Bank — compliance analyst (query methods only, own balance only) |
| Bob   | `did:test:bob`   | Volta Bank — trader (no access to Meridian's contracts) |
| Rita  | `did:test:rita`  | Regulator (sees Alice's activity via an approved disclosure grant) |
| Mia   | `did:test:mia`   | Meridian Bank — org admin (unlocks the admin dashboard, Meridian only) |

The seed deploys a `DEMO` token through the proxy as Alice, pays Carol, sets
up a parameter-level rule ("analysts may query only their *own* balance"),
and records a consented disclosure grant for the regulator — then **verifies
each claim live** and prints ✓/✗ for every step.

## The tour — one question, three answers

The quickstart output contains three copy-paste `curl` commands that ask the
chain the *same question* (a token balance) as three different people:

1. **Carol asks for her own balance** → allowed, returns the value.
2. **Carol asks for Alice's balance** → denied — analysts are restricted to
   `balanceOf(self)` at the function-parameter level.
3. **Bob (the other bank) asks anything about Meridian's contract** →
   denied — cross-org isolation, enforced even for indirect calls through
   intermediary contracts.

Then look at the same data through other lenses:

- **Web UI** — <http://localhost:5173>: the login page lists the demo
  personas as one-click buttons (dev identity picker). Log in as **Mia**
  and follow the **Admin dashboard** button on the user page: as
  Meridian's org admin she can browse the bank's groups, users, contracts,
  grants and disclosure requests — and *only* Meridian's (org admins are
  tenant-scoped; Volta is invisible to her). The other personas are regular
  users (least privilege): they get the user-facing view, e.g. the
  disclosure dashboard at `/disclosure`, no button, and `/admin` denies
  them with a link back to their own dashboard.
  Tenant-independent operator tasks go through the admin API / MCP with
  `X-Admin-Token` (= `ADMIN_API_TOKEN` in `.env.quickstart`).
- **Explorer API** — privacy-filtered per viewer: the same transaction list
  is full for Alice, empty for Bob, and disclosed-by-grant for Rita.
- **Audit trail** — every denial and every disclosed access you just made is
  in the append-only access log (ask the MCP for `access_logs`).

Under the hood everything is standard JSON-RPC plus an
`Authorization: Bearer <JWT>` header. Clients that can set an HTTP header —
`curl`, ethers.js, web3.js, backend SDKs — work unchanged. **Browser wallets
(MetaMask) cannot attach headers**: run a JWT-injecting reverse proxy such as
[`gateway-fm/jwt-injector`](https://github.com/gateway-fm/jwt-injector) and
give the wallet the injector's URL as its RPC endpoint. The injector stamps
the user's JWT onto every request and re-reads its token file whenever the
file changes — but JWTs are short-lived, and keeping that file fresh is your
deployment's job (a refresher that re-mints via the login flow), not the
injector's. In this demo, re-mint persona tokens any time with
`scripts/quickstart.sh --seed-only`.

## Drive it from an AI agent (MCP)

The repo ships an [MCP server](docs/mcp.md) exposing ~94 admin/explorer
tools. Configure once:

```bash
cp .mcp.json.example .mcp.json   # local MCP config (gitignored)
# then fill in the token:
#   PRIVACY_ADMIN_TOKEN = the ADMIN_API_TOKEN value in .env.quickstart
```

Then ask things like:

- *"List the organizations and their groups — who can do what?"*
- *"Using Alice's JWT from `.quickstart-demo.json`, list her transactions in
  the explorer. Now use Bob's JWT — why is his view empty?"*
- *"Use `test_request` with Bob's JWT to read the DemoToken balance and
  explain the denial."*
- *"Using Rita's JWT, list her viewable addresses — where does her access to
  Alice's wallet come from?"*
- *"Show the disclosure grant and its access logs."*

Persona JWTs live in `.quickstart-demo.json` (regenerate any time with
`scripts/quickstart.sh --seed-only`).

## Where things live

| You want | Look at |
|----------|---------|
| Plain-language capabilities & trust model | [docs site → What It Does](https://gateway-fm.github.io/open-privacy-suite/docs/what-it-does/) |
| Full documentation | <https://gateway-fm.github.io/open-privacy-suite/> (source: `site/src/app/docs/`) |
| REST API (149 operations, OpenAPI 3.1) | `GET /openapi.json` on a running proxy, or [interactive reference](https://gateway-fm.github.io/open-privacy-suite/api-reference/) |
| Every registered route | [`API_ENDPOINTS.md`](API_ENDPOINTS.md) |
| Demo internals (what the seed actually does) | `scripts/quickstart-seed.sh` — every API call is plain curl |
| More demo scripts (CREATE3, upgrades, attack scenarios) | [`demo/`](demo/README.md) |
| Redaction semantics (developer-level) | [`REDACTION_SPEC.md`](REDACTION_SPEC.md) |
| Backend code | `internal/` (Go) · admin UI: `frontend/` · MCP: `mcp/` |

## Stack management

```bash
make quickstart          # start / re-seed (idempotent)
make quickstart-down     # stop, keep data
make quickstart-reset    # stop and wipe everything
```

The quickstart runs with **mock authentication** (no real wallet or
ZK-verification needed) and is for evaluation only — production deployments
use ZK-proof credentials (Privado ID), SSO, and a hardened topology; see
[Operator Deployment](https://gateway-fm.github.io/open-privacy-suite/docs/operator-deployment/).

## Common questions

Can Bank B see Bank A's transactions? Can an org admin read a user's wallet
history? What happens if someone bypasses the proxy? — All answered honestly
on [What It Does](https://gateway-fm.github.io/open-privacy-suite/docs/what-it-does/).
If your question isn't there, open a GitHub issue — pre-sales questions are
welcome.
