# Open Privacy Suite - Project Conventions

## Database

### PostgreSQL Access
- Use **pgx v5** (`github.com/jackc/pgx/v5`) for PostgreSQL connections
- Use `database/sql` with pgx stdlib driver for standard SQL interface
- Connection pooling handled by `database/sql`

### Migrations with Tern
- Use **tern v2** (`github.com/jackc/tern/v2`) for database migrations
- Migrations stored in `internal/db/migrations/*.sql`
- Embedded via Go embed in `internal/db/migrations/migrations.go`

#### Creating New Migrations
```bash
make db-new-migration name=add_user_preferences
```

#### Running Migrations
```bash
make db-migrate
```

### Expand-Only Migration Policy

**Production migrations must be additive only (expand-only):**

- `CREATE TABLE`, `ADD COLUMN`, `CREATE INDEX`, `ALTER TABLE ... ADD CONSTRAINT` - allowed
- `DROP TABLE`, `DROP COLUMN`, `DROP INDEX`, `ALTER TABLE ... DROP CONSTRAINT` - never in production

**DOWN migrations** are optional (development only). If a migration needs undoing in production, create a new forward migration.

## Testing

```bash
make test-unit   # Go unit tests
make e2e         # End-to-end tests
```

## Code Style

- Go: idiomatic, explicit error handling, table-driven tests
- Follow `gofmt` for formatting

## Running Services

See README.md for full documentation. Quick reference:

```bash
# Start privacy-proxy
docker-compose up -d

# Start explorer (privacy-proxy must be running first)
docker-compose -f ../explorer/docker-compose.privacy-proxy.yml up -d
```

**Note:** For network access from other devices, see `DEV.local.md` (gitignored) for machine-specific setup.

## Security Review

Every PR must include a security review before merging if it touches any of:

- **Auth / RBAC** — JWT handling, claims, permissions, group access
- **Visibility / redaction** — `GetBatchVisibility`, `RedactTransactions`, `RedactLogs`, event filtering
- **New or changed API endpoints** — any new route, changed parameters, changed response shape
- **Disclosure / grants** — disclosure requests, grants, logVisibleTo, shared logs
- **Explorer API** — any endpoint that returns chain data filtered by privacy rules
- **Cross-org isolation** — contract ownership, org context, default claims

The review must check for:
1. **Data leakage** — does the response expose addresses, DIDs, org IDs, or counts that the viewer shouldn't see?
2. **Error message exposure** — are raw DB/internal errors returned to the client? (must be opaque)
3. **Rate limiting** — is the endpoint behind rate-limiting middleware?
4. **Cross-org isolation** — can a user in org A access data from org B?
5. **Fail-closed** — does a missing/invalid token, missing DB row, or query error result in denial (not accidental access)?
6. **Input validation** — are user-supplied params (addresses, hex values, DIDs) validated before use in queries?

## Documentation Site

The docs site lives in `site/` (Next.js + MDX). When changing auth, RBAC, security, compliance, or other user-facing logic, update the corresponding docs page in `site/src/app/docs/`. Docs should be updated in the same PR as the code change.

### Docs-only changes

For PRs that only touch `site/` (no Go or frontend code), use `--no-verify` on `git push` to skip the pre-push test suite. The tests don't cover docs and add unnecessary wait time.

### What belongs in user-facing docs

The docs site is for **operators deploying the product**. Document:
- What to configure (env vars, settings)
- What behavior to expect (features, access control rules)
- How to deploy (production requirements)

Do NOT document internal implementation details:
- Algorithm internals (encryption ciphers, circuit breaker cooldown values, semaphore design)
- Prometheus metric names (those are for the monitoring/infra team, not docs readers)
- Code-level patterns (how the resolver caches, how forwarding works internally)

Keep it operator-focused: "Set X to enable Y." Not "X uses AES-256-GCM with a 12-byte nonce to encrypt Y before writing to the database."
