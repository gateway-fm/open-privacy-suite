-- Monotonic generation counter guarding permission-cache publication (RD-1267).
--
-- WHAT: add a single-row table rbac_cache_generation holding one BIGINT that
-- every permission-cache invalidation increments, inside the same transaction
-- as the invalidating DELETE.
--
-- WHY (RD-1267): effective_permissions_cache is written by an unconditional
-- upsert at the end of a permission compute, and invalidated by a DELETE that
-- commits with the mutation that caused it. If a mutation (grant revoked,
-- membership expired, user banned) commits *while* a compute is in flight, the
-- DELETE finds nothing to remove — nothing is cached yet — and the compute
-- then publishes the pre-mutation permissions, which serve from cache for the
-- full TTL. That is a fail-open window: a revoked grant stays usable.
--
-- The guard cannot live in process memory. Invalidation is a DELETE issued
-- from inside DB transactions (internal/db tx helpers, admin_rbac_* handlers)
-- that never call through the resolver, and the cache table is shared by every
-- replica, so an in-process counter would be blind to the dominant
-- invalidation path even in a single process. Putting the counter in the
-- database, bumped by the invalidating transaction itself, makes the guard
-- correct regardless of which code path or which replica invalidated.
--
-- HOW IT IS USED: the resolver reads the generation before computing and
-- publishes only if it is unchanged; the publishing statement takes FOR SHARE
-- on this row, so it serializes against an in-flight invalidation's UPDATE
-- rather than racing it. A moved generation discards the publication — the
-- caller still receives the permissions it computed, and the next request
-- recomputes from fresh state. The failure direction is always "discard and
-- recompute", never "serve stale".
--
-- AFFECTED: one new row, seeded at generation = 1. No existing rows are
-- touched, and no cached entry changes meaning. Detection query for anyone
-- verifying the seed landed:
--
--   SELECT count(*) FROM rbac_cache_generation WHERE id = 1;  -- expect 1
--
-- AUTHORITATIVE RECORD: this migration file (git) + PR review + tern's
-- schema_version applied-at timestamp. Nothing is written to rbac_audit_log
-- from a migration — that table is hash-chained, runtime and actor-attributed,
-- and a hand-built INSERT would trip the integrity verifier.
--
-- GRANTS: the app role must be able to read the counter, bump it on
-- invalidation, and lock it FOR SHARE while publishing — so SELECT + UPDATE.
-- No INSERT/DELETE: the single row is created here and must never be removed
-- or duplicated (a missing row would make every publish fail closed, which is
-- safe but would silently disable caching).
--
-- EXPAND-ONLY: additive (CREATE TABLE + INSERT of one seed row). Not a
-- hash-chained table; no chain considerations. Role separation unaffected —
-- this is a main-DB operational table, not an audit table.

CREATE TABLE IF NOT EXISTS rbac_cache_generation (
    -- Single-row table: the CHECK pins the id so a second row cannot be
    -- inserted by mistake, which would silently split the counter.
    id         INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    generation BIGINT  NOT NULL DEFAULT 1
);

INSERT INTO rbac_cache_generation (id, generation)
VALUES (1, 1)
ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        GRANT SELECT, UPDATE ON rbac_cache_generation TO privacy_proxy_app;
    END IF;
END
$$;

---- create above / drop below ----

DROP TABLE IF EXISTS rbac_cache_generation;
