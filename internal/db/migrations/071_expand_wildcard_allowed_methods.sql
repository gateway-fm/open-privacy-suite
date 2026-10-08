-- 071_expand_wildcard_allowed_methods.sql
-- RD-1311: rewrite group_access.allowed_methods rows that still hold a literal
-- "*" or a "prefix*" glob into the explicit catalog methods they grant.
--
-- ── WHY ──────────────────────────────────────────────────────────────────────
--   Align stored method permissions with the explicit RPC catalog (RD-1311).
--   Runtime permission checks and this rewrite use concrete method names.
--   Operators must configure and grant extra methods by exact name.
--
-- ── WHAT THIS MIGRATION DOES ─────────────────────────────────────────────────
--   1. For every group_access row with an entry containing '*':
--        - entries without '*' are kept unchanged;
--        - a bare "*" becomes the built-in "*" expansion listed in `catalog`
--          below (a point-in-time snapshot of rbac.AllAllowedMethods without
--          operator aliases: ReadMethods ∪ WriteMethods ∪ TraceMethods minus
--          globally blocked methods, which include eth_signTypedData*);
--        - every other entry containing '*' ("linea_*", "eth_get*", ...) is
--          dropped. A "<prefix>*" glob granted methods only through an
--          operator wildcard namespace registered with that exact prefix, and
--          those only ever covered chain namespaces the catalog does not
--          model. Expanding a glob by prefix into catalog methods would grant
--          methods it never granted, so its concrete catalog expansion is
--          empty;
--        - the result is deduplicated and sorted (byte order).
--      The anonymous system group (00000000-0000-0000-0000-000000000002) is the
--      exception: its '*' entries are dropped WITHOUT expansion. The anonymous
--      path never honored "*" (it compares method names literally), so
--      expanding it would widen unauthenticated access.
--   2. Deletes effective_permissions_cache rows that still carry a '*' entry
--      and bumps rbac_cache_generation, the RD-1267 invalidation protocol, so
--      no cached permission derived from a pre-migration row survives.
--
-- ── AFFECTED ROWS / OPERATOR FOLLOW-UP ───────────────────────────────────────
--   Groups that held "*" keep every built-in method but lose implicit access to
--   operator-configured extra methods (aliases such as linea_estimateGas) and
--   to the exact-name-only catalog methods eth_getProof, eth_createAccessList,
--   eth_getBlockReceipts. Groups that held a "linea_*"-style glob lose the
--   methods the glob admitted. Re-grant any such method explicitly.
--   Migrations run automatically at startup, so the pre-upgrade query below
--   belongs in the upgrade runbook (release notes).
--   Detection query (run BEFORE upgrading to list the rows this migration
--   rewrites; after upgrading it must return zero rows):
--     SELECT g.org_id, g.id, g.slug, ga.allowed_methods
--     FROM group_access ga
--     JOIN groups g ON g.id = ga.group_id
--     WHERE EXISTS (SELECT 1 FROM unnest(ga.allowed_methods) AS e
--                   WHERE strpos(e, '*') > 0);
--   A row whose only entries were globs ends up empty: its members can call
--   nothing until an admin grants methods (fail-closed, as migration 060 did
--   for empty org-admin groups). Post-upgrade detection query:
--     SELECT g.org_id, g.id, g.slug, g.is_org_admin
--     FROM group_access ga
--     JOIN groups g ON g.id = ga.group_id
--     WHERE array_length(ga.allowed_methods, 1) IS NULL;
--   Rows without any '*' entry are NOT touched. Explicit names the proxy no
--   longer forwards (unknown methods) stay in place and are refused at request
--   time; the admin UI drops them (with a notice) and the admin API rejects
--   them on the next save of that group.
--
-- ── AUTHORITATIVE RECORD / AUDIT ─────────────────────────────────────────────
--   This migration rewrites security-relevant rows. Per the audit model
--   (site/src/app/docs/security/audit-integrity), rbac_audit_log is the runtime,
--   actor-attributed, hash-chained trail and is deliberately NOT written from
--   migrations: a SQL INSERT with a wrong/absent entry_hash would trip the
--   integrity verifier's tamper alarm. The authoritative change-management
--   record for this rewrite is THIS file (git history) + the PR (RD-1311, code
--   review) + tern's schema_version table (applied-at timestamp); each
--   rewritten row also gets updated_at = NOW().
--
-- ── ROLE-SEPARATION (RD-858) CHECK ───────────────────────────────────────────
--   No new table is created here, so no privacy_proxy_app GRANT block is
--   required (see migration 058's new-table checklist). Migrations run as
--   privacy_proxy_admin.
--
-- ── EXPAND-ONLY ──────────────────────────────────────────────────────────────
--   Data rewrite only; no DDL, nothing dropped. Forward-only: the prior "*" /
--   glob entries are not restored by the down section.
--
-- ── MIGRATION NUMBER ─────────────────────────────────────────────────────────
--   tern requires contiguous numbers and derives versions from sorted order.
--   Open PR #466 (071_policy_check_log) and other in-flight branches also add a
--   071 migration; whichever merges later must rebase and renumber to the next
--   free contiguous number (see the note in 070_rbac_cache_generation.sql).

WITH catalog(method) AS (
    VALUES
        ('debug_traceCall'),
        ('debug_traceTransaction'),
        ('eth_accounts'),
        ('eth_blockNumber'),
        ('eth_call'),
        ('eth_chainId'),
        ('eth_estimateGas'),
        ('eth_feeHistory'),
        ('eth_gasPrice'),
        ('eth_getBalance'),
        ('eth_getBlockByHash'),
        ('eth_getBlockByNumber'),
        ('eth_getBlockTransactionCountByHash'),
        ('eth_getBlockTransactionCountByNumber'),
        ('eth_getCode'),
        ('eth_getLogs'),
        ('eth_getStorageAt'),
        ('eth_getTransactionByBlockHashAndIndex'),
        ('eth_getTransactionByBlockNumberAndIndex'),
        ('eth_getTransactionByHash'),
        ('eth_getTransactionCount'),
        ('eth_getTransactionReceipt'),
        ('eth_maxPriorityFeePerGas'),
        ('eth_sendRawTransaction'),
        ('eth_sendTransaction'),
        ('eth_syncing'),
        ('net_listening'),
        ('net_peerCount'),
        ('net_version'),
        ('web3_clientVersion'),
        ('web3_sha3')
),
rewritten AS (
    SELECT ga.id,
           ARRAY(
               SELECT s.m
               FROM (
                   -- entries without '*' are kept
                   SELECT e AS m
                   FROM unnest(ga.allowed_methods) AS e
                   WHERE strpos(e, '*') = 0
                   UNION
                   -- a bare "*" → the snapshot (never for the anonymous group)
                   SELECT c.method
                   FROM catalog AS c
                   WHERE '*' = ANY (ga.allowed_methods)
                     AND ga.group_id <> '00000000-0000-0000-0000-000000000002'
               ) AS s
               ORDER BY s.m COLLATE "C"
           ) AS methods
    FROM group_access AS ga
    WHERE EXISTS (SELECT 1 FROM unnest(ga.allowed_methods) AS e WHERE strpos(e, '*') > 0)
)
UPDATE group_access AS ga
SET allowed_methods = r.methods,
    updated_at      = NOW()
FROM rewritten AS r
WHERE ga.id = r.id;

DELETE FROM effective_permissions_cache
WHERE EXISTS (SELECT 1 FROM unnest(allowed_methods) AS e WHERE strpos(e, '*') > 0);

UPDATE rbac_cache_generation SET generation = generation + 1 WHERE id = 1;

---- create above / drop below ----

-- Forward-only data rewrite: nothing to undo (see EXPAND-ONLY above).
