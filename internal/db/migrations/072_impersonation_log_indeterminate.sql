-- 072_impersonation_log_indeterminate.sql
-- PR #466 (cross-org authorization oracle, dry-run indeterminate): admin
-- dry-run can now answer decision=indeterminate when nested execution reaches
-- a contract owned by another organization.
--
-- ── WHAT THIS MIGRATION DOES ─────────────────────────────────────────────────
--   Adds impersonation_log.response_decision, the wire outcome of a dry-run
--   when it differs from the coarse allow/deny/error bucket in `decision`, and
--   a CHECK that limits it to allow/deny/error/indeterminate.
--
-- ── WHAT IT DELIBERATELY DOES NOT DO ─────────────────────────────────────────
--   It does not change impersonation_decision_chk or rewrite existing rows:
--   `decision` keeps its legacy allow/deny/error values. Existing rows keep a
--   NULL response_decision, which means "same as decision". No row needs a
--   manual fix.
--
-- ── AUTHORITATIVE RECORD / AUDIT ─────────────────────────────────────────────
--   Schema-only change; no security-relevant rows are rewritten and nothing is
--   written to rbac_audit_log. The record of this change is this file (git
--   history) + the PR review + tern's schema_version table.
--
-- ── ROLE-SEPARATION (RD-858) CHECK ───────────────────────────────────────────
--   No new table is created here, so no privacy_proxy_app GRANT block is
--   required (see migration 058's new-table checklist).
--
-- ── EXPAND-ONLY ──────────────────────────────────────────────────────────────
--   ADD COLUMN and ADD CONSTRAINT are additive. The DOWN section is for
--   development only.

ALTER TABLE impersonation_log
    ADD COLUMN IF NOT EXISTS response_decision TEXT;

ALTER TABLE impersonation_log
    ADD CONSTRAINT impersonation_response_decision_chk
    CHECK (
        response_decision IS NULL
        OR response_decision IN ('allow', 'deny', 'error', 'indeterminate')
    );

---- create above / drop below ----

ALTER TABLE impersonation_log DROP CONSTRAINT IF EXISTS impersonation_response_decision_chk;
ALTER TABLE impersonation_log DROP COLUMN IF EXISTS response_decision;
