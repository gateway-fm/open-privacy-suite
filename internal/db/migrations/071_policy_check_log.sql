-- Audit log for POST /api/v1/admin/policy-check, which answers "would this
-- subject be allowed to make this call?" for a service credential. Separate
-- from access_logs (calls that actually happened) and impersonation_log (which
-- requires the target to be a known org member).
--
-- Schema choices:
--   * subject_did / subject_address / org_id are plain text, not FKs: a check
--     can legitimately deny before any DID or org is resolved, and the audit
--     write must never be blocked by a downstream validity check.
--   * params_hash, not raw params: never persist the checked payload, which
--     could carry private addresses or signed-tx blobs.
--   * reason: sanitized by the handler before insert. AccessCheckResult.Reason
--     is operator-only by contract (internal/rbac/models.go).
--   * caller_auth_method: JWT admins are rejected before reaching this table.

CREATE TABLE policy_check_log (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    caller_auth_method TEXT        NOT NULL,
    subject_did        TEXT,
    subject_address    TEXT,
    org_id             TEXT,
    method             TEXT        NOT NULL,
    params_hash        CHAR(64)    NOT NULL,        -- sha256, hex
    allowed            BOOLEAN     NOT NULL,
    reason             TEXT,
    correlation_id     UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT policy_check_log_caller_auth_method_chk
        CHECK (caller_auth_method IN ('admin_token', 'operator_token'))
);

-- Browse by subject (who was checked, when?)
CREATE INDEX idx_policy_check_log_subject ON policy_check_log (subject_did, created_at DESC);
CREATE INDEX idx_policy_check_log_subject_address ON policy_check_log (subject_address, created_at DESC);
-- Org-scoped queries (an org admin reviewing checks resolved against their org)
CREATE INDEX idx_policy_check_log_org ON policy_check_log (org_id, created_at DESC);
-- Time-ordered browsing / retention sweeps
CREATE INDEX idx_policy_check_log_created_at ON policy_check_log (created_at DESC);

GRANT SELECT, INSERT ON policy_check_log TO privacy_proxy_app;

---- create above / drop below ----

DROP INDEX IF EXISTS idx_policy_check_log_created_at;
DROP INDEX IF EXISTS idx_policy_check_log_org;
DROP INDEX IF EXISTS idx_policy_check_log_subject;
DROP INDEX IF EXISTS idx_policy_check_log_subject_address;
DROP TABLE IF EXISTS policy_check_log;
