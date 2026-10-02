-- RD-872 follow-up: dry-run can return decision=indeterminate when nested
-- execution reaches a foreign organization. Expand-only: keep the legacy
-- decision constraint and record the wire outcome in response_decision when
-- it differs from the coarse allow/deny/error bucket.

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
