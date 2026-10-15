-- WHAT: retain the complete per-group compiler output on an execution revision.
-- WHY: one organization document is reviewed and activated atomically, while
-- each group's bytecode must fit independently within the runtime size limit.
-- AFFECTED ROWS: no policies are rebuilt or changed. NULL identifies an existing
-- approved organization-wide artifact. New grouped projections store the whole
-- set, including every digest, in the same transaction as activation and audit.
-- AUTHORITATIVE RECORD: immutable configuration revision, reviewed artifact set,
-- actor-attributed activation audit, this migration and tern schema_version.
-- EXPAND-ONLY / ROLE SEPARATION: additive column; existing table grants and the
-- configuration projection writer guard apply. No audit-table writes here.
-- Detection: SELECT org_id,revision FROM execution_policy_revisions
-- WHERE status='active' AND artifact_set IS NULL;

ALTER TABLE execution_policy_revisions ADD COLUMN artifact_set JSONB
    CHECK (artifact_set IS NULL OR jsonb_typeof(artifact_set) = 'object');

---- create above / drop below ----

-- Forward-only: preserve approved artifact evidence.
