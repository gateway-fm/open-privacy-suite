-- WHAT: record the ACTIVE authoring base separately from the draft sequence.
-- WHY: activation must compare the reviewed base atomically and must not let
-- concurrent sibling drafts silently replace one another.
-- AFFECTED ROWS: existing revisions retain NULL because their active authoring
-- base cannot be reconstructed reliably. Existing active policies remain active;
-- legacy drafts must be exported and resubmitted before activation.
-- Detection query for drafts requiring resubmission:
-- SELECT org_id, id, revision FROM execution_policy_revisions
-- WHERE status = 'draft' AND (base_revision IS NULL OR created_by IS NULL);
-- AUTHORITATIVE RECORD: this file, reviewed Git history and tern schema_version.
-- No hash-chained audit table is written by this migration.
-- EXPAND-ONLY / ROLE SEPARATION: additive column and constraint; existing table
-- grants continue to apply. No new table or privilege is introduced.

ALTER TABLE execution_policy_revisions ADD COLUMN base_revision BIGINT;
ALTER TABLE execution_policy_revisions ADD CONSTRAINT execution_policy_base_nonnegative
    CHECK (base_revision IS NULL OR (base_revision >= 0 AND base_revision < revision));

---- create above / drop below ----

-- Forward-only: revision provenance must not be removed.
