-- Versioned execution policies and the artifacts built from them (RD-1287).
--
-- WHAT: add execution_policy_revisions, one row per submitted policy document
-- for an organisation, holding the verbatim source, the Solidity generated from
-- it, the compiled runtime bytecode, and the digests and compiler settings that
-- let the pair be rebuilt and compared rather than trusted.
--
-- WHY (RD-1287): an execution policy is a change-management artifact. A person
-- approves a specific document, which produces specific bytecode, which is what
-- later decides whether a transaction may execute. All three have to be stored
-- together and immutably, or "what was approved" and "what is enforced" become
-- two different questions with no way to reconcile them.
--
-- AFFECTED ROWS: none. This migration creates an empty table and changes no
-- existing row. Organisations without a policy simply have no rows here, and
-- absence of a row means this mechanism grants nothing.
--
-- AUTHORITATIVE RECORD: the revision rows themselves. Source, generated source
-- and bytecode are written once at submission and never updated; activation
-- only moves the status and stamps the actor. There is no path that edits an
-- approved document in place, which is what makes the digest meaningful.
--
-- NOTE ON AUDIT: this migration writes nothing to rbac_audit_log or any other
-- hash-chained table. Activation is a runtime, actor-attributed action and is
-- audited there by the handler at the time it happens.
--
-- EXPAND-ONLY: additive. CREATE TABLE plus indexes, no ALTER or DROP of
-- anything that exists.
--
-- ROLE SEPARATION: the app role needs full CRUD on this table. Rows are
-- inserted when a policy is submitted and updated when one is activated or
-- superseded; a draft that was never approved can be deleted by its author.
--
-- DETECTION QUERY — organisations with an active policy and the artifact that
-- is enforced for them:
--
--   SELECT org_id, revision, runtime_digest, activated_at
--     FROM execution_policy_revisions
--    WHERE status = 'active'
--    ORDER BY org_id;

CREATE TABLE IF NOT EXISTS execution_policy_revisions (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id   UUID   NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Monotonic per organisation. A submission states the revision it was
    -- written against, and a stale base is refused rather than merged, so two
    -- administrators cannot silently overwrite each other's policy.
    revision BIGINT NOT NULL,

    -- draft:      submitted and compiled, not approved, enforces nothing.
    -- active:     the policy in force. At most one per organisation.
    -- superseded: was active, replaced by a later revision.
    -- withdrawn:  a draft abandoned without ever being activated.
    status   TEXT   NOT NULL CHECK (status IN ('draft', 'active', 'superseded', 'withdrawn')),

    -- The document exactly as submitted. Kept verbatim so that what a reviewer
    -- read can be shown again, byte for byte, after any later schema change.
    source            TEXT NOT NULL,
    policy_digest     TEXT NOT NULL,

    -- The generated contract and what it compiled to.
    solidity_source   TEXT  NOT NULL,
    solidity_digest   TEXT  NOT NULL,
    runtime_bytecode  BYTEA NOT NULL,
    runtime_digest    TEXT  NOT NULL,

    -- Exact compiler version, optimiser runs and EVM target.
    compiler          JSONB NOT NULL,

    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    activated_at TIMESTAMPTZ,

    UNIQUE (org_id, revision)
);

-- At most one active policy per organisation. Enforced by the database rather
-- than by the handler: two concurrent activations would otherwise both succeed
-- and leave the organisation with two policies and no defined winner.
CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_policy_one_active
    ON execution_policy_revisions (org_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_execution_policy_org_revision
    ON execution_policy_revisions (org_id, revision DESC);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON execution_policy_revisions TO privacy_proxy_app;
    END IF;
END
$$;

---- create above / drop below ----

DROP TABLE IF EXISTS execution_policy_revisions;
