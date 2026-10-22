-- WHAT: additive source-of-truth revision streams for typed configuration.
-- WHY: reviewed desired state, its authoring base and dependencies must be
-- retained independently of the projected groups/contracts/configuration rows.
-- AFFECTED ROWS: none. Legacy execution revisions remain authoritative until
-- their explicit import/transition guard and execution projector are enabled.
-- AUTHORITATIVE RECORD: source/digest/actors in these immutable revision rows;
-- projection activation uses the runtime RBAC hash chain in the same transaction.
-- This migration does not write any hash-chained audit table.
-- EXPAND-ONLY / ROLE SEPARATION: new table/indexes and runtime grants only.
-- Actor IDs are retained as immutable references even after user deletion;
-- runtime submission/activation verifies current user existence and authority.
-- Detection: SELECT scope_kind, org_id, kind, revision, digest
-- FROM configuration_revisions WHERE status = 'active';

CREATE TABLE configuration_revisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('organization', 'platform')),
    org_id UUID REFERENCES organizations(id),
    kind TEXT NOT NULL CHECK (kind IN ('groups','contract-registry','compliance','approvers','execution-rules','platform')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    base_revision BIGINT NOT NULL CHECK (base_revision >= 0 AND base_revision < revision),
    source TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    dependencies JSONB NOT NULL CHECK (jsonb_typeof(dependencies) = 'object'),
    compiled_artifact JSONB,
    status TEXT NOT NULL CHECK (status IN ('draft','active','superseded','withdrawn')),
    created_by UUID NOT NULL,
    created_principal_kind TEXT NOT NULL DEFAULT '' CHECK(created_principal_kind IN ('','human','service')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_by UUID,
    activated_at TIMESTAMPTZ,
    CHECK ((scope_kind = 'organization' AND org_id IS NOT NULL AND kind <> 'platform') OR
           (scope_kind = 'platform' AND org_id IS NULL AND kind = 'platform')),
    CHECK (status NOT IN ('active','superseded') OR
           (activated_by IS NOT NULL AND activated_at IS NOT NULL))
);
CREATE UNIQUE INDEX configuration_revision_sequence ON configuration_revisions
    (scope_kind, COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, revision);
CREATE UNIQUE INDEX configuration_revision_active ON configuration_revisions
    (scope_kind, COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), kind) WHERE status = 'active';

CREATE FUNCTION configuration_revision_preserve_source() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.scope_kind,NEW.org_id,NEW.kind,NEW.revision,NEW.base_revision,NEW.source,NEW.digest,NEW.dependencies,NEW.compiled_artifact,NEW.created_by,NEW.created_principal_kind,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.scope_kind,OLD.org_id,OLD.kind,OLD.revision,OLD.base_revision,OLD.source,OLD.digest,OLD.dependencies,OLD.compiled_artifact,OLD.created_by,OLD.created_principal_kind,OLD.created_at)
    THEN RAISE EXCEPTION 'configuration revision source is immutable'; END IF;
    IF OLD.activated_at IS NOT NULL AND
       ROW(NEW.activated_by,NEW.activated_at) IS DISTINCT FROM ROW(OLD.activated_by,OLD.activated_at)
    THEN RAISE EXCEPTION 'configuration activation evidence is immutable'; END IF;
    IF NOT ((NEW.status = OLD.status) OR
            (OLD.status = 'draft' AND NEW.status IN ('active','withdrawn')) OR
            (OLD.status = 'active' AND NEW.status = 'superseded'))
    THEN RAISE EXCEPTION 'invalid configuration revision transition'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER configuration_revision_preserve_source BEFORE UPDATE ON configuration_revisions
    FOR EACH ROW EXECUTE FUNCTION configuration_revision_preserve_source();

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        GRANT SELECT, INSERT, UPDATE ON configuration_revisions TO privacy_proxy_app;
    END IF;
END $$;

---- create above / drop below ----

-- Forward-only: revision and approval evidence must not be removed.
