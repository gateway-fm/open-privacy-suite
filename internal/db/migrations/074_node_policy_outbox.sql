-- WHAT: a commit-ordered fact change stream for the private execution node.
-- WHY: every relevant write, including background/batch writers, must publish
-- facts in the same transaction. A plain sequence can publish commit order 2,1
-- and make a consumer skip revocation 1. The singleton clock serializes writers.
-- AFFECTED ROWS: existing identity/configuration rows are unchanged; version 1
-- denotes the initial full export. Outbox entries contain only resource keys.
-- AUTHORITATIVE RECORD: Postgres rows remain authoritative, the outbox projects
-- them. No audit-chain table is written by this migration.
-- EXPAND-ONLY / ROLE SEPARATION: new tables/functions/triggers and app grants.
-- Detection: SELECT version, changes FROM node_policy_outbox ORDER BY version;

CREATE TABLE node_policy_clock (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    version BIGINT NOT NULL CHECK (version > 0)
);
INSERT INTO node_policy_clock(singleton, version) VALUES (true, 1);

CREATE TABLE node_policy_outbox (
    version BIGINT PRIMARY KEY CHECK (version > 0),
    transaction_id BIGINT UNIQUE NOT NULL,
    changes JSONB NOT NULL CHECK (jsonb_typeof(changes) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO node_policy_outbox(version,transaction_id,changes)
VALUES (1, txid_current(), '{"full":{"bootstrap":true}}');

CREATE TABLE node_policy_cursors (
    consumer_id TEXT PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0),
    payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION node_policy_mark_dirty(entity TEXT, resource_key TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    batch_version BIGINT;
BEGIN
    IF resource_key IS NULL OR resource_key = '' THEN RETURN; END IF;
    IF entity NOT IN ('principal','group','contract','policy','sanctions') THEN
        RAISE EXCEPTION 'unsupported node policy entity';
    END IF;
    SELECT version INTO batch_version FROM node_policy_outbox
    WHERE transaction_id = txid_current();
    IF batch_version IS NULL THEN
        -- The row lock survives until commit, ordering every later batch after
        -- this one. All further writes in this transaction reuse the batch.
        UPDATE node_policy_clock SET version = version + 1 WHERE singleton
        RETURNING version INTO batch_version;
        INSERT INTO node_policy_outbox(version,transaction_id,changes)
        VALUES (batch_version,txid_current(),'{}');
    END IF;
    UPDATE node_policy_outbox
    SET changes = changes || jsonb_build_object(entity,
        COALESCE(changes->entity,'{}'::jsonb) || jsonb_build_object(resource_key,true))
    WHERE version = batch_version;
END
$$;

CREATE FUNCTION node_policy_capture_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    row_data JSONB;
    entity TEXT := TG_ARGV[0];
    key_column TEXT := TG_ARGV[1];
    principal_id TEXT;
BEGIN
    -- Mark both keys on moves and updates; the exporter reads the final state
    -- from one repeatable-read snapshot, turning removed resources into deletes.
    FOR row_data IN SELECT value FROM jsonb_array_elements(
        CASE TG_OP
            WHEN 'INSERT' THEN jsonb_build_array(to_jsonb(NEW))
            WHEN 'DELETE' THEN jsonb_build_array(to_jsonb(OLD))
            ELSE jsonb_build_array(to_jsonb(OLD),to_jsonb(NEW))
        END)
    LOOP
        IF entity = 'linked-principal' THEN
            FOR principal_id IN SELECT id::text FROM users
                WHERE external_id = row_data->>key_column
            LOOP
                PERFORM node_policy_mark_dirty('principal',principal_id);
            END LOOP;
        ELSIF entity = 'policy' THEN
            IF row_data->>'status' = 'active' THEN
                PERFORM node_policy_mark_dirty(entity,row_data->>key_column);
            END IF;
        ELSE
            PERFORM node_policy_mark_dirty(entity,row_data->>key_column);
        END IF;
    END LOOP;
    RETURN NULL;
END
$$;

CREATE TRIGGER node_policy_users AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('principal','id');
CREATE TRIGGER node_policy_memberships AFTER INSERT OR UPDATE OR DELETE ON user_memberships
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('principal','user_id');
CREATE TRIGGER node_policy_links AFTER INSERT OR UPDATE OR DELETE ON eth_address_links
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('linked-principal','did');
CREATE TRIGGER node_policy_legacy_flags AFTER INSERT OR UPDATE OR DELETE ON access_policies
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('linked-principal','external_id');
CREATE TRIGGER node_policy_groups AFTER INSERT OR UPDATE OR DELETE ON groups
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('group','id');
CREATE TRIGGER node_policy_group_access AFTER INSERT OR UPDATE OR DELETE ON group_access
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('group','group_id');
CREATE TRIGGER node_policy_contract_claims AFTER INSERT OR UPDATE OR DELETE ON contract_grants
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('group','group_id');
CREATE TRIGGER node_policy_contracts AFTER INSERT OR UPDATE OR DELETE ON contracts
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('contract','address');
CREATE TRIGGER node_policy_shared AFTER INSERT OR UPDATE OR DELETE ON shared_infrastructure
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('contract','address');
CREATE TRIGGER node_policy_pending AFTER INSERT OR UPDATE OR DELETE ON preregistered_addresses
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('contract','address');
CREATE TRIGGER node_policy_sanctions AFTER INSERT OR UPDATE OR DELETE ON sanctioned_addresses
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('sanctions','address');
CREATE TRIGGER node_policy_execution AFTER INSERT OR UPDATE OR DELETE ON execution_policy_revisions
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('policy','org_id');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        GRANT SELECT,INSERT,UPDATE,DELETE ON node_policy_outbox,node_policy_cursors TO privacy_proxy_app;
        GRANT SELECT,UPDATE ON node_policy_clock TO privacy_proxy_app;
        GRANT EXECUTE ON FUNCTION node_policy_mark_dirty(TEXT,TEXT),node_policy_capture_change() TO privacy_proxy_app;
    END IF;
END
$$;

---- create above / drop below ----

-- Forward-only: facts and checkpoints must remain reproducible.
