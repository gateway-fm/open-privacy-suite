-- WHAT: durable, network-scoped transaction intents and reconciliation state.
-- WHY: retain the named principal independently of shared signers and recover
-- actual node outcomes/deployments after an OPS crash. Saving an intent is not
-- authority to execute; the node verifies current facts on actual execution.
-- AFFECTED ROWS: no existing security rows are rewritten. IDs deliberately have
-- no user/org FK: deleting an identity must not delete evidence or strand a
-- transaction already submitted. Status endpoints still require a live user.
-- AUTHORITATIVE RECORD: immutable intent binding plus canonical node outcome;
-- this migration never writes an application audit chain.
-- EXPAND-ONLY / ROLE SEPARATION: additive operational table and app grants.
CREATE TABLE node_submissions (
    chain_id BIGINT NOT NULL CHECK (chain_id > 0),
    deployment_id TEXT NOT NULL,
    tx_hash TEXT NOT NULL CHECK (tx_hash ~ '^0x[0-9a-f]{64}$'),
    principal_id UUID NOT NULL,
    org_id UUID NOT NULL,
    signer TEXT NOT NULL CHECK (signer ~ '^0x[0-9a-f]{40}$'),
    context_id TEXT NOT NULL,
    raw_transaction TEXT NOT NULL,
    identity_envelope BYTEA NOT NULL,
    sender_did TEXT NOT NULL,
    visible_to TEXT[] NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','accepted','pending','denied','included','reverted','expired')),
    outcome JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    next_check_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reconciled_at TIMESTAMPTZ,
    reconciliation_note TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (chain_id,deployment_id,tx_hash)
);
CREATE INDEX node_submissions_pending ON node_submissions(chain_id,deployment_id,next_check_at) WHERE reconciled_at IS NULL;
CREATE FUNCTION node_submission_preserve_binding() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.chain_id,NEW.deployment_id,NEW.tx_hash,NEW.principal_id,NEW.org_id,NEW.signer,NEW.raw_transaction,NEW.sender_did,NEW.visible_to)
       IS DISTINCT FROM ROW(OLD.chain_id,OLD.deployment_id,OLD.tx_hash,OLD.principal_id,OLD.org_id,OLD.signer,OLD.raw_transaction,OLD.sender_did,OLD.visible_to) THEN
        RAISE EXCEPTION 'node submission binding is immutable' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER node_submission_binding_guard BEFORE UPDATE ON node_submissions
FOR EACH ROW EXECUTE FUNCTION node_submission_preserve_binding();
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='privacy_proxy_app') THEN
        GRANT SELECT,INSERT,UPDATE,DELETE ON node_submissions TO privacy_proxy_app;
    END IF;
END $$;
