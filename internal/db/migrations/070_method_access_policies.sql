-- RD-1206: method access policies — per-record gating of record-reader eth_calls.
--
-- WHAT: adds one nullable JSONB policy column to `contracts` and two new
--   operational tables:
--     - contract_record_captures : the durable per-record capture store. Rows
--       are (org, contract, record_type, record_key, field, value) — the
--       stakeholders/audience remembered from a writer call, used to gate a
--       later reader call (getPaymentInfo) to the record's parties.
--     - pending_record_captures  : the write-ahead outbox. A send that matches
--       a capture spec enqueues its PRE-DECODED capture payload here; a
--       reconciler promotes it into contract_record_captures ONLY after the
--       tx receipt confirms status==1 (a reverted create must not plant rows).
--
-- WHY: a contract grant authorizes a function all-or-nothing; record-reader
--   methods return record-level private data (payer/payee/amount), so access
--   must be parameter-bound. See docs/rd-1206-method-policies-design.md and the
--   two security audits recorded there. NULL method_policies = feature off for
--   the contract (unchanged behaviour).
--
-- AFFECTED ROWS: none rewritten. Purely additive (expand-only): one ADD COLUMN
--   (nullable, no default backfill) + two CREATE TABLE. No existing row changes.
--
-- AUTHORITATIVE RECORD: this migration file (git) + PR review + tern
--   schema_version applied-at timestamp. No audit-table writes from here.
--
-- ROLE SEPARATION: privacy_proxy_app / privacy_proxy_admin exist as of
--   migration 058; the admin role inherits new tables via ALTER DEFAULT
--   PRIVILEGES, the app role needs the explicit CRUD + sequence grants below
--   (both new tables are operational — full CRUD; BIGSERIAL needs the sequence
--   grant or INSERTs fail).

ALTER TABLE contracts
    ADD COLUMN method_policies JSONB NULL;

CREATE TABLE contract_record_captures (
    id               BIGSERIAL PRIMARY KEY,
    org_id           UUID        NOT NULL,
    contract_address VARCHAR(42) NOT NULL,   -- lowercase 0x-prefixed
    record_type      TEXT        NOT NULL,
    record_key       TEXT        NOT NULL,   -- canonical typed string
    field            TEXT        NOT NULL,
    value            TEXT        NOT NULL,    -- DID | lowercase 0x address | scalar
    merge_mode       TEXT        NOT NULL,    -- 'union' | 'set_once'
    source_tx_hash   VARCHAR(66) NOT NULL,
    sender_did       TEXT        NOT NULL,    -- for set-once poison detection
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- org_id is IN the uniqueness/lookup key (defense in depth: cross-org
    -- isolation is enforced here, not merely by the one-owner invariant).
    UNIQUE (org_id, contract_address, record_type, record_key, field, value)
);

CREATE INDEX idx_contract_record_captures_lookup
    ON contract_record_captures (org_id, contract_address, record_type, record_key);

CREATE TABLE pending_record_captures (
    id               BIGSERIAL PRIMARY KEY,
    tx_hash          VARCHAR(66) NOT NULL,
    org_id           UUID        NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    captures         JSONB       NOT NULL,   -- [{record_type,record_key,field,value,merge}]
    sender_did       TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempt_count    INT         NOT NULL DEFAULT 0,
    last_attempt_at  TIMESTAMPTZ NULL,
    last_error       TEXT        NULL
);

-- Reconciler-friendly index: only rows still under the soft attempt cap.
CREATE INDEX idx_pending_record_captures_due
    ON pending_record_captures (created_at)
    WHERE attempt_count < 20;

-- App-role grants (roles guaranteed to exist by migration 058).
GRANT SELECT, INSERT, UPDATE, DELETE ON contract_record_captures TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pending_record_captures  TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE contract_record_captures_id_seq TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE pending_record_captures_id_seq  TO privacy_proxy_app;

---- create above / drop below ----

DROP TABLE IF EXISTS pending_record_captures;
DROP TABLE IF EXISTS contract_record_captures;
ALTER TABLE contracts DROP COLUMN IF EXISTS method_policies;
