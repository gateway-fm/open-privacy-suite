-- WHAT: close legacy execution-policy writes after execution-rules adoption.
-- WHY: the reviewed generic revision must be the single desired-state writer;
-- its existing execution_policy_revisions row is a node-export projection.
-- AFFECTED ROWS: none. Unmanaged organizations retain their existing writer.
-- AUTHORITATIVE RECORD: immutable configuration source/compiled artifact plus
-- the runtime actor-attributed RBAC audit transaction. No audit rows are written
-- by this migration. Projection IDs equal their source configuration IDs;
-- legacy and generic revision sequences remain independent and monotonic.
-- EXPAND-ONLY / ROLE SEPARATION: new trigger, using the existing scoped guard.
-- Detection: SELECT org_id,id FROM configuration_revisions
-- WHERE kind='execution-rules' AND status='active';

CREATE TRIGGER configuration_execution_policy
BEFORE INSERT OR UPDATE OR DELETE ON execution_policy_revisions
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('execution-rules');

---- create above / drop below ----

-- Forward-only: revision-owned execution state retains its writer barrier.
