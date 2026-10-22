-- WHAT: database barriers for revision-owned desired state.
-- WHY: an HTTP setter check can race the first activation. A volatile trigger
-- locks the same scope as activation, then checks the committed stream state.
-- AFFECTED ROWS: none; future desired-state writes in managed scopes must use
-- a reviewed projection transaction. Identity/membership/sanctions operations
-- are unaffected. Secrets and deployment facts remain operational.
-- AUTHORITATIVE RECORD: configuration_revisions plus its transactional audit.
-- This migration creates no audit rows and never rewrites existing data.
-- EXPAND-ONLY: new functions/triggers; runtime privileges granted explicitly.
-- Detection: legacy mutation errors include 'use a configuration revision'.

CREATE FUNCTION configuration_require_projection(target_org UUID, stream_kind TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF target_org IS NULL THEN
        PERFORM pg_advisory_xact_lock(730074);
    ELSE
        PERFORM id FROM organizations WHERE id=target_org FOR UPDATE;
    END IF;
    IF current_setting('ops.configuration_projection',true) = COALESCE(target_org::text,'platform') THEN RETURN; END IF;
    IF EXISTS(SELECT 1 FROM configuration_revisions
              WHERE org_id IS NOT DISTINCT FROM target_org AND kind=stream_kind AND status='active') THEN
        RAISE EXCEPTION 'use a configuration revision for managed % state',stream_kind USING ERRCODE='55000';
    END IF;
END $$;

CREATE FUNCTION configuration_guard_projection() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    row_data JSONB;
    target_org UUID;
    stream_kind TEXT := TG_ARGV[0];
BEGIN
    -- Upstream API credentials are operational secrets, never source content.
    IF TG_TABLE_NAME='group_access' AND TG_OP='UPDATE' AND
       (to_jsonb(NEW)-ARRAY['rpc_api_key','updated_at']) IS NOT DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['rpc_api_key','updated_at']) THEN RETURN NEW; END IF;
    -- Chain-derived deployment metadata is not a registry setter.
    IF TG_TABLE_NAME='contracts' AND TG_OP='UPDATE' AND
       (to_jsonb(NEW)-ARRAY['metadata','deployed_by_user_id','deployed_at','updated_at']) IS NOT DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['metadata','deployed_by_user_id','deployed_at','updated_at']) THEN RETURN NEW; END IF;

    FOR row_data IN SELECT value FROM jsonb_array_elements(
        CASE TG_OP WHEN 'INSERT' THEN jsonb_build_array(to_jsonb(NEW))
                   WHEN 'DELETE' THEN jsonb_build_array(to_jsonb(OLD))
                   ELSE jsonb_build_array(to_jsonb(OLD),to_jsonb(NEW)) END)
    LOOP
        IF stream_kind='platform' THEN target_org := NULL;
        ELSIF TG_TABLE_NAME='group_access' THEN
            SELECT org_id INTO target_org FROM groups WHERE id=(row_data->>'group_id')::uuid;
        ELSIF TG_TABLE_NAME='contract_grants' THEN
            SELECT org_id INTO target_org FROM contracts WHERE id=(row_data->>'contract_id')::uuid;
        ELSE target_org := (row_data->>'org_id')::uuid;
        END IF;

        -- This marker is set only by an internal transaction method after
        -- scope locking. It permits new deployment-discovered resources,
        -- never UPDATE/DELETE of managed desired state.
        IF TG_OP='INSERT' AND TG_TABLE_NAME IN ('groups','group_access','contracts','contract_grants') AND
           current_setting('ops.configuration_operation',true)='deployment-registration' AND
           current_setting('ops.configuration_operation_scope',true)=target_org::text THEN CONTINUE; END IF;

        IF TG_TABLE_NAME='contract_grants' THEN
            IF TG_OP<>'UPDATE' OR NEW.functions IS DISTINCT FROM OLD.functions THEN
                PERFORM configuration_require_projection(target_org,'execution-rules');
            END IF;
            -- Until the execution stream is imported, retain its existing
            -- independent writer semantics without claiming registry owns it.
            IF TG_OP='UPDATE' AND
               (to_jsonb(NEW)-ARRAY['functions','updated_at']) IS NOT DISTINCT FROM
               (to_jsonb(OLD)-ARRAY['functions','updated_at']) THEN CONTINUE; END IF;
        END IF;
        PERFORM configuration_require_projection(target_org,stream_kind);
    END LOOP;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER configuration_groups BEFORE INSERT OR UPDATE OR DELETE ON groups
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('groups');
CREATE TRIGGER configuration_group_access BEFORE INSERT OR UPDATE OR DELETE ON group_access
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('groups');
CREATE TRIGGER configuration_contracts BEFORE INSERT OR UPDATE OR DELETE ON contracts
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('contract-registry');
CREATE TRIGGER configuration_grants BEFORE INSERT OR UPDATE OR DELETE ON contract_grants
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('contract-registry');
CREATE TRIGGER configuration_compliance BEFORE INSERT OR UPDATE OR DELETE ON compliance_config
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('compliance');
CREATE TRIGGER configuration_thresholds BEFORE INSERT OR UPDATE OR DELETE ON address_threshold_overrides
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('compliance');
CREATE TRIGGER configuration_token_prices BEFORE INSERT OR UPDATE OR DELETE ON token_prices
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('compliance');
CREATE TRIGGER configuration_shared BEFORE INSERT OR UPDATE OR DELETE ON shared_infrastructure
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('platform');
CREATE TRIGGER configuration_tenants BEFORE INSERT OR UPDATE OR DELETE ON allowed_azure_tenants
FOR EACH ROW EXECUTE FUNCTION configuration_guard_projection('platform');

DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='privacy_proxy_app') THEN
        GRANT EXECUTE ON FUNCTION configuration_require_projection(UUID,TEXT),configuration_guard_projection() TO privacy_proxy_app;
    END IF;
END $$;

---- create above / drop below ----

-- Forward-only: managed desired state must retain its revision barrier.
