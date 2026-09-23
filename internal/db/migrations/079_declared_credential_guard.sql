-- WHAT: the projection barrier stops exempting key-only writes to group_access
-- rows whose credential a reviewed groups document declared.
-- WHY: 075 lets an UPDATE that changes only rpc_api_key (and updated_at) pass,
-- so an operator can rotate an operational key on a managed stream. Since 078
-- a document may declare the credential (rpc_api_key_source IS NOT NULL);
-- the same exemption would let a legacy writer that raced the first activation
-- overwrite the declared ciphertext while the row still says "declared". The
-- exemption now applies only when the row's credential is operational.
-- Projection writes carry the ops.configuration_projection marker and are not
-- affected; the rotation endpoint already refuses declared rows.
-- AFFECTED ROWS: none rewritten. Detection of writes this now refuses: errors
-- containing 'use a configuration revision for managed groups state'.
-- AUTHORITATIVE RECORD: the reviewed groups revision (configuration_revisions)
-- plus its transactional audit; this migration writes no audit rows.
-- EXPAND-ONLY / ROLE SEPARATION: replaces one function body in place; every
-- trigger created by 075 keeps pointing at it. Grants are unchanged.
CREATE OR REPLACE FUNCTION configuration_guard_projection() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    row_data JSONB;
    target_org UUID;
    stream_kind TEXT := TG_ARGV[0];
BEGIN
    -- Upstream API credentials are operational secrets, never source content —
    -- unless a document declared where this one lives (rpc_api_key_source),
    -- in which case only a projection may write it. The column is read through
    -- jsonb because this function body is compiled per table it guards.
    IF TG_TABLE_NAME='group_access' AND TG_OP='UPDATE' AND (to_jsonb(OLD)->>'rpc_api_key_source') IS NULL AND
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

---- create above / drop below ----

-- Forward-only: a declared credential must keep its revision barrier.
