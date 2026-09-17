package db

import (
	"context"

	"github.com/google/uuid"
	"privacy-proxy/internal/configuration"
)

func configurationPlatform(ctx context.Context, q DBTX, active *ConfigurationRevision, lock bool) (configuration.PlatformSnapshot, error) {
	out := configuration.PlatformSnapshot{ManagedIDs: []string{}, Spec: configuration.PlatformSpec{SharedInfrastructure: []configuration.SharedInfrastructure{}, Tenants: []configuration.Tenant{}}}
	sharedIDs := map[string]string{}
	if active != nil {
		out.ActiveRevision = active.Revision
		doc, err := configuration.Parse([]byte(active.Source))
		if err != nil {
			return out, err
		}
		spec := doc.Spec.(configuration.PlatformSpec)
		for _, v := range spec.SharedInfrastructure {
			sharedIDs[v.Address] = v.ID
			out.ManagedIDs = append(out.ManagedIDs, v.ID)
		}
		for _, v := range spec.Tenants {
			out.ManagedIDs = append(out.ManagedIDs, v.ID)
		}
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	rows, err := q.QueryContext(ctx, `SELECT address,name,COALESCE(description,''),COALESCE(codehash,'') FROM shared_infrastructure ORDER BY address`+suffix)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v configuration.SharedInfrastructure
		if err := rows.Scan(&v.Address, &v.Name, &v.Description, &v.Codehash); err != nil {
			rows.Close()
			return out, err
		}
		v.ID = sharedIDs[v.Address]
		if v.ID == "" {
			v.ID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("ops:shared-infrastructure:"+v.Address)).String()
		}
		out.Spec.SharedInfrastructure = append(out.Spec.SharedInfrastructure, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = q.QueryContext(ctx, `SELECT id,tenant_id,label,COALESCE(default_org_id::text,''),COALESCE(default_group_id::text,''),auto_provision FROM allowed_azure_tenants ORDER BY id`+suffix)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var v configuration.Tenant
		if err := rows.Scan(&v.ID, &v.TenantID, &v.Label, &v.DefaultOrgID, &v.DefaultGroupID, &v.AutoProvision); err != nil {
			return out, err
		}
		out.Spec.Tenants = append(out.Spec.Tenants, v)
	}
	return out, rows.Err()
}
func validateConfigurationPlatform(ctx context.Context, q DBTX, diff *configuration.PlatformDiff, lock bool) error {
	if diff == nil {
		return nil
	}
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	for _, tenant := range diff.Projection.Tenants {
		if tenant.DefaultOrgID == "" {
			continue
		}
		var id string
		if err := q.QueryRowContext(ctx, `SELECT id FROM organizations WHERE id=$1`+suffix, tenant.DefaultOrgID).Scan(&id); err != nil {
			return ConfigurationConflict("tenant default organization is unavailable")
		}
		if tenant.DefaultGroupID != "" {
			if err := q.QueryRowContext(ctx, `SELECT id FROM groups WHERE id=$1 AND org_id=$2`+suffix, tenant.DefaultGroupID, tenant.DefaultOrgID).Scan(&id); err != nil {
				return ConfigurationConflict("tenant default group must belong to its default organization")
			}
		}
	}
	return nil
}
func projectConfigurationPlatform(ctx context.Context, tx *Tx, view ConfigurationActivation) error {
	if view.PlatformDiff == nil {
		return nil
	}
	diff := view.PlatformDiff
	shared := map[string]configuration.SharedInfrastructure{}
	for _, v := range view.Platform.Spec.SharedInfrastructure {
		shared[v.ID] = v
	}
	for _, change := range diff.Changes {
		if change.Action != "delete" {
			continue
		}
		if change.Resource == "sharedInfrastructure" {
			if _, err := tx.tx.ExecContext(ctx, `DELETE FROM shared_infrastructure WHERE address=$1`, shared[change.ID].Address); err != nil {
				return err
			}
		} else {
			if _, err := tx.tx.ExecContext(ctx, `DELETE FROM allowed_azure_tenants WHERE id=$1`, change.ID); err != nil {
				return err
			}
		}
	}
	for _, v := range diff.Projection.SharedInfrastructure {
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO shared_infrastructure(address,name,description,codehash)VALUES($1,$2,$3,$4) ON CONFLICT(address)DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,codehash=EXCLUDED.codehash`, v.Address, v.Name, v.Description, v.Codehash); err != nil {
			return err
		}
	}
	for _, v := range diff.Projection.Tenants {
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO allowed_azure_tenants(id,tenant_id,label,default_org_id,default_group_id,auto_provision)VALUES($1,$2,$3,NULLIF($4,'')::uuid,NULLIF($5,'')::uuid,$6) ON CONFLICT(id)DO UPDATE SET label=EXCLUDED.label,default_org_id=EXCLUDED.default_org_id,default_group_id=EXCLUDED.default_group_id,auto_provision=EXCLUDED.auto_provision,updated_at=NOW()`, v.ID, v.TenantID, v.Label, v.DefaultOrgID, v.DefaultGroupID, v.AutoProvision); err != nil {
			return err
		}
	}
	return nil
}
