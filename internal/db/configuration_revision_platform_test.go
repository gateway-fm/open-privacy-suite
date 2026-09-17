package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
)

func TestConfigurationPlatformScopeProjectsAndClosesLegacyWriters(t *testing.T) {
	d, org, author, reviewer, _ := configurationFixture(t)
	author.PrincipalKind = "human"
	ctx := t.Context()
	scope := configuration.Scope{Kind: "platform"}
	spec := configuration.PlatformSpec{SharedInfrastructure: []configuration.SharedInfrastructure{{ID: uuid.NewString(), Address: "0x1111111111111111111111111111111111111111", Name: "Library", Codehash: "0x" + strings.Repeat("a", 64)}}, Tenants: []configuration.Tenant{{ID: uuid.NewString(), TenantID: uuid.NewString(), Label: "OPS", DefaultOrgID: org.ID, AutoProvision: true}}}
	raw, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Platform, Scope: scope, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: spec})
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.NoError(t, err)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.Platform)
	require.NoError(t, err)
	require.Equal(t, spec, exported.Source.Spec)
	_, err = d.conn.ExecContext(ctx, `UPDATE allowed_azure_tenants SET label='bypass' WHERE id=$1`, spec.Tenants[0].ID)
	require.ErrorContains(t, err, "configuration revision")
	_, err = d.conn.ExecContext(ctx, `DELETE FROM shared_infrastructure WHERE address=$1`, spec.SharedInfrastructure[0].Address)
	require.ErrorContains(t, err, "configuration revision")
	var auditedOrg *string
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT org_id FROM rbac_audit_log WHERE resource_id=$1`, draft.ID).Scan(&auditedOrg))
	require.Nil(t, auditedOrg)
}
