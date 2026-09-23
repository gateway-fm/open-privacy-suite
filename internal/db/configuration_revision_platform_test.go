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

// The platform document's price feed is desired state like the rest of the
// platform stream: activation projects it into a guarded singleton row the
// poller reads, the current state renders it back, direct writes to the row
// are refused, and a document without the feed clears it.
func TestConfigurationPlatformPriceFeedProjectsRendersAndClears(t *testing.T) {
	d, _, author, reviewer, _ := configurationFixture(t)
	author.PrincipalKind = "human"
	ctx := t.Context()
	scope := configuration.Scope{Kind: "platform"}
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	submit := func(base int64, feed *configuration.PriceFeed) *ConfigurationRevision {
		t.Helper()
		raw, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Platform, Scope: scope, BaseRevision: base, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.PlatformSpec{SharedInfrastructure: []configuration.SharedInfrastructure{}, Tenants: []configuration.Tenant{}, PriceFeed: feed}})
		require.NoError(t, err)
		draft, err := d.SubmitConfigurationRevision(ctx, raw, author)
		require.NoError(t, err)
		_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
		require.NoError(t, err)
		return draft
	}

	// Nothing declared yet: the poller keeps its environment defaults.
	current, err := d.GetPlatformPriceFeed(ctx)
	require.NoError(t, err)
	require.Nil(t, current)

	feed := configuration.PriceFeed{URI: "https://prices.example.test/api/v3/simple/price?precision=full", RefreshIntervalSeconds: 120, Format: configuration.PriceFeedFormatCoinGeckoSimple}
	first := submit(0, &feed)
	current, err = d.GetPlatformPriceFeed(ctx)
	require.NoError(t, err)
	require.Equal(t, &feed, current)
	view, err := d.GetConfigurationContext(ctx, scope, configuration.Platform)
	require.NoError(t, err)
	require.Equal(t, &feed, view.Source.Spec.(configuration.PlatformSpec).PriceFeed)
	require.Equal(t, &feed, view.Platform.Spec.PriceFeed)

	// The row is a projection: only an activation may write it.
	_, err = d.conn.ExecContext(ctx, `UPDATE platform_price_feed SET refresh_interval_seconds=61`)
	require.ErrorContains(t, err, "configuration revision")
	_, err = d.conn.ExecContext(ctx, `DELETE FROM platform_price_feed`)
	require.ErrorContains(t, err, "configuration revision")

	changed := feed
	changed.RefreshIntervalSeconds = 600
	second := submit(first.Revision, &changed)
	current, err = d.GetPlatformPriceFeed(ctx)
	require.NoError(t, err)
	require.Equal(t, &changed, current)

	// Dropping the field is the delete: the poller returns to its defaults.
	submit(second.Revision, nil)
	current, err = d.GetPlatformPriceFeed(ctx)
	require.NoError(t, err)
	require.Nil(t, current)
	view, err = d.GetConfigurationContext(ctx, scope, configuration.Platform)
	require.NoError(t, err)
	require.Nil(t, view.Source.Spec.(configuration.PlatformSpec).PriceFeed)
}
