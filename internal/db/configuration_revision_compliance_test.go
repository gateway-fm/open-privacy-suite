package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
)

func TestConfigurationComplianceProjectionPreservesOperationalSanctions(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	sanction := uuid.NewString()
	_, err := d.conn.ExecContext(ctx, `INSERT INTO sanctioned_addresses(id,org_id,address,reason)VALUES($1,$2,$3,'urgent')`, sanction, scope.ID, "0x1111111111111111111111111111111111111111")
	require.NoError(t, err)
	spec := configuration.ComplianceSpec{Settings: configuration.ComplianceSettings{Enabled: true, ThresholdFiat: 1234, Currency: "eur", UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []configuration.AddressThreshold{{ID: uuid.NewString(), Address: "0x2222222222222222222222222222222222222222", ThresholdFiat: 23, Note: "reviewed"}}, TokenPrices: []configuration.TokenPrice{{ID: uuid.NewString(), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{"eur": 2345}}}}
	doc := configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Compliance, Scope: scope, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: spec}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
	var currency string
	var threshold, price float64
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT currency,threshold_fiat FROM compliance_config WHERE org_id=$1`, scope.ID).Scan(&currency, &threshold))
	require.Equal(t, "eur", currency)
	require.Equal(t, 1234., threshold)
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT price_fiat FROM token_prices WHERE org_id=$1`, scope.ID).Scan(&price))
	require.Equal(t, 2345., price)
	_, err = d.conn.ExecContext(ctx, `UPDATE compliance_config SET enabled=false WHERE org_id=$1`, scope.ID)
	require.ErrorContains(t, err, "configuration revision")
	_, err = d.conn.ExecContext(ctx, `UPDATE sanctioned_addresses SET reason='urgent update' WHERE id=$1`, sanction)
	require.NoError(t, err)
	exported, err := d.GetConfigurationContext(ctx, scope, configuration.Compliance)
	require.NoError(t, err)
	require.Equal(t, spec, exported.Source.Spec)
	doc.BaseRevision = draft.Revision
	spec.TokenPrices = []configuration.TokenPrice{}
	doc.Spec = spec
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	removal, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{removal.ID}, reviewer, allow)
	require.ErrorContains(t, err, "explicit deletion")
}
