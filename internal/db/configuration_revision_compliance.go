package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"privacy-proxy/internal/configuration"
)

func configurationCompliance(ctx context.Context, q DBTX, scope configuration.Scope, active *ConfigurationRevision, lock bool) (configuration.ComplianceSnapshot, error) {
	out := configuration.ComplianceSnapshot{Scope: scope, ManagedIDs: []string{}, Spec: configuration.ComplianceSpec{Settings: configuration.ComplianceSettings{ThresholdFiat: 1000, Currency: "usd", UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []configuration.AddressThreshold{}, TokenPrices: []configuration.TokenPrice{}}}
	if active != nil {
		out.ActiveRevision = active.Revision
		doc, err := configuration.Parse([]byte(active.Source))
		if err != nil {
			return out, err
		}
		spec := doc.Spec.(configuration.ComplianceSpec)
		for _, v := range spec.AddressThresholds {
			out.ManagedIDs = append(out.ManagedIDs, v.ID)
		}
		for _, v := range spec.TokenPrices {
			out.ManagedIDs = append(out.ManagedIDs, v.ID)
		}
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	s := &out.Spec.Settings
	err := q.QueryRowContext(ctx, `SELECT enabled,threshold_fiat,currency,unknown_price_policy,enforcement_mode FROM compliance_config WHERE org_id=$1`+suffix, scope.ID).Scan(&s.Enabled, &s.ThresholdFiat, &s.Currency, &s.UnknownPricePolicy, &s.EnforcementMode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	rows, err := q.QueryContext(ctx, `SELECT id,address,threshold_fiat,COALESCE(note,'') FROM address_threshold_overrides WHERE org_id=$1 ORDER BY id`+suffix, scope.ID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var v configuration.AddressThreshold
		if err := rows.Scan(&v.ID, &v.Address, &v.ThresholdFiat, &v.Note); err != nil {
			rows.Close()
			return out, err
		}
		out.Spec.AddressThresholds = append(out.Spec.AddressThresholds, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = q.QueryContext(ctx, `SELECT id,token_address,symbol,decimals,prices_by_currency,COALESCE(coingecko_id,''),price_fiat FROM token_prices WHERE org_id=$1 ORDER BY id`+suffix, scope.ID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var v configuration.TokenPrice
		var prices []byte
		var legacyPrice float64
		if err := rows.Scan(&v.ID, &v.TokenAddress, &v.Symbol, &v.Decimals, &prices, &v.CoingeckoID, &legacyPrice); err != nil {
			return out, err
		}
		if err := json.Unmarshal(prices, &v.PricesByCurrency); err != nil {
			return out, err
		}
		if v.PricesByCurrency == nil {
			v.PricesByCurrency = map[string]float64{}
		}
		// Old manual rows predate multi-currency metadata. Preserve their authored
		// value in the export; fetched CoinGecko values never enter desired state.
		if len(v.PricesByCurrency) == 0 && v.CoingeckoID == "" && legacyPrice > 0 {
			v.PricesByCurrency[s.Currency] = legacyPrice
		}
		out.Spec.TokenPrices = append(out.Spec.TokenPrices, v)
	}
	return out, rows.Err()
}

func projectConfigurationCompliance(ctx context.Context, tx *Tx, view ConfigurationActivation) error {
	if view.ComplianceDiff == nil {
		return nil
	}
	diff := view.ComplianceDiff
	spec := diff.Projection
	s := spec.Settings
	_, err := tx.tx.ExecContext(ctx, `INSERT INTO compliance_config(id,org_id,enabled,threshold_fiat,currency,unknown_price_policy,enforcement_mode)VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(org_id)DO UPDATE SET enabled=EXCLUDED.enabled,threshold_fiat=EXCLUDED.threshold_fiat,currency=EXCLUDED.currency,unknown_price_policy=EXCLUDED.unknown_price_policy,enforcement_mode=EXCLUDED.enforcement_mode,updated_at=NOW()`, uuid.NewString(), view.Scope.ID, s.Enabled, s.ThresholdFiat, s.Currency, s.UnknownPricePolicy, s.EnforcementMode)
	if err != nil {
		return err
	}
	for _, change := range diff.Changes {
		if change.Action != "delete" {
			continue
		}
		table := "address_threshold_overrides"
		if change.Resource == "tokenPrice" {
			table = "token_prices"
		}
		if _, err := tx.tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE id=$1 AND org_id=$2`, change.ID, view.Scope.ID); err != nil {
			return err
		}
	}
	for _, row := range spec.AddressThresholds {
		result, err := tx.tx.ExecContext(ctx, `INSERT INTO address_threshold_overrides(id,org_id,address,threshold_fiat,note)VALUES($1,$2,$3,$4,$5) ON CONFLICT(id)DO UPDATE SET address=EXCLUDED.address,threshold_fiat=EXCLUDED.threshold_fiat,note=EXCLUDED.note,updated_at=NOW() WHERE address_threshold_overrides.org_id=EXCLUDED.org_id`, row.ID, view.Scope.ID, row.Address, row.ThresholdFiat, row.Note)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return ErrConfigurationForbidden
		}
	}
	for _, row := range spec.TokenPrices {
		prices, err := json.Marshal(row.PricesByCurrency)
		if err != nil {
			return err
		}
		result, err := tx.tx.ExecContext(ctx, `INSERT INTO token_prices(id,org_id,token_address,symbol,decimals,price_fiat,prices_by_currency,coingecko_id,updated_by_user_id)VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9) ON CONFLICT(id)DO UPDATE SET token_address=EXCLUDED.token_address,symbol=EXCLUDED.symbol,decimals=EXCLUDED.decimals,price_fiat=EXCLUDED.price_fiat,prices_by_currency=EXCLUDED.prices_by_currency,coingecko_id=EXCLUDED.coingecko_id,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=NOW() WHERE token_prices.org_id=EXCLUDED.org_id`, row.ID, view.Scope.ID, row.TokenAddress, row.Symbol, row.Decimals, row.PricesByCurrency[s.Currency], prices, row.CoingeckoID, view.Actor.UserID)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return ErrConfigurationForbidden
		}
	}
	return nil
}
