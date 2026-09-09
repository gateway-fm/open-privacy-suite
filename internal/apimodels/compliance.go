package apimodels

// Spec-only response models for the admin compliance handlers (RD-1166).
//
// The handlers in admin_compliance.go marshal real Go structs (compliance.*)
// directly where possible — those are referenced straight from the @Success
// annotations. The handlers that respond through gin.H (map) literals have no
// Go type to reference; the structs below mirror those wire shapes exactly
// (same JSON keys and value types) so swaggo can emit a schema.
//
// These types are never constructed at runtime — they exist purely as
// annotation targets. This file must compile standalone: plain structs only,
// no imports. For the "data + total" list wrappers, the `data` field is a
// placeholder ([]interface{}); each @Success line overrides it with the real
// element type via swag's composition syntax, e.g.
// `ComplianceListResponse{data=[]compliance.SanctionedAddress}`.

// --- Request bodies ---
//
// The compliance write handlers bind anonymous inline structs. The types below
// mirror those request shapes exactly so the @Param request annotations can
// reference a named type. Spec-only; never constructed at runtime.

// ComplianceConfigUpdateRequest is the PUT
// /api/v1/admin/orgs/{org_id}/compliance/config body. All fields are optional;
// only those present are changed (partial update). unknown_price_policy is
// "allowed" or "forbidden"; enforcement_mode is "enforce" or "monitor";
// currency is one of usd, eur, chf, gbp, aed.
type ComplianceConfigUpdateRequest struct {
	Enabled            *bool    `json:"enabled" example:"true"`
	ThresholdFiat      *float64 `json:"threshold_fiat" example:"1000"`
	UnknownPricePolicy *string  `json:"unknown_price_policy" example:"forbidden"`
	EnforcementMode    *string  `json:"enforcement_mode" example:"enforce"`
	Currency           *string  `json:"currency" example:"usd"`
}

// ComplianceTokenPriceUpsertRequest is the PUT
// /api/v1/admin/orgs/{org_id}/compliance/tokens/{token_address} body. Set
// coingecko_id (one of ethereum, tether, usd-coin) to source the price from the
// system price cache; otherwise supply at least one entry in prices keyed by
// currency code. symbol is required (max 20 chars); decimals is 0–77.
type ComplianceTokenPriceUpsertRequest struct {
	Symbol      string             `json:"symbol" binding:"required" example:"ETH"`
	Decimals    int                `json:"decimals" example:"18"`
	Prices      map[string]float64 `json:"prices"`
	CoingeckoID *string            `json:"coingecko_id" example:"ethereum"`
}

// ComplianceTravelRuleRecordCreateRequest is the POST
// /api/v1/admin/orgs/{org_id}/compliance/travel-rule-records body. amount_fiat
// is NOT accepted — it is computed server-side from amount_wei and the
// configured token price. transfer_type is "eth" or "erc20"; token_address is
// required for erc20. The originator must be a member of the org.
type ComplianceTravelRuleRecordCreateRequest struct {
	OriginatorUserID   string                 `json:"originator_user_id" binding:"required"`
	OriginatorData     map[string]interface{} `json:"originator_data" binding:"required"`
	BeneficiaryData    map[string]interface{} `json:"beneficiary_data" binding:"required"`
	TransferType       string                 `json:"transfer_type" binding:"required" example:"eth"`
	TokenAddress       *string                `json:"token_address"`
	BeneficiaryAddress string                 `json:"beneficiary_address" binding:"required" example:"0x0000000000000000000000000000000000000001"`
	AmountWei          string                 `json:"amount_wei" binding:"required" example:"1000000000000000000"`
}

// ComplianceSanctionAddRequest is the POST /api/v1/admin/compliance/sanctions
// body. Omit org_id (or set null) for a GLOBAL sanction (super-admin only); set
// it for a per-org sanction (org-admin only). reason is required (max 1000
// chars); source is a free-text provenance label.
type ComplianceSanctionAddRequest struct {
	OrgID   *string `json:"org_id"`
	Address string  `json:"address" binding:"required" example:"0x0000000000000000000000000000000000000001"`
	Reason  string  `json:"reason" binding:"required" example:"OFAC SDN listing"`
	Source  string  `json:"source" example:"manual"`
}

// ComplianceThresholdOverrideUpsertRequest is the PUT
// /api/v1/admin/orgs/{org_id}/compliance/address-thresholds/{address} body.
// threshold_fiat must be >= 0; note is optional free text (max 1000 chars).
type ComplianceThresholdOverrideUpsertRequest struct {
	ThresholdFiat float64 `json:"threshold_fiat" example:"5000"`
	Note          string  `json:"note" example:"elevated limit for treasury address"`
}

// ComplianceSetBaseCurrencyRequest is the PUT /api/v1/admin/compliance/currency
// body. currency is one of usd, eur, chf, gbp, aed. Set force=true to switch
// even when manual token prices are missing for the new currency (those tokens
// then block transactions until priced).
type ComplianceSetBaseCurrencyRequest struct {
	Currency string `json:"currency" binding:"required" example:"eur"`
	Force    bool   `json:"force" example:"false"`
}

// ComplianceListResponse is the generic paginated "data + total + limit +
// offset" envelope returned by the compliance list endpoints (sanctions,
// travel-rule records, address-threshold overrides, and compliance logs).
// `data` is a placeholder — each @Success overrides it with the concrete
// element type.
type ComplianceListResponse struct {
	Data   []interface{} `json:"data"`
	Total  int           `json:"total" example:"42"`
	Limit  int           `json:"limit" example:"50"`
	Offset int           `json:"offset" example:"0"`
}

// ComplianceDataResponse is the un-paginated "{data: [...]}" envelope returned
// by the per-org token-price listing. `data` is a placeholder — the @Success
// line overrides it with the concrete element type.
type ComplianceDataResponse struct {
	Data []interface{} `json:"data"`
}

// ComplianceSystemTokenPrice mirrors the per-entry shape of
// listSystemTokenPrices, which augments each cached CoinGecko price with a
// computed is_stale flag (derived from PRICE_STALENESS_THRESHOLD).
type ComplianceSystemTokenPrice struct {
	ID           int     `json:"id" example:"1"`
	CoingeckoID  *string `json:"coingecko_id,omitempty" example:"ethereum"`
	Symbol       string  `json:"symbol" example:"ETH"`
	Decimals     int     `json:"decimals" example:"18"`
	PriceFiat    float64 `json:"price_fiat" example:"3500"`
	Source       string  `json:"source" example:"coingecko"`
	TokenAddress *string `json:"token_address,omitempty"`
	UpdatedAt    string  `json:"updated_at" example:"2026-01-02T15:04:05Z"`
	IsStale      bool    `json:"is_stale" example:"false"`
}

// ComplianceSystemTokenPriceListResponse is the GET
// /api/v1/admin/compliance/system-token-prices body: the cached system prices
// plus the active global base currency they are valued in.
type ComplianceSystemTokenPriceListResponse struct {
	Data     []ComplianceSystemTokenPrice `json:"data"`
	Currency string                       `json:"currency" example:"usd"`
}

// ComplianceCurrencyInfo describes one supported fiat currency.
type ComplianceCurrencyInfo struct {
	Code   string `json:"code" example:"usd"`
	Name   string `json:"name" example:"US Dollar"`
	Symbol string `json:"symbol" example:"$"`
}

// ComplianceBaseCurrencyResponse is the GET /api/v1/admin/compliance/currency
// body: the active global base currency, the full list of supported
// currencies, and whether CoinGecko polling is enabled.
type ComplianceBaseCurrencyResponse struct {
	Currency         string                   `json:"currency" example:"usd"`
	AllCurrencies    []ComplianceCurrencyInfo `json:"all_currencies"`
	CoingeckoEnabled bool                     `json:"coingecko_enabled" example:"true"`
}

// ComplianceAffectedToken identifies a manual token price that has no price set
// for a currency being switched to (reported by setBaseCurrency).
type ComplianceAffectedToken struct {
	OrgID        string `json:"org_id"`
	TokenAddress string `json:"token_address" example:"native"`
	Symbol       string `json:"symbol" example:"ETH"`
}

// ComplianceSetBaseCurrencyResponse is the 200 body of PUT
// /api/v1/admin/compliance/currency. `warning` and `affected_tokens` are
// present only when force=true switched the currency despite manual tokens
// lacking a price for it.
type ComplianceSetBaseCurrencyResponse struct {
	Currency       string                    `json:"currency" example:"eur"`
	Message        string                    `json:"message" example:"Base currency updated to EUR."`
	Warning        string                    `json:"warning,omitempty"`
	AffectedTokens []ComplianceAffectedToken `json:"affected_tokens,omitempty"`
}

// ComplianceCurrencyConflictResponse is the 409 body of PUT
// /api/v1/admin/compliance/currency when manual token prices are missing for
// the target currency and force was not set.
type ComplianceCurrencyConflictResponse struct {
	Error          string                    `json:"error" example:"manual token prices are missing for the target currency; set force=true to switch anyway"`
	AffectedTokens []ComplianceAffectedToken `json:"affected_tokens"`
	Currency       string                    `json:"currency" example:"eur"`
}
