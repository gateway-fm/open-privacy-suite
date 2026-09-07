package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// Default travel rule record expiration duration.
const travelRuleRecordTTL = 24 * time.Hour

// Max pagination limit to prevent memory exhaustion from unbounded queries.
const maxPaginationLimit = 1000

// internalError logs the real error server-side and returns a generic message to the client.
func internalError(c *gin.Context, msg string, err error) {
	slog.Error(msg, "error", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
}

// registerComplianceRoutes adds compliance management endpoints to the admin API.
func (s *Server) registerComplianceRoutes(adminGroup *gin.RouterGroup) {
	// org-scoped routes
	orgRoutes := adminGroup.Group("/orgs/:org_id/compliance")
	orgRoutes.GET("/config", s.getComplianceConfig)
	orgRoutes.PUT("/config", s.updateComplianceConfig)
	orgRoutes.GET("/tokens", s.listTokenPrices)
	orgRoutes.PUT("/tokens/:token_address", s.upsertTokenPrice)
	orgRoutes.DELETE("/tokens/:token_address", s.deleteTokenPrice)
	orgRoutes.POST("/travel-rule-records", s.createTravelRuleRecord)
	orgRoutes.GET("/travel-rule-records", s.listTravelRuleRecords)
	orgRoutes.DELETE("/travel-rule-records/:id", s.deleteTravelRuleRecord)
	orgRoutes.GET("/logs", s.listComplianceLogs)
	orgRoutes.GET("/address-thresholds", s.listAddressThresholdOverrides)
	orgRoutes.PUT("/address-thresholds/:address", s.upsertAddressThresholdOverride)
	orgRoutes.DELETE("/address-thresholds/:address", s.deleteAddressThresholdOverride)

	// global routes
	adminGroup.GET("/compliance/system-token-prices", s.listSystemTokenPrices)
	adminGroup.GET("/compliance/sanctions", s.listSanctionedAddresses)
	adminGroup.POST("/compliance/sanctions", s.addSanctionedAddress)
	adminGroup.DELETE("/compliance/sanctions/:id", s.removeSanctionedAddress)

	// Currency management
	adminGroup.GET("/compliance/currency", s.getBaseCurrency)
	adminGroup.PUT("/compliance/currency", s.setBaseCurrency)

}

// compliancePaginationParams parses and caps pagination parameters.
// The cap now lives in parsePaginationParams (RD-1179 — applied to all admin
// list endpoints), so this is a thin alias kept for call-site clarity.
func compliancePaginationParams(c *gin.Context, defaultLimit int) (int, int) {
	return parsePaginationParams(c, defaultLimit)
}

// defaultEnforcementMode returns the cluster-wide default compliance
// enforcement mode (RD-1044), falling back to enforce. Per-org config
// overrides it; this only seeds the value shown/created when an org has no
// compliance config row yet.
func (s *Server) defaultEnforcementMode() compliance.EnforcementMode {
	if s.config != nil && s.config.ComplianceDefaultMode == string(compliance.EnforcementMonitor) {
		return compliance.EnforcementMonitor
	}
	return compliance.EnforcementEnforce
}

// Compliance Config handlers

// orgCurrency returns the fiat currency an org values transfers in (RD-1158):
// the per-org compliance_config.currency, falling back to the global
// base_currency default, then "usd". Use this anywhere a per-org fiat amount is
// computed or displayed, so display/record valuation stays consistent with the
// currency the compliance checker actually enforces for the org.
func (s *Server) orgCurrency(ctx context.Context, orgID string) string {
	cfg, err := s.db.GetComplianceConfig(ctx, orgID)
	if err != nil {
		// Fall back rather than fail the caller, but leave a diagnostic: a
		// transient lookup failure here would otherwise silently value a
		// transfer/record against the wrong currency with no signal.
		slog.WarnContext(ctx, "orgCurrency: compliance-config lookup failed; falling back to base/system currency",
			"org_id", orgID, "error", err)
	} else if cfg != nil && cfg.Currency != "" {
		return cfg.Currency
	}
	if c, err := s.db.GetSystemSetting(ctx, "base_currency"); err == nil && c != "" {
		return c
	}
	return "usd"
}

// getComplianceConfig returns an org's compliance configuration.
//
// @Summary      Get an org's compliance configuration
// @Description  Returns the organization's travel-rule compliance settings (enabled flag, fiat threshold, per-org currency, unknown-price policy, and enforcement mode). If the org has no config row yet, a default (disabled, cluster-default enforcement mode) is returned. Tenant-confidential: not readable with the operator token — use a tier-2 org-admin JWT.
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Success      200 {object} compliance.ComplianceConfig
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope, or operator token (tenant data not readable)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/config [get]
func (s *Server) getComplianceConfig(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")

	config, err := s.db.GetComplianceConfig(c.Request.Context(), orgID)
	if err != nil {
		internalError(c, "failed to load compliance config", err)
		return
	}

	// Return default config if none exists. EnforcementMode reflects the
	// cluster default so the dashboard shows the mode that would actually
	// apply to this org (RD-1044).
	if config == nil {
		config = &compliance.ComplianceConfig{
			OrgID:           orgID,
			Enabled:         false,
			ThresholdFiat:   1000,
			EnforcementMode: s.defaultEnforcementMode(),
			Currency:        "usd",
		}
	}

	c.JSON(http.StatusOK, config)
}

// updateComplianceConfig creates or updates an org's compliance configuration.
//
// @Summary      Update an org's compliance configuration
// @Description  Creates or updates the organization's compliance settings (enabled flag, fiat threshold, per-org currency, unknown-price policy, enforce/monitor mode). A partial update — only the fields present in the body are changed. Per-org management is the org admin's job; the operator/super-admin token cannot mutate per-org config (RD-1107). RD-1158 made currency a per-org setting owned here (the global base currency stays super-admin only). The change is written to the RBAC audit log.
// @Tags         Admin: compliance
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        request body apimodels.ComplianceConfigUpdateRequest true "compliance config fields to change"
// @Success      200 {object} compliance.ComplianceConfig
// @Failure      400 {object} apimodels.APIError "invalid body, negative threshold, or unsupported policy/mode/currency"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/config [put]
func (s *Server) updateComplianceConfig(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job; the
	// super-admin token is platform/bootstrap only.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	var input struct {
		Enabled            *bool                          `json:"enabled"`
		ThresholdFiat      *float64                       `json:"threshold_fiat"`
		UnknownPricePolicy *compliance.UnknownPricePolicy `json:"unknown_price_policy"`
		EnforcementMode    *compliance.EnforcementMode    `json:"enforcement_mode"`
		// RD-1158: per-org currency. This is now a normal per-org setting the
		// org admin owns (no cross-org blast radius), so it lives on this
		// per-org, org-admin-gated config endpoint rather than the global
		// super-admin base-currency switch.
		Currency *string `json:"currency"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_compliance: invalid travel-rule config body", "err", err)
		return
	}

	// Fetch existing config or create a new one
	config, err := s.db.GetComplianceConfig(c.Request.Context(), orgID)
	if err != nil {
		internalError(c, "failed to load compliance config", err)
		return
	}

	isNew := false
	if config == nil {
		isNew = true
		config = &compliance.ComplianceConfig{
			ID:            uuid.New().String(),
			OrgID:         orgID,
			Enabled:       false,
			ThresholdFiat: 1000,
			// RD-1111: default to the fail-closed policy on CREATE. Pricing is
			// fail-closed throughout the proxy (an unknown/zero token price
			// BLOCKS the transfer), so a newly-created config must block on
			// unknown price unless the caller explicitly opts into "allowed"
			// below. Leaving this empty persisted "" and violated the
			// unknown_price_policy CHECK constraint, surfacing as a 500 on the
			// first PUT for a brand-new org.
			UnknownPricePolicy: compliance.UnknownPriceForbidden,
			EnforcementMode:    s.defaultEnforcementMode(),
			Currency:           "usd",
		}
	}

	// Capture before-image for audit log (M2).
	before := map[string]any{
		"enabled":              config.Enabled,
		"threshold_fiat":       config.ThresholdFiat,
		"unknown_price_policy": config.UnknownPricePolicy,
		"enforcement_mode":     config.EnforcementMode,
		"currency":             config.Currency,
	}

	if input.Enabled != nil {
		config.Enabled = *input.Enabled
	}
	if input.ThresholdFiat != nil {
		if *input.ThresholdFiat < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "threshold_fiat must be >= 0"})
			return
		}
		config.ThresholdFiat = *input.ThresholdFiat
	}
	if input.UnknownPricePolicy != nil {
		if *input.UnknownPricePolicy != compliance.UnknownPriceAllowed && *input.UnknownPricePolicy != compliance.UnknownPriceForbidden {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown_price_policy must be 'allowed' or 'forbidden'"})
			return
		}
		config.UnknownPricePolicy = *input.UnknownPricePolicy
	}
	// RD-1044: enforce (block, default) vs monitor (allow + record). Changing
	// this goes through this audited config-change path. Sanctions stay
	// hard-blocked regardless of mode (enforced in the checker).
	if input.EnforcementMode != nil {
		if !compliance.IsValidEnforcementMode(*input.EnforcementMode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "enforcement_mode must be 'enforce' or 'monitor'"})
			return
		}
		config.EnforcementMode = *input.EnforcementMode
	}
	// RD-1158: per-org currency. threshold_fiat is denominated in — and
	// transfers are valued against — this currency. Setting it is per-org and
	// has no cross-org effect, so it is allowed on this org-admin-gated path
	// (unlike the global base-currency switch, which stays super-admin only).
	if input.Currency != nil {
		cur := strings.ToLower(strings.TrimSpace(*input.Currency))
		if !compliance.IsValidCurrency(cur) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported currency; valid options: usd, eur, chf, gbp, aed"})
			return
		}
		config.Currency = cur
	}

	if err := s.db.UpsertComplianceConfig(c.Request.Context(), config); err != nil {
		internalError(c, "failed to save compliance config", err)
		return
	}

	// M2: audit-log the mutation (including the new unknown_price_policy
	// "allowed" flip, which is the only fail-OPEN path in compliance).
	action := rbac.AuditActionUpdate
	if isNew {
		action = rbac.AuditActionCreate
	}
	s.recordAuditActionScoped(c, action, rbac.ResourceTypeCompliance, config.ID, "compliance_config", orgID,
		before,
		map[string]any{
			"enabled":              config.Enabled,
			"threshold_fiat":       config.ThresholdFiat,
			"unknown_price_policy": config.UnknownPricePolicy,
			"enforcement_mode":     config.EnforcementMode,
			"currency":             config.Currency,
		})

	c.JSON(http.StatusOK, config)
}

// Token Price handlers

// listTokenPrices returns an org's configured token prices.
//
// @Summary      List an org's token prices
// @Description  Returns the fiat token prices configured for the organization, used to value transfers for the travel-rule threshold. Tenant-confidential: not readable with the operator token — use a tier-2 org-admin JWT.
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Success      200 {object} apimodels.ComplianceDataResponse{data=[]compliance.TokenPrice}
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope, or operator token (tenant data not readable)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/tokens [get]
func (s *Server) listTokenPrices(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")

	prices, err := s.db.ListTokenPrices(c.Request.Context(), orgID)
	if err != nil {
		internalError(c, "failed to list token prices", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": prices})
}

// upsertTokenPrice creates or updates a token price for an org.
//
// @Summary      Set a token price for an org
// @Description  Creates or updates the fiat price of a token for the organization. token_address is "native" (for the chain's native coin) or a 0x-prefixed contract address. Supply coingecko_id to source the price from the system cache, or a manual prices map keyed by currency code. Per-org management is the org admin's job (RD-1107). The change is written to the RBAC audit log.
// @Tags         Admin: compliance
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        token_address path string true "Token contract address (0x-prefixed) or 'native'"
// @Param        request body apimodels.ComplianceTokenPriceUpsertRequest true "token price fields"
// @Success      200 {object} compliance.TokenPrice
// @Failure      400 {object} apimodels.APIError "invalid body, address, coingecko_id, currency, price, decimals, or symbol"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/tokens/{token_address} [put]
func (s *Server) upsertTokenPrice(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	tokenAddress := strings.ToLower(c.Param("token_address"))

	// Validate token address: must be "native" or a valid 0x-prefixed 20-byte hex address
	if tokenAddress != "native" && !auth.IsValidAddress(tokenAddress) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token_address must be 'native' or a valid 0x-prefixed Ethereum address (42 characters)"})
		return
	}

	var input struct {
		Symbol      string             `json:"symbol" binding:"required"`
		Decimals    int                `json:"decimals"`
		Prices      map[string]float64 `json:"prices"`       // multi-currency: {"usd": 3500, "eur": 3200}
		CoingeckoID *string            `json:"coingecko_id"` // null = manual, "ethereum"/"tether"/"usd-coin" = CoinGecko
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_compliance: invalid token-price body", "err", err)
		return
	}

	isCoingecko := input.CoingeckoID != nil && *input.CoingeckoID != ""
	// Validate coingecko_id against whitelist to prevent arbitrary external API calls
	validCoingeckoIDs := map[string]bool{"ethereum": true, "tether": true, "usd-coin": true}
	if isCoingecko && !validCoingeckoIDs[*input.CoingeckoID] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid coingecko_id; valid values are: ethereum, tether, usd-coin"})
		return
	}

	// Validate currency codes in prices map
	for code := range input.Prices {
		if !compliance.IsValidCurrency(code) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported currency in prices: " + code + "; valid options: usd, eur, chf, gbp, aed"})
			return
		}
		if input.Prices[code] <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "price must be greater than 0 for currency: " + code})
			return
		}
	}

	// For manual pricing, require at least one price via prices map
	if !isCoingecko && len(input.Prices) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "manual pricing requires at least one price; use 'prices' map with currency codes, e.g. {\"usd\": 42.50}"})
		return
	}

	// Validate decimals range (EVM tokens use 0-77; standard tokens 0-18)
	if input.Decimals < 0 || input.Decimals > 77 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decimals must be between 0 and 77"})
		return
	}
	// Validate symbol length
	if len(input.Symbol) > 20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "symbol must be 20 characters or fewer"})
		return
	}

	ctx := c.Request.Context()

	// Check if a price entry already exists
	existing, err := s.db.GetTokenPrice(ctx, orgID, tokenAddress)
	if err != nil {
		internalError(c, "failed to look up token price", err)
		return
	}

	// Build prices_by_currency from input (merge with existing is done atomically in SQL via ||)
	pricesByCurrency := make(map[string]float64)
	for k, v := range input.Prices {
		pricesByCurrency[k] = v
	}

	// Read the org's active currency once (RD-1158: per-org, not global).
	activeCurrency := s.orgCurrency(ctx, orgID)

	// Resolve price_fiat from the prices being submitted (SQL || will merge with existing).
	// If the caller didn't provide a price for the active currency, price_fiat stays 0
	// and the SQL merge will preserve the existing prices_by_currency entry.
	priceFiat := pricesByCurrency[activeCurrency]

	price := &compliance.TokenPrice{
		OrgID:            orgID,
		TokenAddress:     tokenAddress,
		Symbol:           input.Symbol,
		Decimals:         input.Decimals,
		PriceFiat:        priceFiat,
		PricesByCurrency: pricesByCurrency,
		CoingeckoID:      input.CoingeckoID,
	}

	// M2: record updater for ISO-27001 / SOC2 evidence. The SQL schema
	// has the column but the handler previously never populated it,
	// leaving it permanently NULL.
	if uid := c.GetString("admin_user_id"); uid != "" {
		price.UpdatedByUserID = &uid
	}

	var before map[string]any
	action := rbac.AuditActionCreate
	if existing != nil {
		price.ID = existing.ID
		action = rbac.AuditActionUpdate
		before = map[string]any{
			"symbol":             existing.Symbol,
			"decimals":           existing.Decimals,
			"price_fiat":         existing.PriceFiat,
			"prices_by_currency": existing.PricesByCurrency,
			"coingecko_id":       existing.CoingeckoID,
		}
	} else {
		price.ID = uuid.New().String()
	}

	if err := s.db.UpsertTokenPrice(ctx, price, activeCurrency); err != nil {
		internalError(c, "failed to save token price", err)
		return
	}

	// M2: audit-log the mutation.
	s.recordAuditActionScoped(c, action, rbac.ResourceTypeTokenPrice, price.ID, price.Symbol, orgID,
		before,
		map[string]any{
			"symbol":             price.Symbol,
			"decimals":           price.Decimals,
			"price_fiat":         price.PriceFiat,
			"prices_by_currency": price.PricesByCurrency,
			"coingecko_id":       price.CoingeckoID,
			"token_address":      price.TokenAddress,
		})

	c.JSON(http.StatusOK, price)
}

// deleteTokenPrice removes a token price for an org.
//
// @Summary      Delete a token price for an org
// @Description  Removes the configured fiat price for a token in the organization. token_address is "native" or a 0x-prefixed contract address. Per-org management is the org admin's job (RD-1107).
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        token_address path string true "Token contract address (0x-prefixed) or 'native'"
// @Success      200 {object} apimodels.APIMessage "token price deleted"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      404 {object} apimodels.APIError "token price not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/tokens/{token_address} [delete]
func (s *Server) deleteTokenPrice(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	tokenAddress := strings.ToLower(c.Param("token_address"))

	existing, err := s.db.GetTokenPrice(c.Request.Context(), orgID, tokenAddress)
	if err != nil {
		internalError(c, "failed to look up token price", err)
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token price not found"})
		return
	}

	if err := s.db.DeleteTokenPrice(c.Request.Context(), orgID, tokenAddress); err != nil {
		internalError(c, "failed to delete token price", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token price deleted"})
}

// System Token Price handlers

// listSystemTokenPrices returns the global CoinGecko-sourced price cache.
//
// @Summary      List system token prices
// @Description  Returns the fleet-wide system token price cache (populated by the CoinGecko poller) plus the active global base currency. Each entry carries an is_stale flag when its last update is older than the configured staleness threshold. Read-only; any admin token.
// @Tags         Admin: compliance
// @Produce      json
// @Success      200 {object} apimodels.ComplianceSystemTokenPriceListResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/compliance/system-token-prices [get]
func (s *Server) listSystemTokenPrices(c *gin.Context) {
	ctx := c.Request.Context()
	prices, err := s.db.ListSystemTokenPrices(ctx)
	if err != nil {
		internalError(c, "failed to list system token prices", err)
		return
	}

	// Get base currency
	currency, _ := s.db.GetSystemSetting(ctx, "base_currency")
	if currency == "" {
		currency = "usd"
	}

	// Add staleness info
	type systemPriceResponse struct {
		ID           int     `json:"id"`
		CoingeckoID  *string `json:"coingecko_id,omitempty"`
		Symbol       string  `json:"symbol"`
		Decimals     int     `json:"decimals"`
		PriceFiat    float64 `json:"price_fiat"`
		Source       string  `json:"source"`
		TokenAddress *string `json:"token_address,omitempty"`
		UpdatedAt    string  `json:"updated_at"`
		IsStale      bool    `json:"is_stale"`
	}

	staleThreshold := s.config.PriceStalenessThreshold
	result := make([]systemPriceResponse, len(prices))
	for i, p := range prices {
		result[i] = systemPriceResponse{
			ID:           p.ID,
			CoingeckoID:  p.CoingeckoID,
			Symbol:       p.Symbol,
			Decimals:     p.Decimals,
			PriceFiat:    p.PriceFiat,
			Source:       p.Source,
			TokenAddress: p.TokenAddress,
			UpdatedAt:    p.UpdatedAt.Format(time.RFC3339),
			IsStale:      time.Since(p.UpdatedAt) > staleThreshold,
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": result, "currency": currency})
}

// Travel Rule Record handlers

// M5: No rate limit on record creation. This is an admin-only endpoint accessible
// only from localhost. Rate limiting is out of scope for PoC but should be added
// before production deployment.

// createTravelRuleRecord creates a pre-transfer travel-rule record for an org.
//
// @Summary      Create a travel-rule record
// @Description  Creates an IVMS101 travel-rule record (originator/beneficiary data) that satisfies the compliance check for a subsequent transfer above the threshold. The fiat amount is computed server-side from amount_wei and the configured token price — it is never taken from the request. transfer_type is "eth" or "erc20" (token_address required for erc20); the originator must be a member of the org. The response includes an advisory warning when the amount is below the applicable threshold (the record may never be used). Per-org management is the org admin's job (RD-1107).
// @Tags         Admin: compliance
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        request body apimodels.ComplianceTravelRuleRecordCreateRequest true "travel-rule record fields"
// @Success      201 {object} compliance.TravelRuleRecord
// @Failure      400 {object} apimodels.APIError "invalid body, amount, transfer_type, address, or no configured token price"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/travel-rule-records [post]
func (s *Server) createTravelRuleRecord(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	// C3: amount_fiat is NOT accepted from input — it is computed server-side from
	// amount_wei and the configured token price to prevent forged fiat values.
	var input struct {
		OriginatorUserID   string         `json:"originator_user_id" binding:"required"`
		OriginatorData     map[string]any `json:"originator_data" binding:"required"`
		BeneficiaryData    map[string]any `json:"beneficiary_data" binding:"required"`
		TransferType       string         `json:"transfer_type" binding:"required"`
		TokenAddress       *string        `json:"token_address"`
		BeneficiaryAddress string         `json:"beneficiary_address" binding:"required"`
		AmountWei          string         `json:"amount_wei" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_compliance: invalid travel-rule report body", "err", err)
		return
	}

	// H3: Validate amount_wei is a valid positive numeric string
	amountWei, ok := new(big.Int).SetString(input.AmountWei, 10)
	if !ok || amountWei.Sign() <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount_wei must be a positive integer string"})
		return
	}

	// H4: Verify originator_user_id belongs to this org before creating the record.
	// Previously only the DB foreign key was checked, allowing cross-org originator references.
	originatorMemberships, err := s.db.ListUserMembershipsInOrg(c.Request.Context(), input.OriginatorUserID, orgID)
	if err != nil {
		internalError(c, "failed to verify originator org membership", err)
		return
	}
	if len(originatorMemberships) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "originator_user_id is not a member of this organization"})
		return
	}

	// Validate transfer type
	transferType := compliance.TransferType(input.TransferType)
	if transferType != compliance.TransferTypeETH && transferType != compliance.TransferTypeERC20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transfer_type, must be 'eth' or 'erc20'"})
		return
	}

	// H5: Require token_address for ERC-20 records
	if transferType == compliance.TransferTypeERC20 {
		if input.TokenAddress == nil || !auth.IsValidAddress(*input.TokenAddress) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token_address is required and must be a valid address for erc20 transfer type"})
			return
		}
	}

	// Validate beneficiary address
	if !auth.IsValidAddress(input.BeneficiaryAddress) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid beneficiary_address format"})
		return
	}

	// C3: Look up the token price and compute amount_fiat server-side.
	tokenAddr := "native"
	if transferType == compliance.TransferTypeERC20 && input.TokenAddress != nil {
		tokenAddr = strings.ToLower(*input.TokenAddress)
	}

	ctx := c.Request.Context()

	// Per-org currency (RD-1158) — needed for price resolution and the record's
	// currency snapshot.
	currency := s.orgCurrency(ctx, orgID)

	priceFiat, decimals, err := s.resolveTokenPriceForRecord(ctx, orgID, tokenAddr, currency)
	if err != nil {
		internalError(c, "failed to look up token price", err)
		return
	}
	if priceFiat <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no token price configured for " + tokenAddr + " in currency " + strings.ToUpper(currency) + "; configure it in Token Prices first"})
		return
	}

	amountFiat, err := compliance.WeiToFiat(amountWei, decimals, priceFiat)
	if err != nil {
		respondBadRequestAndLog(c, "failed to compute fiat value",
			"admin_compliance: WeiToFiat failed",
			"token_address", tokenAddr, "currency", currency, "err", err)
		return
	}
	if amountFiat <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "computed amount_fiat must be greater than 0"})
		return
	}

	record := &compliance.TravelRuleRecord{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		OriginatorUserID:   input.OriginatorUserID,
		OriginatorData:     input.OriginatorData,
		BeneficiaryData:    input.BeneficiaryData,
		TransferType:       transferType,
		TokenAddress:       lowercasePtr(input.TokenAddress),
		BeneficiaryAddress: strings.ToLower(input.BeneficiaryAddress),
		AmountWei:          input.AmountWei,
		AmountFiat:         amountFiat,
		Currency:           currency,
		ExpiresAt:          time.Now().Add(travelRuleRecordTTL),
	}

	if err := s.db.CreateTravelRuleRecord(c.Request.Context(), record); err != nil {
		internalError(c, "failed to create travel rule record", err)
		return
	}

	// Check if the record amount is below the applicable threshold for this address.
	// If so, include a warning — the record may never be claimed.
	beneficiary := strings.ToLower(input.BeneficiaryAddress)
	config, err := s.db.GetComplianceConfig(ctx, orgID)
	if err == nil && config != nil && config.Enabled {
		threshold := config.ThresholdFiat
		override, err := s.db.GetAddressThresholdOverride(ctx, orgID, beneficiary)
		if err == nil && override != nil {
			threshold = override.ThresholdFiat
		}
		if amountFiat < threshold {
			record.Warning = fmt.Sprintf(
				"Record amount %.2f is below the applicable threshold %.2f for address %s — this record may never be used.",
				amountFiat, threshold, beneficiary,
			)
		}
	}

	c.JSON(http.StatusCreated, record)
}

// listTravelRuleRecords returns an org's travel-rule records (paginated).
//
// @Summary      List travel-rule records
// @Description  Returns the organization's travel-rule records, most recent first, with pagination. Tenant-confidential: not readable with the operator token — use a tier-2 org-admin JWT.
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        limit query int false "Max rows to return (default 50, capped at 1000)"
// @Param        offset query int false "Rows to skip (default 0)"
// @Success      200 {object} apimodels.ComplianceListResponse{data=[]compliance.TravelRuleRecord}
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope, or operator token (tenant data not readable)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/travel-rule-records [get]
func (s *Server) listTravelRuleRecords(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	limit, offset := compliancePaginationParams(c, 50)

	records, total, err := s.db.ListTravelRuleRecords(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		internalError(c, "failed to list travel rule records", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": records, "total": total, "limit": limit, "offset": offset})
}

// deleteTravelRuleRecord deletes an unused travel-rule record.
//
// @Summary      Delete a travel-rule record
// @Description  Deletes a travel-rule record by ID. A record that has already been consumed by a transfer cannot be deleted (409). Per-org management is the org admin's job (RD-1107).
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        id path string true "Travel-rule record ID (UUID)"
// @Success      204 "record deleted"
// @Failure      400 {object} apimodels.APIError "invalid record id format"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      404 {object} apimodels.APIError "travel rule record not found"
// @Failure      409 {object} apimodels.APIError "cannot delete a used travel rule record"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/travel-rule-records/{id} [delete]
func (s *Server) deleteTravelRuleRecord(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	id := c.Param("id")

	// Validate id is a valid UUID
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid record id format"})
		return
	}

	err := s.db.DeleteTravelRuleRecord(c.Request.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "travel rule record not found"})
			return
		}
		if errors.Is(err, db.ErrRecordAlreadyUsed) {
			c.JSON(http.StatusConflict, gin.H{"error": "cannot delete used travel rule record"})
			return
		}
		internalError(c, "failed to delete travel rule record", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// Sanctioned Address handlers

// listSanctionedAddresses returns sanction rows.
//
// Audit H8: pre-fix the ?org_id= query was honoured verbatim — any
// tier-2 admin could enumerate every other org's blocklist. JWT
// admins are now restricted to their own scope (and to global rows
// for super-admin only).
//
// @Summary      List sanctioned addresses
// @Description  Returns blocklisted addresses (global or per-org), paginated. Scope is enforced by caller type: super-admin sees any scope; a tier-2 org-admin JWT must pass an in-scope org_id (global rows are super-admin only); the operator token may read the global list but not a specific org's blocklist.
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id query string false "Restrict to one org's blocklist (required for tier-2 org-admin JWTs; omit for the global list)"
// @Param        limit query int false "Max rows to return (default 50, capped at 1000)"
// @Param        offset query int false "Rows to skip (default 0)"
// @Success      200 {object} apimodels.ComplianceListResponse{data=[]compliance.SanctionedAddress}
// @Failure      400 {object} apimodels.APIError "org_id query parameter is required (tier-2 org-admin JWT)"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org out of scope, or a per-org read attempted with the operator token"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/compliance/sanctions [get]
func (s *Server) listSanctionedAddresses(c *gin.Context) {
	limit, offset := compliancePaginationParams(c, 50)

	var orgID *string
	if q := c.Query("org_id"); q != "" {
		orgID = &q
	}

	// RD-1132: the operator token may read GLOBAL sanctions (fleet) but not a
	// specific org's blocklist (tenant-confidential). Block only the per-org
	// query for operator_token; the global listing (org_id nil) passes.
	if c.GetString("auth_method") == "operator_token" && orgID != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errOperatorNoTenantRead})
		return
	}

	// For JWT admins, the caller MUST specify org_id (and it must be in
	// scope); listing global sanctions (org_id IS NULL) is super-admin
	// only.
	if c.GetString("auth_method") == "jwt_admin" {
		if orgID == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "org_id query parameter is required"})
			return
		}
		if !requireTargetInScope(c, *orgID) {
			return
		}
	}

	addresses, total, err := s.db.ListSanctionedAddresses(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		internalError(c, "failed to list sanctioned addresses", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": addresses, "total": total, "limit": limit, "offset": offset})
}

// addSanctionedAddress adds a row to the compliance blocklist.
//
// Audit C6: pre-fix this accepted any org_id (or nil for "global")
// in the body with no scope check. A tier-2 admin in Org A could
// inject sanctions into Org B's blocklist or create a tenant-wide
// global sanction. Now the org_id must be in caller's scope; global
// (nil) requires super-admin.
//
// @Summary      Add a sanctioned address
// @Description  Adds an address to the compliance blocklist. Omit org_id for a GLOBAL sanction (super-admin only); set it for a per-org sanction (the org admin's job — the operator/super-admin token cannot add per-org rows). Tier-2 org-admin JWTs must scope to an org they fully administer. The address is normalized to lowercase and the action is written to the RBAC audit log.
// @Tags         Admin: compliance
// @Accept       json
// @Produce      json
// @Param        request body apimodels.ComplianceSanctionAddRequest true "sanction fields"
// @Success      201 {object} compliance.SanctionedAddress
// @Failure      400 {object} apimodels.APIError "invalid body, address, or reason too long"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, global requires super-admin, or per-org must be in scope and is not addable with the operator token"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/compliance/sanctions [post]
func (s *Server) addSanctionedAddress(c *gin.Context) {
	// RD-1173: sanctions are compliance controls (per-org = org admin's job,
	// global = super-admin only) — never the platform operator's. Deny the
	// operator token outright; admin_token and jwt_admin keep their existing
	// per-org / global handling below.
	if denyOperatorOrgScoped(c) {
		return
	}
	var input struct {
		OrgID   *string `json:"org_id"`
		Address string  `json:"address" binding:"required"`
		Reason  string  `json:"reason" binding:"required"`
		Source  string  `json:"source"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if !auth.IsValidAddress(input.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}
	// Validate reason length
	if len(input.Reason) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason must be 1000 characters or fewer"})
		return
	}

	// Cross-org gate. JWT admins must scope to their own org; global
	// sanctions (org_id == nil) require super-admin.
	if c.GetString("auth_method") == "jwt_admin" {
		if input.OrgID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "only super-admin can add global sanctions"})
			return
		}
		if !requireFullAdminInScope(c, *input.OrgID) {
			return
		}
	}
	// RD-1107: a PER-ORG sanction (org_id set) is the org admin's job; the
	// super-admin token may only manage GLOBAL sanctions (org_id nil).
	if c.GetString("auth_method") == "operator_token" && input.OrgID != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errOperatorNoTenantMgmt})
		return
	}

	sanction := &compliance.SanctionedAddress{
		ID:      uuid.New().String(),
		OrgID:   input.OrgID,
		Address: strings.ToLower(input.Address),
		Reason:  input.Reason,
		Source:  input.Source,
	}

	if err := s.db.AddSanctionedAddress(c.Request.Context(), sanction); err != nil {
		internalError(c, "failed to add sanctioned address", err)
		return
	}

	scopeOrgID := ""
	if sanction.OrgID != nil {
		scopeOrgID = *sanction.OrgID
	}
	s.recordAuditActionScoped(c, rbac.AuditActionCreate, rbac.ResourceTypeSanction, sanction.ID, sanction.Address, scopeOrgID,
		nil,
		map[string]any{
			"address": sanction.Address,
			"reason":  sanction.Reason,
			"source":  sanction.Source,
			"org_id":  sanction.OrgID,
		})

	c.JSON(http.StatusCreated, sanction)
}

// removeSanctionedAddress deletes a sanction row.
//
// Audit C7: pre-fix the handler resolved the row's org_id but never
// compared it to the caller's scope. A tier-2 admin in Org A could
// delete sanctions added by any org or globally — silently weakening
// any other tenant's blocklist. Now the loaded row's org_id must be
// in caller's full-admin scope; deletion of global rows requires
// super-admin.
//
// @Summary      Remove a sanctioned address
// @Description  Removes a sanction from the blocklist by ID. Removing a global row requires super-admin; removing a per-org row is the org admin's job (in scope) and is not permitted with the operator/super-admin token. To avoid a cross-org existence oracle, an unknown ID and an out-of-scope row both return the same opaque 403. The action is written to the RBAC audit log.
// @Tags         Admin: compliance
// @Produce      json
// @Param        id path string true "Sanction row ID (UUID)"
// @Success      200 {object} apimodels.APIMessage "sanctioned address removed"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, row not found, out of scope, global requires super-admin, or per-org not removable with the operator token"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/compliance/sanctions/{id} [delete]
func (s *Server) removeSanctionedAddress(c *gin.Context) {
	// RD-1173: the operator token must not touch sanctions (per-org or
	// global). admin_token/jwt_admin keep their existing handling below.
	if denyOperatorOrgScoped(c) {
		return
	}
	id := c.Param("id")

	existing, err := s.db.GetSanctionedAddress(c.Request.Context(), id)
	if err != nil {
		internalError(c, "failed to look up sanctioned address", err)
		return
	}
	if existing == nil {
		// Generic 403 to avoid existence oracle across orgs.
		c.JSON(http.StatusForbidden, gin.H{"error": errTargetForeignOrg})
		return
	}

	if c.GetString("auth_method") == "jwt_admin" {
		if existing.OrgID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "only super-admin can remove global sanctions"})
			return
		}
		if !requireFullAdminInScope(c, *existing.OrgID) {
			return
		}
	}
	// RD-1107: removing a PER-ORG sanction (org_id set) is the org admin's job;
	// the super-admin token may only manage GLOBAL sanctions (org_id nil).
	if c.GetString("auth_method") == "operator_token" && existing.OrgID != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errOperatorNoTenantMgmt})
		return
	}

	if err := s.db.RemoveSanctionedAddress(c.Request.Context(), id); err != nil {
		internalError(c, "failed to remove sanctioned address", err)
		return
	}

	scopeOrgID := ""
	if existing.OrgID != nil {
		scopeOrgID = *existing.OrgID
	}
	s.recordAuditActionScoped(c, rbac.AuditActionDelete, rbac.ResourceTypeSanction, existing.ID, existing.Address, scopeOrgID,
		map[string]any{
			"address": existing.Address,
			"reason":  existing.Reason,
			"source":  existing.Source,
			"org_id":  existing.OrgID,
		}, nil)

	c.JSON(http.StatusOK, gin.H{"message": "sanctioned address removed"})
}

// Address Threshold Override handlers

// listAddressThresholdOverrides returns an org's per-address threshold overrides.
//
// @Summary      List address threshold overrides
// @Description  Returns the organization's per-address travel-rule threshold overrides (paginated). An override takes precedence over the org-level threshold for that address. Tenant-confidential: not readable with the operator token — use a tier-2 org-admin JWT.
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        limit query int false "Max rows to return (default 50, capped at 1000)"
// @Param        offset query int false "Rows to skip (default 0)"
// @Success      200 {object} apimodels.ComplianceListResponse{data=[]compliance.AddressThresholdOverride}
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope, or operator token (tenant data not readable)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/address-thresholds [get]
func (s *Server) listAddressThresholdOverrides(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	limit, offset := compliancePaginationParams(c, 50)

	overrides, total, err := s.db.ListAddressThresholdOverrides(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		internalError(c, "failed to list address threshold overrides", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": overrides, "total": total, "limit": limit, "offset": offset})
}

// upsertAddressThresholdOverride creates or updates a per-address threshold override.
//
// @Summary      Set an address threshold override
// @Description  Creates or updates a per-address travel-rule threshold override for the organization. The override replaces the org-level threshold when valuing transfers involving that address. Per-org management is the org admin's job (RD-1107).
// @Tags         Admin: compliance
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Address (0x-prefixed hex) the override applies to"
// @Param        request body apimodels.ComplianceThresholdOverrideUpsertRequest true "override fields"
// @Success      200 {object} compliance.AddressThresholdOverride
// @Failure      400 {object} apimodels.APIError "invalid address, body, negative threshold, or note too long"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/address-thresholds/{address} [put]
func (s *Server) upsertAddressThresholdOverride(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := strings.ToLower(c.Param("address"))

	if !auth.IsValidAddress(address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}

	var input struct {
		ThresholdFiat float64 `json:"threshold_fiat"`
		Note          string  `json:"note"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_compliance: invalid address-threshold body", "address", address, "err", err)
		return
	}
	if input.ThresholdFiat < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threshold_fiat must be >= 0"})
		return
	}
	if len(input.Note) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "note must be 1000 characters or fewer"})
		return
	}

	// Check if an override already exists
	existing, err := s.db.GetAddressThresholdOverride(c.Request.Context(), orgID, address)
	if err != nil {
		internalError(c, "failed to look up address threshold override", err)
		return
	}

	override := &compliance.AddressThresholdOverride{
		OrgID:         orgID,
		Address:       address,
		ThresholdFiat: input.ThresholdFiat,
		Note:          input.Note,
	}

	if existing != nil {
		override.ID = existing.ID
	} else {
		override.ID = uuid.New().String()
	}

	if err := s.db.UpsertAddressThresholdOverride(c.Request.Context(), override); err != nil {
		internalError(c, "failed to save address threshold override", err)
		return
	}

	c.JSON(http.StatusOK, override)
}

// deleteAddressThresholdOverride removes a per-address threshold override.
//
// @Summary      Delete an address threshold override
// @Description  Removes a per-address threshold override for the organization; the org-level threshold then applies to that address again. Per-org management is the org admin's job (RD-1107).
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Address (0x-prefixed hex) the override applies to"
// @Success      200 {object} apimodels.APIMessage "address threshold override deleted"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope (read-only admins cannot mutate), or operator token (per-org management is the org admin's job)"
// @Failure      404 {object} apimodels.APIError "address threshold override not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/address-thresholds/{address} [delete]
func (s *Server) deleteAddressThresholdOverride(c *gin.Context) {
	// RD-1107: per-org compliance management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := strings.ToLower(c.Param("address"))

	existing, err := s.db.GetAddressThresholdOverride(c.Request.Context(), orgID, address)
	if err != nil {
		internalError(c, "failed to look up address threshold override", err)
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "address threshold override not found"})
		return
	}

	if err := s.db.DeleteAddressThresholdOverride(c.Request.Context(), orgID, address); err != nil {
		internalError(c, "failed to delete address threshold override", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "address threshold override deleted"})
}

// Compliance Log handlers

// listComplianceLogs returns an org's compliance decision log (paginated).
//
// @Summary      List compliance decision logs
// @Description  Returns the organization's immutable compliance decision log (each allowed/denied transfer decision), paginated and filterable. Tenant-confidential: not readable with the operator token — use a tier-2 org-admin JWT.
// @Tags         Admin: compliance
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        limit query int false "Max rows to return (default 50, capped at 1000)"
// @Param        offset query int false "Rows to skip (default 0)"
// @Param        user_search query string false "Filter by originating user (substring match)"
// @Param        decision query string false "Filter by decision" Enums(allowed, denied)
// @Param        transfer_type query string false "Filter by transfer type" Enums(eth, erc20)
// @Success      200 {object} apimodels.ComplianceListResponse{data=[]compliance.ComplianceLog}
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, org outside the caller's scope, or operator token (tenant data not readable)"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/compliance/logs [get]
func (s *Server) listComplianceLogs(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	limit, offset := compliancePaginationParams(c, 50)

	filters := &compliance.ComplianceLogFilters{
		Limit:  limit,
		Offset: offset,
	}

	if userSearch := c.Query("user_search"); userSearch != "" {
		filters.UserSearch = &userSearch
	}
	// Whitelist decision values
	if decision := c.Query("decision"); decision == "allowed" || decision == "denied" {
		filters.Decision = &decision
	}
	// Whitelist transfer_type values
	if transferType := c.Query("transfer_type"); transferType == "eth" || transferType == "erc20" {
		tt := compliance.TransferType(transferType)
		filters.TransferType = &tt
	}

	logs, total, err := s.db.ListComplianceLogs(c.Request.Context(), orgID, filters)
	if err != nil {
		internalError(c, "failed to list compliance logs", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "limit": limit, "offset": offset})
}

// resolveTokenPriceForRecord resolves the effective price and decimals for a token,
// using the same fallback chain as the compliance checker.
func (s *Server) resolveTokenPriceForRecord(ctx context.Context, orgID, tokenAddr, activeCurrency string) (float64, int, error) {
	tokenPrice, err := s.db.GetTokenPrice(ctx, orgID, tokenAddr)
	if err != nil {
		return 0, 0, err
	}

	if tokenPrice != nil {
		if tokenPrice.CoingeckoID != nil && *tokenPrice.CoingeckoID != "" {
			sysPrice, err := s.db.GetSystemTokenPrice(ctx, *tokenPrice.CoingeckoID)
			if err != nil {
				return 0, 0, err
			}
			if sysPrice != nil {
				if sysPrice.PricesByCurrency != nil {
					if price, ok := sysPrice.PricesByCurrency[activeCurrency]; ok && price > 0 {
						return price, tokenPrice.Decimals, nil
					}
				}
				if sysPrice.PriceFiat > 0 {
					return sysPrice.PriceFiat, tokenPrice.Decimals, nil
				}
			}
			// System price unavailable — fail closed (no silent fallback)
			return 0, 0, nil
		}
		// Manual price: resolve from prices_by_currency
		if len(tokenPrice.PricesByCurrency) > 0 {
			if price, ok := tokenPrice.PricesByCurrency[activeCurrency]; ok && price > 0 {
				return price, tokenPrice.Decimals, nil
			}
			// prices_by_currency is populated but doesn't have the active currency
			return 0, 0, nil
		}
		// Legacy: prices_by_currency not populated, use price_fiat
		if tokenPrice.PriceFiat > 0 {
			return tokenPrice.PriceFiat, tokenPrice.Decimals, nil
		}
		return 0, 0, nil
	}

	// Auto-resolve native from system ethereum price
	if tokenAddr == "native" {
		sysPrice, err := s.db.GetSystemTokenPrice(ctx, "ethereum")
		if err != nil {
			return 0, 0, err
		}
		if sysPrice != nil {
			if sysPrice.PricesByCurrency != nil {
				if price, ok := sysPrice.PricesByCurrency[activeCurrency]; ok && price > 0 {
					return price, sysPrice.Decimals, nil
				}
			}
			if sysPrice.PriceFiat > 0 {
				return sysPrice.PriceFiat, sysPrice.Decimals, nil
			}
		}
	}

	return 0, 0, nil
}

// lowercasePtr returns a pointer to the lowercased string, or nil if the input is nil.
func lowercasePtr(s *string) *string {
	if s == nil {
		return nil
	}
	lower := strings.ToLower(*s)
	return &lower
}

// Currency admin endpoints

// getBaseCurrency returns the global base currency and supported currencies.
//
// @Summary      Get the global base currency
// @Description  Returns the fleet-wide default (base) currency, the full list of supported fiat currencies, and whether CoinGecko price polling is enabled. This is the platform-wide fallback; each org can override it with its own per-org currency (RD-1158). Read-only; any admin token.
// @Tags         Admin: compliance
// @Produce      json
// @Success      200 {object} apimodels.ComplianceBaseCurrencyResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/compliance/currency [get]
func (s *Server) getBaseCurrency(c *gin.Context) {
	currency, err := s.db.GetSystemSetting(c.Request.Context(), "base_currency")
	if err != nil {
		internalError(c, "failed to get base currency", err)
		return
	}
	if currency == "" {
		currency = "usd"
	}

	type currencyInfo struct {
		Code   string `json:"code"`
		Name   string `json:"name"`
		Symbol string `json:"symbol"`
	}

	allCurrencies := make([]currencyInfo, 0, len(compliance.ValidCurrencies))
	for code, name := range compliance.ValidCurrencies {
		allCurrencies = append(allCurrencies, currencyInfo{
			Code:   string(code),
			Name:   name,
			Symbol: compliance.CurrencySymbols[code],
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"currency":          currency,
		"all_currencies":    allCurrencies,
		"coingecko_enabled": !s.config.DisableCoinGecko,
	})
}

// setBaseCurrency switches the cluster-wide compliance base currency.
//
// Audit C5: pre-fix this mutation was reachable by any tier-2 JWT
// admin, allowing a malicious admin in Org A to fail-close every
// other org's value transfers by switching to a currency whose
// prices they don't have. Restrict to super-admin (X-Admin-Token);
// it's a platform-wide setting that affects every tenant.
//
// @Summary      Set the global base currency
// @Description  Switches the fleet-wide base currency and re-values the cached system and manual token prices from their stored multi-currency prices. Super-admin only — it is a platform-wide setting affecting every tenant. If manual token prices are missing for the target currency, the switch is refused with 409 and the affected tokens unless force=true is set (those tokens then block transfers until priced). The change is written to the RBAC audit log.
// @Tags         Admin: compliance
// @Accept       json
// @Produce      json
// @Param        request body apimodels.ComplianceSetBaseCurrencyRequest true "target currency and force flag"
// @Success      200 {object} apimodels.ComplianceSetBaseCurrencyResponse
// @Failure      400 {object} apimodels.APIError "invalid body or unsupported currency"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "source address not on the private network, or super-admin token required"
// @Failure      409 {object} apimodels.ComplianceCurrencyConflictResponse "manual token prices missing for the target currency; set force=true"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/compliance/currency [put]
func (s *Server) setBaseCurrency(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	var input struct {
		Currency string `json:"currency" binding:"required"`
		Force    bool   `json:"force"` // set true to switch even if manual tokens lack prices for this currency
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if !compliance.IsValidCurrency(input.Currency) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported currency; valid options: usd, eur, chf, gbp, aed"})
		return
	}

	ctx := c.Request.Context()

	// Check for manual per-org tokens that don't have a price for the target currency
	manualTokens, err := s.db.ListAllManualTokenPrices(ctx)
	if err != nil {
		internalError(c, "failed to list manual token prices for currency switch check", err)
		return
	}

	type affectedToken struct {
		OrgID        string `json:"org_id"`
		TokenAddress string `json:"token_address"`
		Symbol       string `json:"symbol"`
	}
	var affected []affectedToken
	for _, tp := range manualTokens {
		if tp.PricesByCurrency == nil {
			// Legacy token without multi-currency prices — affected if price_fiat > 0
			if tp.PriceFiat > 0 {
				affected = append(affected, affectedToken{OrgID: tp.OrgID, TokenAddress: tp.TokenAddress, Symbol: tp.Symbol})
			}
			continue
		}
		if _, ok := tp.PricesByCurrency[input.Currency]; !ok {
			affected = append(affected, affectedToken{OrgID: tp.OrgID, TokenAddress: tp.TokenAddress, Symbol: tp.Symbol})
		}
	}

	if len(affected) > 0 && !input.Force {
		c.JSON(http.StatusConflict, gin.H{
			"error":           fmt.Sprintf("%d manual token price(s) do not have a price set for %s; these tokens will block transactions until prices are configured. Set force=true to switch anyway.", len(affected), strings.ToUpper(input.Currency)),
			"affected_tokens": affected,
			"currency":        input.Currency,
		})
		return
	}

	// Save the new currency
	if err := s.db.SetSystemSetting(ctx, "base_currency", input.Currency); err != nil {
		internalError(c, "failed to set base currency", err)
		return
	}

	// Update system token price_fiat from stored prices_by_currency
	sysPrices, err := s.db.ListSystemTokenPrices(ctx)
	if err != nil {
		// Revert: currency was set but prices couldn't be loaded — revert is best-effort
		slog.Error("failed to list system token prices after currency change", "error", err)
		internalError(c, "currency saved but failed to update system prices; retry the switch", err)
		return
	}
	for _, p := range sysPrices {
		if p.Source == "coingecko" && p.PricesByCurrency != nil {
			if newPrice, ok := p.PricesByCurrency[input.Currency]; ok {
				p.PriceFiat = newPrice
			} else {
				p.PriceFiat = 0
			}
			if err := s.db.UpsertSystemTokenPrice(ctx, p); err != nil {
				slog.Error("failed to update system price during currency switch", "symbol", p.Symbol, "error", err)
				internalError(c, "failed to update system prices during currency switch", err)
				return
			}
		}
	}

	// Update manual per-org token price_fiat from prices_by_currency
	for _, tp := range manualTokens {
		if tp.PricesByCurrency != nil {
			if newPrice, ok := tp.PricesByCurrency[input.Currency]; ok {
				tp.PriceFiat = newPrice
			} else {
				tp.PriceFiat = 0 // No price for this currency — will block transactions (fail closed)
			}
			if err := s.db.UpsertTokenPrice(ctx, tp, input.Currency); err != nil {
				slog.Error("failed to update token price during currency switch", "org_id", tp.OrgID, "symbol", tp.Symbol, "error", err)
				internalError(c, "failed to update token prices during currency switch", err)
				return
			}
		}
	}

	// M18: kick a fresh CoinGecko poll so any currency that wasn't in
	// the cached prices_by_currency at switch time is populated as
	// soon as possible — without this, system tokens with no cached
	// price for the new currency stay at zero (fail-closed) until the
	// next scheduled refresh.
	if s.priceService != nil {
		s.priceService.RefreshNow()
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeBaseCurrency, "system", "base_currency",
		nil,
		map[string]any{
			"currency":        input.Currency,
			"force":           input.Force,
			"affected_tokens": len(affected),
		})

	resp := gin.H{
		"currency": input.Currency,
		"message":  "Base currency updated to " + strings.ToUpper(input.Currency) + ".",
	}
	if len(affected) > 0 {
		resp["warning"] = fmt.Sprintf("%d manual token(s) lack prices for %s and will block transactions until updated.", len(affected), strings.ToUpper(input.Currency))
		resp["affected_tokens"] = affected
	}
	c.JSON(http.StatusOK, resp)
}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
