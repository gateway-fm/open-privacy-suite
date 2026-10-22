package compliance

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"strings"
	"time"
)

// Checker performs compliance checks on value transfers.
type Checker struct {
	store                   Store
	recordExpiry            time.Duration // how long travel rule records stay valid
	priceStalenessThreshold time.Duration // after this duration, system prices are considered stale
	// defaultMode is the cluster-wide enforcement mode applied when a per-org
	// compliance config leaves EnforcementMode unset. Empty resolves to
	// enforce. Set once at startup via SetDefaultEnforcementMode from the
	// COMPLIANCE_DEFAULT_MODE env var.
	defaultMode EnforcementMode
}

// NewChecker creates a new compliance checker.
func NewChecker(store Store, recordExpiry time.Duration, priceStalenessThreshold time.Duration) *Checker {
	return &Checker{
		store:                   store,
		recordExpiry:            recordExpiry,
		priceStalenessThreshold: priceStalenessThreshold,
	}
}

// SetDefaultEnforcementMode sets the cluster-wide fallback enforcement mode,
// applied when a per-org compliance config leaves EnforcementMode unset. An
// empty or unrecognised value pins the default at enforce (fail-safe). Wired
// once at startup from the COMPLIANCE_DEFAULT_MODE env var.
func (c *Checker) SetDefaultEnforcementMode(mode EnforcementMode) {
	if mode == EnforcementMonitor {
		c.defaultMode = EnforcementMonitor
		return
	}
	c.defaultMode = EnforcementEnforce
}

// effectiveMode resolves the enforcement mode for one check: a per-org config
// value wins; an unset per-org value falls back to the cluster default; that
// in turn defaults to enforce. Fail-safe — anything unrecognised => enforce.
func (c *Checker) effectiveMode(config *ComplianceConfig) EnforcementMode {
	if config != nil {
		switch config.EnforcementMode {
		case EnforcementMonitor:
			return EnforcementMonitor
		case EnforcementEnforce:
			return EnforcementEnforce
		}
	}
	// Per-org mode unset — use the cluster default.
	if c.defaultMode == EnforcementMonitor {
		return EnforcementMonitor
	}
	return EnforcementEnforce
}

// allowMonitored records a would-have-blocked violation under monitor mode and
// allows the transfer to proceed. The fail-closed-on-log-failure invariant is
// preserved: if the audit row cannot be persisted we DENY rather than silently
// allow — a monitored violation with no forensic record defeats the purpose of
// monitor mode and would break the ISO 27001 / FATF evidence trail.
//
// Sanctions never reach this path; callers only invoke it for monitor-eligible
// violations (threshold-breach, travel-rule-record-required, unknown-price).
func (c *Checker) allowMonitored(ctx context.Context, req *CheckRequest, info *TransferInfo,
	amountFiat, thresholdFiat *float64, blockReason, currency string) (*CheckResult, error) {
	slog.Warn("compliance MONITOR mode: violation allowed but recorded (would have blocked under enforce)",
		"org", req.OrgID, "user", req.UserID, "reason", blockReason)
	if err := c.logWouldBlock(ctx, req, info, amountFiat, thresholdFiat, blockReason, currency); err != nil {
		slog.Error("compliance monitor: failed to persist would-block log, failing closed",
			"org", req.OrgID, "user", req.UserID, "error", err)
		return &CheckResult{
			Allowed:      false,
			Reason:       "compliance audit log unavailable, failing closed",
			TransferInfo: info,
		}, nil
	}
	return &CheckResult{
		Allowed:      true,
		Monitored:    true,
		Reason:       "monitor mode (would block): " + blockReason,
		TransferInfo: info,
	}, nil
}

// logWouldBlock writes a compliance_logs row for a monitor-mode violation:
// Decision="allowed" (the transfer proceeded) with would_block=true and the
// real reason in denial_reason. Kept separate from logDecision so the
// would_block flag is explicit at every monitor call site.
func (c *Checker) logWouldBlock(ctx context.Context, req *CheckRequest, info *TransferInfo,
	amountFiat, thresholdFiat *float64, blockReason, currency string) error {
	reason := blockReason
	entry := &ComplianceLog{
		OrgID:         req.OrgID,
		UserID:        req.UserID,
		TransferType:  info.Type,
		TokenAddress:  info.TokenAddress,
		FromAddress:   info.FromAddress,
		ToAddress:     info.ToAddress,
		AmountWei:     info.AmountWei.String(),
		AmountFiat:    amountFiat,
		ThresholdFiat: thresholdFiat,
		Currency:      currency,
		Decision:      "allowed",
		DenialReason:  &reason,
		WouldBlock:    true,
		CorrelationID: req.CorrelationID,
	}
	_, err := c.store.CreateComplianceLog(ctx, entry)
	return err
}

// CheckRequest contains the parameters for a compliance check.
type CheckRequest struct {
	OrgID         string
	UserID        string // internal user UUID
	From          string // sender address (hex)
	To            string // recipient address (hex)
	Data          string // calldata (hex)
	Value         string // transfer value (hex)
	CorrelationID string // request correlation ID for audit trail
}

// CheckResult is the outcome of a compliance check.
type CheckResult struct {
	Allowed      bool
	Reason       string
	TransferInfo *TransferInfo
	// Monitored is true when Allowed was forced true by monitor mode for a
	// violation that would have blocked under enforce mode. Callers use it to
	// emit a distinct metric / log line; the violation is also recorded in the
	// compliance audit log with would_block=true.
	Monitored bool
}

// Check performs a compliance check on the given transaction.
func (c *Checker) Check(ctx context.Context, req *CheckRequest) (*CheckResult, error) {
	// Step 1: Detect if this is a value transfer
	info := DetectTransfer(req.From, req.To, req.Data, req.Value)
	if info == nil {
		return &CheckResult{
			Allowed: true,
			Reason:  "not a value transfer",
		}, nil
	}

	// Step 2: Check if compliance is enabled for this org
	config, err := c.store.GetComplianceConfig(ctx, req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance config: %w", err)
	}
	if config == nil || !config.Enabled {
		return &CheckResult{
			Allowed:      true,
			Reason:       "compliance not enabled for org",
			TransferInfo: info,
		}, nil
	}

	// Per-org currency (RD-1158): the transfer is valued in — and threshold_fiat
	// is denominated in — this org's own currency, not a cluster-wide setting, so
	// one org's currency choice can never fail-close another. Read once for the
	// whole decision (valuation + audit snapshot). Defensive fallback for a
	// pre-RD-1158 / unset config: the global base_currency default, then usd.
	// Production rows always have currency set (migration 068 default 'usd'), so
	// the global is never consulted when a per-org currency exists.
	currency := config.Currency
	if currency == "" {
		currency, _ = c.store.GetSystemSetting(ctx, "base_currency")
	}
	if currency == "" {
		currency = "usd"
	}

	// Step 3: Sanctions check (sender, recipient, and tx originator if different)

	// For transferFrom, info.FromAddress is the allowance owner, but req.From is the
	// actual spender (msg.sender). Check the spender first if they differ.
	if req.From != "" && strings.ToLower(req.From) != strings.ToLower(info.FromAddress) {
		sanctionedSpender, err := c.store.IsAddressSanctioned(ctx, req.OrgID, req.From)
		if err != nil {
			return nil, fmt.Errorf("failed to check sanctions for spender address: %w", err)
		}
		if sanctionedSpender {
			reason := fmt.Sprintf("transaction sender %s is sanctioned", req.From)
			slog.Warn("compliance denied", "org", req.OrgID, "user", req.UserID, "reason", reason)
			// M11: denial paths previously warned on log failure and
			// still returned deny — escalate to slog.Error and surface
			// a retryable internal-error so the audit row can be
			// persisted on retry.
			if err := c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil, currency); err != nil {
				slog.Error("compliance: failed to persist denial log, failing closed retryable", "org", req.OrgID, "user", req.UserID, "error", err)
				return nil, fmt.Errorf("compliance audit log unavailable")
			}
			return &CheckResult{
				Allowed:      false,
				Reason:       reason,
				TransferInfo: info,
			}, nil
		}
	}

	sanctionedTo, err := c.store.IsAddressSanctioned(ctx, req.OrgID, info.ToAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check sanctions for to address: %w", err)
	}
	if sanctionedTo {
		reason := fmt.Sprintf("recipient address %s is sanctioned", info.ToAddress)
		slog.Warn("compliance denied", "org", req.OrgID, "user", req.UserID, "reason", reason)
		// M11: denial paths previously warned on log failure and still
		// returned deny, leaving no forensic row for ISO 27001 / FATF
		// evidence. Escalate to slog.Error and surface a retryable
		// internal-error so the audit row can be persisted on retry.
		if err := c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil, currency); err != nil {
			slog.Error("compliance: failed to persist denial log, failing closed retryable", "org", req.OrgID, "user", req.UserID, "error", err)
			return nil, fmt.Errorf("compliance audit log unavailable")
		}
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	sanctionedFrom, err := c.store.IsAddressSanctioned(ctx, req.OrgID, info.FromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check sanctions for from address: %w", err)
	}
	if sanctionedFrom {
		reason := fmt.Sprintf("sender address %s is sanctioned", info.FromAddress)
		slog.Warn("compliance denied", "org", req.OrgID, "user", req.UserID, "reason", reason)
		// M11: denial paths previously warned on log failure and still
		// returned deny, leaving no forensic row for ISO 27001 / FATF
		// evidence. Escalate to slog.Error and surface a retryable
		// internal-error so the audit row can be persisted on retry.
		if err := c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil, currency); err != nil {
			slog.Error("compliance: failed to persist denial log, failing closed retryable", "org", req.OrgID, "user", req.UserID, "error", err)
			return nil, fmt.Errorf("compliance audit log unavailable")
		}
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Step 4: Calculate fiat value
	tokenAddr := "native"
	if info.TokenAddress != nil {
		tokenAddr = strings.ToLower(*info.TokenAddress)
	}

	// Resolve token price with fallback chain:
	// 1. Per-org token_prices entry with coingecko_id → system price
	// 2. Per-org token_prices entry without coingecko_id → manual price
	// 3. No per-org entry + native token → auto-resolve from system "ethereum" price
	// 4. No entry → fail closed
	priceFiat, decimals, err := c.resolveTokenPrice(ctx, req.OrgID, tokenAddr, currency)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve token price: %w", err)
	}
	if priceFiat < 0 {
		// Sentinel: price unavailable
		if config.UnknownPricePolicy == UnknownPriceAllowed {
			reason := fmt.Sprintf("no price configured for token %s, allowing per unknown price policy", tokenAddr)
			slog.Info("compliance allowed (unknown price policy)", "org", req.OrgID, "user", req.UserID, "reason", reason)
			if err := c.logDecision(ctx, req, info, nil, nil, "allowed", "", nil, currency); err != nil {
				slog.Error("failed to log allowed decision, failing closed", "org", req.OrgID, "user", req.UserID, "error", err)
				return &CheckResult{
					Allowed:      false,
					Reason:       "compliance audit log unavailable, failing closed",
					TransferInfo: info,
				}, nil
			}
			return &CheckResult{
				Allowed:      true,
				Reason:       reason,
				TransferInfo: info,
			}, nil
		}

		reason := fmt.Sprintf("no price configured for token %s and unknown price policy is forbidden", tokenAddr)
		// Monitor mode: record the would-block and allow the transfer. Sanctions
		// were already hard-checked above and are never monitor-eligible.
		if c.effectiveMode(config) == EnforcementMonitor {
			return c.allowMonitored(ctx, req, info, nil, nil, reason, currency)
		}
		slog.Warn("compliance denied (fail closed)", "org", req.OrgID, "user", req.UserID, "reason", reason)
		if err := c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil, currency); err != nil {
			slog.Warn("failed to log denial decision", "org", req.OrgID, "user", req.UserID, "error", err)
		}
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Convert amountWei to fiat: amountWei / 10^decimals * priceFiat
	amountFiat, err := WeiToFiat(info.AmountWei, decimals, priceFiat)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate fiat value: %w", err)
	}

	// Determine threshold: per-address overrides take precedence over org config.
	threshold, err := c.resolveThreshold(ctx, req.OrgID, config, info.FromAddress, info.ToAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve threshold: %w", err)
	}

	// Step 5: Below threshold -> allow
	// M1: Strict `<` is intentional per FATF guidance. The threshold is the ceiling
	// below which no travel rule record is needed. A transfer of exactly the threshold
	// amount requires a record. Example: threshold $1000, transfer $1000 -> record needed.
	if amountFiat < threshold {
		reason := fmt.Sprintf("transfer value $%.2f below threshold $%.2f", amountFiat, threshold)
		slog.Info("compliance allowed", "org", req.OrgID, "user", req.UserID, "reason", reason)
		// M2: Allowed decision — fail closed on log failure. Allowing a transaction
		// without an audit trail is a compliance violation. Deny instead.
		if err := c.logDecision(ctx, req, info, &amountFiat, &threshold, "allowed", "", nil, currency); err != nil {
			slog.Error("failed to log allowed decision, failing closed", "org", req.OrgID, "user", req.UserID, "error", err)
			return &CheckResult{
				Allowed:      false,
				Reason:       "compliance audit log unavailable, failing closed",
				TransferInfo: info,
			}, nil
		}
		return &CheckResult{
			Allowed:      true,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Step 6: Above threshold -> atomically claim a travel rule record
	// Uses ClaimUnusedTravelRuleRecord which does UPDATE ... FOR UPDATE SKIP LOCKED
	// in a single query to prevent TOCTOU race conditions.
	// The record must cover the transfer amount (amount_fiat >= amountFiat).
	record, err := c.store.ClaimUnusedTravelRuleRecord(ctx, req.OrgID, req.UserID, info.ToAddress, tokenAddr, amountFiat)
	if err != nil {
		return nil, fmt.Errorf("failed to claim travel rule record: %w", err)
	}
	if record == nil {
		reason := fmt.Sprintf("transfer value $%.2f exceeds threshold $%.2f and no travel rule record found", amountFiat, threshold)
		// Monitor mode: record the would-block and allow the transfer. Sanctions
		// were already hard-checked above and are never monitor-eligible.
		if c.effectiveMode(config) == EnforcementMonitor {
			return c.allowMonitored(ctx, req, info, &amountFiat, &threshold, reason, currency)
		}
		slog.Warn("compliance denied", "org", req.OrgID, "user", req.UserID, "reason", reason)
		// M2: Denial — warn on log failure, still deny.
		if err := c.logDecision(ctx, req, info, &amountFiat, &threshold, "denied", reason, nil, currency); err != nil {
			slog.Warn("failed to log denial decision", "org", req.OrgID, "user", req.UserID, "error", err)
		}
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// M4: Record consumed even if transfer amount is much less than record amount.
	// This is intentional per travel rule semantics — each transfer above threshold needs
	// its own authorization. The record covers a specific planned transfer, not a balance.
	reason := fmt.Sprintf("transfer value $%.2f exceeds threshold $%.2f, travel rule record %s applied", amountFiat, threshold, record.ID)
	slog.Info("compliance allowed", "org", req.OrgID, "user", req.UserID, "reason", reason)
	// M2: Allowed decision — fail closed on log failure.
	if err := c.logDecision(ctx, req, info, &amountFiat, &threshold, "allowed", "", &record.ID, currency); err != nil {
		slog.Error("failed to log allowed decision, failing closed", "org", req.OrgID, "user", req.UserID, "error", err)
		return &CheckResult{
			Allowed:      false,
			Reason:       "compliance audit log unavailable, failing closed",
			TransferInfo: info,
		}, nil
	}
	return &CheckResult{
		Allowed:      true,
		Reason:       reason,
		TransferInfo: info,
	}, nil
}

// CheckPreview evaluates compliance without logs or travel-rule record claims.
func (c *Checker) CheckPreview(ctx context.Context, req *CheckRequest) (*CheckResult, error) {
	preview := *c
	preview.store = previewStore{Store: c.store}
	return preview.Check(ctx, req)
}

type previewStore struct {
	Store
}

func (s previewStore) ClaimUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*TravelRuleRecord, error) {
	return s.FindUnusedTravelRuleRecord(ctx, orgID, userID, beneficiaryAddr, tokenAddr, amountFiat)
}

func (previewStore) CreateComplianceLog(context.Context, *ComplianceLog) (int64, error) {
	return 0, nil
}

// resolveTokenPrice implements the price fallback chain.
// Returns (priceFiat, decimals, error). A negative priceFiat signals "not found / fail closed".
func (c *Checker) resolveTokenPrice(ctx context.Context, orgID, tokenAddr, activeCurrency string) (float64, int, error) {
	// Step 1: Check per-org token_prices
	tokenPrice, err := c.store.GetTokenPrice(ctx, orgID, tokenAddr)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get token price: %w", err)
	}

	if tokenPrice != nil {
		// Step 2a: Has coingecko_id → resolve from system price
		if tokenPrice.CoingeckoID != nil && *tokenPrice.CoingeckoID != "" {
			sysPrice, err := c.store.GetSystemTokenPrice(ctx, *tokenPrice.CoingeckoID)
			if err != nil {
				return 0, 0, fmt.Errorf("failed to get system token price: %w", err)
			}
			if sysPrice != nil {
				// Check staleness
				if c.priceStalenessThreshold > 0 && time.Since(sysPrice.UpdatedAt) > c.priceStalenessThreshold {
					slog.Warn("system price is stale, failing closed", "coingecko_id", *tokenPrice.CoingeckoID, "age", time.Since(sysPrice.UpdatedAt).Round(time.Second), "threshold", c.priceStalenessThreshold)
					return -1, 0, nil
				}
				// Use prices_by_currency for the active currency
				if sysPrice.PricesByCurrency != nil {
					if price, ok := sysPrice.PricesByCurrency[activeCurrency]; ok && price > 0 {
						return price, tokenPrice.Decimals, nil
					}
				}
				// Fall back to price_fiat if prices_by_currency doesn't have the active currency
				if sysPrice.PriceFiat > 0 {
					return sysPrice.PriceFiat, tokenPrice.Decimals, nil
				}
			}
			// System price unavailable — fail closed (no silent fallback to manual)
			return -1, 0, nil
		}
		// Step 2b: No coingecko_id → manual price, resolve from prices_by_currency
		if len(tokenPrice.PricesByCurrency) > 0 {
			if price, ok := tokenPrice.PricesByCurrency[activeCurrency]; ok && price > 0 {
				return price, tokenPrice.Decimals, nil
			}
			// prices_by_currency is populated but doesn't have the active currency — fail closed
			return -1, 0, nil
		}
		// Legacy: prices_by_currency not populated, use price_fiat
		if tokenPrice.PriceFiat > 0 {
			return tokenPrice.PriceFiat, tokenPrice.Decimals, nil
		}
		return -1, 0, nil
	}

	// Step 3: No per-org entry — auto-resolve native token from system "ethereum" price
	if tokenAddr == "native" {
		sysPrice, err := c.store.GetSystemTokenPrice(ctx, "ethereum")
		if err != nil {
			return 0, 0, fmt.Errorf("failed to get system ethereum price: %w", err)
		}
		if sysPrice != nil {
			if c.priceStalenessThreshold > 0 && time.Since(sysPrice.UpdatedAt) > c.priceStalenessThreshold {
				slog.Warn("system ethereum price is stale, failing closed", "age", time.Since(sysPrice.UpdatedAt).Round(time.Second), "threshold", c.priceStalenessThreshold)
				return -1, 0, nil
			}
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

	// Step 4: Not found → fail closed (signaled by negative price)
	return -1, 0, nil
}

// logDecision creates a compliance log entry for an allow or deny decision.
// M3: The log records the compliance *decision* (allow/deny), not the transaction outcome.
// The transaction may still fail at the node (bad nonce, revert, etc.). The actual tx
// result is captured separately in the RPC access log. This is a deliberate design
// trade-off: we log the decision at check time because we need the audit trail before
// forwarding the transaction to the node.
func (c *Checker) logDecision(ctx context.Context, req *CheckRequest, info *TransferInfo,
	amountFiat *float64, thresholdFiat *float64, decision, denialReason string, recordID *string, currency string) error {

	var denialReasonPtr *string
	if denialReason != "" {
		denialReasonPtr = &denialReason
	}

	entry := &ComplianceLog{
		OrgID:              req.OrgID,
		UserID:             req.UserID,
		TransferType:       info.Type,
		TokenAddress:       info.TokenAddress,
		FromAddress:        info.FromAddress,
		ToAddress:          info.ToAddress,
		AmountWei:          info.AmountWei.String(),
		AmountFiat:         amountFiat,
		ThresholdFiat:      thresholdFiat,
		Currency:           currency,
		Decision:           decision,
		DenialReason:       denialReasonPtr,
		TravelRuleRecordID: recordID,
		CorrelationID:      req.CorrelationID,
	}

	_, err := c.store.CreateComplianceLog(ctx, entry)
	if err != nil {
		slog.Warn("failed to create compliance log", "error", err)
	}
	return err
}

// resolveThreshold determines the applicable threshold for a transfer.
// Per-address overrides (checked for both sender and recipient) take precedence over
// the org-level config. If multiple address overrides match, the lowest threshold wins.
// Returns an error if any database lookup fails (fail-closed: caller should deny).
func (c *Checker) resolveThreshold(ctx context.Context, orgID string, config *ComplianceConfig, fromAddr, toAddr string) (float64, error) {
	var lowestOverride *AddressThresholdOverride

	for _, addr := range []string{fromAddr, toAddr} {
		if addr == "" {
			continue
		}
		// Normalize to lowercase for consistent lookup
		addr = strings.ToLower(addr)
		override, err := c.store.GetAddressThresholdOverride(ctx, orgID, addr)
		if err != nil {
			// Fail closed: if we can't check overrides, we can't make a safe decision
			return 0, fmt.Errorf("failed to get address threshold override for %s: %w", addr, err)
		}
		if override != nil && (lowestOverride == nil || override.ThresholdFiat < lowestOverride.ThresholdFiat) {
			lowestOverride = override
		}
	}

	if lowestOverride != nil {
		return lowestOverride.ThresholdFiat, nil
	}
	return config.ThresholdFiat, nil
}

// WeiToUSD converts a wei amount to USD given the token decimals and price.
// Returns the USD value and an error if the inputs are out of range or produce
// an invalid result (Inf/NaN).
func WeiToUSD(amountWei *big.Int, decimals int, priceUSD float64) (float64, error) {
	if amountWei == nil || amountWei.Sign() == 0 {
		return 0, nil
	}

	// Guard against negative amounts — these are invalid and likely a bug upstream
	if amountWei.Sign() < 0 {
		return 0, fmt.Errorf("negative amountWei: %s", amountWei.String())
	}

	// Guard against invalid decimals (EVM tokens use 0-77 range)
	if decimals < 0 || decimals > 77 {
		return 0, fmt.Errorf("token decimals %d out of valid range [0, 77]", decimals)
	}

	// Guard against invalid price
	if priceUSD < 0 || math.IsInf(priceUSD, 0) || math.IsNaN(priceUSD) {
		return 0, fmt.Errorf("invalid price_usd: %v", priceUSD)
	}

	// Use big.Float for precision during the division
	amountFloat := new(big.Float).SetInt(amountWei)
	divisor := new(big.Float).SetFloat64(math.Pow10(decimals))
	tokenAmount := new(big.Float).Quo(amountFloat, divisor)

	// Multiply by price
	price := new(big.Float).SetFloat64(priceUSD)
	usdValue := new(big.Float).Mul(tokenAmount, price)

	result, _ := usdValue.Float64()

	// Guard against overflow producing Inf/NaN
	if math.IsInf(result, 0) || math.IsNaN(result) {
		return 0, fmt.Errorf("USD calculation overflow: wei=%s decimals=%d price=%f", amountWei.String(), decimals, priceUSD)
	}

	return result, nil
}
