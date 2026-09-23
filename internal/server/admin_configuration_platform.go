package server

import (
	"fmt"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/netguard"
)

// platformPriceFeedProblem checks the two things about a declared price feed
// that only the deployment knows, which the pure validator therefore leaves
// alone, and returns the reason it cannot be accepted here, or "" when it
// can. The interval must be at most half the staleness threshold the
// compliance checker fails closed on, so one missed fetch does not make every
// valued transfer deniable; and the destination must pass the outbound URL
// guard for this environment (https to a public host in production; a
// cleartext loopback or private destination only outside it). The reason is
// about the author's document and the deployment's settings, so it is safe
// to show. Callers run it when a document is submitted and again when it is
// activated, because the environment may change in between.
func (s *Server) platformPriceFeedProblem(feed *configuration.PriceFeed) string {
	if feed == nil || s.config == nil {
		return ""
	}
	if threshold := s.config.PriceStalenessThreshold; threshold > 0 && 2*time.Duration(feed.RefreshIntervalSeconds)*time.Second > threshold {
		return fmt.Sprintf("priceFeed.refreshIntervalSeconds must be at most half the price staleness threshold of %s, so one missed fetch does not make every price stale", threshold)
	}
	// netguard's validation errors are bare reasons about the URL under test
	// ("must use https in production", "must not target a loopback address");
	// the one branch that wraps a parse error is unreachable here because the
	// document validator has already parsed the URI. That contract is what
	// makes folding the text into a client message safe.
	if err := netguard.ValidateWebhookURLForEnv(feed.URI, !s.config.IsProduction()); err != nil {
		return "priceFeed.uri is not an allowed destination in this deployment: " + err.Error()
	}
	return ""
}

// priceFeedCapability tells a client whether a feed declared in the platform
// document is polled by this deployment at all; the environment's switches
// decide that, never the document.
func (s *Server) priceFeedCapability() apimodels.ConfigurationPriceFeed {
	switch {
	case s.priceService != nil:
		return apimodels.ConfigurationPriceFeed{Available: true}
	case s.config != nil && !s.config.EnableTravelRule:
		return apimodels.ConfigurationPriceFeed{Reason: "the pricing service is off because ENABLE_TRAVEL_RULE is not set"}
	case s.config != nil && s.config.DisableCoinGecko:
		return apimodels.ConfigurationPriceFeed{Reason: "price fetching is off because DISABLE_COINGECKO is set"}
	default:
		return apimodels.ConfigurationPriceFeed{Reason: "the pricing service is not running"}
	}
}
