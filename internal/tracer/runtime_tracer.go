package tracer

import (
	"context"
	"strings"
	"time"

	"privacy-proxy/internal/nodehttp"
)

// RuntimeTracer provides integrated runtime tracing with caching.
// It combines the Tracer (for debug_traceCall) and TraceCache.
type RuntimeTracer struct {
	tracer  *Tracer
	cache   *TraceCache
	enabled bool
	tiered  bool // If true, skip trace for known addresses
}

// RuntimeTracerConfig configures the RuntimeTracer.
type RuntimeTracerConfig struct {
	NodeURL       string
	Enabled       bool
	CacheTTL      time.Duration
	Timeout       time.Duration
	TieredEnabled bool
	// Transport tunes the upstream node connection pool (RD-1112). Zero fields
	// fall back to nodehttp defaults.
	Transport nodehttp.TransportConfig
}

// NewRuntimeTracer creates a new RuntimeTracer.
func NewRuntimeTracer(cfg RuntimeTracerConfig) *RuntimeTracer {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 10 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	return &RuntimeTracer{
		tracer:  NewTracer(cfg.NodeURL, cfg.Timeout),
		cache:   NewTraceCache(cfg.CacheTTL, cfg.CacheTTL/2),
		enabled: cfg.Enabled,
		tiered:  cfg.TieredEnabled,
	}
}

// IsEnabled returns whether runtime tracing is enabled.
func (rt *RuntimeTracer) IsEnabled() bool {
	return rt.enabled
}

// IsTieredEnabled returns whether tiered validation is enabled.
// When enabled, simple value transfers to EOAs skip tracing (all contract calls are traced).
// Org-owned contracts are always traced because they could make cross-org calls via user-supplied calldata.
func (rt *RuntimeTracer) IsTieredEnabled() bool {
	return rt.tiered
}

// HasCode checks if an address has contract code deployed (is a contract vs EOA).
func (rt *RuntimeTracer) HasCode(ctx context.Context, address string) (bool, error) {
	return rt.tracer.HasCode(ctx, address)
}

// GetCodeHash returns the keccak256 of the bytecode at address at the
// latest block, as a lowercase 0x-prefixed hex string. Empty
// bytecode (EOA) returns the keccak of the empty byte slice. Used by
// the M5 codehash-pin path in rbac.TraceValidator (see
// rbac.CodeHashFetcher interface).
//
// The hash is computed over the raw bytecode the node returns from
// eth_getCode — not the deployment bytecode and not the metadata-
// stripped variant. Operators who attest a codehash should compute it
// the same way (eth_getCode → keccak256).
func (rt *RuntimeTracer) GetCodeHash(ctx context.Context, address string) (string, error) {
	return rt.tracer.GetCodeHash(ctx, address)
}

// TraceTransaction traces a transaction and returns all call targets.
// It uses the cache to avoid redundant traces for identical transactions.
func (rt *RuntimeTracer) TraceTransaction(
	ctx context.Context,
	from, to, data, value string,
) (*TraceResult, error) {
	if !rt.enabled {
		return nil, nil
	}

	// Normalize inputs for cache key
	from = strings.ToLower(strings.TrimSpace(from))
	to = strings.ToLower(strings.TrimSpace(to))
	data = strings.ToLower(strings.TrimSpace(data))
	value = strings.TrimSpace(value)

	// Check cache first
	if cached := rt.cache.Get(from, to, data, value, "latest"); cached != nil {
		return cached, nil
	}

	// Perform trace
	result, err := rt.tracer.TraceCall(ctx, from, to, data, value, "latest")
	if err != nil {
		return nil, err
	}

	// Cache the result
	rt.cache.Set(from, to, data, value, "latest", result)

	return result, nil
}

// TraceTransactionUncached traces a transaction WITHOUT consulting or
// updating the cache. Used by the eth_call validation path (RD-915) where
// caching is unsafe: proxy-pattern contracts (EIP-1967, Diamond, Beacon,
// TransparentUpgradeable) can re-target their internal calls by rewriting
// a storage slot, so a cache keyed by (from,to,data,value) returns stale
// "allow" decisions after a cross-org upgrade. See docs/rd-915-design.md
// §KD-7. Regression net: TestTraceTransactionUncached_BypassesCachedHit
// in this package (cache leak at the tracer layer) plus
// TestEthCallTracing_ProxyImplementationFlip in internal/server (proxy
// re-targeting flips the validator decision on the second call).
//
// blockParam must match the block parameter that the corresponding eth_call
// will be forwarded with — otherwise the trace runs against a different
// chain state than the actual call and an attacker can mount a time-shifted
// variant of the proxy-flip attack (allow at latest, exfil at
// historical-where-foreign). Accepts the same shapes as eth_call's second
// param: a string tag/hex, an EIP-1898 object, or nil/"" (treated as
// "latest"). The caller is responsible for shape validation.
//
// Sibling of TraceTransaction rather than a useCache boolean parameter
// so the cache-bypass intent is legible at every call site.
func (rt *RuntimeTracer) TraceTransactionUncached(
	ctx context.Context,
	from, to, data, value string,
	blockParam any,
) (*TraceResult, error) {
	if !rt.enabled {
		return nil, nil
	}

	from = strings.ToLower(strings.TrimSpace(from))
	to = strings.ToLower(strings.TrimSpace(to))
	data = strings.ToLower(strings.TrimSpace(data))
	value = strings.TrimSpace(value)
	// TraceCall handles the empty-string/nil → "latest" fallback itself.
	if s, ok := blockParam.(string); ok {
		blockParam = strings.ToLower(strings.TrimSpace(s))
	}

	return rt.tracer.TraceCall(ctx, from, to, data, value, blockParam)
}

// TraceCallObjectUncached preserves the full call object and never uses the
// four-field transaction cache. Callers validate the request before invoking it.
func (rt *RuntimeTracer) TraceCallObjectUncached(ctx context.Context, callObj map[string]any, blockParam any) (*TraceResult, error) {
	if !rt.enabled {
		return nil, nil
	}
	return rt.tracer.TraceCallObject(ctx, callObj, blockParam)
}

// TraceMinedTransaction traces a mined transaction to discover actual CREATE/CREATE2 addresses.
// No caching — mined transactions are traced once during deployment finalization.
func (rt *RuntimeTracer) TraceMinedTransaction(ctx context.Context, txHash string) (*TraceResult, error) {
	if !rt.enabled {
		return nil, nil
	}

	return rt.tracer.TraceTransaction(ctx, txHash)
}

// Stop gracefully stops the RuntimeTracer.
func (rt *RuntimeTracer) Stop() {
	if rt.cache != nil {
		rt.cache.Stop()
	}
}
