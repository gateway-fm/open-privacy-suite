package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const namespace = "privacyproxy"

// knownRPCMethods is the set of Ethereum JSON-RPC methods that are safe to use
// as Prometheus label values. Any method not in this set is normalized to "other"
// to prevent label cardinality bombs from malicious clients sending random method names.
var knownRPCMethods = func() map[string]struct{} {
	methods := []string{
		// Standard Ethereum methods
		"eth_accounts", "eth_blockNumber", "eth_call", "eth_chainId",
		"eth_estimateGas", "eth_feeHistory", "eth_gasPrice", "eth_getBalance",
		"eth_getBlockByHash", "eth_getBlockByNumber",
		"eth_getBlockTransactionCountByHash", "eth_getBlockTransactionCountByNumber",
		"eth_getCode", "eth_getFilterChanges", "eth_getFilterLogs", "eth_getLogs",
		"eth_getProof", "eth_getStorageAt",
		"eth_getTransactionByBlockHashAndIndex", "eth_getTransactionByBlockNumberAndIndex",
		"eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt",
		"eth_getUncleByBlockHashAndIndex", "eth_getUncleByBlockNumberAndIndex",
		"eth_getUncleCountByBlockHash", "eth_getUncleCountByBlockNumber",
		"eth_maxPriorityFeePerGas", "eth_newBlockFilter", "eth_newFilter",
		"eth_newPendingTransactionFilter", "eth_protocolVersion",
		"eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "eth_signTransaction",
		"eth_subscribe", "eth_syncing", "eth_uninstallFilter", "eth_unsubscribe",
		"eth_createAccessList", "eth_blobBaseFee",
		// Network / utility
		"net_listening", "net_peerCount", "net_version",
		"web3_clientVersion", "web3_sha3",
		// Debug (used for runtime tracing)
		"debug_traceCall", "debug_traceTransaction",
		"debug_traceBlockByNumber", "debug_traceBlockByHash",
		// Txpool
		"txpool_content", "txpool_inspect", "txpool_status",
	}
	m := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		m[strings.ToLower(method)] = struct{}{}
	}
	return m
}()

// NormalizeRPCMethod returns the method name if it's a known Ethereum JSON-RPC
// method, or "other" if not. This prevents label cardinality bombs from
// malicious clients sending arbitrary method names.
func NormalizeRPCMethod(method string) string {
	if _, ok := knownRPCMethods[strings.ToLower(method)]; ok {
		return method
	}
	return "other"
}

// Metrics holds all Prometheus collectors for the Open Privacy Suite.
type Metrics struct {
	Registry *prometheus.Registry

	// HTTP layer
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	// JSON-RPC
	RPCRequestsTotal       *prometheus.CounterVec
	RPCRequestDuration     *prometheus.HistogramVec
	RPCNodeForwardDuration *prometheus.HistogramVec

	// RBAC
	RBACDecisionsTotal *prometheus.CounterVec

	// Compliance
	ComplianceDecisionsTotal *prometheus.CounterVec
	ComplianceCheckDuration  *prometheus.HistogramVec

	// Authentication
	AuthAttemptsTotal       *prometheus.CounterVec
	AuthTokenRefreshesTotal *prometheus.CounterVec

	// Rate limiting
	RateLimitHitsTotal *prometheus.CounterVec

	// Circuit breaker & concurrency
	CircuitBreakerTripsTotal   *prometheus.CounterVec // label: api_key_masked (last 4 chars only)
	ConcurrencyRejectionsTotal prometheus.Counter
	UpstreamRateLimitTotal     *prometheus.CounterVec // label: api_key_masked (last 4 chars only)

	// Pricing (CoinGecko)
	PricingFetchesTotal        *prometheus.CounterVec
	PricingFetchDuration       prometheus.Histogram
	PricingConsecutiveFailures prometheus.Gauge

	// SIEM
	SIEMBatchesTotal       *prometheus.CounterVec
	SIEMEventsDroppedTotal prometheus.Counter

	// Audit hash chain integrity (RD-858)
	AuditChainIntegrityViolations *prometheus.CounterVec

	// Cross-org authorization oracle answers that could not be judged
	CrossOrgOracleIndeterminateTotal *prometheus.CounterVec

	// Pending deployments
	PendingDeployments prometheus.Gauge

	// Build info
	Info *prometheus.GaugeVec
}

// New creates a new Metrics instance with a dedicated registry.
func New(version string) *Metrics {
	reg := prometheus.NewRegistry()

	// Go runtime + process collectors
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		Registry: reg,

		HTTPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total HTTP requests by method, path, and status code.",
		}, []string{"method", "path", "status"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"method", "path"}),

		RPCRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rpc_requests_total",
			Help:      "Total JSON-RPC requests by method and outcome.",
		}, []string{"rpc_method", "outcome"}),
		RPCRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "rpc_request_duration_seconds",
			Help:      "JSON-RPC request processing duration in seconds.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"rpc_method"}),
		RPCNodeForwardDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "rpc_node_forward_duration_seconds",
			Help:      "Duration of forwarding requests to the Ethereum node.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"rpc_method"}),

		RBACDecisionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rbac_decisions_total",
			Help:      "Total RBAC access decisions by outcome.",
		}, []string{"decision"}),

		ComplianceDecisionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "compliance_decisions_total",
			Help:      "Total compliance check decisions by outcome.",
		}, []string{"decision"}),
		ComplianceCheckDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "compliance_check_duration_seconds",
			Help:      "Duration of compliance checks.",
			Buckets:   prometheus.DefBuckets,
		}, []string{}),

		AuthAttemptsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_attempts_total",
			Help:      "Total authentication attempts by provider and outcome.",
		}, []string{"provider", "outcome"}),
		AuthTokenRefreshesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_token_refreshes_total",
			Help:      "Total token refresh attempts by outcome.",
		}, []string{"outcome"}),

		RateLimitHitsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_hits_total",
			Help:      "Total rate limit rejections by type.",
		}, []string{"limit_type"}),

		CircuitBreakerTripsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "circuit_breaker_trips_total",
			Help:      "Total circuit breaker trip events (request rejected because upstream was rate-limited).",
		}, []string{"api_key_masked"}),
		ConcurrencyRejectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "concurrency_rejections_total",
			Help:      "Total requests rejected due to per-user concurrency limit.",
		}),
		UpstreamRateLimitTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "upstream_rate_limit_total",
			Help:      "Total HTTP 429 responses received from the upstream RPC node.",
		}, []string{"api_key_masked"}),

		PricingFetchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "pricing_fetches_total",
			Help:      "Total CoinGecko price fetch attempts by outcome.",
		}, []string{"outcome"}),
		PricingFetchDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "pricing_fetch_duration_seconds",
			Help:      "Duration of CoinGecko price fetches.",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}),
		PricingConsecutiveFailures: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "pricing_consecutive_failures",
			Help:      "Current number of consecutive CoinGecko fetch failures.",
		}),

		SIEMBatchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "siem_batches_total",
			Help:      "Total SIEM batch flush attempts by outcome.",
		}, []string{"outcome"}),
		SIEMEventsDroppedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "siem_events_dropped_total",
			Help:      "Total SIEM events dropped due to send failures.",
		}),

		AuditChainIntegrityViolations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "audit_chain_integrity_violations_total",
			Help:      "Total audit hash-chain integrity violations detected by the scheduled verifier, labelled by chain and reason. NON-ZERO MEANS POTENTIAL TAMPERING — alert immediately. RD-858.",
		}, []string{"chain", "reason"}),

		CrossOrgOracleIndeterminateTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cross_org_oracle_indeterminate_total",
			Help:      "Cross-org authorization oracle answers of indeterminate, by reason. Recurring answers usually mean a setup gap.",
		}, []string{"reason"}),

		PendingDeployments: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "pending_deployments",
			Help:      "Number of pending contract deployments awaiting confirmation.",
		}),

		Info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "build_info",
			Help:      "Build information.",
		}, []string{"version"}),
	}

	// Register all collectors
	reg.MustRegister(
		m.HTTPRequestsTotal, m.HTTPRequestDuration,
		m.RPCRequestsTotal, m.RPCRequestDuration, m.RPCNodeForwardDuration,
		m.RBACDecisionsTotal,
		m.ComplianceDecisionsTotal, m.ComplianceCheckDuration,
		m.AuthAttemptsTotal, m.AuthTokenRefreshesTotal,
		m.RateLimitHitsTotal,
		m.CircuitBreakerTripsTotal, m.ConcurrencyRejectionsTotal, m.UpstreamRateLimitTotal,
		m.PricingFetchesTotal, m.PricingFetchDuration, m.PricingConsecutiveFailures,
		m.SIEMBatchesTotal, m.SIEMEventsDroppedTotal,
		m.AuditChainIntegrityViolations,
		m.CrossOrgOracleIndeterminateTotal,
		m.PendingDeployments,
		m.Info,
	)

	m.Info.WithLabelValues(version).Set(1)

	return m
}

// NewNoop creates a Metrics instance with valid but unregistered collectors.
// Use in tests where you don't care about metrics values.
func NewNoop() *Metrics {
	return New("test")
}
