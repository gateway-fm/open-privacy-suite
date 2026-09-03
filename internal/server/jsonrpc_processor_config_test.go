package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/proxy"
)

// RD-1259: the processor is fully wired at construction. These tests lock the
// two contracts that used to live implicitly in the Set* call order:
// (a) an omitted optional dependency behaves exactly like the setter never
// being called did (nil-safe degraded mode), and (b) a supplied dependency is
// installed — no field silently dropped on the constructor floor.

type stubTxVisibilityProvider struct{}

func (stubTxVisibilityProvider) GetBatchTxVisibility(context.Context, []string) (map[string][]string, error) {
	return nil, nil
}

type stubAddrVisResolver struct{}

func (stubAddrVisResolver) GetBatchVisibilityDetailed(context.Context, string, []string) (map[string]explorer.AddressVisibility, error) {
	return nil, nil
}

type stubAuditBuffer struct{}

func (stubAuditBuffer) Append([]byte) (uint64, error) { return 0, nil }

func TestNewJSONRPCProcessor_OptionalDepsOmitted(t *testing.T) {
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		CircuitBreaker:     NewCircuitBreaker(),
		ConcurrencyLimiter: NewConcurrencyLimiter(1, 0),
	})

	// RD-915 wire-level safe default: tracing ON until env says otherwise.
	eth := p.EthCallTracingSnapshot()
	require.True(t, eth.Enabled)
	require.True(t, eth.EnvDefault)
	require.Equal(t, "env", eth.Source)
	require.Equal(t, 5*time.Second, p.ethCallTraceTimeout)

	// RD-1053 default: intra-org grant scoping OFF.
	intra := p.IntraOrgGrantTracingSnapshot()
	require.False(t, intra.Enabled)
	require.False(t, intra.EnvDefault)
	require.Equal(t, "env", intra.Source)

	// Degraded modes match the previously-unwired-setter behavior.
	require.Equal(t, proxy.DefaultAPIKeyHeader, p.resolveAPIKeyHeader())
	require.Nil(t, p.metrics)
	require.Nil(t, p.txVisibilityStore)
	require.Nil(t, p.addrVisResolver)
	require.Nil(t, p.complianceChecker)
	require.Nil(t, p.enhancedLogger)
	require.Nil(t, p.hashChain)
	require.Nil(t, p.siemForwarder)
	require.False(t, p.logParams)
	require.Nil(t, p.auditBuffer)
	require.Nil(t, p.visibilityKick)
}

func TestNewJSONRPCProcessor_OptionalDepsInstalled(t *testing.T) {
	kicked := false
	cl := &captureEnhancedLogger{}
	chain := audit.NewHashChain("")
	checker := &compliance.Checker{}
	m := &metrics.Metrics{}

	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		CircuitBreaker:              NewCircuitBreaker(),
		ConcurrencyLimiter:          NewConcurrencyLimiter(1, 0),
		Metrics:                     m,
		TxVisibilityStore:           stubTxVisibilityProvider{},
		AddressVisibilityResolver:   stubAddrVisResolver{},
		RPCAPIKeyHeader:             "X-Custom-Key",
		ComplianceChecker:           checker,
		EnhancedAuditLogger:         cl,
		HashChain:                   chain,
		AuditLogParams:              true,
		AuditBuffer:                 stubAuditBuffer{},
		VisibilityKick:              func() { kicked = true },
		EthCallTracing:              &EthCallTracingConfig{Enabled: false, Timeout: 7 * time.Second},
		IntraOrgGrantTracingEnabled: true,
	})

	require.Same(t, m, p.metrics)
	require.NotNil(t, p.txVisibilityStore)
	require.NotNil(t, p.addrVisResolver)
	require.Equal(t, "X-Custom-Key", p.resolveAPIKeyHeader())
	require.Same(t, checker, p.complianceChecker)
	require.Same(t, cl, p.enhancedLogger.(*captureEnhancedLogger))
	require.Same(t, chain, p.hashChain)
	require.True(t, p.logParams)
	require.NotNil(t, p.auditBuffer)
	p.visibilityKick()
	require.True(t, kicked)

	eth := p.EthCallTracingSnapshot()
	require.False(t, eth.Enabled)
	require.False(t, eth.EnvDefault)
	require.Equal(t, "env", eth.Source)
	require.Equal(t, 7*time.Second, p.ethCallTraceTimeout)

	intra := p.IntraOrgGrantTracingSnapshot()
	require.True(t, intra.Enabled)
	require.True(t, intra.EnvDefault)
}

func TestNewJSONRPCProcessor_EthCallTimeoutZeroKeepsDefault(t *testing.T) {
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		EthCallTracing: &EthCallTracingConfig{Enabled: true, Timeout: 0},
	})
	require.Equal(t, 5*time.Second, p.ethCallTraceTimeout)
	require.True(t, p.EthCallTracingSnapshot().Enabled)
}
