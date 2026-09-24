package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodehttp"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"
)

func TestNodeApprovalSettings(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed")
	require.NoError(t, os.WriteFile(seed, []byte(strings.Repeat("07", 32)), 0o600))
	t.Setenv("OPS_APPROVAL_SEED_FILE", seed)
	configure := func() (*JSONRPCProcessor, error) {
		p := &JSONRPCProcessor{}
		err := p.configureNodeApprovals("http://127.0.0.1:1", nodehttp.DefaultTransportConfig())
		if p.nodeApprovals != nil {
			t.Cleanup(p.nodeApprovals.Close)
		}
		return p, err
	}

	t.Run("no targets leaves the gate off", func(t *testing.T) {
		t.Setenv("OPS_APPROVAL_TARGET", "")
		t.Setenv("OPS_APPROVAL_TARGETS", "")
		p, err := configure()
		require.NoError(t, err)
		require.Nil(t, p.nodeApprovals)
	})
	t.Run("the retired single target fails start-up", func(t *testing.T) {
		// Ignoring it would switch the gate off without a word.
		t.Setenv("OPS_APPROVAL_TARGET", "127.0.0.1:50051")
		t.Setenv("OPS_APPROVAL_TARGETS", "")
		_, err := configure()
		require.ErrorContains(t, err, "OPS_APPROVAL_TARGETS")
	})
	t.Run("an invalid target list fails start-up", func(t *testing.T) {
		t.Setenv("OPS_APPROVAL_TARGET", "")
		t.Setenv("OPS_APPROVAL_TARGETS", "sequencer")
		_, err := configure()
		require.ErrorContains(t, err, "OPS_APPROVAL_TARGETS")
	})
	t.Run("targets turn the gate on", func(t *testing.T) {
		t.Setenv("OPS_APPROVAL_TARGET", "")
		t.Setenv("OPS_APPROVAL_TARGETS", "127.0.0.1:50051,127.0.0.1:50052")
		p, err := configure()
		require.NoError(t, err)
		require.NotNil(t, p.nodeApprovals)
	})
}

// With the gate on and no producer ready to take the approval, a transaction is refused with an
// opaque 503 and never forwarded: forwarding it would only have it time out in the pool.
func TestRawTransactionRefusedWhenNoApprovalProducerIsReady(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	did := seedPermittedUser(t, ctx, ts.db)
	rawHex, body := signedValueTransfer(t)
	var tx types.Transaction
	require.NoError(t, tx.UnmarshalBinary(hexutil.MustDecode(rawHex)))
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), &tx)
	require.NoError(t, err)
	to := strings.ToLower(tx.To().Hex())
	calls := map[string]any{"type": "CALL", "from": strings.ToLower(from.Hex()), "to": to, "input": "0x", "value": hexutil.EncodeBig(tx.Value()), "calls": []any{}}
	fingerprint, _, err := nodeapproval.CallFingerprint(calls, map[string]any{to: map[string]any{"code": "0x"}})
	require.NoError(t, err)

	var forwarded, preflights atomic.Int64
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result any = "0x0"
		switch req.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "eth_getCode":
			result = "0x"
		case "ops_prepareApproval": // the plugin's preflight of a plain transfer to an account without code
			preflights.Add(1)
			result = map[string]any{"hashMode": 3, "chainId": "0x7a69", "txHash": tx.Hash().Hex(), "fingerprint": fingerprint.Hex(),
				"calls": calls, "codeHashes": map[string]string{to: crypto.Keccak256Hash(nil).Hex()}}
		case "eth_sendRawTransaction":
			forwarded.Add(1)
			result = tx.Hash().Hex()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(node.Close)

	// A target nothing listens on: the lane never connects, so no producer is ever ready.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	target := closed.Addr().String()
	require.NoError(t, closed.Close())
	approvals, err := nodeapproval.New(node.URL, target, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	t.Cleanup(approvals.Close)

	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: node.URL, Enabled: true, TieredEnabled: true, Timeout: 5 * time.Second})
	t.Cleanup(rt.Stop)
	p := NewJSONRPCProcessorWithTracing(ts.rbacAccessCtrl, &noopRateLimiter{}, proxy.New(node.URL), ts.db, rt, rbac.NewTraceValidator(ts.db),
		NewCircuitBreaker(), NewConcurrencyLimiter(50, 0), "")
	p.nodeApprovals = approvals
	require.NoError(t, p.configurePreflightLimit(nil))

	res := p.Process(ctx, &ProcessRequest{UserID: did, Method: "eth_sendRawTransaction", Params: []any{rawHex}, Body: body, ClientIP: "127.0.0.1"})
	require.NotNil(t, res.Error, "status %d body %s", res.StatusCode, res.ResponseBody)
	require.Equal(t, http.StatusServiceUnavailable, res.Error.StatusCode)
	require.Equal(t, "approval delivery unavailable", res.Error.Message)
	require.Zero(t, forwarded.Load(), "the transaction was forwarded without a producer to approve it")
	require.Zero(t, preflights.Load(), "a preflight ran on the node although no producer could take its approval")
}

// The delivery metrics are only useful if /metrics serves them: the gate's own
// collector has to be registered next to the server's.
func TestNodeApprovalMetricsAreRegistered(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed")
	require.NoError(t, os.WriteFile(seed, []byte(strings.Repeat("07", 32)), 0o600))
	t.Setenv("OPS_APPROVAL_SEED_FILE", seed)
	t.Setenv("OPS_APPROVAL_TARGET", "")

	t.Run("gate off registers nothing", func(t *testing.T) {
		t.Setenv("OPS_APPROVAL_TARGETS", "")
		p := &JSONRPCProcessor{}
		require.NoError(t, p.configureNodeApprovals("http://127.0.0.1:1", nodehttp.DefaultTransportConfig()))
		reg := prometheus.NewRegistry()
		require.NoError(t, p.registerNodeApprovalMetrics(reg))
		families, err := reg.Gather()
		require.NoError(t, err)
		require.Empty(t, families)
	})
	t.Run("gate on serves the delivery metrics", func(t *testing.T) {
		t.Setenv("OPS_APPROVAL_TARGETS", "127.0.0.1:1")
		p := &JSONRPCProcessor{}
		require.NoError(t, p.configureNodeApprovals("http://127.0.0.1:1", nodehttp.DefaultTransportConfig()))
		t.Cleanup(p.nodeApprovals.Close)
		reg := prometheus.NewRegistry()
		require.NoError(t, p.registerNodeApprovalMetrics(reg))
		families, err := reg.Gather()
		require.NoError(t, err)
		served := false
		for _, f := range families {
			served = served || strings.HasPrefix(f.GetName(), "privacyproxy_approval_")
		}
		require.True(t, served, "no approval delivery metric is registered")
	})
}
