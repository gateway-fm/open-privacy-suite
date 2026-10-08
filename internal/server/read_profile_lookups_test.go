package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingTxVisibility counts visibleTo lookups (tx_visible_to reads).
type countingTxVisibility struct {
	inner rbac.TxVisibilityProvider
	calls atomic.Int32
}

func (c *countingTxVisibility) GetBatchTxVisibility(ctx context.Context, txHashes []string) (map[string][]string, error) {
	c.calls.Add(1)
	return c.inner.GetBatchTxVisibility(ctx, txHashes)
}

// RD-1299: the strict read decisions ignore visibleTo listings and the RD-1162
// sender resolution (an event needs an indexed self address, a receipt needs
// from/to). The read path must not pay for inputs it ignores: under strict no
// tx_visible_to lookup and no upstream eth_getTransactionByHash batch run on
// eth_getLogs, eth_getTransactionReceipt, eth_getBlockReceipts or a
// transaction lookup. The standard profile is the control: the same requests
// do run them, so the counters are known to work.
func TestReadProfile_Strict_SkipsVisibleToAndSenderLookups(t *testing.T) {
	f := setupRPFixture(t)

	node := fakeTxByHashNode(t, map[string]txFromTo{rpTx1: {from: rpE, to: rpC}})
	defer node.Close()
	var upstream atomic.Int32
	counted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		node.Config.Handler.ServeHTTP(w, r)
	}))
	defer counted.Close()

	newProcessor := func(profile rbac.ReadProfile, vis rbac.TxVisibilityProvider) *JSONRPCProcessor {
		return NewJSONRPCProcessor(JSONRPCProcessorConfig{
			Proxy:                     proxy.New(counted.URL),
			RBACAccessCtrl:            f.srv.rbacAccessCtrl,
			RateLimiter:               &noopRateLimiter{},
			AccessLogger:              f.db,
			CircuitBreaker:            middleware.NewCircuitBreaker(),
			ConcurrencyLimiter:        middleware.NewConcurrencyLimiter(50, 0),
			TxVisibilityStore:         vis,
			AddressVisibilityResolver: f.db,
			ReadProfile:               profile,
		})
	}

	getLogsBody := rpEnvelope(t, rpRawLogs(rpTx1))
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))
	blockReceiptsBody := rpEnvelope(t, []any{rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1))})
	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))

	type request struct {
		name   string
		viewer string
		method string
		params []any
		body   []byte
		// upstreamInStandard: the standard profile resolves senders upstream.
		upstreamInStandard bool
	}
	requests := []request{
		{"eth_getLogs", "participant", rbac.MethodGetLogs, []any{map[string]any{"address": rpC}}, getLogsBody, true},
		{"eth_getTransactionReceipt", "participant", rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody, false},
		{"eth_getBlockReceipts", "participant", rbac.MethodGetBlockReceipts, []any{"0x1"}, blockReceiptsBody, false},
		// A nonparticipant: standard consults visibleTo for the envelope.
		{"eth_getTransactionByHash", "ordinary", rbac.MethodGetTransactionByHash, []any{rpTx1}, txBody, false},
	}

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, r := range requests {
			t.Run(profile.String()+"/"+r.name, func(t *testing.T) {
				vis := &countingTxVisibility{inner: f.db}
				p := newProcessor(profile, vis)
				upstream.Store(0)

				out := f.call(t, p, f.viewers[r.viewer], r.method, r.params, r.body)

				if !profile.Strict() {
					assert.Positive(t, vis.calls.Load(), "standard must consult visibleTo (control)")
					if r.upstreamInStandard {
						assert.Positive(t, upstream.Load(), "standard must resolve senders upstream (control)")
					}
					return
				}
				assert.Zero(t, vis.calls.Load(), "strict must not look up visibleTo listings")
				assert.Zero(t, upstream.Load(), "strict must not resolve senders upstream")

				// The strict answer is unchanged (same as the read-profile matrix).
				v := f.viewers[r.viewer]
				res := rpResult(t, out)
				switch r.method {
				case rbac.MethodGetLogs:
					var logs []json.RawMessage
					require.NoError(t, json.Unmarshal(res, &logs))
					assertRPCLogs(t, r.name, v, logs, []int{0})
				case rbac.MethodGetTransactionReceipt:
					var rc struct {
						Logs []json.RawMessage `json:"logs"`
					}
					require.NoError(t, json.Unmarshal(res, &rc))
					assertRPCLogs(t, r.name, v, rc.Logs, []int{0})
				case rbac.MethodGetBlockReceipts:
					var rcs []struct {
						Logs []json.RawMessage `json:"logs"`
					}
					require.NoError(t, json.Unmarshal(res, &rcs))
					require.Len(t, rcs, 1)
					assertRPCLogs(t, r.name, v, rcs[0].Logs, []int{0})
				case rbac.MethodGetTransactionByHash:
					assert.Equal(t, "null", string(res))
				}
			})
		}
	}
}
