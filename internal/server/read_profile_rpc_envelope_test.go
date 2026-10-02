package server

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1299 acceptance 1 and 3 on JSON-RPC: the transaction object (by hash and
// both by-block-index aliases), the receipt, full-object block listings and
// block receipts reach the same admission verdict per (viewer, profile). Under
// strict only the participant (tx from/to) receives anything, and a refused
// viewer never sees the sender, calldata, value or nonce anywhere in the body.
func TestReadProfile_RPCTxEnvelope_Matrix(t *testing.T) {
	f := setupRPFixture(t)

	// Who receives rpTx1's transaction object / receipt, per profile.
	txAdmit := map[rbac.ReadProfile]map[string]bool{
		rbac.ReadProfileStandard: {"participant": true, "contract_admin": true, "org_admin": true, "visibleto": true},
		rbac.ReadProfileStrict:   {"participant": true},
	}
	receiptAdmit := map[rbac.ReadProfile]map[string]bool{
		// payee (must_be:self rule) and ordinary (wildcard rules) are admitted
		// by log entitlement (RD-1183) under standard only.
		rbac.ReadProfileStandard: {"participant": true, "payee": true, "ordinary": true, "contract_admin": true, "org_admin": true, "visibleto": true},
		rbac.ReadProfileStrict:   {"participant": true},
	}

	txBody := rpEnvelope(t, rpTxObject(rpTx1, rpE, rpData))
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))
	blockBody := rpEnvelope(t, map[string]any{
		"number": "0x1", "logsBloom": "0x" + strings.Repeat("f", 512), "gasUsed": "0x10",
		"transactions": []any{rpTxObject(rpTx1, rpE, rpData), rpTxObject(rpTx2, rpQ, "0x")},
	})
	blockReceiptsBody := rpEnvelope(t, []any{
		rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)),
		rpReceiptObject(rpTx2, rpQ, nil),
	})

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		p := f.rpProcessor(profile)
		for _, name := range rpViewerNames {
			v := f.viewers[name]
			t.Run(profile.String()+"/"+name, func(t *testing.T) {
				for _, m := range []string{
					rbac.MethodGetTransactionByHash,
					rbac.MethodGetTransactionByBlockHashAndIndex,
					rbac.MethodGetTransactionByBlockNumberAndIndex,
				} {
					out := f.call(t, p, v, m, []any{rpTx1}, txBody)
					res := rpResult(t, out)
					if txAdmit[profile][name] {
						var tx map[string]any
						require.NoError(t, json.Unmarshal(res, &tx), "%s: %s", m, out)
						assert.Equal(t, rpE, tx["from"], m)
						assert.Equal(t, rpData, tx["input"], m)
						assert.Equal(t, "0x2a", tx["value"], m)
						assert.Equal(t, "0x7", tx["nonce"], m)
					} else {
						assert.Equal(t, "null", string(res), "%s must be null: %s", m, out)
						assert.False(t, rpHasAddr(out, rpE), "%s leaked the sender: %s", m, out)
					}
				}

				out := f.call(t, p, v, rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody)
				res := rpResult(t, out)
				if receiptAdmit[profile][name] {
					var rc map[string]any
					require.NoError(t, json.Unmarshal(res, &rc), "receipt: %s", out)
					assert.Equal(t, rpE, rc["from"])
					assert.Equal(t, "0x"+strings.Repeat("0", 512), rc["logsBloom"], "logsBloom is always zeroed")
				} else {
					assert.Equal(t, "null", string(res), "receipt must be null: %s", out)
					assert.False(t, rpHasAddr(out, rpE), "receipt leaked the sender: %s", out)
				}

				// Block listings and block receipts: participant only, in BOTH
				// profiles; the other user's tx never appears.
				blk := rpResult(t, f.call(t, p, v, rbac.MethodGetBlockByNumber, []any{"0x1", true}, blockBody))
				var block struct {
					Transactions []map[string]any `json:"transactions"`
				}
				require.NoError(t, json.Unmarshal(blk, &block))
				br := rpResult(t, f.call(t, p, v, rbac.MethodGetBlockReceipts, []any{"0x1"}, blockReceiptsBody))
				var receipts []map[string]any
				require.NoError(t, json.Unmarshal(br, &receipts))
				if name == "participant" {
					require.Len(t, block.Transactions, 1)
					assert.Equal(t, rpTx1, block.Transactions[0]["hash"])
					require.Len(t, receipts, 1)
					assert.Equal(t, rpTx1, receipts[0]["transactionHash"])
				} else {
					assert.Empty(t, block.Transactions, "block listing must hold no foreign tx")
					assert.Empty(t, receipts, "block receipts must hold no foreign receipt")
				}
				assert.False(t, rpHasAddr(blk, rpQ), "a third party's tx appeared in the block listing")
				assert.False(t, rpHasAddr(br, rpQ), "a third party's receipt appeared in block receipts")
			})
		}
	}
}

// Acceptance 3 / A5: a receipt inside eth_getBlockReceipts carries exactly the
// logs eth_getTransactionReceipt returns for the same viewer — same shared
// engine (grant, ABI, dynamic-payload gate, event rules, RD-1162), same
// embedded-address masking — in both profiles.
func TestReadProfile_BlockReceiptsLogsMatchReceipt(t *testing.T) {
	f := setupRPFixture(t)
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))
	blockReceiptsBody := rpEnvelope(t, []any{
		rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)),
		rpReceiptObject(rpTx2, rpQ, nil),
	})
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		p := f.rpProcessor(profile)
		v := f.viewers["participant"]
		t.Run(profile.String(), func(t *testing.T) {
			var rc struct {
				Logs []json.RawMessage `json:"logs"`
			}
			require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody)), &rc))
			var brs []struct {
				TransactionHash string            `json:"transactionHash"`
				Logs            []json.RawMessage `json:"logs"`
				LogsBloom       string            `json:"logsBloom"`
			}
			require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetBlockReceipts, []any{"0x1"}, blockReceiptsBody)), &brs))
			require.Len(t, brs, 1)
			assert.Equal(t, "0x"+strings.Repeat("0", 512), brs[0].LogsBloom)
			require.Equal(t, len(rc.Logs), len(brs[0].Logs), "same admitted log set")
			for i := range rc.Logs {
				assert.JSONEq(t, string(rc.Logs[i]), string(brs[0].Logs[i]), "log %d must render identically", i)
			}
			// Masking: the participant's own address stays, third parties are zeroed.
			for _, l := range brs[0].Logs {
				for _, other := range []string{rpP, rpQ, rpR, rpAA} {
					assert.False(t, rpHasAddr(l, other), "embedded third-party address %s not masked: %s", other, l)
				}
			}
			if profile == rbac.ReadProfileStandard {
				// RD-1162: the participant sees every log of their own tx on a
				// granted contract (masked).
				assert.Len(t, brs[0].Logs, 3)
			}
		})
	}
}
