package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1299 acceptance 2: under strict, an event is admitted only when its
// registered ABI identifies an indexed address parameter equal to one of the
// viewer's linked addresses; the admin claim, wildcard rules, visibleTo and
// participation do not override that. The same (viewer, profile) must get the
// same admitted set with the same masked fields on eth_getLogs, receipt logs and
// every explorer log endpoint (fixture: L0 Transfer(E,P), L1 Transfer(Q,R),
// L2 Transfer(AA,R)).
func TestReadProfile_EventLogs_Matrix(t *testing.T) {
	f := setupRPFixture(t)
	router := f.explorerRouter()

	// Admitted log indexes per surface class.
	type want struct {
		getLogs     []int // eth_getLogs (no participant resolution in this harness)
		receipt     []int // eth_getTransactionReceipt logs; nil = envelope refused
		txLogs      []int // explorer /transactions/:hash/logs (parent from/to known)
		addrLogs    []int // explorer /addresses/:C/logs and /logs?address=C (no tx context)
		addrPage404 bool  // /addresses/:C/logs answers 404 (address not visible)
	}
	all := []int{0, 1, 2}
	expect := map[rbac.ReadProfile]map[string]want{
		rbac.ReadProfileStandard: {
			"participant":    {getLogs: []int{0}, receipt: all, txLogs: all, addrLogs: []int{0}},
			"payee":          {getLogs: []int{0}, receipt: []int{0}, txLogs: []int{0}, addrLogs: []int{0}},
			"ordinary":       {getLogs: all, receipt: all, txLogs: all, addrLogs: all},
			"contract_admin": {getLogs: all, receipt: all, txLogs: all, addrLogs: all},
			"org_admin":      {getLogs: all, receipt: all, txLogs: all, addrLogs: all},
			"visibleto":      {getLogs: all, receipt: all, txLogs: all, addrLogs: []int{}},
			"other_org":      {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}, addrPage404: true},
			"anonymous":      {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}, addrPage404: true},
		},
		rbac.ReadProfileStrict: {
			"participant":    {getLogs: []int{0}, receipt: []int{0}, txLogs: []int{0}, addrLogs: []int{0}},
			"payee":          {getLogs: []int{0}, receipt: nil, txLogs: []int{0}, addrLogs: []int{0}},
			"ordinary":       {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}},
			"contract_admin": {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}},
			// The org admin sees the one event that names their own address
			// (admin relaxes their nil event rules, never IndexedSelf).
			"org_admin": {getLogs: []int{2}, receipt: nil, txLogs: []int{2}, addrLogs: []int{2}},
			"visibleto": {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}},
			"other_org": {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}, addrPage404: true},
			"anonymous": {getLogs: []int{}, receipt: nil, txLogs: []int{}, addrLogs: []int{}, addrPage404: true},
		},
	}

	getLogsBody := rpEnvelope(t, rpRawLogs(rpTx1))
	receiptBody := rpEnvelope(t, rpReceiptObject(rpTx1, rpE, rpRawLogs(rpTx1)))

	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		f.wireExplorer(profile)
		p := f.rpProcessor(profile)
		for _, name := range rpViewerNames {
			v := f.viewers[name]
			w := expect[profile][name]
			t.Run(profile.String()+"/"+name, func(t *testing.T) {
				// RPC eth_getLogs.
				var rpcLogs []json.RawMessage
				require.NoError(t, json.Unmarshal(rpResult(t, f.call(t, p, v, rbac.MethodGetLogs, []any{map[string]any{"address": rpC}}, getLogsBody)), &rpcLogs))
				assertRPCLogs(t, "eth_getLogs", v, rpcLogs, w.getLogs)

				// RPC receipt logs.
				res := rpResult(t, f.call(t, p, v, rbac.MethodGetTransactionReceipt, []any{rpTx1}, receiptBody))
				if w.receipt == nil {
					assert.Equal(t, "null", string(res), "receipt envelope must be refused")
				} else {
					var rc struct {
						Logs []json.RawMessage `json:"logs"`
					}
					require.NoError(t, json.Unmarshal(res, &rc))
					assertRPCLogs(t, "receipt", v, rc.Logs, w.receipt)
				}

				// Explorer log endpoints, same fixture.
				code, body := f.explorerGet(t, router, v, "/api/v1/explorer/transactions/"+rpTx1+"/logs")
				require.Equal(t, http.StatusOK, code, string(body))
				var txLogs []explorer.Log
				require.NoError(t, json.Unmarshal(body, &txLogs))
				assertExplorerLogs(t, "/transactions/:hash/logs", v, body, txLogs, w.txLogs)

				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/addresses/"+rpC+"/logs")
				if w.addrPage404 {
					assert.Equal(t, http.StatusNotFound, code, string(body))
				} else {
					require.Equal(t, http.StatusOK, code, string(body))
					var page struct {
						Data  []explorer.Log `json:"data"`
						Total int            `json:"total"`
					}
					require.NoError(t, json.Unmarshal(body, &page))
					assertExplorerLogs(t, "/addresses/:C/logs", v, body, page.Data, w.addrLogs)
					assert.Equal(t, len(w.addrLogs), page.Total, "total must count visible rows only")
				}

				code, body = f.explorerGet(t, router, v, "/api/v1/explorer/logs?address="+rpC)
				require.Equal(t, http.StatusOK, code, string(body))
				var logs []explorer.Log
				require.NoError(t, json.Unmarshal(body, &logs))
				assertExplorerLogs(t, "/logs", v, body, logs, w.addrLogs)
			})
		}
	}
}

// rpMaskedTopic is the expected rendering of an embedded address for viewer v:
// the viewer's own address stays; every other fixture address is a private EOA
// of another user and is zeroed on both layers (RD-1214).
func rpMaskedTopic(v rpViewer, addr string) string {
	if strings.EqualFold(addr, v.addr) {
		return zeroPadAddrToTopic(addr)
	}
	return zeroTopic
}

func assertRPCLogs(t *testing.T, surface string, v rpViewer, got []json.RawMessage, wantIdx []int) {
	t.Helper()
	logs := rpLogs()
	idx := make([]int, 0, len(got))
	for _, raw := range got {
		var l struct {
			LogIndex string   `json:"logIndex"`
			Topics   []string `json:"topics"`
			Data     string   `json:"data"`
		}
		require.NoError(t, json.Unmarshal(raw, &l), "%s: %s", surface, raw)
		i, err := strconv.ParseInt(strings.TrimPrefix(l.LogIndex, "0x"), 16, 64)
		require.NoError(t, err)
		idx = append(idx, int(i))
		src := logs[i]
		require.Len(t, l.Topics, 3, "%s log %d topics", surface, i)
		assert.Equal(t, rpT0, l.Topics[0], "%s log %d topic0", surface, i)
		assert.Equal(t, rpMaskedTopic(v, src.from), strings.ToLower(l.Topics[1]), "%s log %d from", surface, i)
		assert.Equal(t, rpMaskedTopic(v, src.to), strings.ToLower(l.Topics[2]), "%s log %d to", surface, i)
		assert.Equal(t, src.data, l.Data, "%s log %d data (a value, not an address)", surface, i)
	}
	sort.Ints(idx)
	if wantIdx == nil {
		wantIdx = []int{}
	}
	assert.Equal(t, wantIdx, idx, "%s: admitted logs for %s", surface, v.name)
}

func assertExplorerLogs(t *testing.T, surface string, v rpViewer, body []byte, got []explorer.Log, wantIdx []int) {
	t.Helper()
	logs := rpLogs()
	idx := make([]int, 0, len(got))
	for _, l := range got {
		idx = append(idx, l.LogIndex)
		src := logs[l.LogIndex]
		require.NotNil(t, l.Topic1, "%s log %d topic1", surface, l.LogIndex)
		require.NotNil(t, l.Topic2, "%s log %d topic2", surface, l.LogIndex)
		assert.Equal(t, rpMaskedTopic(v, src.from), strings.ToLower(*l.Topic1), "%s log %d from", surface, l.LogIndex)
		assert.Equal(t, rpMaskedTopic(v, src.to), strings.ToLower(*l.Topic2), "%s log %d to", surface, l.LogIndex)
		assert.Equal(t, src.data, l.Data, "%s log %d data", surface, l.LogIndex)
		for a := range l.AddressMetadata {
			assert.Truef(t, strings.EqualFold(a, v.addr) || strings.EqualFold(a, rpC),
				"%s: addressMetadata keyed by a masked address %s", surface, a)
		}
	}
	sort.Ints(idx)
	if wantIdx == nil {
		wantIdx = []int{}
	}
	assert.Equal(t, wantIdx, idx, "%s: admitted logs for %s", surface, v.name)
	// Refused log responses contain no third-party addresses.
	for _, other := range []string{rpQ, rpR} {
		assert.False(t, rpHasAddr(body, other), "%s: body includes %s: %s", surface, other, body)
	}
}
