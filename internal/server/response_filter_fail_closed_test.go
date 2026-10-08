package server

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The response filters must fail CLOSED on any upstream shape they cannot
// evaluate: returning the upstream body unchanged would hand an unfiltered
// transaction, block or receipt list to the caller (RD-1299). A null result is
// the fail-closed form (indistinguishable from "not found").

func resultOf(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoErrorf(t, json.Unmarshal(body, &resp), "filter output must be valid JSON-RPC: %s", body)
	return string(resp.Result)
}

func TestResponseFilters_FailClosedOnUnexpectedShape(t *testing.T) {
	const fixtureAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	cases := []struct {
		name string
		body string
		run  func([]byte) []byte
		want string
	}{
		{
			name: "tx-by-hash: body is not JSON",
			body: `{"jsonrpc":"2.0","id":1,"result":{"from":"` + fixtureAddress + `"`,
			run:  func(b []byte) []byte { return FilterTransactionByHash(rbac.ReadProfileStandard, b, nil, false, nil) },
			want: "null",
		},
		{
			name: "tx-by-hash: result is not an object",
			body: `{"jsonrpc":"2.0","id":1,"result":["` + fixtureAddress + `"]}`,
			run:  func(b []byte) []byte { return FilterTransactionByHash(rbac.ReadProfileStandard, b, nil, false, nil) },
			want: "null",
		},
		{
			name: "block receipts: result is not an array",
			body: `{"jsonrpc":"2.0","id":1,"result":{"from":"` + fixtureAddress + `","to":"` + fixtureAddress + `"}}`,
			run: func(b []byte) []byte {
				return FilterBlockReceipts(rbac.ReadProfileStandard, b, nil, nil, nil, nil, nil, nil)
			},
			want: "null",
		},
		{
			name: "block receipts: body is not JSON",
			body: `{"jsonrpc":"2.0","id":1,"result":[{"from":"` + fixtureAddress + `"}`,
			run: func(b []byte) []byte {
				return FilterBlockReceipts(rbac.ReadProfileStandard, b, nil, nil, nil, nil, nil, nil)
			},
			want: "null",
		},
		{
			name: "block: result is not an object",
			body: `{"jsonrpc":"2.0","id":1,"result":["` + fixtureAddress + `"]}`,
			run:  func(b []byte) []byte { return FilterBlockTransactions(rbac.ReadProfileStandard, b, nil, true) },
			want: "null",
		},
		{
			name: "block: body is not JSON",
			body: `{"jsonrpc":"2.0","id":1,"result":{"transactions":[{"from":"` + fixtureAddress + `"}`,
			run:  func(b []byte) []byte { return FilterBlockTransactions(rbac.ReadProfileStandard, b, nil, true) },
			want: "null",
		},
		{
			name: "block: transactions is not an array",
			body: `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":{"x":{"from":"` + fixtureAddress + `"}}}}`,
			run:  func(b []byte) []byte { return FilterBlockTransactions(rbac.ReadProfileStandard, b, nil, true) },
			want: `{"number":"0x1","transactions":[]}`,
		},
		{
			// Count filters require a rewritten block response.
			name: "tx count: result is a raw count, not a block",
			body: `{"jsonrpc":"2.0","id":1,"result":"0x2a"}`,
			run:  func(b []byte) []byte { return FilterBlockTransactionCount(b, nil) },
			want: "null",
		},
		{
			name: "tx count: body is not JSON",
			body: `{"jsonrpc":"2.0","id":1,"result":{"transactions":[`,
			run:  func(b []byte) []byte { return FilterBlockTransactionCount(b, nil) },
			want: "null",
		},
		{
			// Empty blocks return the numeric zero count.
			name: "tx count: empty block counts zero",
			body: `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","miner":"` + fixtureAddress + `","transactions":[]}}`,
			run:  func(b []byte) []byte { return FilterBlockTransactionCount(b, nil) },
			want: `"0x0"`,
		},
		{
			name: "tx count: block without a transactions field counts zero",
			body: `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","miner":"` + fixtureAddress + `"}}`,
			run:  func(b []byte) []byte { return FilterBlockTransactionCount(b, nil) },
			want: `"0x0"`,
		},
		{
			name: "tx count: unparseable transactions fail closed",
			body: `{"jsonrpc":"2.0","id":1,"result":{"number":"0x1","transactions":"` + fixtureAddress + `"}}`,
			run:  func(b []byte) []byte { return FilterBlockTransactionCount(b, nil) },
			want: "null",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.run([]byte(tc.body))
			assert.NotContains(t, string(out), fixtureAddress[2:], "unfiltered upstream data passed through: %s", out)
			assert.Equal(t, tc.want, resultOf(t, out))
		})
	}
}

// A null or error upstream result still passes through unchanged: there is
// nothing to filter and the caller needs the upstream error.
func TestResponseFilters_PassNullAndErrors(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":7,"result":null}`,
		`{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"not found"}}`,
	} {
		assert.JSONEq(t, body, string(FilterTransactionByHash(rbac.ReadProfileStandard, []byte(body), nil, false, nil)))
		assert.JSONEq(t, body, string(FilterBlockReceipts(rbac.ReadProfileStandard, []byte(body), nil, nil, nil, nil, nil, nil)))
		assert.JSONEq(t, body, string(FilterBlockTransactions(rbac.ReadProfileStandard, []byte(body), nil, true)))
		assert.JSONEq(t, body, string(FilterBlockTransactionCount([]byte(body), nil)))
	}
}

func TestResponseFilters_RejectMixedErrorAndResult(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"upstream failure"},"result":{"from":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"}}`
	cases := []struct {
		name string
		run  func([]byte) []byte
		want string
	}{
		{"transaction", func(b []byte) []byte { return FilterTransactionByHash(rbac.ReadProfileStandard, b, nil, false, nil) }, "null"},
		{"block", func(b []byte) []byte { return FilterBlockTransactions(rbac.ReadProfileStandard, b, nil, true) }, "null"},
		{"block receipts", func(b []byte) []byte {
			return FilterBlockReceipts(rbac.ReadProfileStandard, b, nil, nil, nil, nil, nil, nil)
		}, "null"},
		{"block count", func(b []byte) []byte { return FilterBlockTransactionCount(b, nil) }, "null"},
		{"logs", func(b []byte) []byte {
			return filterLogsWithEventRules(rbac.ReadProfileStandard, b, nil, nil, nil, nil, nil, nil)
		}, "[]"},
		{"receipt logs", func(b []byte) []byte {
			return filterReceiptLogsWithEventRules(rbac.ReadProfileStandard, b, nil, nil, nil, nil, nil, nil)
		}, "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.run([]byte(body))
			assert.Equal(t, tc.want, resultOf(t, out))
			assert.NotContains(t, string(out), "aaaaaaaa")
			assert.NotContains(t, string(out), `"error"`)
		})
	}
}
