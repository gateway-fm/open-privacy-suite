package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/require"
)

// RD-1300: the RPC renders each admitted log with the payload policy decided
// at admission. These unit tests pin the renderer in isolation (no DB): a
// Full log leaves byte-for-byte, a Masked log keeps the RD-1214 masking, and
// the two never influence each other inside one response.

func TestRedactAdmittedLogs_PolicyPerLog(t *testing.T) {
	emitter := "0x1111111111111111111111111111111111111111"
	third := "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
	transfer := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	// Same content twice: identical input, different policy.
	raw := rawLogJSON(t, emitter, []string{transfer, topicOf(third), topicOf(third)}, "0x")
	// Every address resolves non-Full for this viewer.
	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{vis: map[string]explorer.VisibilityLevel{}}}

	out := p.redactAdmittedLogs(context.Background(), "did:viewer", []rbac.AdmittedLog{
		{Raw: raw, Payload: rbac.LogPayloadFull},
		{Raw: raw, Payload: rbac.LogPayloadMasked},
		{Raw: raw}, // zero value → masked
	}, noABIProvider{})
	require.Len(t, out, 3)
	require.Equal(t, string(raw), string(out[0]), "Full payload must be returned byte-for-byte")
	for _, i := range []int{1, 2} {
		topics := topicsOf(t, out[i])
		require.Equal(t, transfer, topics[0])
		require.Equal(t, zeroTopic, topics[1], "masked log %d: third party must be zeroed", i)
		require.Equal(t, zeroTopic, topics[2], "masked log %d: third party must be zeroed", i)
	}
}

func TestRedactAdmittedLogs_MaskedLogThatCannotBeParsedIsDropped(t *testing.T) {
	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{vis: map[string]explorer.VisibilityLevel{}}}
	good := rawLogJSON(t, "0x1111111111111111111111111111111111111111", []string{"0x" + strings.Repeat("ab", 32)}, "0x")
	out := p.redactAdmittedLogs(context.Background(), "did:viewer", []rbac.AdmittedLog{
		{Raw: json.RawMessage(`"not-a-log-object"`), Payload: rbac.LogPayloadMasked},
		{Raw: good, Payload: rbac.LogPayloadMasked},
	}, noABIProvider{})
	require.Len(t, out, 1, "a masked log the renderer cannot parse must be dropped, never emitted raw")
}

func TestRedactAdmittedLogs_ResolverErrorMasksEverythingButFull(t *testing.T) {
	emitter := "0x1111111111111111111111111111111111111111"
	own := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	raw := rawLogJSON(t, emitter, []string{"0x" + strings.Repeat("ab", 32), topicOf(own)}, "0x")
	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{err: context.DeadlineExceeded}}
	out := p.redactAdmittedLogs(context.Background(), "did:viewer", []rbac.AdmittedLog{
		{Raw: raw, Payload: rbac.LogPayloadFull},
		{Raw: raw, Payload: rbac.LogPayloadMasked},
	}, noABIProvider{})
	require.Len(t, out, 2)
	require.Equal(t, string(raw), string(out[0]))
	require.Equal(t, zeroTopic, topicsOf(t, out[1])[1], "resolver error: masked log fails closed")
}

// TestFilterReceiptLogs_UnlockBoundToReceiptHash: a receipt's logs are only
// unlocked by the listing of THAT receipt's transaction. A log carrying a
// different transactionHash (only a faulty upstream could produce one) must
// not borrow another transaction's listing.
func TestFilterReceiptLogs_UnlockBoundToReceiptHash(t *testing.T) {
	const (
		flagged     = "0xa00000000000000000000000000000000000000a"
		viewer      = "did:test:viewer"
		receiptHash = "0x1111111111111111111111111111111111111111111111111111111111111111"
		otherHash   = "0x2222222222222222222222222222222222222222222222222222222222222222"
		third       = "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
		from        = "0x3333333333333333333333333333333333333333"
	)
	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	perms := &rbac.EffectivePermissions{ContractAccess: map[string]rbac.ContractAccess{flagged: {EventRules: &rbac.EventRulesField{}}}}
	abiProv := mapABIProvider{flagged: erc20ABI}
	logFor := func(tx string) map[string]any {
		return map[string]any{"address": flagged, "topics": []string{topic0, topicOf(third), topicOf(third)},
			"data": "0x" + strings.Repeat("0", 63) + "1", "transactionHash": tx, "logIndex": "0x0"}
	}
	receipt := map[string]any{"transactionHash": receiptHash, "from": from, "to": flagged,
		"logs": []any{logFor(receiptHash), logFor(otherHash)}}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": receipt})
	require.NoError(t, err)

	visCtx := &rbac.TxVisibilityContext{
		ViewerDID:           viewer,
		TxVisibility:        map[string][]string{receiptHash: {viewer}, otherHash: {viewer}},
		UnlockableContracts: map[string]bool{flagged: true},
	}
	p := &JSONRPCProcessor{readProfile: rbac.ReadProfileStandard, addrVisResolver: &mockAddrVisResolver{vis: map[string]explorer.VisibilityLevel{}}}
	out := filterReceiptLogsWithEventRules(rbac.ReadProfileStandard, body, nil, perms, abiProv, visCtx, nil, p.logFieldRenderer(context.Background(), viewer, abiProv))

	var resp struct {
		Result struct {
			Logs []json.RawMessage `json:"logs"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	require.Len(t, resp.Result.Logs, 1, "only the log of the listed receipt tx is unlocked; the foreign-hash log falls to deny-all")
	topics := topicsOf(t, resp.Result.Logs[0])
	require.Equal(t, topicOf(third), topics[1], "the receipt's own log keeps its full payload")
}

func TestReceiptWithEmptyLogs_UnparseableFailsClosed(t *testing.T) {
	require.Equal(t, "null", string(receiptWithEmptyLogs(json.RawMessage(`[1,2,3]`))),
		"a receipt that cannot be parsed must not be returned raw")
}
