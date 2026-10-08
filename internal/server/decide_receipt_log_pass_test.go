package server

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
)

// A receipt whose envelope no entitled-log count could admit (a block entry or
// a strict receipt for a non-participant) is dropped before the log pass: the
// renderer, which costs a visibility lookup per receipt, never runs for it.
// eth_getBlockReceipts then pays one log pass per KEPT receipt, not per block
// entry. A standard single receipt still needs the pass (RD-1183 admission).
func TestDecideReceipt_DroppedEnvelopeSkipsLogPass(t *testing.T) {
	const viewer = "0x00000000000000000000000000000000000000a1"
	receipt := json.RawMessage(`{"from":"0x00000000000000000000000000000000000000b2","to":"0x00000000000000000000000000000000000000c3",` +
		`"transactionHash":"0x01","logs":[{"address":"0x00000000000000000000000000000000000000c3","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"data":"0x","transactionHash":"0x01","logIndex":"0x0"}]}`)

	cases := []struct {
		name     string
		profile  rbac.ReadProfile
		surface  rbac.TxSurface
		wantPass bool
	}{
		{"standard block entry, non-participant", rbac.ReadProfileStandard, rbac.TxSurfaceBlockEntry, false},
		{"strict block entry, non-participant", rbac.ReadProfileStrict, rbac.TxSurfaceBlockEntry, false},
		{"strict receipt, non-participant", rbac.ReadProfileStrict, rbac.TxSurfaceReceipt, false},
		{"standard receipt, non-participant (RD-1183 needs the count)", rbac.ReadProfileStandard, rbac.TxSurfaceReceipt, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			render := func(a []rbac.AdmittedLog) []json.RawMessage {
				calls++
				return rawAdmittedLogs(a)
			}
			out, admit := decideReceipt(tc.profile, tc.surface, receipt, []string{viewer}, nil, nil, nil, nil, render)
			assert.False(t, admit)
			assert.Nil(t, out)
			assert.Equal(t, tc.wantPass, calls > 0, "log pass ran")
		})
	}
}
