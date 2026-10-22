package explorer

import (
	"context"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/rbac"
	"testing"
)

// Ordinary readers must not apply a counterparty lens, retain rows, or preserve
// private amounts based on the obsolete disclosure metadata reason. The DB
// regression matrix separately verifies that grants never produce these levels.
func TestRedactorsDoNotApplyDisclosureLensRD1353(t *testing.T) {
	const subject = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const counter = "0xcccccccccccccccccccccccccccccccccccccccc"
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, level := range []VisibilityLevel{VisibilityFull, VisibilityPseudonymous, VisibilityRedacted} {
			for _, surface := range []string{"transactions", "transfers", "internal"} {
				t.Run(profile.String()+"/"+string(level)+"/"+surface, func(t *testing.T) {
					detailed := map[string]AddressVisibility{
						subject: {Level: level, Reason: VisibilityReason("disclosure_grant")},
						counter: {Level: VisibilityHidden, Reason: ReasonNoAccess},
					}
					engine := NewRedactionEngine(nil, &rd1079DB{detailedMap: detailed, visMap: visibilityMapFromDetailed(detailed)}, profile)
					to := counter
					switch surface {
					case "transactions":
						rows, err := engine.RedactTransactions(context.Background(), []Transaction{{Hash: "0x01", From: subject, To: &to, Value: "42"}}, "did:auditor")
						require.NoError(t, err)
						require.Empty(t, rows, "a disclosure reason cannot admit a transaction")
					case "transfers":
						rows, err := engine.RedactTransfers(context.Background(), []TokenTransfer{{TxHash: "0x01", From: subject, To: counter, Value: "42"}}, "did:auditor")
						require.NoError(t, err)
						require.Empty(t, rows, "a disclosure reason cannot admit a transfer")
					case "internal":
						rows, err := engine.RedactInternalTransactions(context.Background(), []InternalTransaction{{TxHash: "0x01", From: subject, To: &to, Value: "42"}}, "did:auditor")
						require.NoError(t, err)
						if profile.Strict() || level == VisibilityRedacted {
							require.Empty(t, rows)
						} else {
							require.Len(t, rows, 1)
							require.Equal(t, "[PRIVATE]", *rows[0].To)
							require.Empty(t, rows[0].Value)
						}
					}
				})
			}
		}
	}
}

func TestStrictAllowlistIgnoresDisclosureMetadataRD1353(t *testing.T) {
	detailed := map[string]AddressVisibility{
		"0xown":   {Level: VisibilityFull, Reason: ReasonOwnAddress},
		"0xgrant": {Level: VisibilityFull, Reason: VisibilityReason("disclosure_grant")},
		"0xrbac":  {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
	}
	require.Equal(t, []string{"0xown"}, StrictAllowlist(detailed))
}
