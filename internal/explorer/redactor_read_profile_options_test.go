package explorer

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"privacy-proxy/internal/rbac"
)

type readProfileOptionRow struct {
	From, To, Value string
	Metadata        map[string]VisibilityReason
}

func redactReadProfileOptionRows(engine *RedactionEngine, surface string, opts RedactOpts) ([]readProfileOptionRow, error) {
	ctx := context.Background()
	to := sbToken
	var result []readProfileOptionRow
	switch surface {
	case "transactions":
		rows, err := engine.RedactTransactions(ctx, []Transaction{{Hash: sbHash(0), From: sbOther, To: &to, Value: "42"}}, "did:viewer", opts)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result = append(result, readProfileOptionRow{row.From, *row.To, string(row.Value), row.AddressMetadata})
		}
	case "transfers":
		rows, err := engine.RedactTransfers(ctx, []TokenTransfer{{TxHash: sbHash(0), TokenAddress: sbToken, From: sbOther, To: to, Value: "42"}}, "did:viewer", opts)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result = append(result, readProfileOptionRow{row.From, row.To, string(row.Value), row.AddressMetadata})
		}
	case "internal":
		rows, err := engine.RedactInternalTransactions(ctx, []InternalTransaction{{TxHash: sbHash(0), From: sbOther, To: &to, Value: "42"}}, "did:viewer", opts)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result = append(result, readProfileOptionRow{row.From, *row.To, string(row.Value), row.AddressMetadata})
		}
	}
	return result, nil
}

func readProfileOptionEngine(profile rbac.ReadProfile, grantLevel *VisibilityLevel) *RedactionEngine {
	db := newCountingDB(VisibilityMap{sbOther: VisibilityHidden, sbToken: VisibilityRedacted}, []string{sbViewer})
	db.eventAccessMap = map[string]bool{sbToken: true}
	if grantLevel != nil {
		db.detailed[sbToken] = AddressVisibility{Address: sbToken, Level: *grantLevel, Reason: ReasonDisclosureGrant, Visible: true}
	}
	engine := NewRedactionEngine(nil, db, profile)
	to := sbToken
	engine.SetTxDataResolver(&countingTxData{txs: map[string]*Transaction{
		sbHash(0): {Hash: sbHash(0), From: sbOther, To: &to},
	}})
	return engine
}

func readProfileShareOpts(listed, union bool) RedactOpts {
	opts := RedactOpts{VisibleTxHashes: map[string]bool{sbHash(0): true}}
	if listed {
		opts.ListedTxHashes = map[string]bool{sbHash(0): true}
	}
	if union {
		opts.ParticipantTxHashes = map[string]bool{sbHash(0): true}
	}
	return opts
}

// Standard honors genuine transaction shares. Strict still requires its
// participant, exact-event or approved-disclosure decision on each surface.
func TestRedactors_GenuineShareOptionsByReadProfile(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, surface := range []string{"transactions", "transfers", "internal"} {
			for _, union := range []bool{false, true} {
				t.Run(profile.String()+"/"+surface+"/union="+strconv.FormatBool(union), func(t *testing.T) {
					engine := readProfileOptionEngine(profile, nil)
					got, err := redactReadProfileOptionRows(engine, surface, readProfileShareOpts(true, union))
					if err != nil {
						t.Fatal(err)
					}
					if profile.Strict() {
						if len(got) != 0 {
							t.Fatalf("a share does not admit a strict nonparticipant row: %+v", got)
						}
						return
					}
					if len(got) != 1 || got[0].From != sbOther || got[0].To != sbToken || got[0].Value != "42" {
						t.Fatalf("standard must retain genuine-share fields: %+v", got)
					}
				})
			}
		}
	}
}

// Strict disclosure views keep the approved lens and its audit count,
// regardless of the optional share and transfer-participant sets supplied.
func TestRedactors_StrictGrantLensIgnoresShareOptions(t *testing.T) {
	for _, level := range []VisibilityLevel{VisibilityFull, VisibilityPseudonymous, VisibilityRedacted} {
		for _, surface := range []string{"transactions", "transfers", "internal"} {
			for _, option := range []struct {
				name          string
				listed, union bool
			}{{"union", false, true}, {"share", true, false}, {"share-and-union", true, true}} {
				t.Run(string(level)+"/"+surface+"/"+option.name, func(t *testing.T) {
					engine := readProfileOptionEngine(rbac.ReadProfileStrict, &level)
					baselineStats := &RedactStats{}
					baseline, err := redactReadProfileOptionRows(engine, surface, RedactOpts{Stats: baselineStats})
					if err != nil {
						t.Fatal(err)
					}
					if len(baseline) != 1 || baseline[0].Value != "42" {
						t.Fatalf("approved grant must retain its activity row and amount: %+v", baseline)
					}
					wantAddress := func(addr string) string { return engine.applyRedaction(addr, level) }
					if baseline[0].From != wantAddress(sbOther) || baseline[0].To != wantAddress(sbToken) {
						t.Fatalf("grant %s must determine both address fields: %+v", level, baseline)
					}
					wantReveals := 0
					if level == VisibilityFull {
						wantReveals = 1
					}
					if baselineStats.GrantFullReveals != wantReveals {
						t.Fatalf("grant audit count = %d, want %d", baselineStats.GrantFullReveals, wantReveals)
					}
					stats := &RedactStats{}
					opts := readProfileShareOpts(option.listed, option.union)
					opts.Stats = stats
					got, err := redactReadProfileOptionRows(engine, surface, opts)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, baseline) || *stats != *baselineStats {
						t.Fatalf("strict options must preserve the approved lens and audit result: got %+v stats=%+v, want %+v stats=%+v", got, stats, baseline, baselineStats)
					}
				})
			}
		}
	}
}

func TestRedactInternalTransactions_StrictParentOptionsPreserveFrameVisibility(t *testing.T) {
	to := sbToken
	frameTo := sbOther
	input, output := "0x12345678", "0x01"
	parent := &Transaction{Hash: sbHash(0), From: sbViewer, To: &to}
	frame := InternalTransaction{TxHash: sbHash(0), From: sbToken, To: &frameTo, Value: "42", Input: &input, Output: &output}
	db := newCountingDB(VisibilityMap{sbViewer: VisibilityFull, sbToken: VisibilityFull, sbOther: VisibilityHidden}, []string{sbViewer})
	engine := NewRedactionEngine(nil, db, rbac.ReadProfileStrict)
	engine.SetTxDataResolver(&countingTxData{txs: map[string]*Transaction{sbHash(0): parent}})
	baseline, err := engine.RedactInternalTransactions(context.Background(), []InternalTransaction{frame}, "did:viewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 1 || baseline[0].From != sbToken || baseline[0].To == nil || *baseline[0].To != "[PRIVATE]" || baseline[0].Value != "42" || baseline[0].Input != nil || baseline[0].Output != nil {
		t.Fatalf("parent participation keeps the amount and each frame side's visibility: %+v", baseline)
	}
	for _, option := range []struct {
		name          string
		listed, union bool
	}{{"union", false, true}, {"share", true, false}, {"share-and-union", true, true}} {
		t.Run(option.name, func(t *testing.T) {
			got, err := engine.RedactInternalTransactions(context.Background(), []InternalTransaction{frame}, "did:viewer", readProfileShareOpts(option.listed, option.union))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, baseline) {
				t.Fatalf("strict options must preserve each frame side's visibility: got %+v, want %+v", got, baseline)
			}
		})
	}
}
