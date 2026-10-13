package rbac

import (
	"context"
	"encoding/json"
	"testing"
)

// The JSON-RPC log filter resolves the disclosure-grant fact for each log from
// the per-response grant set (TxVisibilityContext.DisclosureGrants) with the
// same indexed-address matcher the strict profile uses, and hands the verdict
// to the shared decision. An admitted grant log stays masked, carries the
// parties the grant lens reveals, is marked for the audit trail, and does not
// count as the viewer's own entitlement (RD-1183 receipt admission stays the
// viewer's own). A literal param rule binds the grant like the viewer.
func TestFilterEventLogsDetailed_FullDisclosureGrant(t *testing.T) {
	const (
		emitter = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
		subject = "0x5b1ec70000000000000000000000000000000001"
		viewer  = "0x7e7e000000000000000000000000000000000002"
		other   = "0x07e4000000000000000000000000000000000003"
	)
	perms := &EffectivePermissions{ContractAccess: map[string]ContractAccess{
		emitter: {EventRules: &EventRulesField{Rules: []EventRule{{
			Topic0: isTransferT0, Name: "Transfer",
			ParamRules: []ParamRule{{Index: 0, MustBe: "self"}, {Index: 1, MustBe: "self"}},
		}}}},
	}}
	abis := &testABIProvider{abis: map[string]string{emitter: indexedSelfABI}}
	mk := func(from, to, tx string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{
			"address": emitter, "topics": []string{isTransferT0, isTopic(from), isTopic(to)},
			"data": "0x" + isWord(5), "transactionHash": tx,
		})
		return b
	}
	subjectLog := mk(subject, other, "0x01")
	ownLog := mk(viewer, subject, "0x02")
	otherLog := mk(other, other, "0x03")
	logs := []json.RawMessage{subjectLog, ownLog, otherLog}

	grants := ResolveDisclosureGrants(context.Background(),
		&fakeFullGrantResolver{addrs: map[string][]string{subject: {grantID}}}, "did:test:auditor")

	for _, profile := range []ReadProfile{ReadProfileStandard, ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			without := FilterEventLogsDetailed(profile, logs, perms, []string{viewer}, abis, nil, nil)
			if len(without) != 1 || string(without[0].Raw) != string(ownLog) {
				t.Fatalf("without a grant only the viewer's own transfer is admitted, got %d", len(without))
			}

			got := FilterEventLogsDetailed(profile, logs, perms, []string{viewer}, abis,
				&TxVisibilityContext{DisclosureGrants: grants}, nil)
			if len(got) != 2 {
				t.Fatalf("want the subject's transfer and the viewer's own, got %d", len(got))
			}
			byTx := map[string]AdmittedLog{}
			for _, a := range got {
				var m struct {
					TransactionHash string `json:"transactionHash"`
				}
				_ = json.Unmarshal(a.Raw, &m)
				byTx[m.TransactionHash] = a
			}
			s := byTx["0x01"]
			if s.Payload != LogPayloadMasked || !s.DisclosureGrant || !s.ViaGrantOnly {
				t.Errorf("subject's transfer: %+v, want masked, grant-attributed, grant-only", s)
			}
			if len(s.GrantLensAddresses) != 2 || s.GrantLensAddresses[0] != subject || s.GrantLensAddresses[1] != other {
				t.Errorf("the lens reveals the parties the Transfer names: %v", s.GrantLensAddresses)
			}
			o := byTx["0x02"]
			// The viewer's own transfer also names the subject: it gets the
			// grant lens, but the viewer was entitled to it anyway.
			if o.Payload != LogPayloadMasked || !o.DisclosureGrant || o.ViaGrantOnly {
				t.Errorf("viewer's own transfer naming the subject: %+v, want masked, grant-attributed, not grant-only", o)
			}
		})
	}

	// A literal param rule (must_be a fixed recipient) binds the grantee: the
	// grant changes whose events count as "self", not which events.
	literal := &EffectivePermissions{ContractAccess: map[string]ContractAccess{
		emitter: {EventRules: &EventRulesField{Rules: []EventRule{{
			Topic0: isTransferT0, Name: "Transfer",
			ParamRules: []ParamRule{{Index: 1, MustBe: viewer}},
		}}}},
	}}
	for _, profile := range []ReadProfile{ReadProfileStandard, ReadProfileStrict} {
		got := FilterEventLogsDetailed(profile, []json.RawMessage{subjectLog}, literal, []string{viewer}, abis,
			&TxVisibilityContext{DisclosureGrants: grants}, nil)
		if len(got) != 0 {
			t.Errorf("%v: a literal param rule the event fails must not admit through a grant", profile)
		}
	}
}
