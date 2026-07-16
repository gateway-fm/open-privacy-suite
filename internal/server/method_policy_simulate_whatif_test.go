package server

import (
	"testing"

	"privacy-proxy/internal/rbac"
)

// TestHypotheticalCaptures_WhatIf proves the what-if simulate path: admin-supplied
// parties (no DB read) drive the SAME SimulateReader capture eval as a live
// record, so a freshly authored policy can be validated before any record exists.
func TestHypotheticalCaptures_WhatIf(t *testing.T) {
	const policy = `{"records":{"payment":{
      "capture":[{"method":"createPayment(string,address,uint256)","key":{"source":"param","index":0},
        "remember":{"payer":{"source":"sender","merge":"set_once"},"audience":{"source":"visibleTo","merge":"union"}}}],
      "access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},
        "allow":[{"callerIn":["payer","audience"]}],"onNoRecord":"deny","else":"deny"}]
    }}}`
	doc, err := rbac.ParseMethodPolicyDocument([]byte(policy))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	rows := hypotheticalCaptures(map[string][]string{
		"payer":    {"did:test:alice"},
		"audience": {"did:test:charlie"},
	})
	load := func(string) ([]rbac.CapturedField, error) { return rows, nil }

	// A supplied party → allow (same eval a live record would give).
	for _, did := range []string{"did:test:alice", "did:test:charlie"} {
		res, gated, err := doc.SimulateReader("getPaymentInfo(string)", rbac.NewCallerIdentity(did, nil), load)
		if err != nil || !gated {
			t.Fatalf("%s: gated=%v err=%v", did, gated, err)
		}
		if !res.Allow {
			t.Fatalf("%s: expected allow", did)
		}
	}

	// A caller not among the supplied parties → deny.
	if res, _, _ := doc.SimulateReader("getPaymentInfo(string)", rbac.NewCallerIdentity("did:test:diana", nil), load); res.Allow {
		t.Fatal("diana (not a supplied party) must be denied")
	}

	// Merge is forced to "union", so multiple values in one field never trip
	// set-once poisoning — a what-if run tests admission, not accumulation.
	multi := func(string) ([]rbac.CapturedField, error) {
		return hypotheticalCaptures(map[string][]string{"payer": {"did:test:alice", "did:test:bob"}}), nil
	}
	res, _, _ := doc.SimulateReader("getPaymentInfo(string)", rbac.NewCallerIdentity("did:test:bob", nil), multi)
	if res.Poisoned {
		t.Fatal("what-if rows must not trip set-once poisoning")
	}
	if !res.Allow {
		t.Fatal("bob is among the supplied payer values → allow")
	}
}
