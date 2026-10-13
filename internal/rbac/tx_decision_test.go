package rbac

import "testing"

// DecideTxEnvelope is the single admission decision for a transaction object,
// a receipt and a block entry on every read surface (RD-1299). Each case
// varies one fact to verify its contribution to the verdict.
func TestDecideTxEnvelope_TruthTable(t *testing.T) {
	type tc struct {
		name     string
		f        TxEnvelopeFacts
		standard bool
		strict   bool
	}
	tx := TxSurfaceTransaction
	rc := TxSurfaceReceipt
	be := TxSurfaceBlockEntry
	cases := []tc{
		// Participant: admitted everywhere, in both profiles.
		{"tx participant", TxEnvelopeFacts{Surface: tx, IsParticipant: true}, true, true},
		{"receipt participant", TxEnvelopeFacts{Surface: rc, IsParticipant: true}, true, true},
		{"block entry participant", TxEnvelopeFacts{Surface: be, IsParticipant: true}, true, true},
		{"deployment receipt participant", TxEnvelopeFacts{Surface: rc, IsParticipant: true, IsDeployment: true}, true, true},

		// Nothing: never admitted.
		{"tx nobody", TxEnvelopeFacts{Surface: tx}, false, false},
		{"receipt nobody", TxEnvelopeFacts{Surface: rc}, false, false},
		{"block entry nobody", TxEnvelopeFacts{Surface: be}, false, false},

		// Admin on the destination contract (RD-751 extension): standard only.
		{"tx admin", TxEnvelopeFacts{Surface: tx, IsAdminOnTo: true}, true, false},
		{"receipt admin", TxEnvelopeFacts{Surface: rc, IsAdminOnTo: true}, true, false},
		{"block entry admin", TxEnvelopeFacts{Surface: be, IsAdminOnTo: true}, false, false},

		// visibleTo recipient: standard only; never on block lists.
		{"tx visibleTo", TxEnvelopeFacts{Surface: tx, InVisibleTo: true}, true, false},
		{"receipt visibleTo", TxEnvelopeFacts{Surface: rc, InVisibleTo: true}, true, false},
		{"block entry visibleTo", TxEnvelopeFacts{Surface: be, InVisibleTo: true}, false, false},

		// Log-entitled non-participant (RD-1183): receipt only, standard only,
		// never for a deployment receipt.
		{"receipt entitled log", TxEnvelopeFacts{Surface: rc, EntitledLogs: 1}, true, false},
		{"receipt entitled log, deployment", TxEnvelopeFacts{Surface: rc, EntitledLogs: 2, IsDeployment: true}, false, false},
		{"tx entitled log (RD-1191 not inherited)", TxEnvelopeFacts{Surface: tx, EntitledLogs: 1}, false, false},

		// Everything but participation: strict still refuses.
		{"tx all non-participant facts", TxEnvelopeFacts{Surface: tx, IsAdminOnTo: true, InVisibleTo: true, EntitledLogs: 3}, true, false},
		{"receipt all non-participant facts", TxEnvelopeFacts{Surface: rc, IsAdminOnTo: true, InVisibleTo: true, EntitledLogs: 3}, true, false},

		// Unknown surface: participant only (fail closed).
		{"unknown surface admin", TxEnvelopeFacts{IsAdminOnTo: true, InVisibleTo: true, EntitledLogs: 1}, false, false},
		{"unknown surface participant", TxEnvelopeFacts{IsParticipant: true}, true, true},

		// Full disclosure grant over the tx's from or to: the consented
		// exception, admitted on every surface in BOTH profiles, deployments
		// included. An unknown surface stays participant-only.
		{"tx full grant", TxEnvelopeFacts{Surface: tx, FullDisclosureGrant: true}, true, true},
		{"receipt full grant", TxEnvelopeFacts{Surface: rc, FullDisclosureGrant: true}, true, true},
		{"block entry full grant", TxEnvelopeFacts{Surface: be, FullDisclosureGrant: true}, true, true},
		{"deployment receipt full grant", TxEnvelopeFacts{Surface: rc, FullDisclosureGrant: true, IsDeployment: true}, true, true},
		{"deployment block receipt full grant", TxEnvelopeFacts{Surface: be, FullDisclosureGrant: true, IsDeployment: true}, true, true},
		{"unknown surface full grant", TxEnvelopeFacts{FullDisclosureGrant: true}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DecideTxEnvelope(ReadProfileStandard, c.f); got != c.standard {
				t.Errorf("standard = %v, want %v", got, c.standard)
			}
			if got := DecideTxEnvelope(ReadProfileStrict, c.f); got != c.strict {
				t.Errorf("strict = %v, want %v", got, c.strict)
			}
			// An unset profile is enforced as strict.
			if got := DecideTxEnvelope(ReadProfileUnset, c.f); got != c.strict {
				t.Errorf("unset = %v, want strict verdict %v", got, c.strict)
			}
		})
	}
}

// TxEnvelopeRevealedByGrant attributes an admission to the disclosure grant
// only when the grant is what admits the envelope: the reveal the audit trail
// records. Any other admitting fact (participation, standard admin or
// visibleTo) makes the grant immaterial, and a refused envelope reveals
// nothing.
func TestTxEnvelopeRevealedByGrant(t *testing.T) {
	tx := TxSurfaceTransaction
	cases := []struct {
		name     string
		f        TxEnvelopeFacts
		standard bool
		strict   bool
	}{
		{"grant only", TxEnvelopeFacts{Surface: tx, FullDisclosureGrant: true}, true, true},
		{"grant + participant", TxEnvelopeFacts{Surface: tx, FullDisclosureGrant: true, IsParticipant: true}, false, false},
		// Standard admits the admin anyway; strict admits only through the grant.
		{"grant + admin on to", TxEnvelopeFacts{Surface: tx, FullDisclosureGrant: true, IsAdminOnTo: true}, false, true},
		{"grant + visibleTo", TxEnvelopeFacts{Surface: tx, FullDisclosureGrant: true, InVisibleTo: true}, false, true},
		{"no grant", TxEnvelopeFacts{Surface: tx, IsAdminOnTo: true}, false, false},
		{"grant on a deployment receipt", TxEnvelopeFacts{Surface: TxSurfaceReceipt, FullDisclosureGrant: true, IsDeployment: true}, true, true},
		// RD-1183 log entitlement admits a standard receipt on its own.
		{"grant + entitled log", TxEnvelopeFacts{Surface: TxSurfaceReceipt, FullDisclosureGrant: true, EntitledLogs: 1}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TxEnvelopeRevealedByGrant(ReadProfileStandard, c.f); got != c.standard {
				t.Errorf("standard = %v, want %v", got, c.standard)
			}
			if got := TxEnvelopeRevealedByGrant(ReadProfileStrict, c.f); got != c.strict {
				t.Errorf("strict = %v, want %v", got, c.strict)
			}
		})
	}
}
