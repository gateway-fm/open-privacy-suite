package nodepolicy

import (
	"errors"
	"testing"
	"time"
)

func snapshotFixture() Snapshot {
	i := identityFixture()
	return Snapshot{Header: i.Header, Version: 7,
		Principals: []Principal{{ID: "user-a", LinkedAddresses: []string{i.Signer}, Memberships: []Membership{{GroupID: "payments", ExpiresAt: 1050}}}, {ID: "user-b", LinkedAddresses: []string{i.Signer}, Memberships: []Membership{{GroupID: "readers"}}}},
		Groups:     []Group{{ID: "payments", OrgID: "org-a", Claims: ClaimDeploy}, {ID: "readers", OrgID: "org-a"}},
		Contracts:  []Contract{{Address: i.Signer, OrgID: "org-a"}}}
}

func TestPinnedSnapshotKeepsPrincipalsSeparateAndExpiresMembership(t *testing.T) {
	s := snapshotFixture()
	p, err := Pin(s)
	if err != nil {
		t.Fatal(err)
	}
	i := identityFixture()
	a, err := p.Resolve(i, time.Unix(1020, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Groups) != 1 || a.Groups[0].ID != "payments" {
		t.Fatalf("wrong principal facts %+v", a)
	}
	i.PrincipalID = "user-b"
	b, err := p.Resolve(i, time.Unix(1020, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Groups) != 1 || b.Groups[0].ID != "readers" {
		t.Fatalf("shared signer combined facts: %+v", b)
	}
	i.PrincipalID = "user-a"
	expired, err := p.Resolve(i, time.Unix(1050, 0))
	if !errors.Is(err, ErrPrincipal) {
		t.Fatalf("expired org membership must deny: %v", err)
	}
	if len(expired.Groups) != 0 {
		t.Fatal("expired membership still active")
	}
	s.Principals[0].Memberships[0].GroupID = "readers"
	a.Groups[0].ID = "readers"
	again, err := p.Resolve(i, time.Unix(1020, 0))
	if err != nil || again.Groups[0].ID != "payments" {
		t.Fatal("pinned snapshot aliased mutable input or output")
	}
}

func TestIdentityCannotSelectAnUnrelatedOrganization(t *testing.T) {
	p, err := Pin(snapshotFixture())
	if err != nil {
		t.Fatal(err)
	}
	i := identityFixture()
	i.OrgID = "org-b"
	if _, err := p.Resolve(i, time.Unix(1020, 0)); err == nil {
		t.Fatal("principal selected an org without membership")
	}
}

func TestSignedIdentityDoesNotPreserveRevokedAuthority(t *testing.T) {
	for _, what := range []string{"ban", "unlink", "delete", "lag", "expired_snapshot", "expired_identity", "wrong_network"} {
		t.Run(what, func(t *testing.T) {
			s := snapshotFixture()
			i := identityFixture()
			at := time.Unix(1020, 0)
			switch what {
			case "ban":
				s.Principals[0].Banned = true
			case "unlink":
				s.Principals[0].LinkedAddresses = nil
			case "delete":
				s.Principals = s.Principals[1:]
			case "lag":
				i.MinSnapshotVersion = 8
			case "expired_snapshot":
				s.ExpiresAt = 1020
			case "expired_identity":
				i.ExpiresAt = 1020
			case "wrong_network":
				i.Network.DeploymentID = "other"
			}
			p, err := Pin(s)
			if err != nil {
				return
			}
			if _, err := p.Resolve(i, at); err == nil {
				t.Fatal("revoked or invalid context permitted")
			}
		})
	}
}

func TestIdentityBindingsCannotBeReassigned(t *testing.T) {
	registry := NewIdentityRegistry(2)
	a := identityFixture()
	wire, err := testSigner().Seal("identity", a)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Accept(testVerifier(), wire); err != nil {
		t.Fatal(err)
	}
	if err := registry.Accept(testVerifier(), wire); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	b := a
	b.ContextID = "context-2"
	b.PrincipalID = "user-b"
	other, err := testSigner().Seal("identity", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Accept(testVerifier(), other); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("rebound same tx: %v", err)
	}
	got, err := registry.Lookup(a.Scope, a.BindingHash, time.Unix(1020, 0))
	if err != nil || got.PrincipalID != "user-a" {
		t.Fatalf("binding was overwritten: %+v %v", got, err)
	}
	if _, err := registry.Lookup(a.Scope, a.BindingHash, time.Unix(1100, 0)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired identity: %v", err)
	}
}

func TestSnapshotRejectsAmbiguousAndDanglingFacts(t *testing.T) {
	for _, what := range []string{"duplicate_principal", "duplicate_group", "missing_group", "missing_org", "bad_address", "bad_claim"} {
		t.Run(what, func(t *testing.T) {
			s := snapshotFixture()
			switch what {
			case "duplicate_principal":
				s.Principals = append(s.Principals, s.Principals[0])
			case "duplicate_group":
				s.Groups = append(s.Groups, s.Groups[0])
			case "missing_group":
				s.Groups = s.Groups[1:]
			case "missing_org":
				s.Groups[0].OrgID = ""
			case "bad_address":
				s.Principals[0].LinkedAddresses = []string{"0x1234"}
			case "bad_claim":
				s.Groups[0].Claims = 128
			}
			if _, err := Pin(s); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestSnapshotSignedRoundTrip(t *testing.T) {
	s := snapshotFixture()
	wire, err := testSigner().Seal("snapshot", s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := testVerifier().OpenSnapshot(wire)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := got.Resolve(identityFixture(), time.Unix(1020, 0))
	if err != nil || len(facts.Groups) != 1 || facts.Groups[0].ID != "payments" {
		t.Fatalf("signed snapshot facts: %+v %v", facts, err)
	}
}

func TestSanctionsKeepOrganizationScope(t *testing.T) {
	s := snapshotFixture()
	address := identityFixture().Signer
	s.Sanctions = []Sanction{{OrgID: "org-b", Address: address}}
	p, err := Pin(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(identityFixture(), time.Unix(1020, 0)); err != nil {
		t.Fatalf("another organisation's sanction denied principal: %v", err)
	}
	if p.IsSanctioned(address, "org-a") || !p.IsSanctioned(address, "org-b") {
		t.Fatal("organisation sanction scope lost")
	}
	s.Sanctions[0].OrgID = "org-a"
	p, err = Pin(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(identityFixture(), time.Unix(1020, 0)); !errors.Is(err, ErrPrincipal) {
		t.Fatal("selected organisation's signer sanction did not deny execution")
	}
	s.Sanctions = append(s.Sanctions, Sanction{Address: address})
	p, err = Pin(s)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsSanctioned(address, "org-a") {
		t.Fatal("global sanction did not apply")
	}
	if _, err := p.Resolve(identityFixture(), time.Unix(1020, 0)); err == nil {
		t.Fatal("global sanction did not deny signer")
	}
}
