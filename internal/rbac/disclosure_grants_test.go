package rbac

import (
	"context"
	"errors"
	"testing"

	"privacy-proxy/internal/disclosure"
)

type fakeFullGrantResolver struct {
	addrs map[string][]string
	err   error
	calls int
}

func (f *fakeFullGrantResolver) FullDisclosureGrantAddresses(_ context.Context, _ string) (map[string][]string, error) {
	f.calls++
	return f.addrs, f.err
}

const (
	grantSubjectAddr = "0x5b1ec70000000000000000000000000000000001"
	grantOtherAddr   = "0x07e4000000000000000000000000000000000002"
	grantID          = "11111111-1111-1111-1111-111111111111"
)

// The shared fact builder resolves the viewer's Full disclosure grants at most
// once per response and answers "covers from or to" for every row of it. It
// fails closed: no resolver, no viewer, an impersonation mark (View-as /
// dry-run, RD-1318) or a lookup error all yield no grant.
func TestResolveDisclosureGrants(t *testing.T) {
	ctx := context.Background()
	ok := func() *fakeFullGrantResolver {
		return &fakeFullGrantResolver{addrs: map[string][]string{grantSubjectAddr: {grantID}}}
	}

	t.Run("covers from or to, case-insensitively", func(t *testing.T) {
		g := ResolveDisclosureGrants(ctx, ok(), "did:test:auditor")
		if !g.Covers(grantSubjectAddr) || !g.Covers("0x5B1EC70000000000000000000000000000000001") {
			t.Fatal("the grant subject must be covered")
		}
		if g.Covers(grantOtherAddr) || g.Covers("") {
			t.Fatal("an address outside the grant must not be covered")
		}
		if !g.CoversTx(grantSubjectAddr, grantOtherAddr) || !g.CoversTx(grantOtherAddr, grantSubjectAddr) {
			t.Fatal("a tx with the subject as from or to is covered")
		}
		if g.CoversTx(grantOtherAddr, "") {
			t.Fatal("a tx with no subject party is not covered")
		}
		if !g.Addresses()[grantSubjectAddr] {
			t.Fatal("Addresses exposes the covered set for the indexed-address match")
		}
	})

	t.Run("at most one lookup per response, none when unused", func(t *testing.T) {
		r := ok()
		g := ResolveDisclosureGrants(ctx, r, "did:test:auditor")
		if r.calls != 0 {
			t.Fatalf("resolver called %d times before use, want 0", r.calls)
		}
		for i := 0; i < 10; i++ {
			g.CoversTx(grantSubjectAddr, grantOtherAddr)
			g.Addresses()
		}
		if r.calls != 1 {
			t.Fatalf("resolver called %d times, want 1", r.calls)
		}
	})

	failClosed := []struct {
		name string
		ctx  context.Context
		r    FullDisclosureGrantResolver
		did  string
	}{
		{"nil resolver", ctx, nil, "did:test:auditor"},
		{"anonymous viewer", ctx, ok(), ""},
		{"impersonation mark", disclosure.WithoutViewerGrants(ctx), ok(), "did:test:auditor"},
		{"lookup error", ctx, &fakeFullGrantResolver{addrs: map[string][]string{grantSubjectAddr: {grantID}}, err: errors.New("db down")}, "did:test:auditor"},
	}
	for _, c := range failClosed {
		t.Run(c.name, func(t *testing.T) {
			g := ResolveDisclosureGrants(c.ctx, c.r, c.did)
			if g.Covers(grantSubjectAddr) || g.CoversTx(grantSubjectAddr, grantOtherAddr) || len(g.Addresses()) != 0 {
				t.Fatal("must yield no grant (fail closed)")
			}
		})
	}

	t.Run("the impersonation mark skips the lookup", func(t *testing.T) {
		r := ok()
		g := ResolveDisclosureGrants(disclosure.WithoutViewerGrants(ctx), r, "did:test:auditor")
		g.Covers(grantSubjectAddr)
		if r.calls != 0 {
			t.Fatalf("resolver called %d times under the mark, want 0", r.calls)
		}
	})

	t.Run("nil grants are safe", func(t *testing.T) {
		var g *DisclosureGrants
		g.RecordReveal(grantSubjectAddr)
		if g.Reveals() != 0 || g.Covers(grantSubjectAddr) || g.RevealGrantIDs() != nil {
			t.Fatal("a nil set covers nothing and records nothing")
		}
	})

	t.Run("reveals accumulate per response with their grants", func(t *testing.T) {
		g := ResolveDisclosureGrants(ctx, ok(), "did:test:auditor")
		g.RecordReveal(grantSubjectAddr, grantOtherAddr)
		g.RecordReveal(grantSubjectAddr)
		if g.Reveals() != 2 {
			t.Fatalf("reveals = %d, want 2", g.Reveals())
		}
		if ids := g.RevealGrantIDs(); len(ids) != 1 || ids[0] != grantID {
			t.Fatalf("reveal grant ids = %v, want [%s]", ids, grantID)
		}
	})
}
