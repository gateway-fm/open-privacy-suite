package rbac

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"privacy-proxy/internal/disclosure"
)

// FullDisclosureGrantResolver returns, for the viewer, each address that an
// active, approved Full disclosure grant covers for regular reads, mapped to
// the ids of the grants that cover it. "Active and approved": unexpired,
// unrevoked, the viewer requested it, and the viewer is a current member of
// the organization it was requested in. "For regular reads": the grant's scope
// covers the subject's transaction history (no date range, no contract list,
// methods empty or including transaction_history / full_disclosure); any other
// grant is used only through its own grant pages. Keys
// are lower-case 0x-prefixed addresses. Implemented by *db.DB on the grant set
// the explorer's visibility resolution merges, so both read surfaces start
// from one set.
type FullDisclosureGrantResolver interface {
	FullDisclosureGrantAddresses(ctx context.Context, viewerDID string) (map[string][]string, error)
}

// DisclosureGrants is the disclosure-grant input of the shared read decisions
// (DecideTxEnvelope, DecideLogEmitter) for one response or redaction pass: the
// addresses the viewer's Full grants cover, and the reveals made through them
// in that response (for the audit trail).
//
// The lookup runs at most once, on first use, so a response that never needs
// the fact (a participant's own transaction, an empty block) costs no query.
// A failed lookup covers nothing. A nil *DisclosureGrants covers nothing; every
// method is nil-safe. Not for concurrent use across responses.
type DisclosureGrants struct {
	ctx       context.Context
	resolver  FullDisclosureGrantResolver
	viewerDID string

	once sync.Once
	full map[string][]string // address -> covering grant ids

	reveals  int
	grantIDs map[string]bool
}

// ResolveDisclosureGrants is the shared fact builder for disclosure grants: the
// JSON-RPC response filters and the explorer redactor both call it, once per
// response, and derive every grant fact from its result. It fails closed —
// covers nothing — when there is no resolver or viewer, when the request is an
// impersonation (View-as or admin dry-run: a grant never travels to an admin
// viewing as its grantee, see disclosure.WithoutViewerGrants), and when the
// lookup fails.
func ResolveDisclosureGrants(ctx context.Context, resolver FullDisclosureGrantResolver, viewerDID string) *DisclosureGrants {
	if resolver == nil || viewerDID == "" || disclosure.ViewerGrantsSuppressed(ctx) {
		return nil
	}
	return &DisclosureGrants{ctx: ctx, resolver: resolver, viewerDID: viewerDID}
}

// load runs the lookup once.
func (g *DisclosureGrants) load() map[string][]string {
	g.once.Do(func() {
		addrs, err := g.resolver.FullDisclosureGrantAddresses(g.ctx, g.viewerDID)
		if err != nil {
			slog.Warn("disclosure grant lookup failed; no grant applies to this read", "error", err)
			return
		}
		full := make(map[string][]string, len(addrs))
		for a, ids := range addrs {
			if a != "" && len(ids) > 0 {
				full[strings.ToLower(a)] = ids
			}
		}
		g.full = full
	})
	return g.full
}

// Covers reports whether a Full grant of the viewer covers addr.
func (g *DisclosureGrants) Covers(addr string) bool {
	if g == nil || addr == "" {
		return false
	}
	_, ok := g.load()[strings.ToLower(addr)]
	return ok
}

// CoversTx reports whether a Full grant of the viewer covers the transaction's
// `from` or `to` — the TxEnvelopeFacts.FullDisclosureGrant fact.
func (g *DisclosureGrants) CoversTx(from, to string) bool {
	return g.Covers(from) || g.Covers(to)
}

// Addresses returns the covered addresses (lower-case), for matching them
// against an event's indexed address parameters (the
// LogEmitterFacts.FullDisclosureGrant fact).
func (g *DisclosureGrants) Addresses() map[string]bool {
	if g == nil {
		return nil
	}
	full := g.load()
	if len(full) == 0 {
		return nil
	}
	out := make(map[string]bool, len(full))
	for a := range full {
		out[a] = true
	}
	return out
}

// RecordReveal records one object (a transaction, receipt, block entry or
// event) returned only, or only through the grant lens, because of a Full
// grant, attributing it to the grants covering addrs (the parties involved).
func (g *DisclosureGrants) RecordReveal(addrs ...string) {
	if g == nil {
		return
	}
	g.reveals++
	full := g.load()
	for _, a := range addrs {
		for _, id := range full[strings.ToLower(a)] {
			if g.grantIDs == nil {
				g.grantIDs = make(map[string]bool)
			}
			g.grantIDs[id] = true
		}
	}
}

// Reveals returns the number of objects recorded by RecordReveal.
func (g *DisclosureGrants) Reveals() int {
	if g == nil {
		return 0
	}
	return g.reveals
}

// RevealGrantIDs returns the ids of the grants the recorded reveals were made
// through, sorted.
func (g *DisclosureGrants) RevealGrantIDs() []string {
	if g == nil || len(g.grantIDs) == 0 {
		return nil
	}
	out := make([]string, 0, len(g.grantIDs))
	for id := range g.grantIDs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// GrantIDs returns the ids of the grants covering addr.
func (g *DisclosureGrants) GrantIDs(addr string) []string {
	if g == nil || addr == "" {
		return nil
	}
	return g.load()[strings.ToLower(addr)]
}
