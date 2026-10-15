// Package viewscope carries the organization an impersonated read is anchored
// to (RD-1308). The tier-2 impersonation surfaces — the admin dry-run and the
// View-as RPC mirror — answer "what would this user see?" in one named org;
// every layer that resolves the user's authorizations (the RPC response
// filter, the nested-call gate, the address-visibility resolver) reads the
// scope from the request context and resolves in that org only.
//
// The value is set only by those two surfaces (internal/server). A user's own
// request never carries it.
package viewscope

import "context"

type orgKey struct{}

// WithOrg returns ctx anchored to orgID. An empty orgID is still a scope: it
// matches no org, so every scoped lookup fails closed instead of widening.
func WithOrg(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, orgKey{}, orgID)
}

// Org reports the org ctx is anchored to. present is true whenever a scope was
// set, including an empty one.
func Org(ctx context.Context) (orgID string, present bool) {
	v, ok := ctx.Value(orgKey{}).(string)
	return v, ok
}
