package disclosure

import "context"

type viewerGrantsSuppressedKey struct{}

// WithoutViewerGrants marks ctx as a read performed by someone other than the
// viewer it resolves to: the tier-2 impersonation surfaces (View-as and the
// admin dry-run). A disclosure grant is approved by its subject for one
// grantee, is time-bound, and its reveals are audited against that grantee;
// it never travels to an admin who views as the grantee. The viewer-keyed
// grant lookups reachable from those surfaces (visibility resolution, the
// grant routes, the viewer's list of disclosed addresses) return nothing under
// the mark; any new viewer-keyed grant read must check ViewerGrantsSuppressed
// too (REDACTION_SPEC §6).
func WithoutViewerGrants(ctx context.Context) context.Context {
	return context.WithValue(ctx, viewerGrantsSuppressedKey{}, true)
}

// ViewerGrantsSuppressed reports whether ctx was marked by WithoutViewerGrants.
func ViewerGrantsSuppressed(ctx context.Context) bool {
	suppressed, _ := ctx.Value(viewerGrantsSuppressedKey{}).(bool)
	return suppressed
}
