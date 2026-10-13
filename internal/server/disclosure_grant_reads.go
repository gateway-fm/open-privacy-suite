package server

import (
	"context"
	"log/slog"
	"strings"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// The production grant lookup behind both read surfaces: JSON-RPC
// (JSONRPCProcessorConfig.DisclosureGrantResolver) and the explorer
// (wireExplorerRedactor). A signature drift fails the build instead of
// silently disabling grants.
var _ rbac.FullDisclosureGrantResolver = (*db.DB)(nil)

// withDisclosureGrants attaches the viewer's per-response disclosure-grant set
// to the log filter's context, creating one when the profile resolved none
// (strict, or no visibleTo data), so the grant reaches the shared event and
// receipt decisions under both read profiles. nil grants leave visCtx as is.
func withDisclosureGrants(visCtx *rbac.TxVisibilityContext, viewerDID string, grants *rbac.DisclosureGrants) *rbac.TxVisibilityContext {
	if grants == nil {
		return visCtx
	}
	if visCtx == nil {
		visCtx = &rbac.TxVisibilityContext{ViewerDID: viewerDID}
	}
	visCtx.DisclosureGrants = grants
	return visCtx
}

// auditDisclosureGrantReveals records, in the hash-chained rbac_audit_log, a
// JSON-RPC response that returned anything only, or only in full, because of
// the viewer's Full disclosure grant — the JSON-RPC counterpart of the
// explorer's grant-reveal entry (auditGrantFullReveal), on the same resource
// type so a reviewer pivots from a grant to every reveal it produced on both
// surfaces. One entry per response: actor = the grantee, the method, the
// transaction hash when the request names one, how many objects (transactions,
// receipts, block entries, events) the grant revealed, and the ids of the
// grants they were revealed through. The hash goes in the entry payload; the
// resource id is a UUID column. No address is written.
//
// No entry under View-as or dry-run: the grant set is empty there, so nothing
// is revealed through it. Best-effort, like the other audit call sites: a
// failed write is logged and does not fail the read.
func (p *JSONRPCProcessor) auditDisclosureGrantReveals(ctx context.Context, req *ProcessRequest, grants *rbac.DisclosureGrants) {
	n := grants.Reveals()
	if n == 0 || p.rbacAccessCtrl == nil {
		return
	}
	entry := &rbac.AuditLogEntry{
		ActorExternalID: req.UserID,
		Action:          rbac.AuditActionAccess,
		ResourceType:    rbac.ResourceTypeDisclosureGrant,
		ResourceName:    req.Method,
		NewValue: map[string]any{
			"endpoint":         req.Method,
			"target":           grantRevealTarget(req),
			"objects_revealed": n,
			"grant_ids":        grants.RevealGrantIDs(),
			"reveal_class":     "disclosure_grant_full_rpc",
		},
		IPAddress: req.ClientIP,
	}
	if err := p.rbacAccessCtrl.Store().CreateAuditLog(ctx, entry); err != nil {
		slog.Error("failed to write disclosure-grant reveal audit log",
			"viewer", req.UserID, "method", req.Method, "error", err)
	}
}

// grantRevealTarget returns the transaction hash a by-hash read names
// (eth_getTransactionByHash, eth_getTransactionReceipt and their aliases), or
// "" for block and log reads.
func grantRevealTarget(req *ProcessRequest) string {
	m := rbac.ResolveMethodAlias(req.Method)
	if !strings.EqualFold(m, rbac.MethodGetTransactionByHash) && !strings.EqualFold(m, rbac.MethodGetTransactionReceipt) {
		return ""
	}
	if len(req.Params) == 0 {
		return ""
	}
	h, ok := req.Params[0].(string)
	if !ok || !isTxHash(h) {
		return ""
	}
	return strings.ToLower(h)
}
