package rbac

// TxSurface identifies which transaction-level object a read returns.
type TxSurface uint8

const (
	// TxSurfaceTransaction: a transaction object — eth_getTransactionByHash and
	// the by-block-index aliases, and the explorer's transaction rows.
	TxSurfaceTransaction TxSurface = iota + 1
	// TxSurfaceReceipt: an eth_getTransactionReceipt envelope.
	TxSurfaceReceipt
	// TxSurfaceBlockEntry: one transaction or receipt inside a block listing
	// (eth_getBlockBy* with full objects, eth_getBlockReceipts).
	TxSurfaceBlockEntry
)

// TxEnvelopeFacts are the per-(viewer, transaction) inputs to the shared
// transaction-level admission decision. Each read surface resolves them from its
// own data and calls DecideTxEnvelope, so the RPC filters and the explorer reach
// the same verdict for the same viewer and transaction (RD-1299).
type TxEnvelopeFacts struct {
	Surface TxSurface

	// IsParticipant: one of the viewer's authenticated linked addresses is the
	// transaction's `from` or `to`. Nothing else (calldata, event topics,
	// token-transfer rows) counts as participation.
	IsParticipant bool

	// IsAdminOnTo: the viewer holds the admin claim on the transaction's `to`
	// contract in that contract's owning org.
	IsAdminOnTo bool

	// InVisibleTo: the sender listed the viewer in this transaction's visibleTo.
	InVisibleTo bool

	// EntitledLogs: receipts only — how many of the transaction's logs the
	// viewer is entitled to under their event rules (RD-1183).
	EntitledLogs int

	// IsDeployment: the transaction creates a contract (`to` is empty).
	IsDeployment bool

	// FullDisclosureGrant: the viewer holds an approved, active Full
	// disclosure grant covering the transaction's `from` or `to`
	// (DisclosureGrants.CoversTx, resolved by ResolveDisclosureGrants). The
	// subject consented to show their activity to this viewer; the grant is
	// time-bound and every reveal through it is audited. False under View-as
	// and admin dry-run.
	FullDisclosureGrant bool
}

// DecideTxEnvelope decides whether the viewer may receive a transaction object,
// a receipt or a block entry at all. It is the single source of truth for that
// question on JSON-RPC and on the explorer (RD-1299).
//
// Both profiles: a participant is admitted on every surface, and so is the
// holder of a Full disclosure grant over the transaction's `from` or `to` on a
// transaction object, a receipt or a block entry. The grant shows the
// transaction as its subject sees it, deployments included (a deployment's
// address follows from its sender and nonce, which the transaction carries).
//
// Strict profile (and an unset profile): nothing else. The admin claim,
// visibleTo and log entitlement never admit.
//
// Standard profile — the documented default policy, in addition:
//   - transaction: admin on `to`, or visibleTo recipient;
//   - receipt: visibleTo recipient, admin on `to`, or (not a deployment)
//     entitled to at least one of its logs (RD-1183);
//   - block entry: nothing else;
//   - unknown surface: participant only (fail closed).
func DecideTxEnvelope(profile ReadProfile, f TxEnvelopeFacts) bool {
	if f.IsParticipant {
		return true
	}
	if f.FullDisclosureGrant && knownTxSurface(f.Surface) {
		return true
	}
	if profile.Strict() {
		return false
	}
	switch f.Surface {
	case TxSurfaceTransaction:
		return f.IsAdminOnTo || f.InVisibleTo
	case TxSurfaceReceipt:
		return f.IsAdminOnTo || f.InVisibleTo || (!f.IsDeployment && f.EntitledLogs > 0)
	default: // TxSurfaceBlockEntry and any unknown surface
		return false
	}
}

// knownTxSurface reports whether s is one of the defined surfaces. Only a
// participant is admitted on an unknown surface (fail closed).
func knownTxSurface(s TxSurface) bool {
	switch s {
	case TxSurfaceTransaction, TxSurfaceReceipt, TxSurfaceBlockEntry:
		return true
	default:
		return false
	}
}

// TxEnvelopeRevealedByGrant reports whether the Full disclosure grant is what
// admits this envelope: DecideTxEnvelope admits it, and would not without the
// grant. Such a reveal is recorded in the audit trail; an envelope the viewer
// receives anyway (participant, or a standard-profile admin or visibleTo
// recipient) is not attributed to the grant.
func TxEnvelopeRevealedByGrant(profile ReadProfile, f TxEnvelopeFacts) bool {
	if !f.FullDisclosureGrant || !DecideTxEnvelope(profile, f) {
		return false
	}
	without := f
	without.FullDisclosureGrant = false
	return !DecideTxEnvelope(profile, without)
}
