package server

import (
	"context"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
)

// retentionAuditStore routes access_logs retention operations to the audit
// database's ADMIN/owner pool (RD-1147) while every other retention target
// (compliance_logs, rbac_audit_log, travel_records, expired records, orphaned
// preregistrations, and the audit-of-the-audit LogAuditAction row that lands in
// rbac_audit_log) stays on the MAIN database.
//
// The access_logs prune requires UPDATE/DELETE on access_logs + writes the
// access_logs chain anchor — all of which live in the audit DB and require the
// admin/owner credential (the restricted runtime role is sealed to INSERT-only
// there). So Cleanup/Count/Trim for access_logs go to auditAdminDB; the rest to
// main.
//
// When auditAdminDB == main (both AUDIT_*_DATABASE_URL unset), this is a
// transparent pass-through identical to the pre-RD-1147 single-store behaviour.
type retentionAuditStore struct {
	main         *db.DB
	auditAdminDB *db.DB
}

var _ audit.RetentionStore = (*retentionAuditStore)(nil)

func newRetentionAuditStore(main, auditAdminDB *db.DB) *retentionAuditStore {
	return &retentionAuditStore{main: main, auditAdminDB: auditAdminDB}
}

// --- access_logs prune: audit admin pool -----------------------------------

func (s *retentionAuditStore) CleanupAccessLogs(ctx context.Context, olderThan time.Time) (audit.PruneResult, error) {
	res, err := s.auditAdminDB.CleanupAccessLogs(ctx, olderThan)
	return toAuditPruneResult(res), err
}

func (s *retentionAuditStore) CountAccessLogsTotal(ctx context.Context) (int64, error) {
	return s.auditAdminDB.CountAccessLogsTotal(ctx)
}

func (s *retentionAuditStore) TrimAccessLogsFIFOBatch(ctx context.Context, maxRows int64, batchSize int) (audit.PruneResult, error) {
	res, err := s.auditAdminDB.TrimAccessLogsFIFOBatch(ctx, maxRows, batchSize)
	return toAuditPruneResult(res), err
}

// toAuditPruneResult maps the db-owned prune metadata onto the audit-owned
// vocabulary. The two structs are deliberately separate types: audit must not
// import db (RD-1255), so this adapter — not the interface — pays the
// conversion.
func toAuditPruneResult(res db.PruneResult) audit.PruneResult {
	return audit.PruneResult{
		Deleted:    res.Deleted,
		LowestID:   res.LowestID,
		HighestID:  res.HighestID,
		AnchorHash: res.AnchorHash,
	}
}

// --- everything else: main DB ----------------------------------------------

func (s *retentionAuditStore) CleanupComplianceLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	return s.main.CleanupComplianceLogs(ctx, olderThan)
}

func (s *retentionAuditStore) CleanupRBACAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	return s.main.CleanupRBACAuditLogs(ctx, olderThan)
}

func (s *retentionAuditStore) CleanupUsedTravelRecords(ctx context.Context, olderThan time.Time) (int64, error) {
	return s.main.CleanupUsedTravelRecords(ctx, olderThan)
}

func (s *retentionAuditStore) CleanupExpiredRecords(ctx context.Context) (int64, error) {
	return s.main.CleanupExpiredRecords(ctx)
}

func (s *retentionAuditStore) DeleteOrphanedPreregisteredAddresses(ctx context.Context, olderThan time.Duration) (int64, error) {
	return s.main.DeleteOrphanedPreregisteredAddresses(ctx, olderThan)
}

// LogAuditAction records the audit-of-the-audit row in rbac_audit_log, which
// stays on the main DB (advancing the main DB's installed rbac_audit_log chain).
func (s *retentionAuditStore) LogAuditAction(ctx context.Context, action string, details map[string]any) error {
	return s.main.LogAuditAction(ctx, action, details)
}
