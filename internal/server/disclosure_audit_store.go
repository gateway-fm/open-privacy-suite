package server

import (
	"context"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
)

// disclosureAuditStore composes the disclosure store from two databases (RD-1147).
// Every disclosure operation (requests, grants, events, reports, user lookups)
// runs against the MAIN database; only the two methods that read the access_logs
// audit trail — GetActivityLogs and GetActivitySummary — are routed to the audit
// database. This keeps the split invisible to disclosure.Service, which still
// sees a single disclosure.Store.
//
// When auditDB == main (both AUDIT_*_DATABASE_URL unset), this is a transparent
// pass-through: the embedded *db.DB already implements all methods and the two
// overrides target the same connection, so behaviour is identical to the
// pre-RD-1147 single-DB deployment.
type disclosureAuditStore struct {
	*db.DB              // main DB: satisfies the full disclosure.Store surface
	auditDB *db.AuditDB // access_logs reads route here (RD-1256 role handle)
}

// compile-time assertion that the wrapper still satisfies disclosure.Store.
var _ disclosure.Store = (*disclosureAuditStore)(nil)

// newDisclosureAuditStore wraps the main DB so access_logs reads go to auditDB.
func newDisclosureAuditStore(main *db.DB, auditDB *db.AuditDB) *disclosureAuditStore {
	return &disclosureAuditStore{DB: main, auditDB: auditDB}
}

// GetActivityLogs reads the access_logs audit trail from the audit DB.
func (s *disclosureAuditStore) GetActivityLogs(ctx context.Context, userExternalID string, scope *disclosure.Scope, limit, offset int) ([]*disclosure.ActivityLogEntry, error) {
	return s.auditDB.GetActivityLogs(ctx, userExternalID, scope, limit, offset)
}

// GetActivitySummary reads the access_logs audit trail from the audit DB.
func (s *disclosureAuditStore) GetActivitySummary(ctx context.Context, userExternalID string, scope *disclosure.Scope) (*disclosure.ActivitySummary, error) {
	return s.auditDB.GetActivitySummary(ctx, userExternalID, scope)
}

// accessLogDB returns the handle that holds the access_logs audit trail: the
// separate audit DB when configured, else the main DB. Server instances built
// by New always set auditDB (== db's pool when not separated); the nil
// fallback wraps s.db on the fly so lightweight test Server literals that only
// set db keep working unchanged (RD-1256: callers always see the role-scoped
// handle).
func (s *Server) accessLogDB() *db.AuditDB {
	if s.auditDB != nil {
		return s.auditDB
	}
	return db.NewAuditHandle(s.db)
}

// getActivityLogsForGrant resolves a disclosure grant's target external_id and
// time window from the MAIN DB, then reads the matching access_logs from the
// audit DB (RD-1147). This replaces the single-query cross-table join in
// db.GetActivityLogsForGrant, which cannot run when access_logs and the grant
// tables live in different databases. Returns ([], 0, nil) for an unknown grant.
func (s *Server) getActivityLogsForGrant(ctx context.Context, grantID string, limit, offset int) ([]disclosure.ActivityLogEntry, int, error) {
	bounds, err := s.db.GetGrantActivityBounds(ctx, grantID)
	if err != nil {
		return nil, 0, err
	}
	if bounds == nil {
		return []disclosure.ActivityLogEntry{}, 0, nil
	}
	return s.accessLogDB().GetAccessLogsForExternalIDInRange(ctx, bounds.ExternalID, bounds.GrantedAt, bounds.ExpiresAt, limit, offset)
}
