// RD-1256: role-scoped handles for the separate audit database (RD-1147).
//
// The server holds three Postgres pools: main, audit-runtime and audit-admin.
// All three used to be the same concrete *DB, so nothing prevented calling a
// main-DB method (users, contracts, grants, ...) on an audit handle — the
// audit-isolation guarantee rested on SQL grants and convention only. These
// wrappers expose exactly the method subset each role legitimately uses, so a
// cross-role call is a compile error. They are thin explicit delegations (NOT
// embeddings — embedding *DB would re-expose its entire method set and defeat
// the separation).
//
// Roles (see the RD-1147 notes on the Server struct):
//   - AuditDB (runtime): access_logs writes/reads, hash-chain sealing,
//     checkpoint/anchor persistence, integrity-verifier seed reads, and the
//     activity views the disclosure service serves to users.
//   - AuditAdminDB (owner): lean audit migrations and retention pruning
//     (DELETE), which the restricted runtime role must not be able to do.
//
// Conn() is deliberately exposed on both: the integrity verifier walks the
// chain over the raw *sql.DB, and Server.Stop uses pool identity (Conn
// pointer equality) for its double-close aliasing guards in co-located
// deployments where the pools are reused.

package db

import (
	"context"
	"database/sql"
	"io/fs"
	"time"

	"privacy-proxy/internal/disclosure"
)

// AuditDB is the runtime handle for the append-only audit database. It wraps a
// *DB pool and exposes only the access_logs / audit-chain surface.
type AuditDB struct {
	pool *DB
}

// NewAuditHandle wraps an open pool as the runtime audit handle.
func NewAuditHandle(pool *DB) *AuditDB { return &AuditDB{pool: pool} }

// Conn exposes the wrapped pool's connection (integrity verifier + pool
// identity for Server.Stop's double-close guards).
func (a *AuditDB) Conn() *sql.DB { return a.pool.Conn() }

// Close closes the wrapped pool.
func (a *AuditDB) Close() error { return a.pool.Close() }

// --- access-log writes (AccessLogger / EnhancedAccessLogger surfaces) ---

func (a *AuditDB) LogAccess(ctx context.Context, externalID, method string, statusCode int, ipAddress string) error {
	return a.pool.LogAccess(ctx, externalID, method, statusCode, ipAddress)
}

func (a *AuditDB) LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte, responseStatus *int, orgID string, denialReason string) (int64, time.Time, error) {
	return a.pool.LogAccessEnhanced(ctx, externalID, method, statusCode, ipAddress, correlationID, params, responseStatus, orgID, denialReason)
}

func (a *AuditDB) UpdateAccessLogHash(ctx context.Context, id int64, hash string) error {
	return a.pool.UpdateAccessLogHash(ctx, id, hash)
}

func (a *AuditDB) LogAccessChained(
	ctx context.Context,
	chain RBACAuditChain,
	externalID, method string,
	statusCode int,
	ipAddress, correlationID string,
	params []byte,
	responseStatus *int,
	orgID string,
	denialReason string,
) (int64, time.Time, string, error) {
	return a.pool.LogAccessChained(ctx, chain, externalID, method, statusCode, ipAddress, correlationID, params, responseStatus, orgID, denialReason)
}

// --- access-log reads (admin endpoints + disclosure activity views) ---

func (a *AuditDB) GetAccessLogs(ctx context.Context, f AccessLogFilter) ([]*AccessLog, error) {
	return a.pool.GetAccessLogs(ctx, f)
}

func (a *AuditDB) CountAccessLogs(ctx context.Context, f AccessLogFilter) (int64, error) {
	return a.pool.CountAccessLogs(ctx, f)
}

func (a *AuditDB) GetActivityLogs(ctx context.Context, userExternalID string, scope *disclosure.Scope, limit, offset int) ([]*disclosure.ActivityLogEntry, error) {
	return a.pool.GetActivityLogs(ctx, userExternalID, scope, limit, offset)
}

func (a *AuditDB) GetActivitySummary(ctx context.Context, userExternalID string, scope *disclosure.Scope) (*disclosure.ActivitySummary, error) {
	return a.pool.GetActivitySummary(ctx, userExternalID, scope)
}

func (a *AuditDB) GetAccessLogsForExternalIDInRange(ctx context.Context, externalID string, start, end string, limit, offset int) ([]disclosure.ActivityLogEntry, int, error) {
	return a.pool.GetAccessLogsForExternalIDInRange(ctx, externalID, start, end, limit, offset)
}

// --- hash chain: seed reads, buffered sealing (RD-1112), checkpoints (#8) ---

func (a *AuditDB) GetLatestAccessLogHash(ctx context.Context) (string, error) {
	return a.pool.GetLatestAccessLogHash(ctx)
}

// GetLatestRBACAuditLogHash satisfies audit.SeedReader. The rbac_audit_log
// chain lives on the MAIN database (RD-1147 always splits the chains), so on a
// separated audit DB this only serves the interface — the access_logs verifier
// never asks for it.
func (a *AuditDB) GetLatestRBACAuditLogHash(ctx context.Context) (string, error) {
	return a.pool.GetLatestRBACAuditLogHash(ctx)
}

func (a *AuditDB) GetLatestAccessLogHashForChain(ctx context.Context, chainName string) (string, error) {
	return a.pool.GetLatestAccessLogHashForChain(ctx, chainName)
}

func (a *AuditDB) SealBufferedAccessLog(ctx context.Context, chain RBACAuditChain, rec AccessLogRecord, bufferSeq uint64, chainName string) (string, error) {
	return a.pool.SealBufferedAccessLog(ctx, chain, rec, bufferSeq, chainName)
}

func (a *AuditDB) GetMaxAccessLogBufferSeq(ctx context.Context, chainName string) (uint64, error) {
	return a.pool.GetMaxAccessLogBufferSeq(ctx, chainName)
}

func (a *AuditDB) GetAccessLogChainStats(ctx context.Context, chainName string) (rowCount, headID int64, headHash string, err error) {
	return a.pool.GetAccessLogChainStats(ctx, chainName)
}

func (a *AuditDB) WriteAuditChainCheckpoint(ctx context.Context, c AuditChainCheckpointRow) error {
	return a.pool.WriteAuditChainCheckpoint(ctx, c)
}

func (a *AuditDB) GetLatestAuditChainCheckpoint(ctx context.Context, chainName string) (*AuditChainCheckpointRow, error) {
	return a.pool.GetLatestAuditChainCheckpoint(ctx, chainName)
}

func (a *AuditDB) UpsertAuditChainAnchor(ctx context.Context, chainName string, lastPrunedID int64, lastPrunedEntryHash string) error {
	return a.pool.UpsertAuditChainAnchor(ctx, chainName, lastPrunedID, lastPrunedEntryHash)
}

func (a *AuditDB) WriteAuditChainReAnchor(ctx context.Context, chainName, reason, actor string, fromHeadID int64, fromHash string, toHeadID int64, toHash, keyID, signature string, createdAt time.Time) error {
	return a.pool.WriteAuditChainReAnchor(ctx, chainName, reason, actor, fromHeadID, fromHash, toHeadID, toHash, keyID, signature, createdAt)
}

// AuditAdminDB is the owner handle for the audit database: migrations and
// retention pruning only.
type AuditAdminDB struct {
	pool *DB
}

// NewAuditAdminHandle wraps an open pool as the audit admin/owner handle.
func NewAuditAdminHandle(pool *DB) *AuditAdminDB { return &AuditAdminDB{pool: pool} }

// Conn exposes the wrapped pool's connection (pool identity for Server.Stop's
// double-close guards).
func (a *AuditAdminDB) Conn() *sql.DB { return a.pool.Conn() }

// Close closes the wrapped pool.
func (a *AuditAdminDB) Close() error { return a.pool.Close() }

// MigrateAuditOnly applies the lean, standalone audit migration set (RD-1147).
func (a *AuditAdminDB) MigrateAuditOnly(ctx context.Context, auditFS fs.FS) error {
	return a.pool.MigrateAuditOnly(ctx, auditFS)
}

// --- access_logs retention (DELETE — owner-only, RD-1147) ---

func (a *AuditAdminDB) CleanupAccessLogs(ctx context.Context, olderThan time.Time) (PruneResult, error) {
	return a.pool.CleanupAccessLogs(ctx, olderThan)
}

func (a *AuditAdminDB) CountAccessLogsTotal(ctx context.Context) (int64, error) {
	return a.pool.CountAccessLogsTotal(ctx)
}

func (a *AuditAdminDB) TrimAccessLogsFIFOBatch(ctx context.Context, maxRows int64, batchSize int) (PruneResult, error) {
	return a.pool.TrimAccessLogsFIFOBatch(ctx, maxRows, batchSize)
}
