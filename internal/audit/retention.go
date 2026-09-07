package audit

import (
	"context"
	"log/slog"
	"time"
)

// RetentionConfig holds per-table retention durations and the cleanup interval.
// A zero duration means "keep forever" (skip cleanup for that table).
type RetentionConfig struct {
	AccessLogs      time.Duration
	ComplianceLogs  time.Duration
	RBACAuditLogs   time.Duration
	TravelRecords   time.Duration
	CleanupInterval time.Duration

	// MaxAccessLogRows, when > 0, caps the access_logs table at this row count.
	// After the time-based prune runs, any excess rows (oldest first) are
	// deleted in batches. The chain anchor is written before each batch so
	// the hash chain stays verifiable across the cut. A value of 0 disables
	// the row cap (time-based retention only).
	MaxAccessLogRows int64
	// AccessLogTrimBatchSize is the maximum number of rows deleted per FIFO
	// trim transaction. A zero value uses defaultAccessLogTrimBatchSize.
	AccessLogTrimBatchSize int

	// PreregistrationTTL is the age above which orphaned preregistered_addresses
	// rows (pre-reg rows with no matching contracts row) are deleted. A zero
	// value means "use the default" (see defaultPreregistrationTTL).
	PreregistrationTTL time.Duration
	// PreregistrationCleanupInterval controls how often the orphan sweep runs.
	// A zero value means "use the default" (see defaultPreregistrationCleanup).
	PreregistrationCleanupInterval time.Duration
}

const (
	// defaultPreregistrationTTL is the default age threshold for considering a
	// preregistered_addresses row orphaned. Normal deployments finalize in seconds;
	// 1h is conservative.
	defaultPreregistrationTTL = 1 * time.Hour
	// defaultPreregistrationCleanup is the default interval between orphan sweeps.
	defaultPreregistrationCleanup = 5 * time.Minute

	// defaultAccessLogTrimBatchSize bounds the number of rows the FIFO sweeper
	// deletes per transaction. Small enough to keep the lock window short on
	// heavy traffic; large enough that drains converge quickly.
	defaultAccessLogTrimBatchSize = 1000
	// maxAccessLogTrimIterations bounds how many batches the sweeper drains in
	// a single cleanup() invocation, as defence in depth against a runaway
	// loop (e.g. concurrent inserts outpacing deletions). One cleanup tick can
	// at most delete maxAccessLogTrimIterations * batchSize rows.
	maxAccessLogTrimIterations = 50
)

// PruneResult carries the metadata an audit-of-the-audit row needs after a
// prune operation. CleanupAccessLogs and TrimAccessLogsFIFOBatch return this
// so the retention manager can attach the deleted id range and the new chain
// anchor hash to the rbac_audit_log entry alongside the row count. All four
// fields are zero-valued when Deleted == 0.
//
// This is the audit package's own vocabulary (RD-1255): RetentionStore
// implementations over the persistence layer live with the consumer (see
// internal/server/retention_audit_store.go), because audit must not import
// db — the same rule the checkpoint store documents in checkpoint_worker.go.
type PruneResult struct {
	// Deleted is the number of rows deleted in this call.
	Deleted int64
	// LowestID is the lowest id deleted; useful so an auditor can reconstruct
	// the deleted range from "rows [LowestID..HighestID] are gone".
	LowestID int64
	// HighestID is the highest id deleted. Equals the new anchor's
	// last_pruned_id (set inside the same transaction as the DELETE).
	HighestID int64
	// AnchorHash is the entry_hash now persisted in audit_chain_anchor for
	// chain "access_logs". Equals the deleted row's stored entry_hash, or
	// the previous anchor when that row's entry_hash was NULL (process crash
	// between insert and UpdateAccessLogHash).
	AnchorHash string
}

// RetentionStore defines the database operations needed for retention cleanup.
type RetentionStore interface {
	// CleanupAccessLogs returns a PruneResult so the retention manager can
	// surface deleted-range metadata + the new chain anchor hash in the
	// audit-of-the-audit row.
	CleanupAccessLogs(ctx context.Context, olderThan time.Time) (PruneResult, error)
	CleanupComplianceLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupRBACAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupUsedTravelRecords(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupExpiredRecords(ctx context.Context) (int64, error)

	// DeleteOrphanedPreregisteredAddresses deletes preregistered_addresses rows older
	// than olderThan that have no matching contracts row (abandoned / crash-leftover).
	DeleteOrphanedPreregisteredAddresses(ctx context.Context, olderThan time.Duration) (int64, error)

	// CountAccessLogsTotal returns the current number of rows in access_logs.
	// Used by the FIFO sweeper to decide whether trimming is needed.
	CountAccessLogsTotal(ctx context.Context) (int64, error)
	// TrimAccessLogsFIFOBatch deletes the oldest rows so that at most maxRows
	// remain. Each call deletes up to batchSize rows. Returns a PruneResult
	// describing the deleted range and the new chain anchor for this batch.
	// Implementations MUST update the access_logs hash chain anchor in the
	// same transaction so the chain stays verifiable across pruning cuts.
	TrimAccessLogsFIFOBatch(ctx context.Context, maxRows int64, batchSize int) (PruneResult, error)

	// LogAuditAction records an audit-of-the-audit row in rbac_audit_log so
	// retention prunes themselves are auditable. action is a stable string
	// identifier (e.g. "audit.access_logs.prune"); details is JSON-encodable
	// metadata. actorID may be nil when no system actor is configured.
	LogAuditAction(ctx context.Context, action string, details map[string]any) error
}

// RetentionManager runs periodic retention cleanup on audit tables.
type RetentionManager struct {
	cfg        RetentionConfig
	store      RetentionStore
	stop       chan struct{}
	done       chan struct{}
	preregDone chan struct{}
}

// RetentionCleaner is an alias for RetentionManager for API compatibility.
type RetentionCleaner = RetentionManager

// NewRetentionManager creates a new retention manager. Call Start() to begin cleanup.
func NewRetentionManager(cfg RetentionConfig, store RetentionStore) *RetentionManager {
	if cfg.PreregistrationTTL <= 0 {
		cfg.PreregistrationTTL = defaultPreregistrationTTL
	}
	if cfg.PreregistrationCleanupInterval <= 0 {
		cfg.PreregistrationCleanupInterval = defaultPreregistrationCleanup
	}
	return &RetentionManager{
		cfg:        cfg,
		store:      store,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		preregDone: make(chan struct{}),
	}
}

// NewRetentionCleaner creates a new retention cleaner. If travelRuleEnabled is false,
// the TravelRecords retention duration is zeroed (skip cleanup). Starts automatically.
func NewRetentionCleaner(cfg RetentionConfig, store RetentionStore, travelRuleEnabled bool) *RetentionCleaner {
	if !travelRuleEnabled {
		cfg.TravelRecords = 0
	}
	mgr := NewRetentionManager(cfg, store)
	mgr.Start()
	return mgr
}

// Start begins the periodic cleanup loop in a goroutine.
func (r *RetentionManager) Start() {
	go r.run()
	go r.runPreregistrationCleanup()
}

// Stop signals the cleanup loop to stop and waits for it to finish.
func (r *RetentionManager) Stop() {
	close(r.stop)
	<-r.done
	<-r.preregDone
}

func (r *RetentionManager) run() {
	defer close(r.done)

	if r.cfg.CleanupInterval <= 0 {
		// Retention disabled.
		return
	}

	// Run cleanup immediately on start, then on interval.
	r.cleanup()

	ticker := time.NewTicker(r.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

func (r *RetentionManager) cleanup() {
	ctx := context.Background()
	// UTC, not local: retention timestamp columns (e.g. access_logs.created_at)
	// are `timestamp without time zone` populated by the DB's CURRENT_TIMESTAMP
	// (UTC). Computing the cutoff in the process's local zone would skew the
	// comparison by the UTC offset on any non-UTC host, pruning the wrong rows.
	now := time.Now().UTC()

	// access_logs gets its own branch because it is the only retention path
	// that owns a hash chain anchor and emits an audit-of-the-audit row. The
	// other tables share a uniform int64-returning signature.
	if r.cfg.AccessLogs > 0 {
		cutoff := now.Add(-r.cfg.AccessLogs)
		slog.Info("retention: deleting old records", "table", "access_logs", "retention", r.cfg.AccessLogs, "cutoff", cutoff.Format(time.RFC3339))
		res, err := r.store.CleanupAccessLogs(ctx, cutoff)
		if err != nil {
			slog.Error("retention: error cleaning table", "table", "access_logs", "error", err)
		} else if res.Deleted > 0 {
			slog.Info("retention: deleted rows", "table", "access_logs", "count", res.Deleted)
			_ = r.store.LogAuditAction(ctx, "audit.access_logs.prune", map[string]any{
				"reason":          "ttl",
				"deleted_count":   res.Deleted,
				"lowest_id":       res.LowestID,
				"highest_id":      res.HighestID,
				"new_anchor_hash": res.AnchorHash,
				"retention":       r.cfg.AccessLogs.String(),
				"cutoff":          cutoff.UTC().Format(time.RFC3339Nano),
			})
		}
	}

	type tableCleanup struct {
		name     string
		duration time.Duration
		fn       func(ctx context.Context, olderThan time.Time) (int64, error)
	}

	tables := []tableCleanup{
		{"compliance_logs", r.cfg.ComplianceLogs, r.store.CleanupComplianceLogs},
		{"rbac_audit_logs", r.cfg.RBACAuditLogs, r.store.CleanupRBACAuditLogs},
		{"travel_records", r.cfg.TravelRecords, r.store.CleanupUsedTravelRecords},
	}

	for _, tc := range tables {
		if tc.duration <= 0 {
			continue
		}

		cutoff := now.Add(-tc.duration)

		// M3 fix: log BEFORE deletion so operators have an auditable trail of retention events.
		slog.Info("retention: deleting old records", "table", tc.name, "retention", tc.duration, "cutoff", cutoff.Format(time.RFC3339))

		deleted, err := tc.fn(ctx, cutoff)
		if err != nil {
			slog.Error("retention: error cleaning table", "table", tc.name, "error", err)
			continue
		}
		if deleted > 0 {
			slog.Info("retention: deleted rows", "table", tc.name, "count", deleted)
		}
	}

	// Always clean up expired records regardless of config.
	expired, err := r.store.CleanupExpiredRecords(ctx)
	if err != nil {
		slog.Error("retention: error cleaning expired records", "error", err)
	} else if expired > 0 {
		slog.Info("retention: deleted expired records", "count", expired)
	}

	// FIFO row cap on access_logs. Runs after the time-based prune so the
	// time prune handles the bulk and the FIFO step only kicks in when row
	// counts grow beyond MaxAccessLogRows during a single retention window.
	r.trimAccessLogsFIFO(ctx)
}

// trimAccessLogsFIFO drains rows from access_logs in batches until the row
// count is at or below MaxAccessLogRows. The store implementation is
// responsible for writing the chain anchor inside each batch's transaction.
func (r *RetentionManager) trimAccessLogsFIFO(ctx context.Context) {
	if r.cfg.MaxAccessLogRows <= 0 {
		return
	}
	batchSize := r.cfg.AccessLogTrimBatchSize
	if batchSize <= 0 {
		batchSize = defaultAccessLogTrimBatchSize
	}

	total, err := r.store.CountAccessLogsTotal(ctx)
	if err != nil {
		slog.Error("retention: failed to count access_logs for FIFO trim", "error", err)
		return
	}
	if total <= r.cfg.MaxAccessLogRows {
		return
	}

	slog.Info("retention: FIFO trim starting",
		"table", "access_logs",
		"current_rows", total,
		"max_rows", r.cfg.MaxAccessLogRows,
		"batch_size", batchSize)

	var totalDeleted int64
	var minLowestID int64     // 0 == not yet seen; first non-zero LowestID stays
	var maxHighestID int64    // 0 == not yet seen; last batch's HighestID wins
	var lastAnchorHash string // last batch's anchor; equals the anchor row after the loop
	for i := 0; i < maxAccessLogTrimIterations; i++ {
		res, err := r.store.TrimAccessLogsFIFOBatch(ctx, r.cfg.MaxAccessLogRows, batchSize)
		if err != nil {
			slog.Error("retention: error trimming access_logs FIFO batch", "error", err, "deleted_so_far", totalDeleted)
			return
		}
		if res.Deleted == 0 {
			break
		}
		totalDeleted += res.Deleted
		// Lowest across batches: FIFO deletes oldest first, so the first
		// non-zero LowestID seen is the overall minimum. Guard against a
		// store that fills LowestID even when Deleted == 0.
		if minLowestID == 0 && res.LowestID > 0 {
			minLowestID = res.LowestID
		}
		if res.HighestID > maxHighestID {
			maxHighestID = res.HighestID
		}
		if res.AnchorHash != "" {
			lastAnchorHash = res.AnchorHash
		}
	}
	if totalDeleted > 0 {
		slog.Info("retention: FIFO trim deleted rows",
			"table", "access_logs",
			"deleted", totalDeleted,
			"max_rows", r.cfg.MaxAccessLogRows)
		_ = r.store.LogAuditAction(ctx, "audit.access_logs.prune", map[string]any{
			"reason":          "fifo",
			"deleted_count":   totalDeleted,
			"lowest_id":       minLowestID,
			"highest_id":      maxHighestID,
			"new_anchor_hash": lastAnchorHash,
			"max_rows":        r.cfg.MaxAccessLogRows,
		})
	}
}

// runPreregistrationCleanup periodically deletes orphaned preregistered_addresses
// rows. It runs on its own ticker independent of the audit retention cadence
// because pre-registration leaks (from proxy crashes between pre-reg and the
// post-mine / revert cleanup paths) are a security-relevant footprint that
// should be swept aggressively.
func (r *RetentionManager) runPreregistrationCleanup() {
	defer close(r.preregDone)

	interval := r.cfg.PreregistrationCleanupInterval
	ttl := r.cfg.PreregistrationTTL
	if interval <= 0 || ttl <= 0 {
		return
	}

	r.sweepOrphanedPreregistrations(ttl)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.sweepOrphanedPreregistrations(ttl)
		}
	}
}

func (r *RetentionManager) sweepOrphanedPreregistrations(ttl time.Duration) {
	ctx := context.Background()
	deleted, err := r.store.DeleteOrphanedPreregisteredAddresses(ctx, ttl)
	if err != nil {
		slog.Error("retention: error cleaning orphaned preregistered addresses", "error", err)
		return
	}
	if deleted > 0 {
		slog.Info("retention: deleted orphaned preregistered addresses", "count", deleted, "ttl", ttl)
	}
}
