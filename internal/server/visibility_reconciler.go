package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"privacy-proxy/internal/db"
)

// VisibilityReconciler is the M7 outbox drain: it periodically promotes
// pending_tx_visibility rows into tx_visible_to. Each promotion is one
// DB transaction. Failures bump attempt_count on the pending row and
// are retried on the next tick; once attempt_count reaches
// db.MaxVisibilityAttempts the row is parked in dead-letter and surfaced
// via the metric for operator review.
//
// Lifecycle: one instance per Server, started by Server.Start, stopped
// via Stop(). The reconciler holds no in-memory state — restart is safe
// (next tick picks up where the previous one left off).
type VisibilityReconciler struct {
	db        *db.DB
	interval  time.Duration
	batch     int
	stop      chan struct{}
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once

	// receiptStatus, when set, enables RD-1206 method-policy capture promotion:
	// a pending capture is promoted only after its source tx's receipt confirms
	// success. Nil disables capture promotion (tx-visibility promotion is
	// unaffected) — used by tests without a node and by any deployment that
	// hasn't wired a receipt checker.
	receiptStatus ReceiptStatusFunc
}

// ReceiptStatusFunc reports a transaction's mined/success state from the node.
// mined=false means "not yet mined" (retry later). mined=true with
// success=false means the tx reverted (drop the capture). A non-nil err is a
// transient lookup failure (retry).
type ReceiptStatusFunc func(ctx context.Context, txHash string) (mined bool, success bool, err error)

// VisibilityReconcilerConfig holds tunables. Defaults are conservative;
// production can tighten the interval if outbox lag becomes an SLO.
type VisibilityReconcilerConfig struct {
	// Interval between ticks. 5s is chosen so steady-state latency from
	// "node accepted tx" to "recipients can see it in explorer" is
	// bounded by tick + DB roundtrip; mirrors `time.NewTicker(5s)` in
	// other outbox patterns.
	Interval time.Duration

	// BatchSize caps how many pending rows are processed per tick. Keeps
	// a single tick's wall-clock cost bounded if a burst of writes hit
	// the outbox during a DB outage and now need to drain.
	BatchSize int
}

// DefaultVisibilityReconcilerConfig returns the production defaults.
func DefaultVisibilityReconcilerConfig() VisibilityReconcilerConfig {
	return VisibilityReconcilerConfig{
		Interval:  5 * time.Second,
		BatchSize: 100,
	}
}

// NewVisibilityReconciler constructs but does not start the reconciler.
// Pass nil db to disable (no-op Start). The Start method must be called
// to begin the ticker goroutine.
func NewVisibilityReconciler(database *db.DB, cfg VisibilityReconcilerConfig) *VisibilityReconciler {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	return &VisibilityReconciler{
		db:       database,
		interval: cfg.Interval,
		batch:    cfg.BatchSize,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// SetReceiptStatus wires the receipt checker that enables capture promotion
// (RD-1206). Call before Start.
func (r *VisibilityReconciler) SetReceiptStatus(fn ReceiptStatusFunc) {
	if r != nil {
		r.receiptStatus = fn
	}
}

// Start spawns the ticker goroutine. Idempotent. No-op when db is nil.
func (r *VisibilityReconciler) Start(ctx context.Context) {
	if r == nil || r.db == nil {
		return
	}
	r.startOnce.Do(func() {
		go r.run(ctx)
	})
}

// Stop signals the ticker goroutine and waits for it to drain. Safe to
// call multiple times; safe to call without Start.
func (r *VisibilityReconciler) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stop)
	})
	// Wait for the goroutine to exit if Start was called.
	select {
	case <-r.done:
	default:
		// done is only closed if run() exits; if Start was never called,
		// done is unused. Use a non-blocking check to avoid hanging
		// callers that stopped a never-started reconciler.
	}
}

func (r *VisibilityReconciler) run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Run one tick immediately on startup so a recent shutdown doesn't
	// leave the outbox empty-then-stale for `interval` seconds.
	r.tick(ctx)

	for {
		select {
		case <-r.stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick processes one batch of pending rows. Each row is promoted in its
// own DB transaction; one row's failure does not block the next.
func (r *VisibilityReconciler) tick(ctx context.Context) {
	rows, err := r.db.ListDuePendingTxVisibility(ctx, r.batch)
	if err != nil {
		slog.Warn("visibility reconciler: list failed", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	var promoted, failed int
	for _, row := range rows {
		if err := r.db.PromotePendingTxVisibility(ctx, row); err != nil {
			failed++
			if markErr := r.db.MarkPendingTxVisibilityFailed(ctx, row.ID, err); markErr != nil {
				slog.Warn("visibility reconciler: mark-failed update failed",
					"pending_id", row.ID, "promote_err", err, "mark_err", markErr)
			} else {
				slog.Warn("visibility reconciler: promotion failed",
					"pending_id", row.ID,
					"tx_hash", row.TxHash,
					"attempt", row.AttemptCount+1,
					"err", err)
			}
			continue
		}
		promoted++
	}

	if promoted > 0 || failed > 0 {
		slog.Debug("visibility reconciler: tick complete",
			"promoted", promoted, "failed", failed, "batch", len(rows))
	}

	r.tickCaptures(ctx)
}

// tickCaptures drains pending_record_captures (RD-1206). A capture is promoted
// only after its source tx's receipt confirms success; a reverted tx's capture
// is dropped (a failed create must not plant capture rows); an unmined tx or a
// transient lookup error is retried on the next tick. No-op until a receipt
// checker is wired.
func (r *VisibilityReconciler) tickCaptures(ctx context.Context) {
	if r.receiptStatus == nil {
		return
	}
	rows, err := r.db.ListDuePendingRecordCaptures(ctx, r.batch)
	if err != nil {
		slog.Warn("capture reconciler: list failed", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	var promoted, dropped, retried int
	for _, row := range rows {
		mined, success, rerr := r.receiptStatus(ctx, row.TxHash)
		switch {
		case rerr != nil || !mined:
			retried++
			if markErr := r.db.MarkPendingRecordCaptureFailure(ctx, row.ID, receiptErrMsg(rerr, mined)); markErr != nil {
				slog.Warn("capture reconciler: mark-failure update failed", "pending_id", row.ID, "mark_err", markErr)
			}
		case !success:
			// tx reverted → drop the capture (no rows planted for a failed create)
			dropped++
			if delErr := r.db.DeletePendingRecordCapture(ctx, row.ID); delErr != nil {
				slog.Warn("capture reconciler: drop-reverted delete failed", "pending_id", row.ID, "del_err", delErr)
			} else {
				slog.Debug("capture reconciler: dropped capture for reverted tx", "tx_hash", row.TxHash)
			}
		default:
			if err := r.db.PromoteRecordCapture(ctx, row); err != nil {
				retried++
				if markErr := r.db.MarkPendingRecordCaptureFailure(ctx, row.ID, err.Error()); markErr != nil {
					slog.Warn("capture reconciler: mark-failure update failed", "pending_id", row.ID, "mark_err", markErr)
				}
				continue
			}
			promoted++
		}
	}
	if promoted > 0 || dropped > 0 || retried > 0 {
		slog.Debug("capture reconciler: tick complete", "promoted", promoted, "dropped", dropped, "retried", retried, "batch", len(rows))
	}
}

func receiptErrMsg(err error, mined bool) string {
	if err != nil {
		return err.Error()
	}
	if !mined {
		return "tx not yet mined"
	}
	return ""
}
