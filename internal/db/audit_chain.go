package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ChainNameAccessLogs is the chain identifier stored in audit_chain_anchor for
// the access_logs hash chain.
const ChainNameAccessLogs = "access_logs"

// ChainNameRBACAuditLog is the chain identifier stored in audit_chain_anchor
// for the rbac_audit_log hash chain (RD-858). The chain protects admin-
// action records (group / grant / membership mutations, compliance config
// changes, etc.) against silent tampering by an attacker with DB read or
// write access — the auditor scope where the access_logs-only chain was
// strictly insufficient for SOC 2 / ISO 27001 CC7 evidence.
const ChainNameRBACAuditLog = "rbac_audit_log"

// PruneResult carries the metadata an audit-of-the-audit row needs after a
// prune operation. CleanupAccessLogs and TrimAccessLogsFIFOBatch return this
// so the retention manager can attach the deleted id range and the new chain
// anchor hash to the rbac_audit_log entry alongside the row count. All four
// fields are zero-valued when Deleted == 0.
//
// The audit package owns its own copy of this vocabulary
// (audit.PruneResult) so that audit never imports db (RD-1255); the
// server-side retention adapter converts between the two.
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

// AuditChainAnchor records the last-pruned entry hash for an audit hash chain
// so that the chain can be verified across pruning cuts. There is one row per
// chain (PRIMARY KEY chain_name).
type AuditChainAnchor struct {
	ChainName           string    `json:"chain_name"`
	LastPrunedID        int64     `json:"last_pruned_id"`
	LastPrunedEntryHash string    `json:"last_pruned_entry_hash"`
	LastPrunedAt        time.Time `json:"last_pruned_at"`
}

// GetAuditChainAnchor returns the anchor row for chainName, or (nil, nil) if
// no row exists yet. A missing row means no pruning has happened yet for that
// chain.
func (d *DB) GetAuditChainAnchor(ctx context.Context, chainName string) (*AuditChainAnchor, error) {
	row := d.conn.QueryRowContext(ctx, `
		SELECT chain_name, last_pruned_id, last_pruned_entry_hash, last_pruned_at
		FROM audit_chain_anchor
		WHERE chain_name = $1`, chainName)

	var a AuditChainAnchor
	if err := row.Scan(&a.ChainName, &a.LastPrunedID, &a.LastPrunedEntryHash, &a.LastPrunedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read audit chain anchor %q: %w", chainName, err)
	}
	return &a, nil
}

// UpsertAuditChainAnchor inserts or updates the anchor row for chainName with
// the given prune cut. Callers should pass the highest id and its entry_hash
// among the rows that are about to be deleted, BEFORE deleting them.
func (d *DB) UpsertAuditChainAnchor(ctx context.Context, chainName string, lastPrunedID int64, lastPrunedEntryHash string) error {
	return upsertAuditChainAnchorTx(ctx, d.conn, chainName, lastPrunedID, lastPrunedEntryHash)
}

// dbExec is the subset of *sql.DB / *sql.Tx that we need for anchor writes —
// lets the helper run inside a transaction.
type dbExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// LogAuditAction writes a single row to rbac_audit_log so that
// audit-of-the-audit events (retention prunes, anchor writes, etc.) are
// themselves recorded. actor_id is left NULL — there is no human actor for a
// scheduled prune; resource_type pins the affected table for grep/RBAC
// reviews. Any error is wrapped; the caller decides whether to fail the
// surrounding operation or just log.
func (d *DB) LogAuditAction(ctx context.Context, action string, details map[string]any) error {
	var detailsJSON []byte
	if len(details) > 0 {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
	}
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO rbac_audit_log
			(actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address)
		VALUES (NULL, 'system:retention', $1, 'audit_log', NULL, NULL, NULL, $2, NULL)`,
		action, detailsJSON)
	if err != nil {
		return fmt.Errorf("insert rbac_audit_log: %w", err)
	}
	return nil
}

func upsertAuditChainAnchorTx(ctx context.Context, exec dbExec, chainName string, lastPrunedID int64, lastPrunedEntryHash string) error {
	_, err := exec.ExecContext(ctx, `
		INSERT INTO audit_chain_anchor (chain_name, last_pruned_id, last_pruned_entry_hash, last_pruned_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (chain_name) DO UPDATE SET
			last_pruned_id = EXCLUDED.last_pruned_id,
			last_pruned_entry_hash = EXCLUDED.last_pruned_entry_hash,
			last_pruned_at = EXCLUDED.last_pruned_at`,
		chainName, lastPrunedID, lastPrunedEntryHash)
	if err != nil {
		return fmt.Errorf("failed to upsert audit chain anchor %q: %w", chainName, err)
	}
	return nil
}
