package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"privacy-proxy/internal/nodepolicy"
	"strings"
	"time"
)

type NodePolicyProgress struct {
	DesiredVersion uint64                   `json:"desired_version"`
	Applied        *nodepolicy.AppliedState `json:"applied"`
	AcknowledgedAt *time.Time               `json:"acknowledged_at"`
}

func (d *DB) NodePolicyVersion(ctx context.Context) (uint64, error) {
	var version uint64
	err := d.conn.QueryRowContext(ctx, `SELECT version FROM node_policy_clock WHERE singleton`).Scan(&version)
	return version, err
}
func (d *DB) AcknowledgeNodePolicy(ctx context.Context, consumer string, state nodepolicy.AppliedState) error {
	digest, err := hex.DecodeString(state.Digest)
	if err != nil || len(digest) != 32 || strings.ToLower(state.Digest) != state.Digest || state.Version == 0 || state.ExpiresAt <= 0 || strings.TrimSpace(consumer) == "" || len(consumer) > 128 {
		return fmt.Errorf("invalid node acknowledgement")
	}
	result, err := d.conn.ExecContext(ctx, `INSERT INTO node_policy_cursors(consumer_id,version,payload_digest,expires_at)
        SELECT $1,$2,$3,$4 FROM node_policy_clock WHERE singleton AND version >= $2
        ON CONFLICT(consumer_id) DO UPDATE SET version=EXCLUDED.version,payload_digest=EXCLUDED.payload_digest,
            expires_at=EXCLUDED.expires_at,acknowledged_at=clock_timestamp()
        WHERE node_policy_cursors.version <= EXCLUDED.version`, consumer, state.Version, state.Digest, state.ExpiresAt)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return nodepolicy.ErrFeedConflict
	}
	return nil
}
func (d *DB) NodePolicyProgress(ctx context.Context, consumer string) (NodePolicyProgress, error) {
	var out NodePolicyProgress
	var version, expiry sql.NullInt64
	var digest sql.NullString
	var ack sql.NullTime
	err := d.conn.QueryRowContext(ctx, `SELECT c.version,n.version,n.payload_digest,n.expires_at,n.acknowledged_at
        FROM node_policy_clock c LEFT JOIN node_policy_cursors n ON n.consumer_id=$1 WHERE c.singleton`, consumer).
		Scan(&out.DesiredVersion, &version, &digest, &expiry, &ack)
	if err != nil {
		return out, err
	}
	if version.Valid {
		if !digest.Valid || !expiry.Valid || !ack.Valid || version.Int64 <= 0 {
			return NodePolicyProgress{}, errors.New("invalid stored node progress")
		}
		out.Applied = &nodepolicy.AppliedState{Version: uint64(version.Int64), Digest: digest.String, ExpiresAt: expiry.Int64}
		out.AcknowledgedAt = &ack.Time
	}
	return out, nil
}
