package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

var ErrNodeSubmissionConflict = errors.New("transaction is already bound to a different submission")

type NodeSubmission struct {
	Network                                                nodepolicy.Network
	TransactionHash, PrincipalID, OrgID, Signer, ContextID string
	RawTransaction                                         string
	IdentityEnvelope                                       []byte
	SenderDID                                              string
	VisibleTo                                              []string
	State                                                  string
	Outcome                                                json.RawMessage
	CreatedAt, UpdatedAt                                   time.Time
	ReconciledAt                                           *time.Time
	ReconciliationNote                                     string
}

func validSubmissionHex(s string, size int) bool {
	if len(s) != 2+2*size || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}
func (d *DB) SaveNodeSubmission(ctx context.Context, in NodeSubmission) error {
	if in.Network.ChainID == 0 || in.Network.DeploymentID == "" || !validSubmissionHex(in.TransactionHash, 32) || !validSubmissionHex(in.Signer, 20) || in.ContextID == "" || in.RawTransaction == "" || len(in.IdentityEnvelope) == 0 || in.SenderDID == "" {
		return fmt.Errorf("invalid node submission")
	}
	for _, id := range []string{in.PrincipalID, in.OrgID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return fmt.Errorf("invalid node submission principal or organization")
		}
	}
	if in.VisibleTo == nil {
		in.VisibleTo = []string{}
	}
	result, err := d.conn.ExecContext(ctx, `INSERT INTO node_submissions(chain_id,deployment_id,tx_hash,principal_id,org_id,signer,context_id,raw_transaction,identity_envelope,sender_did,visible_to)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
 ON CONFLICT(chain_id,deployment_id,tx_hash) DO UPDATE SET context_id=EXCLUDED.context_id,identity_envelope=EXCLUDED.identity_envelope,updated_at=clock_timestamp(),next_check_at=clock_timestamp(),
 state=CASE WHEN node_submissions.context_id<>EXCLUDED.context_id AND node_submissions.state IN ('expired','denied') THEN 'queued' ELSE node_submissions.state END,
 outcome=CASE WHEN node_submissions.context_id<>EXCLUDED.context_id AND node_submissions.state IN ('expired','denied') THEN NULL ELSE node_submissions.outcome END
 WHERE node_submissions.principal_id=EXCLUDED.principal_id AND node_submissions.org_id=EXCLUDED.org_id
 AND node_submissions.signer=EXCLUDED.signer AND node_submissions.raw_transaction=EXCLUDED.raw_transaction
 AND node_submissions.sender_did=EXCLUDED.sender_did AND node_submissions.visible_to=EXCLUDED.visible_to`, in.Network.ChainID, in.Network.DeploymentID, in.TransactionHash, in.PrincipalID, in.OrgID, in.Signer, in.ContextID, in.RawTransaction, in.IdentityEnvelope, in.SenderDID, in.VisibleTo)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNodeSubmissionConflict
	}
	return nil
}

const nodeSubmissionColumns = `chain_id,deployment_id,tx_hash,principal_id,org_id,signer,context_id,raw_transaction,identity_envelope,sender_did,visible_to,state,outcome,created_at,updated_at,reconciled_at,reconciliation_note`

func scanNodeSubmission(row interface{ Scan(...any) error }) (NodeSubmission, error) {
	var out NodeSubmission
	var outcome []byte
	err := row.Scan(&out.Network.ChainID, &out.Network.DeploymentID, &out.TransactionHash, &out.PrincipalID, &out.OrgID, &out.Signer, &out.ContextID, &out.RawTransaction, &out.IdentityEnvelope, &out.SenderDID, ScanTextArray(&out.VisibleTo), &out.State, &outcome, &out.CreatedAt, &out.UpdatedAt, &out.ReconciledAt, &out.ReconciliationNote)
	out.Outcome = outcome
	return out, err
}
func (d *DB) GetNodeSubmission(ctx context.Context, network nodepolicy.Network, hash string) (NodeSubmission, error) {
	return scanNodeSubmission(d.conn.QueryRowContext(ctx, `SELECT `+nodeSubmissionColumns+` FROM node_submissions WHERE chain_id=$1 AND deployment_id=$2 AND tx_hash=$3`, network.ChainID, network.DeploymentID, hash))
}
func (d *DB) ListPendingNodeSubmissions(ctx context.Context, network nodepolicy.Network, limit int) ([]NodeSubmission, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT `+nodeSubmissionColumns+` FROM node_submissions WHERE chain_id=$1 AND deployment_id=$2 AND reconciled_at IS NULL AND next_check_at<=clock_timestamp() ORDER BY next_check_at LIMIT $3`, network.ChainID, network.DeploymentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NodeSubmission{}
	for rows.Next() {
		row, err := scanNodeSubmission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (d *DB) ScheduleNodeSubmission(ctx context.Context, network nodepolicy.Network, hash string, delay time.Duration) error {
	if delay < 0 || delay > time.Hour {
		return fmt.Errorf("invalid reconciliation delay")
	}
	_, err := d.conn.ExecContext(ctx, `UPDATE node_submissions SET next_check_at=clock_timestamp()+$4*interval '1 millisecond' WHERE chain_id=$1 AND deployment_id=$2 AND tx_hash=$3 AND reconciled_at IS NULL`, network.ChainID, network.DeploymentID, hash, delay.Milliseconds())
	return err
}
func (d *DB) MarkNodeSubmissionAccepted(ctx context.Context, network nodepolicy.Network, hash string) error {
	_, err := d.conn.ExecContext(ctx, `UPDATE node_submissions SET state='accepted',updated_at=clock_timestamp() WHERE chain_id=$1 AND deployment_id=$2 AND tx_hash=$3 AND state='queued'`, network.ChainID, network.DeploymentID, hash)
	return err
}

// RecordNodeOutcome is only called with the authenticated node's canonical
// status. Created contracts and visibility enter OPS in the same transaction
// as reconciliation, so an interruption cannot permanently omit either.
func (d *DB) RecordNodeOutcome(ctx context.Context, network nodepolicy.Network, status nodepolicy.TransactionStatus) error {
	if err := status.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return withRetry(ctx, func() error {
		return d.WithTx(ctx, func(tx *Tx) error {
			// Scope lock precedes resource/intent locks, matching configuration writers.
			note := ""
			if err := tx.AuthorizeDeploymentRegistration(ctx, status.OrgID); err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				note = "organization_deleted"
			}
			stored, err := scanNodeSubmission(tx.tx.QueryRowContext(ctx, `SELECT `+nodeSubmissionColumns+` FROM node_submissions WHERE chain_id=$1 AND deployment_id=$2 AND tx_hash=$3 FOR UPDATE`, network.ChainID, network.DeploymentID, status.TransactionHash))
			if err != nil {
				return err
			}
			if stored.PrincipalID != status.PrincipalID || stored.OrgID != status.OrgID {
				return ErrNodeSubmissionConflict
			}
			if status.Execution.Status == "expired" && stored.ContextID != status.ContextID {
				return ErrNodeSubmissionConflict
			}
			if stored.ReconciledAt != nil {
				return nil
			}
			if status.Execution.Status == "included" && status.Execution.Finalized && note == "" {
				for _, created := range status.Execution.Created {
					if err := reconcileNodeContract(ctx, tx, stored, created); err != nil {
						return err
					}
				}
				if len(stored.VisibleTo) > 0 {
					if _, err := tx.tx.ExecContext(ctx, `INSERT INTO pending_tx_visibility(tx_hash,visible_to_dids,sender_did,org_id) VALUES($1,$2,$3,$4)`, stored.TransactionHash, stored.VisibleTo, stored.SenderDID, stored.OrgID); err != nil {
						return err
					}
				}
			}
			terminal := status.Execution.Finalized && (status.Execution.Status == "included" || status.Execution.Status == "reverted")
			// A denial can be retried after a reviewed facts change. Continue polling
			// until inclusion/revert; preserve the denial for callers in the meantime.
			_, err = tx.tx.ExecContext(ctx, `UPDATE node_submissions SET state=$4,outcome=$5,updated_at=clock_timestamp(),reconciled_at=CASE WHEN $6 THEN clock_timestamp() ELSE NULL END,reconciliation_note=$7 WHERE chain_id=$1 AND deployment_id=$2 AND tx_hash=$3`, network.ChainID, network.DeploymentID, status.TransactionHash, status.Execution.Status, encoded, terminal, note)
			return err
		})
	})
}

func reconcileNodeContract(ctx context.Context, tx *Tx, submission NodeSubmission, created nodepolicy.CreatedContract) error {
	var id, owner string
	err := tx.tx.QueryRowContext(ctx, `SELECT id,org_id FROM contracts WHERE lower(address)=$1 FOR UPDATE`, created.Address).Scan(&id, &owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && owner != submission.OrgID {
		return ErrNodeSubmissionConflict
	}
	var existingPrincipal string
	principalErr := tx.tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 FOR KEY SHARE`, submission.PrincipalID).Scan(&existingPrincipal)
	if principalErr != nil && !errors.Is(principalErr, sql.ErrNoRows) {
		return principalErr
	}
	var deployer *string
	if principalErr == nil {
		deployer = &existingPrincipal
	}
	metadata := map[string]any{"auto_registered": true, "via": "node_execution", "transaction": submission.TransactionHash, "deployer_principal": submission.PrincipalID}
	if errors.Is(err, sql.ErrNoRows) {
		now := time.Now()
		id = uuid.NewString()
		contract := &rbac.Contract{ID: id, OrgID: submission.OrgID, Address: created.Address, Name: "Contract " + created.Address[:10], DeployedByUserID: deployer, DeployedAt: &now, Metadata: metadata}
		if err := tx.CreateContract(ctx, contract); err != nil {
			return err
		}
	} else {
		// A pre-registered catalog entry keeps its reviewed ABI/name, while
		// actual chain evidence supplies the deployer used by access rules.
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE contracts SET deployed_by_user_id=$2,deployed_at=clock_timestamp(),metadata=(CASE WHEN jsonb_typeof(metadata)='object' THEN metadata ELSE '{}'::jsonb END)||$3::jsonb,updated_at=clock_timestamp() WHERE id=$1`, id, deployer, encoded); err != nil {
			return err
		}
	}
	// Preserve the existing deploy-group auto-grant semantics using only a
	// current, active deployment group. Revoked memberships add no grant.
	_, err = tx.tx.ExecContext(ctx, `INSERT INTO contract_grants(id,contract_id,group_id)
 SELECT $1,$2,g.id FROM user_memberships m JOIN groups g ON g.id=m.group_id JOIN group_access ga ON ga.group_id=g.id JOIN users u ON u.id=m.user_id
 WHERE m.user_id=$3 AND g.org_id=$4 AND NOT u.banned AND (m.expires_at IS NULL OR m.expires_at>NOW())
 AND (g.is_org_admin OR 'deploy'=ANY(ga.claims) OR 'admin'=ANY(ga.claims)) ORDER BY g.id LIMIT 1 ON CONFLICT(contract_id,group_id) DO NOTHING`, uuid.NewString(), id, submission.PrincipalID, submission.OrgID)
	return err
}
