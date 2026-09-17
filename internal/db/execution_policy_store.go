package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"privacy-proxy/internal/policydsl"
)

// Execution policy revision operations (RD-1287).
//
// A revision is written once and never edited. Activation moves its status and
// stamps the actor; nothing rewrites the document, the generated source or the
// bytecode. That is what lets a stored digest stand as evidence of what was
// approved.

// Revision statuses.
const (
	PolicyStatusDraft      = "draft"
	PolicyStatusActive     = "active"
	PolicyStatusSuperseded = "superseded"
	PolicyStatusWithdrawn  = "withdrawn"
)

// ErrPolicyStaleBase is returned when a submission was written against an
// active revision that has changed, so applying it would silently discard
// whatever landed in between.
var ErrPolicyStaleBase = errors.New("policy base revision is stale")

// ErrPolicyNotDraft is returned when an activation targets a revision that is
// not awaiting approval.
var ErrPolicyNotDraft = errors.New("policy revision is not a draft")

var ErrPolicyActorRequired = errors.New("an identified policy actor is required")
var ErrPolicySelfApproval = errors.New("policy submitter and activator must be different actors")

// ExecutionPolicyRevision is one stored policy and the artifact built from it.
type ExecutionPolicyRevision struct {
	ID       string `json:"id"`
	OrgID    string `json:"org_id"`
	Revision int64  `json:"revision"`
	// Nil identifies a legacy revision whose authoring base was not recorded.
	BaseRevision *int64 `json:"base_revision"`
	Status       string `json:"status"`

	Source       string `json:"source"`
	PolicyDigest string `json:"policy_digest"`

	SoliditySource  string `json:"solidity_source"`
	SolidityDigest  string `json:"solidity_digest"`
	RuntimeBytecode []byte `json:"-"`
	RuntimeDigest   string `json:"runtime_digest"`

	Compiler policydsl.CompilerSettings `json:"compiler"`

	CreatedBy   *string    `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedBy *string    `json:"activated_by,omitempty"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
}

const executionPolicyColumns = `
    id, org_id, revision, status, source, policy_digest,
    solidity_source, solidity_digest, runtime_bytecode, runtime_digest,
    compiler, created_by, created_at, activated_by, activated_at, base_revision`

func scanExecutionPolicy(scan func(dest ...any) error) (*ExecutionPolicyRevision, error) {
	var (
		rev      ExecutionPolicyRevision
		compiler []byte
	)
	if err := scan(
		&rev.ID, &rev.OrgID, &rev.Revision, &rev.Status, &rev.Source, &rev.PolicyDigest,
		&rev.SoliditySource, &rev.SolidityDigest, &rev.RuntimeBytecode, &rev.RuntimeDigest,
		&compiler, &rev.CreatedBy, &rev.CreatedAt, &rev.ActivatedBy, &rev.ActivatedAt, &rev.BaseRevision,
	); err != nil {
		return nil, err
	}
	if len(compiler) > 0 {
		if err := json.Unmarshal(compiler, &rev.Compiler); err != nil {
			return nil, fmt.Errorf("reading compiler settings: %w", err)
		}
	}
	return &rev, nil
}

// ActiveExecutionPolicyRevisionNumber is the base for authoring. Drafts and
// withdrawals do not change it; zero means no policy has been activated.
func (d *DB) ActiveExecutionPolicyRevisionNumber(ctx context.Context, orgID string) (int64, error) {
	var active int64
	err := d.conn.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(revision), 0) FROM execution_policy_revisions WHERE org_id = $1 AND status = 'active'`, orgID,
	).Scan(&active)
	return active, err
}

// LatestExecutionPolicyRevisionNumber returns the highest revision number an
// organisation has, or zero when it has none.
func (d *DB) LatestExecutionPolicyRevisionNumber(ctx context.Context, orgID string) (int64, error) {
	var latest sql.NullInt64
	err := d.conn.QueryRowContext(ctx,
		`SELECT MAX(revision) FROM execution_policy_revisions WHERE org_id = $1`, orgID,
	).Scan(&latest)
	if err != nil {
		return 0, fmt.Errorf("reading the latest policy revision: %w", err)
	}
	if !latest.Valid {
		return 0, nil
	}
	return latest.Int64, nil
}

// CreateExecutionPolicyRevision stores a submitted policy and its artifact as a
// draft.
//
// baseRevision is the active revision the author wrote against. It must still
// be active, or the submission is refused: merging it would discard whatever was
// approved in between without anyone seeing the difference.
func (d *DB) CreateExecutionPolicyRevision(
	ctx context.Context,
	orgID string,
	baseRevision int64,
	source string,
	artifact *policydsl.Artifact,
	createdBy *string,
) (*ExecutionPolicyRevision, error) {
	if createdBy == nil || strings.TrimSpace(*createdBy) == "" {
		return nil, ErrPolicyActorRequired
	}
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting the policy transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the organisation row first. Two submissions racing here would
	// otherwise both read the same latest revision, both find their base
	// current, and the second would take a revision number the unique index
	// then rejects with an error that says nothing useful. The lock is taken on
	// the organisation rather than on the revisions, because the row that has
	// to exist is the organisation and the revision being guarded is the one
	// that does not exist yet.
	var locked string
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM organizations WHERE id = $1 FOR UPDATE`, orgID,
	).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("locking the organization: %w", err)
	}

	var latest, current int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(revision), 0), COALESCE(MAX(revision) FILTER (WHERE status = 'active'), 0)
         FROM execution_policy_revisions WHERE org_id = $1`, orgID,
	).Scan(&latest, &current); err != nil {
		return nil, fmt.Errorf("reading the latest policy revision: %w", err)
	}

	if baseRevision != current {
		return nil, fmt.Errorf("%w: written against revision %d, current is %d", ErrPolicyStaleBase, baseRevision, current)
	}

	compiler, err := json.Marshal(artifact.Compiler)
	if err != nil {
		return nil, fmt.Errorf("encoding compiler settings: %w", err)
	}

	row := tx.QueryRowContext(ctx, `
        INSERT INTO execution_policy_revisions (
            org_id, revision, status, source, policy_digest,
            solidity_source, solidity_digest, runtime_bytecode, runtime_digest,
            compiler, created_by, base_revision
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING `+executionPolicyColumns,
		orgID, latest+1, PolicyStatusDraft, source, artifact.PolicyDigest,
		artifact.Source, artifact.SourceDigest, artifact.RuntimeBytecode, artifact.RuntimeDigest,
		compiler, createdBy, baseRevision,
	)

	rev, err := scanExecutionPolicy(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("storing the policy revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing the policy revision: %w", err)
	}
	return rev, nil
}

// GetExecutionPolicyRevision returns one revision of an organisation's policy.
//
// The organisation is part of the lookup, not checked afterwards, so a caller
// cannot reach another tenant's revision by knowing its identifier.
func (d *DB) GetExecutionPolicyRevision(ctx context.Context, orgID, id string) (*ExecutionPolicyRevision, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT `+executionPolicyColumns+`
         FROM execution_policy_revisions WHERE org_id = $1 AND id = $2`, orgID, id)

	rev, err := scanExecutionPolicy(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the policy revision: %w", err)
	}
	return rev, nil
}

// GetActiveExecutionPolicy returns the organisation's policy in force, or nil
// when it has none.
func (d *DB) GetActiveExecutionPolicy(ctx context.Context, orgID string) (*ExecutionPolicyRevision, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT `+executionPolicyColumns+`
         FROM execution_policy_revisions WHERE org_id = $1 AND status = $2`, orgID, PolicyStatusActive)

	rev, err := scanExecutionPolicy(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the active policy: %w", err)
	}
	return rev, nil
}

// ListExecutionPolicyRevisions returns an organisation's revisions, newest
// first.
func (d *DB) ListExecutionPolicyRevisions(ctx context.Context, orgID string, limit int) ([]*ExecutionPolicyRevision, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := d.conn.QueryContext(ctx,
		`SELECT `+executionPolicyColumns+`
         FROM execution_policy_revisions WHERE org_id = $1
         ORDER BY revision DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing policy revisions: %w", err)
	}
	defer rows.Close()

	var out []*ExecutionPolicyRevision
	for rows.Next() {
		rev, err := scanExecutionPolicy(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("reading a policy revision: %w", err)
		}
		out = append(out, rev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing policy revisions: %w", err)
	}
	return out, nil
}

// ActivateExecutionPolicyRevision puts a draft into force and retires whatever
// was active before it.
//
// Both changes happen in one transaction. A partial application would leave an
// organisation either with two policies in force or with none, and the second
// is an outage while the first has no defined winner.
func (d *DB) ActivateExecutionPolicyRevision(ctx context.Context, orgID, id string, activatedBy *string) (*ExecutionPolicyRevision, error) {
	if activatedBy == nil || strings.TrimSpace(*activatedBy) == "" {
		return nil, ErrPolicyActorRequired
	}
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("starting the activation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// All stream writers take the organisation lock before any revision lock.
	// This serializes replacement even when there is no active row to lock.
	var locked string
	err = tx.QueryRowContext(ctx, `SELECT id FROM organizations WHERE id = $1 FOR UPDATE`, orgID).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("locking the organization: %w", err)
	}
	candidate, err := scanExecutionPolicy(tx.QueryRowContext(ctx,
		`SELECT `+executionPolicyColumns+` FROM execution_policy_revisions
         WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the policy revision: %w", err)
	}
	if candidate.Status != PolicyStatusDraft {
		return nil, fmt.Errorf("%w: it is %s", ErrPolicyNotDraft, candidate.Status)
	}
	if candidate.CreatedBy == nil || strings.TrimSpace(*candidate.CreatedBy) == "" {
		return nil, ErrPolicyActorRequired
	}
	if strings.EqualFold(*candidate.CreatedBy, *activatedBy) {
		return nil, ErrPolicySelfApproval
	}
	var active int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(revision), 0) FROM execution_policy_revisions WHERE org_id = $1 AND status = 'active'`, orgID,
	).Scan(&active); err != nil {
		return nil, fmt.Errorf("reading the active policy revision: %w", err)
	}
	if candidate.BaseRevision == nil || *candidate.BaseRevision != active {
		return nil, ErrPolicyStaleBase
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE execution_policy_revisions SET status = $1
         WHERE org_id = $2 AND status = $3`, PolicyStatusSuperseded, orgID, PolicyStatusActive); err != nil {
		return nil, fmt.Errorf("retiring the previous policy: %w", err)
	}

	row := tx.QueryRowContext(ctx,
		`UPDATE execution_policy_revisions
         SET status = $1, activated_by = $2, activated_at = NOW()
         WHERE org_id = $3 AND id = $4
         RETURNING `+executionPolicyColumns,
		PolicyStatusActive, activatedBy, orgID, id)

	rev, err := scanExecutionPolicy(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("activating the policy revision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing the activation: %w", err)
	}
	return rev, nil
}

// WithdrawExecutionPolicyRevision abandons a draft that was never activated.
//
// Only a draft can be withdrawn. An active or superseded revision is part of
// the record of what was enforced and stays exactly as it is.
func (d *DB) WithdrawExecutionPolicyRevision(ctx context.Context, orgID, id string) (*ExecutionPolicyRevision, error) {
	row := d.conn.QueryRowContext(ctx,
		`UPDATE execution_policy_revisions SET status = $1
         WHERE org_id = $2 AND id = $3 AND status = $4
         RETURNING `+executionPolicyColumns,
		PolicyStatusWithdrawn, orgID, id, PolicyStatusDraft)

	rev, err := scanExecutionPolicy(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("withdrawing the policy revision: %w", err)
	}
	return rev, nil
}
