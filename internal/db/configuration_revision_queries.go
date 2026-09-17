package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"privacy-proxy/internal/configuration"
)

var ErrConfigurationForbidden = errors.New("current configuration authority is insufficient")

func (d *DB) GetConfigurationRevision(ctx context.Context, scope configuration.Scope, kind configuration.Kind, id string) (*ConfigurationRevision, error) {
	revision, err := scanConfigurationRevision(d.conn.QueryRowContext(ctx, `SELECT `+configurationRevisionColumns+` FROM configuration_revisions WHERE id=$1 AND scope_kind=$2 AND org_id IS NOT DISTINCT FROM $3::uuid AND kind=$4`, id, scope.Kind, configurationOrgID(scope), kind).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return revision, err
}
func (d *DB) ListConfigurationRevisions(ctx context.Context, scope configuration.Scope, kind configuration.Kind, limit, offset int) ([]*ConfigurationRevision, error) {
	if limit < 1 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT `+configurationRevisionColumns+` FROM configuration_revisions WHERE scope_kind=$1 AND org_id IS NOT DISTINCT FROM $2::uuid AND kind=$3 ORDER BY revision DESC LIMIT $4 OFFSET $5`, scope.Kind, configurationOrgID(scope), kind, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []*ConfigurationRevision{}
	for rows.Next() {
		revision, err := scanConfigurationRevision(rows.Scan)
		if err != nil {
			return nil, err
		}
		result = append(result, revision)
	}
	return result, rows.Err()
}
func (d *DB) ReviewConfigurationRevisions(ctx context.Context, scope configuration.Scope, ids []string, actor ConfigurationActor) (ConfigurationActivation, error) {
	tx, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ConfigurationActivation{}, err
	}
	defer tx.Rollback()
	view, err := prepareConfigurationActivation(ctx, tx, scope, ids, actor, false, false)
	if err != nil {
		return view, err
	}
	return view, tx.Commit()
}
func (d *DB) WithdrawConfigurationRevision(ctx context.Context, scope configuration.Scope, kind configuration.Kind, id string, actor ConfigurationActor, authorize ConfigurationAuthorizer) (*ConfigurationRevision, error) {
	if authorize == nil {
		return nil, ErrConfigurationForbidden
	}
	var result *ConfigurationRevision
	err := d.WithTx(ctx, func(tx *Tx) error {
		if err := lockConfigurationScope(ctx, tx.tx, scope); err != nil {
			return err
		}
		if err := validateConfigurationActor(ctx, tx.tx, actor, true); err != nil {
			return err
		}
		candidate, err := scanConfigurationRevision(tx.tx.QueryRowContext(ctx, `SELECT `+configurationRevisionColumns+` FROM configuration_revisions WHERE id=$1 AND scope_kind=$2 AND org_id IS NOT DISTINCT FROM $3::uuid AND kind=$4 FOR UPDATE`, id, scope.Kind, configurationOrgID(scope), kind).Scan)
		if err != nil {
			return err
		}
		if candidate.Status != PolicyStatusDraft {
			return ErrPolicyNotDraft
		}
		view := ConfigurationActivation{Scope: scope, Actor: actor, Candidates: []*ConfigurationRevision{candidate}}
		if scope.Kind == "organization" {
			active, err := activeConfigurationRevision(ctx, tx.tx, scope, configuration.Groups)
			if err != nil {
				return err
			}
			view.Groups, err = configurationGroups(ctx, tx.tx, scope, active, true)
			if err != nil {
				return err
			}
			view.Approvers, err = configurationApprovers(ctx, tx.tx, scope)
			if err != nil {
				return err
			}
		}
		if err := authorize(ctx, tx, view); err != nil {
			return err
		}

		result, err = scanConfigurationRevision(tx.tx.QueryRowContext(ctx, `UPDATE configuration_revisions SET status='withdrawn' WHERE id=$1 RETURNING `+configurationRevisionColumns, id).Scan)
		return err
	})
	return result, err
}
func (d *DB) IsConfigurationManaged(ctx context.Context, scope configuration.Scope, kind configuration.Kind) (bool, error) {
	var managed bool
	err := d.conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM configuration_revisions WHERE scope_kind=$1 AND org_id IS NOT DISTINCT FROM $2::uuid AND kind=$3 AND status='active')`, scope.Kind, configurationOrgID(scope), kind).Scan(&managed)
	return managed, err
}
func (tx *Tx) ConfigurationActorSubject(ctx context.Context, userID string) (string, error) {
	var subject string
	err := tx.tx.QueryRowContext(ctx, `SELECT external_id FROM users WHERE id=$1 AND NOT banned FOR SHARE`, userID).Scan(&subject)
	if err != nil {
		return "", fmt.Errorf("configuration author is not available: %w", ErrConfigurationForbidden)
	}
	return subject, nil
}
