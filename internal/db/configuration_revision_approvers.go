package db

import (
	"context"

	"privacy-proxy/internal/configuration"
)

func configurationApprovers(ctx context.Context, q DBTX, scope configuration.Scope) (*configuration.ApproversSpec, error) {
	active, err := activeConfigurationRevision(ctx, q, scope, configuration.Approvers)
	if err != nil || active == nil {
		return nil, err
	}
	doc, err := configuration.Parse([]byte(active.Source))
	if err != nil {
		return nil, err
	}
	spec := doc.Spec.(configuration.ApproversSpec)
	return &spec, nil
}
func validateConfigurationApprovers(view ConfigurationActivation) error {
	spec := view.Approvers
	if view.ApproversDiff != nil {
		spec = view.ApproversDiff
	}
	if spec == nil {
		return nil
	}
	groups := []configuration.Group{}
	for _, state := range view.Groups.Groups {
		groups = append(groups, state.Group)
	}
	if view.GroupDiff != nil {
		groups = view.GroupDiff.Projection
	}
	if err := configuration.ValidateApprovers(*spec, groups); err != nil {
		return ConfigurationConflict("%s", err)
	}
	// Prevent a source-only trust change from leaving no live eligible member.
	eligible := map[string]bool{}
	for _, id := range spec.GroupIDs {
		eligible[id] = true
	}
	var members int64
	for _, state := range view.Groups.Groups {
		if eligible[state.Group.ID] {
			members += state.ActiveMembers
		}
	}
	if members == 0 {
		return ConfigurationConflict("approver policy must retain a live member of an eligible full-admin group")
	}
	return nil
}

// ConfigurationActorIsApprover checks the previously active policy under the
// scope/group/member locks held by the activation transaction.
func (tx *Tx) ConfigurationActorIsApprover(ctx context.Context, userID string, view ConfigurationActivation) (bool, error) {
	if view.Approvers == nil {
		return true, nil
	}
	var eligible bool
	err := tx.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN user_memberships m ON m.user_id=u.id JOIN groups g ON g.id=m.group_id WHERE u.id=$1 AND NOT u.banned AND g.org_id=$2 AND g.is_org_admin AND g.id=ANY($3::uuid[]) AND (m.expires_at IS NULL OR m.expires_at>NOW()))`, userID, view.Scope.ID, view.Approvers.GroupIDs).Scan(&eligible)
	return eligible, err
}

func (tx *Tx) ConfigurationActorCanApprove(ctx context.Context, userID string, scope configuration.Scope) (bool, error) {
	if scope.Kind == "platform" {
		return false, nil
	}
	full, _, err := tx.ConfigurationActorRoles(ctx, userID, scope.ID)
	if err != nil || !full {
		return false, err
	}
	approvers, err := configurationApprovers(ctx, tx.tx, scope)
	if err != nil {
		return false, err
	}
	return tx.ConfigurationActorIsApprover(ctx, userID, ConfigurationActivation{Scope: scope, Approvers: approvers})
}
