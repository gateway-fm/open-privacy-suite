package db

import (
	"context"
	"time"

	"privacy-proxy/internal/configuration"
)

func validateConfigurationCI(ctx context.Context, q DBTX, view ConfigurationActivation, lock bool) error {
	proof := view.Actor.CIApproval
	if proof == nil {
		return nil
	}
	if view.Scope.Kind != "organization" || view.Actor.PrincipalKind != "service" || view.Approvers == nil {
		return ErrConfigurationForbidden
	}
	digests := map[configuration.Kind]string{}
	for _, candidate := range view.Candidates {
		digests[candidate.Kind] = candidate.Digest
	}
	if err := configuration.VerifyCIApproval(proof, *view.Approvers, view.Scope, view.Actor.ExternalID, digests, time.Now()); err != nil {
		return ConfigurationConflict("%s", err)
	}
	// Trusted external review does not mint new app privileges for the CI caller.
	var full bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN user_memberships m ON m.user_id=u.id JOIN groups g ON g.id=m.group_id WHERE u.id=$1 AND NOT u.banned AND g.org_id=$2 AND g.is_org_admin AND (m.expires_at IS NULL OR m.expires_at>NOW()))`, view.Actor.UserID, view.Scope.ID).Scan(&full); err != nil {
		return err
	}
	if !full {
		return ErrConfigurationForbidden
	}
	if view.GroupDiff != nil {
		for _, change := range view.GroupDiff.Changes {
			if change.RequiresPlatform {
				return ErrConfigurationForbidden
			}
		}
	}
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	for _, subject := range proof.ReviewerSubjects {
		var reviewer string
		if err := q.QueryRowContext(ctx, `SELECT id FROM users WHERE external_id=$1 AND NOT banned`+suffix, subject).Scan(&reviewer); err != nil {
			return ErrConfigurationForbidden
		}
		for _, candidate := range view.Candidates {
			if candidate.CreatedBy == reviewer {
				return ErrPolicySelfApproval
			}
		}
		var eligible bool
		if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_memberships m JOIN groups g ON g.id=m.group_id WHERE m.user_id=$1 AND g.org_id=$2 AND g.is_org_admin AND g.id=ANY($3::uuid[]) AND (m.expires_at IS NULL OR m.expires_at>NOW()))`, reviewer, view.Scope.ID, view.Approvers.GroupIDs).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return ErrConfigurationForbidden
		}
	}
	return nil
}
