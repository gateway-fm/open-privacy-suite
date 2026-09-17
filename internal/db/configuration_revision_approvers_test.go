package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func TestConfigurationApproversReferenceCurrentFullGroups(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	group := &rbac.Group{ID: uuid.NewString(), OrgID: scope.ID, Slug: "reviewers", Name: "Reviewers", IsOrgAdmin: true}
	require.NoError(t, d.CreateGroup(ctx, group))
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: reviewer.UserID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	spec := configuration.ApproversSpec{GroupIDs: []string{group.ID}, TrustedCI: []configuration.TrustedCI{}}
	doc := configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Approvers, Scope: scope, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: spec}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.NoError(t, err)
	view, err := d.GetConfigurationContext(ctx, scope, configuration.Approvers)
	require.NoError(t, err)
	require.Equal(t, spec, view.Source.Spec)
	spec.GroupIDs = []string{uuid.NewString()}
	doc.Spec = spec
	doc.BaseRevision = draft.Revision
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	invalid, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{invalid.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.ErrorContains(t, err, "full-admin group")
}
