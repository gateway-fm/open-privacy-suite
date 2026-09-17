package db

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

func TestConfigurationCIRequiresIndependentCurrentTrustedApproval(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	group := &rbac.Group{ID: uuid.NewString(), OrgID: scope.ID, Slug: "full", Name: "Full", IsOrgAdmin: true}
	require.NoError(t, d.CreateGroup(ctx, group))
	_, err := d.conn.ExecContext(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims)VALUES($1,$2,$3,$4)`, uuid.NewString(), group.ID, []string{"eth_call"}, []string{})
	require.NoError(t, err)
	for _, id := range []string{author.UserID, reviewer.UserID} {
		require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: id, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	trust := configuration.TrustedCI{ID: uuid.NewString(), Issuer: "external-review", Audience: "ops", Subject: author.ExternalID, Repository: "customer/ops", Ref: "refs/heads/main", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	policy := configuration.ApproversSpec{GroupIDs: []string{group.ID}, TrustedCI: []configuration.TrustedCI{trust}}
	raw, err := json.Marshal(configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Approvers, Scope: scope, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: policy})
	require.NoError(t, err)
	draft, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
	ordinary := proposedGroup()
	candidate, err := d.SubmitConfigurationRevision(ctx, configurationSource(t, scope, 0, []configuration.Group{ordinary}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{candidate.ID}, author, allow)
	require.ErrorIs(t, err, ErrPolicySelfApproval)
	now := time.Now()
	approval := &configuration.CIApproval{Version: "ops.configuration-approval/v1", TrustID: trust.ID, Issuer: trust.Issuer, Audience: trust.Audience, Subject: trust.Subject, Repository: trust.Repository, Ref: trust.Ref, Commit: strings.Repeat("a", 40), Scope: scope, CandidateDigests: map[configuration.Kind]string{configuration.Groups: candidate.Digest}, ReviewerSubjects: []string{reviewer.ExternalID}, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Nonce: uuid.NewString()}
	signing, err := approval.SigningBytes()
	require.NoError(t, err)
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, signing))
	author.PrincipalKind = "service"
	author.CIApproval = approval
	bad := *approval
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	author.CIApproval = &bad
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{candidate.ID}, author, allow)
	require.Error(t, err)
	author.CIApproval = approval
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{candidate.ID}, author, allow)
	require.NoError(t, err)
	var recorded string
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT new_value::jsonb->'ciApproval'->>'commit' FROM rbac_audit_log WHERE resource_id=$1`, candidate.ID).Scan(&recorded))
	require.Equal(t, approval.Commit, recorded)
	// A correct signature never overrides current revocation.
	next, err := d.GetConfigurationContext(ctx, scope, configuration.Groups)
	require.NoError(t, err)
	raw, err = json.Marshal(next.Source)
	require.NoError(t, err)
	second, err := d.SubmitConfigurationRevision(ctx, raw, author)
	require.NoError(t, err)
	approval.CandidateDigests[configuration.Groups] = second.Digest
	signing, err = approval.SigningBytes()
	require.NoError(t, err)
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, signing))
	_, err = d.conn.ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, reviewer.UserID)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{second.ID}, author, allow)
	require.Error(t, err)
}
