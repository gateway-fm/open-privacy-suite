package db

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/policydsl"
	"privacy-proxy/internal/rbac"
)

func policyActivationFixture(t *testing.T) (*DB, string, string, string, *policydsl.Artifact) {
	t.Helper()
	database := setupTestDB(t)
	t.Cleanup(func() { _ = database.Close() })
	org := &rbac.Organization{ID: uuid.NewString(), Slug: "policy-" + uuid.NewString(), Name: "Policy activation"}
	require.NoError(t, database.CreateOrganization(t.Context(), org))
	actors := []string{uuid.NewString(), uuid.NewString()}
	for _, id := range actors {
		require.NoError(t, database.CreateUser(t.Context(), &rbac.User{ID: id, ExternalID: "did:test:" + id}))
	}
	return database, org.ID, actors[0], actors[1], &policydsl.Artifact{
		PolicyDigest: "policy", Source: "contract Policy {}", SourceDigest: "source", RuntimeBytecode: []byte{0}, RuntimeDigest: "runtime",
	}
}

func TestExecutionPolicyActivationRequiresDistinctActors(t *testing.T) {
	d, org, author, reviewer, artifact := policyActivationFixture(t)
	ctx := t.Context()
	t.Run("submission requires actor", func(t *testing.T) {
		_, err := d.CreateExecutionPolicyRevision(ctx, org, 0, "{}", artifact, nil)
		require.ErrorContains(t, err, "actor")
	})
	draft, err := d.CreateExecutionPolicyRevision(ctx, org, 0, "{}", artifact, &author)
	require.NoError(t, err)
	blank, sameUppercase := " ", strings.ToUpper(author)
	for _, tc := range []struct {
		name  string
		actor *string
	}{
		{"missing activator", nil}, {"blank activator", &blank}, {"same actor", &author}, {"same UUID with different case", &sameUppercase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.ActivateExecutionPolicyRevision(ctx, org, draft.ID, tc.actor)
			require.Error(t, err)
			active, err := d.GetActiveExecutionPolicy(ctx, org)
			require.NoError(t, err)
			require.Nil(t, active, "a refused activation must not change active state")
		})
	}
	active, err := d.ActivateExecutionPolicyRevision(ctx, org, draft.ID, &reviewer)
	require.NoError(t, err)
	require.Equal(t, author, *active.CreatedBy)
	require.Equal(t, reviewer, *active.ActivatedBy)
}

func TestExecutionPolicyActivationLegacyProvenanceFailsClosed(t *testing.T) {
	d, org, author, reviewer, artifact := policyActivationFixture(t)
	ctx := t.Context()
	for _, column := range []string{"base_revision", "created_by"} {
		t.Run(column, func(t *testing.T) {
			draft, err := d.CreateExecutionPolicyRevision(ctx, org, 0, "legacy", artifact, &author)
			require.NoError(t, err)
			// Model a pre-072 draft or an author deleted through the existing
			// ON DELETE SET NULL foreign key. No unverifiable legacy approval
			// may be silently grandfathered into the active policy.
			_, err = d.Conn().ExecContext(ctx, "UPDATE execution_policy_revisions SET "+column+" = NULL WHERE id = $1", draft.ID)
			require.NoError(t, err)
			_, err = d.ActivateExecutionPolicyRevision(ctx, org, draft.ID, &reviewer)
			require.Error(t, err)
			active, err := d.GetActiveExecutionPolicy(ctx, org)
			require.NoError(t, err)
			require.Nil(t, active)
		})
	}
}

func TestExecutionPolicyActivationRejectsStaleConcurrentDrafts(t *testing.T) {
	d, org, author, reviewer, artifact := policyActivationFixture(t)
	ctx := t.Context()
	first, err := d.CreateExecutionPolicyRevision(ctx, org, 0, "first", artifact, &author)
	require.NoError(t, err)
	second, err := d.CreateExecutionPolicyRevision(ctx, org, 0, "second", artifact, &author)
	require.NoError(t, err, "draft creation must not advance the active base")
	require.Equal(t, first.Revision+1, second.Revision)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{first.ID, second.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := d.ActivateExecutionPolicyRevision(context.Background(), org, id, &reviewer)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	succeeded, stale := 0, 0
	for err := range errs {
		if err == nil {
			succeeded++
		} else {
			require.ErrorIs(t, err, ErrPolicyStaleBase)
			stale++
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, stale)
	active, err := d.GetActiveExecutionPolicy(ctx, org)
	require.NoError(t, err)
	require.NotNil(t, active)
	_, err = d.CreateExecutionPolicyRevision(ctx, org, 0, "stale", artifact, &author)
	require.ErrorIs(t, err, ErrPolicyStaleBase)
}
