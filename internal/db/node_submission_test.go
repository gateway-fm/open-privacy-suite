package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/nodepolicy"
)

func submissionFixture(user, org string) NodeSubmission {
	return NodeSubmission{Network: nodepolicy.Network{ChainID: 31337, DeploymentID: "submission-test"}, TransactionHash: "0x" + strings.Repeat("11", 32), PrincipalID: user, OrgID: org, Signer: "0x" + strings.Repeat("22", 20), ContextID: uuid.NewString(), RawTransaction: "0x01", IdentityEnvelope: []byte(`{"signed":"already verified by bridge"}`), SenderDID: "did:test:submitter", VisibleTo: []string{"did:test:recipient"}}
}

func TestNodeSubmissionPersistsIntentAndPreventsPrincipalRebinding(t *testing.T) {
	d := setupTestDB(t)
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	in := submissionFixture(user, org)
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	stored, err := d.GetNodeSubmission(ctx, in.Network, in.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, in.VisibleTo, stored.VisibleTo)
	require.Equal(t, "queued", stored.State)
	wrong := in
	wrong.PrincipalID = uuid.NewString()
	require.Error(t, d.SaveNodeSubmission(ctx, wrong))
	_, err = d.conn.ExecContext(ctx, `UPDATE node_submissions SET principal_id=$1 WHERE tx_hash=$2`, uuid.NewString(), in.TransactionHash)
	require.Error(t, err, "direct writer must not rebind a submitted transaction")
	wrong = in
	wrong.OrgID = uuid.NewString()
	require.Error(t, d.SaveNodeSubmission(ctx, wrong))
	wrong = in
	wrong.VisibleTo = []string{"did:test:someone-else"}
	require.Error(t, d.SaveNodeSubmission(ctx, wrong))
	pending, err := d.ListPendingNodeSubmissions(ctx, in.Network, 20)
	require.NoError(t, err)
	require.Len(t, pending, 1)
}

func TestNodeSubmissionRetainsTerminalEvidenceAfterOrganizationDeletion(t *testing.T) {
	d := setupTestDB(t)
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	in := submissionFixture(user, org)
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	_, err := d.conn.ExecContext(ctx, `DELETE FROM organizations WHERE id=$1`, org)
	require.NoError(t, err)
	block := "0x" + strings.Repeat("44", 32)
	number := uint64(12)
	outcome := nodepolicy.TransactionStatus{TransactionHash: in.TransactionHash, PrincipalID: user, OrgID: org, ContextID: in.ContextID, Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 7, BlockHash: &block, BlockNumber: &number, Created: []nodepolicy.CreatedContract{{Address: "0x" + strings.Repeat("55", 20), OrgID: org, PrincipalID: user}}}}
	outcome.Execution.Finalized, outcome.Execution.FinalizedBlockHash, outcome.Execution.FinalizedBlockNumber = true, &block, &number
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, outcome))
	stored, err := d.GetNodeSubmission(ctx, in.Network, in.TransactionHash)
	require.NoError(t, err)
	require.NotNil(t, stored.ReconciledAt)
	require.Equal(t, "organization_deleted", stored.ReconciliationNote)
}

func TestNodeSubmissionExpiryRemainsObservableUntilInflightExecutionSettles(t *testing.T) {
	d := setupTestDB(t)
	ctx := t.Context()
	user, org := cacheGenFixtures(t, d, ctx)
	in := submissionFixture(user, org)
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	expired := nodepolicy.TransactionStatus{TransactionHash: in.TransactionHash, PrincipalID: user, OrgID: org, ContextID: in.ContextID, Execution: nodepolicy.ExecutionOutcome{Status: "expired", FactsVersion: 7, Created: []nodepolicy.CreatedContract{}}}
	in.ContextID = uuid.NewString()
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	require.Error(t, d.RecordNodeOutcome(ctx, in.Network, expired))
	expired.ContextID = in.ContextID
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, expired))
	pending, err := d.ListPendingNodeSubmissions(ctx, in.Network, 20)
	require.NoError(t, err)
	require.Len(t, pending, 1, "a pre-expiry candidate may still become canonical")
	in.ContextID = uuid.NewString()
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	pending, err = d.ListPendingNodeSubmissions(ctx, in.Network, 20)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "queued", pending[0].State)
	require.Empty(t, pending[0].Outcome, "renewal must clear obsolete nonterminal outcome")
}

func TestNodeSubmissionReconcilesOnlyCanonicalCreationAtomically(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	// Activate an empty registry to exercise the managed INSERT exception.
	revision, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{revision.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.NoError(t, err)
	in := submissionFixture(author.UserID, scope.ID)
	require.NoError(t, d.SaveNodeSubmission(ctx, in))
	addr := "0x" + strings.Repeat("33", 20)
	block := "0x" + strings.Repeat("44", 32)
	number := uint64(12)
	outcome := nodepolicy.TransactionStatus{TransactionHash: in.TransactionHash, PrincipalID: in.PrincipalID, OrgID: in.OrgID, ContextID: in.ContextID, Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 7, BlockHash: &block, BlockNumber: &number, Created: []nodepolicy.CreatedContract{{Address: addr, OrgID: in.OrgID, PrincipalID: in.PrincipalID}}}}
	bad := outcome
	bad.Execution = outcome.Execution
	bad.Execution.Status = "pending"
	require.Error(t, d.RecordNodeOutcome(ctx, in.Network, bad))
	contract, err := d.GetContractByAddress(ctx, in.OrgID, addr)
	require.NoError(t, err)
	require.Nil(t, contract)
	// A receipt in today's canonical tip can disappear before finality. Keep
	// polling and expose inclusion, but do not create permanent OPS authority.
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, outcome))
	contract, err = d.GetContractByAddress(ctx, in.OrgID, addr)
	require.NoError(t, err)
	require.Nil(t, contract, "unfinalized CREATE must not materialize ownership")
	provisional, err := d.GetNodeSubmission(ctx, in.Network, in.TransactionHash)
	require.NoError(t, err)
	require.Nil(t, provisional.ReconciledAt)
	orphaned := outcome
	orphaned.Execution = nodepolicy.ExecutionOutcome{Status: "pending", FactsVersion: 7, Created: []nodepolicy.CreatedContract{}}
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, orphaned))
	provisional, err = d.GetNodeSubmission(ctx, in.Network, in.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "pending", provisional.State)
	outcome.Execution.Finalized = true
	outcome.Execution.FinalizedBlockHash = &block
	outcome.Execution.FinalizedBlockNumber = &number
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, outcome))
	require.NoError(t, d.RecordNodeOutcome(ctx, in.Network, outcome))
	contract, err = d.GetContractByAddress(ctx, in.OrgID, addr)
	require.NoError(t, err)
	require.NotNil(t, contract)
	require.Equal(t, in.PrincipalID, *contract.DeployedByUserID)
	pending, err := d.ListPendingNodeSubmissions(ctx, in.Network, 20)
	require.NoError(t, err)
	require.Empty(t, pending)
	var count int
	require.NoError(t, d.conn.QueryRowContext(ctx, `SELECT count(*) FROM pending_tx_visibility WHERE tx_hash=$1`, in.TransactionHash).Scan(&count))
	require.Equal(t, 1, count)
	stored, err := d.GetNodeSubmission(ctx, in.Network, in.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "included", stored.State)
	require.NotNil(t, stored.ReconciledAt)
	var got nodepolicy.TransactionStatus
	require.NoError(t, json.Unmarshal(stored.Outcome, &got))
	require.Equal(t, outcome, got)
	snapshot, err := d.ExportNodePolicySnapshot(ctx, in.Network, time.Now(), time.Minute)
	require.NoError(t, err)
	found := false
	for _, c := range snapshot.Contracts {
		if c.Address == addr && c.OrgID == in.OrgID {
			found = true
		}
	}
	require.True(t, found, "committed registration missing from node facts")
}
