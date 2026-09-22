package db

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

// A deployment is a chain fact. Once reviewed documents own an organisation's
// contract registry and execution rules, the projection guard refuses the
// legacy path's plain inserts — and the legacy plain-CREATE finalizer used to
// do exactly that, logging a warning and losing the registration. Registration
// must go through the same authorised transaction the Reth reconciler uses, so
// the contract and its deployer grant are admitted as drift for the next
// revision to adopt.
func TestRegisterDeployedContractIsAdmittedAsDriftUnderManagedStreams(t *testing.T) {
	d, scope, author, reviewer, _ := configurationFixture(t)
	ctx := t.Context()
	allow := func(context.Context, *Tx, ConfigurationActivation) error { return nil }

	// A deploy group and a deployer who is a current member of it.
	group := &rbac.Group{ID: uuid.NewString(), OrgID: scope.ID, Slug: "deployers-" + uuid.NewString(), Name: "Deployers", Path: "deployers"}
	require.NoError(t, d.CreateGroup(ctx, group))
	_, err := d.Conn().ExecContext(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,$3,$4)`, uuid.NewString(), group.ID, []string{"eth_sendRawTransaction"}, []string{"deploy"})
	require.NoError(t, err)
	deployer := &rbac.User{ID: uuid.NewString(), ExternalID: "did:test:deployer-" + uuid.NewString()}
	require.NoError(t, d.CreateUser(ctx, deployer))
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: deployer.ID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	bystander := &rbac.User{ID: uuid.NewString(), ExternalID: "did:test:bystander-" + uuid.NewString()}
	require.NoError(t, d.CreateUser(ctx, bystander))

	// The contract registry becomes managed through the real activation path.
	draft, err := d.SubmitConfigurationRevision(ctx, registrySource(t, scope, 0, []configuration.Contract{}, map[configuration.Kind]string{}, []configuration.Deletion{}), author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, scope, []string{draft.ID}, reviewer, allow)
	require.NoError(t, err)
	// The guard consults configuration_revisions only, so an active
	// execution-rules row is enough to arm the contract_grants guard without
	// compiling a policy here.
	_, err = d.Conn().ExecContext(ctx, `INSERT INTO configuration_revisions(scope_kind,org_id,kind,revision,base_revision,source,digest,dependencies,status,created_by,created_principal_kind,activated_by,activated_at)
		VALUES('organization',$1,'execution-rules',1,0,'{}',$2,'{}','active',$3,'human',$4,NOW())`, scope.ID, "sha256:"+strings.Repeat("0", 64), author.UserID, reviewer.UserID)
	require.NoError(t, err)

	// Both legacy inserts are refused on their own.
	direct := &rbac.Contract{ID: uuid.NewString(), OrgID: scope.ID, Address: "0x" + strings.Repeat("a", 40), Name: "direct"}
	require.ErrorContains(t, d.CreateContract(ctx, direct), "configuration revision")
	activeContract := activeRegistryContract(t, d, scope.ID)
	require.ErrorContains(t, d.GrantContractToDeployerGroup(ctx, scope.ID, activeContract, deployer.ID), "configuration revision")

	// The registration path is admitted: contract and grant together.
	contract := &rbac.Contract{ID: uuid.NewString(), OrgID: scope.ID, Address: "0x" + strings.Repeat("b", 40), Name: "deployed", Metadata: map[string]any{"auto_registered": true, "via": "plain_create"}}
	granted, err := d.RegisterDeployedContract(ctx, contract, deployer.ID)
	require.NoError(t, err)
	require.True(t, granted)
	stored, err := d.GetContract(ctx, contract.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	grants, err := d.ListContractGrantsByContract(ctx, contract.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, group.ID, grants[0].GroupID)

	// A deployer without a current deploy-claim membership still gets the
	// contract registered, and honestly no grant.
	other := &rbac.Contract{ID: uuid.NewString(), OrgID: scope.ID, Address: "0x" + strings.Repeat("c", 40), Name: "no-grant"}
	granted, err = d.RegisterDeployedContract(ctx, other, bystander.ID)
	require.NoError(t, err)
	require.False(t, granted)
	grants, err = d.ListContractGrantsByContract(ctx, other.ID)
	require.NoError(t, err)
	require.Empty(t, grants)

	// A banned deployer gets the contract registered and no grant, as on the
	// Reth path.
	banned := &rbac.User{ID: uuid.NewString(), ExternalID: "did:test:banned-" + uuid.NewString()}
	require.NoError(t, d.CreateUser(ctx, banned))
	require.NoError(t, d.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: banned.ID, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}))
	_, err = d.Conn().ExecContext(ctx, `UPDATE users SET banned=true WHERE id=$1`, banned.ID)
	require.NoError(t, err)
	bannedContract := &rbac.Contract{ID: uuid.NewString(), OrgID: scope.ID, Address: "0x" + strings.Repeat("e", 40), Name: "banned-deployer"}
	granted, err = d.RegisterDeployedContract(ctx, bannedContract, banned.ID)
	require.NoError(t, err)
	require.False(t, granted)

	// A deployer whose account was deleted before finalization: the chain fact
	// is kept without attribution instead of failing on the foreign key.
	goneContract := &rbac.Contract{ID: uuid.NewString(), OrgID: scope.ID, Address: "0x" + strings.Repeat("f", 40), Name: "gone-deployer"}
	gone := uuid.NewString()
	goneContract.DeployedByUserID = &gone
	granted, err = d.RegisterDeployedContract(ctx, goneContract, gone)
	require.NoError(t, err)
	require.False(t, granted)
	stored, err = d.GetContract(ctx, goneContract.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Nil(t, stored.DeployedByUserID)

	// The marker admits inserts only: the registered rows are ordinary managed
	// rows afterwards, so a legacy UPDATE is still refused.
	_, err = d.Conn().ExecContext(ctx, `UPDATE contracts SET name='renamed' WHERE id=$1`, contract.ID)
	require.ErrorContains(t, err, "configuration revision")
}

// activeRegistryContract registers a contract through the authorised path so
// the test has a managed contract row to aim a legacy grant at.
func activeRegistryContract(t *testing.T, d *DB, orgID string) string {
	t.Helper()
	contract := &rbac.Contract{ID: uuid.NewString(), OrgID: orgID, Address: "0x" + strings.Repeat("d", 40), Name: "target"}
	_, err := d.RegisterDeployedContract(t.Context(), contract, "")
	require.NoError(t, err)
	return contract.ID
}
