package server

import (
	"context"
	"net/http"
	"testing"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedOrgMemberWithMethods creates an org, a group with the given method
// allowlist, and a KYC'd member. Returns (orgID, externalID).
func seedOrgMemberWithMethods(t *testing.T, ctx context.Context, database *db.DB, allowedMethods []string) (string, string) {
	t.Helper()
	orgID := uuid.New().String()
	groupID := uuid.New().String()
	userID := uuid.New().String()
	did := "did:test:attr-" + uuid.New().String()

	must := func(err error) {
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	must(database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "attr-" + orgID[:8], Name: "Attribution Org"}))
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, depth, is_org_admin) VALUES ($1,$2,$3,$4,$5,0,false)`,
		groupID, orgID, "g-"+groupID[:8], "Attribution Grp", "g-"+groupID[:8])
	must(err)
	must(database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID,
		Claims:         []rbac.Claim{},
		AllowedMethods: allowedMethods,
	}))
	// KYC must be true — a non-KYC user is denied before org resolution.
	must(database.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	must(database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return orgID, did
}

// TestProcess_MethodDenialLogsCallerOrg is the RD-1199 end-to-end regression:
// a method_not_allowed denial by an authenticated org member must reach the
// access-log writer with the caller's org, so the tier-2 per-org audit view
// (RD-1135) shows the org its own members' RBAC denials. Before the fix,
// CheckAccess deny results carried no OrgID, the processor stamped
// resolvedOrgID="", and the row was written with NULL org_id —
// super-admin-only.
func TestProcess_MethodDenialLogsCallerOrg(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	ctx := context.Background()

	// Group allows only eth_call; the request uses eth_getBalance.
	orgID, did := seedOrgMemberWithMethods(t, ctx, ts.db, []string{"eth_call"})

	cl := &captureEnhancedLogger{}
	proc.enhancedLogger = cl
	proc.hashChain = audit.NewHashChain("")

	res := proc.Process(ctx, &ProcessRequest{
		UserID:   did,
		Method:   "eth_getBalance",
		Params:   []any{"0x00000000000000000000000000000000000000aa", "latest"},
		ClientIP: "203.0.113.9",
	})

	require.NotNil(t, res.Error, "expected an RBAC denial")
	assert.Equal(t, http.StatusNotFound, res.Error.StatusCode, "RBAC denials are masked as 404 method-not-found to the client")
	require.True(t, cl.calledChained, "denial must be access-logged via the chained writer")
	assert.Equal(t, orgID, cl.gotOrgID, "denial row must carry the caller's org — NULL org_id hides it from the tier-2 per-org audit view")
	assert.Equal(t, ReasonMethodNotAllowed, cl.gotDenialReason)
}
