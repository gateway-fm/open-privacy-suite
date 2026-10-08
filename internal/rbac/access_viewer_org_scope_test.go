package rbac

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/viewscope"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAccess_ViewerOrgScopeIncludesDeployerAccess_RD1308(t *testing.T) {
	const target = "0x13080000000000000000000000000000000000d1"
	store := NewMockCrossOrgStore()
	user := &User{ID: "viewer", ExternalID: "did:test:scoped_deployer", KYC: true}
	store.users[user.ExternalID] = user
	methods := []string{MethodCall, MethodGetCode, MethodGetBalance}
	for _, orgID := range []string{"org-o", "org-p"} {
		store.organizations[orgID] = &Organization{ID: orgID, Slug: orgID, Name: orgID}
		group := &Group{ID: "group-" + orgID, OrgID: orgID}
		store.memberships[user.ID] = append(store.memberships[user.ID], &MembershipWithDetails{
			Membership: &UserMembership{UserID: user.ID, GroupID: group.ID}, Group: group,
		})
		store.cachedPermissions[user.ID+":"+orgID] = &EffectivePermissions{
			UserID: user.ID, OrgID: orgID, AllowedMethods: methods,
			ContractAccess: map[string]ContractAccess{}, ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	store.contractOwners[target] = "org-p"
	store.contractDeployers[target] = &user.ID
	controller := NewAccessController(store, time.Minute)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			params := []any{target, "latest"}
			if method == MethodCall {
				params = []any{map[string]any{"to": target, "data": "0x"}, "latest"}
			}
			for _, tc := range []struct {
				name, orgID, scope string
				scoped, allowed    bool
			}{
				{name: "direct multi-org session", orgID: "org-o", allowed: true},
				{name: "named owner org", orgID: "org-p", scope: "org-p", scoped: true, allowed: true},
				{name: "another named org", orgID: "org-o", scope: "org-o", scoped: true},
				{name: "empty scope", orgID: "org-o", scoped: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()
					if tc.scoped {
						ctx = viewscope.WithOrg(ctx, tc.scope)
					}
					result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
						UserExternalID: user.ExternalID, OrgID: tc.orgID, Method: method,
						Params: params, TargetAddress: target,
					})
					require.NoError(t, err)
					require.NotNil(t, result)
					assert.Equal(t, tc.allowed, result.Allowed)
				})
			}
		})
	}
}
