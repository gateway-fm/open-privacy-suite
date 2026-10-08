package rbac

import (
	"context"
	"testing"
	"time"
)

// RD-1305 — CheckAccess must deny any eth_call / eth_estimateGas that carries a
// state/code or block override, for every caller including admins, even when
// the caller otherwise has full access to the target contract. This is the
// defence-in-depth choke point covering the dry-run and test-request paths.
func TestCheckAccess_StateOverrideDenied(t *testing.T) {
	const contractAddr = "0xaaaa000000000000000000000000000000000001"
	ctx := context.Background()

	// setup builds a store where the user in org-a has an explicit grant on
	// contractAddr (owned by org-a), so a plain eth_call is allowed.
	setup := func(claims []Claim) *AccessController {
		store := NewMockCrossOrgStore()
		store.organizations["org-a"] = &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
		store.users["did:test:user"] = &User{ID: "test-user", ExternalID: "did:test:user", KYC: true}
		groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
		store.memberships["test-user"] = []*MembershipWithDetails{
			{Membership: &UserMembership{ID: "m1", UserID: "test-user", GroupID: "group-a"}, Group: groupA},
		}
		methods := []string{"eth_call", "eth_estimateGas"}
		store.groupAccess["group-a"] = &GroupAccess{ID: "ga-a", GroupID: "group-a", Claims: claims, AllowedMethods: methods}
		store.contractOwners[contractAddr] = "org-a"
		store.registeredToAnyOrg[contractAddr] = true
		store.addressOwnedByOrg[contractAddr] = map[string]bool{"org-a": true}
		store.cachedPermissions["test-user:org-a"] = &EffectivePermissions{
			ID: "perms", UserID: "test-user", OrgID: "org-a",
			AllowedMethods: methods,
			ContractAccess: map[string]ContractAccess{contractAddr: {Claims: claims}},
			Claims:         claims,
			ComputedAt:     time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		}
		return NewAccessController(store, 5*time.Minute)
	}

	nonEmpty := map[string]any{contractAddr: map[string]any{"code": "0x00"}}
	txObj := map[string]any{"to": contractAddr, "data": "0x"}

	t.Run("baseline: non-admin eth_call without override is allowed", func(t *testing.T) {
		ctrl := setup([]Claim{})
		res, err := ctrl.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user", OrgID: "org-a",
			Method: "eth_call", Params: []any{txObj, "latest"}, TargetAddress: contractAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("plain eth_call should be allowed; reason=%q", res.Reason)
		}
	})

	cases := []struct {
		name   string
		claims []Claim
		method string
		params []any
	}{
		{"non-admin state override", []Claim{}, "eth_call", []any{txObj, "latest", nonEmpty}},
		{"admin state override (admins not exempt)", []Claim{ClaimAdmin}, "eth_call", []any{txObj, "latest", nonEmpty}},
		{"estimateGas state override", []Claim{}, "eth_estimateGas", []any{txObj, "latest", nonEmpty}},
		{"block override", []Claim{}, "eth_call", []any{txObj, "latest", nil, map[string]any{"number": "0x1"}}},
		{"malformed override fails closed", []Claim{}, "eth_call", []any{txObj, "latest", "0xdeadbeef"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := setup(tc.claims)
			res, err := ctrl.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: "did:test:user", OrgID: "org-a",
				Method: tc.method, Params: tc.params, TargetAddress: contractAddr,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Allowed {
				t.Fatalf("%s: override must be denied", tc.name)
			}
			// Denied BY the override gate, not by some other check — the shared
			// constant is what the dry-run audit mapping keys on.
			if res.Reason != StateOverrideDeniedReason {
				t.Fatalf("%s: reason = %q, want %q", tc.name, res.Reason, StateOverrideDeniedReason)
			}
		})
	}
}

func TestCheckAccess_StateOverrideRequestMethods(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	if err := RegisterExtraNamespaces(
		map[string][]string{"Example": {"example_call", "example_estimateGas", "example_createAccessList"}},
		map[string]string{"example_call": "eth_call", "example_estimateGas": "eth_estimateGas", "example_createAccessList": "eth_createAccessList"},
		nil,
	); err != nil {
		t.Fatalf("register operator methods: %v", err)
	}
	ctrl := NewAccessController(NewMockCrossOrgStore(), time.Minute)
	defer ctrl.Stop()
	for _, tc := range []struct {
		name, method, accessMethod string
	}{
		{"raw call", "eth_call", "eth_getBalance"},
		{"raw estimation", "eth_estimateGas", "eth_getBalance"},
		{"raw access list", "eth_createAccessList", "eth_getBalance"},
		{"operator call", "example_call", "eth_call"},
		{"operator estimation", "example_estimateGas", "eth_estimateGas"},
		{"operator access list", "example_createAccessList", "eth_createAccessList"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ctrl.CheckAccess(context.Background(), &AccessCheckRequest{
				Method: tc.method, AccessMethod: tc.accessMethod,
				Params: []any{tx(), "latest", nonEmptyOverride()},
			})
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			if res.Allowed || res.Reason != StateOverrideDeniedReason {
				t.Fatalf("simulation options must use the shared denial, got %+v", res)
			}
		})
	}
}
