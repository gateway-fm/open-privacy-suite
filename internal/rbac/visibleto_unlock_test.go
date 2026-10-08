package rbac

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// unlockStore is a Store double for the visibleTo-unlock eligibility helper.
// It serves fixed contracts, one user, memberships per org and grants per
// group, can fail any single lookup, and counts the calls that matter for the
// per-request cost.
type unlockStore struct {
	fakeStore
	contracts   map[string]*Contract // lowercase address → contract
	user        *User
	memberships map[string][]*MembershipWithDetails // org ID → memberships
	grants      map[string][]*ContractGrant         // group ID → grants
	failOn      string

	contractCalls, userCalls, membershipCalls, grantCalls int
}

var errUnlockStore = errors.New("store unavailable")

// Each failing lookup still returns its populated value alongside the error,
// so a caller that ignored the error would be caught by the fail-closed tests.
func (s *unlockStore) GetContractByAddressGlobal(_ context.Context, addr string) (*Contract, error) {
	s.contractCalls++
	if s.failOn == "contract" {
		return s.contracts[addr], errUnlockStore
	}
	return s.contracts[addr], nil
}

func (s *unlockStore) GetUserByExternalID(_ context.Context, _ string) (*User, error) {
	s.userCalls++
	if s.failOn == "user" {
		return s.user, errUnlockStore
	}
	return s.user, nil
}

func (s *unlockStore) ListUserMembershipsInOrg(_ context.Context, _, orgID string) ([]*MembershipWithDetails, error) {
	s.membershipCalls++
	if s.failOn == "memberships" {
		return s.memberships[orgID], errUnlockStore
	}
	return s.memberships[orgID], nil
}

func (s *unlockStore) ListContractGrantsBatch(_ context.Context, groupIDs []string) (map[string][]*ContractGrant, error) {
	s.grantCalls++
	out := map[string][]*ContractGrant{}
	for _, g := range groupIDs {
		out[g] = s.grants[g]
	}
	if s.failOn == "grants" {
		return out, errUnlockStore
	}
	return out, nil
}

func membership(g *Group) *MembershipWithDetails {
	return &MembershipWithDetails{Membership: &UserMembership{ID: "m-" + g.ID, GroupID: g.ID}, Group: g}
}

// TestUnlockableContracts_EligibilityBoundary pins the eligibility boundary of
// REDACTION_SPEC §3.7.1 (RD-874, RD-1306) on the single helper both layers use.
func TestUnlockableContracts_EligibilityBoundary(t *testing.T) {
	const (
		orgA = "org-a"
		orgB = "org-b"
		// contracts in org A
		flaggedRegular = "0xa000000000000000000000000000000000000001" // flag on, regular grant
		flaggedDefault = "0xa000000000000000000000000000000000000002" // flag on, grant only via default group
		flaggedSystem  = "0xa000000000000000000000000000000000000003" // flag on, grant only via a system group
		flaggedForeign = "0xa000000000000000000000000000000000000004" // flag on, grant held by an org-B group
		notFlagged     = "0xa000000000000000000000000000000000000005" // flag off, regular grant
		unregistered   = "0xa000000000000000000000000000000000000006"
		// contract in org B, where the viewer is org admin
		flaggedAdmin = "0xb000000000000000000000000000000000000001"
	)
	regular := &Group{ID: "g-regular", OrgID: orgA}
	deflt := &Group{ID: DefaultGroupID, OrgID: orgA}
	system := &Group{ID: "g-system", OrgID: orgA, IsSystem: true}
	foreign := &Group{ID: "g-foreign", OrgID: orgB}
	admins := &Group{ID: "g-admins", OrgID: orgB, IsOrgAdmin: true}
	c := func(id, org string, flag bool) *Contract {
		return &Contract{ID: id, OrgID: org, AllowVisibleToUnlock: flag}
	}
	newStore := func() *unlockStore {
		return &unlockStore{
			contracts: map[string]*Contract{
				flaggedRegular: c("c-regular", orgA, true),
				flaggedDefault: c("c-default", orgA, true),
				flaggedSystem:  c("c-system", orgA, true),
				flaggedForeign: c("c-foreign", orgA, true),
				notFlagged:     c("c-off", orgA, false),
				flaggedAdmin:   c("c-admin", orgB, true),
			},
			user: &User{ID: "u-1", ExternalID: "did:test:viewer"},
			memberships: map[string][]*MembershipWithDetails{
				// The foreign group is returned for org A to prove the per-group
				// org check, even though the SQL already scopes by org.
				orgA: {membership(regular), membership(deflt), membership(system), membership(foreign)},
				orgB: {membership(admins)},
			},
			grants: map[string][]*ContractGrant{
				regular.ID: {{ContractID: "c-regular"}, {ContractID: "c-off"}},
				deflt.ID:   {{ContractID: "c-default"}},
				system.ID:  {{ContractID: "c-system"}},
				foreign.ID: {{ContractID: "c-foreign"}},
			},
		}
	}
	all := []string{flaggedRegular, flaggedDefault, flaggedSystem, flaggedForeign, notFlagged, unregistered, flaggedAdmin, "0xA000000000000000000000000000000000000001", ""}

	t.Run("boundary", func(t *testing.T) {
		store := newStore()
		got := UnlockableContracts(context.Background(), NewAccessController(store, 0), "did:test:viewer", all)
		want := map[string]bool{flaggedRegular: true, flaggedAdmin: true}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("UnlockableContracts = %v, want %v", got, want)
		}
		if store.contractCalls != 7 || store.userCalls != 1 || store.membershipCalls != 2 || store.grantCalls != 1 {
			t.Fatalf("per-request cost: contracts=%d user=%d memberships=%d grants=%d, want 7 (one per unique non-empty address)/1/2 (one per owner org)/1 (org admin needs none)",
				store.contractCalls, store.userCalls, store.membershipCalls, store.grantCalls)
		}
	})

	t.Run("IsViewerEligible agrees and ignores the flag", func(t *testing.T) {
		access := NewAccessController(newStore(), 0)
		for addr, want := range map[string]bool{
			flaggedRegular: true, flaggedAdmin: true, notFlagged: true,
			flaggedDefault: false, flaggedSystem: false, flaggedForeign: false, unregistered: false,
		} {
			if got := IsViewerEligibleForVisibleToUnlock(context.Background(), access, "did:test:viewer", addr); got != want {
				t.Errorf("IsViewerEligibleForVisibleToUnlock(%s) = %v, want %v", addr, got, want)
			}
		}
	})

	t.Run("no flagged contract costs no user lookup", func(t *testing.T) {
		store := newStore()
		if got := UnlockableContracts(context.Background(), NewAccessController(store, 0), "did:test:viewer", []string{notFlagged, unregistered}); len(got) != 0 {
			t.Fatalf("got %v, want none", got)
		}
		if store.userCalls != 0 {
			t.Fatalf("user looked up %d times without any flagged contract", store.userCalls)
		}
	})

	t.Run("fail closed", func(t *testing.T) {
		for _, fail := range []string{"contract", "user", "memberships", "grants"} {
			store := newStore()
			store.failOn = fail
			got := UnlockableContracts(context.Background(), NewAccessController(store, 0), "did:test:viewer", []string{flaggedRegular, flaggedAdmin})
			want := map[string]bool{}
			if fail == "grants" {
				// The org-admin path needs no grant lookup; only the grant-based
				// contract is lost.
				want[flaggedAdmin] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s lookup error: got %v, want %v", fail, got, want)
			}
			if fail == "memberships" && store.grantCalls != 0 {
				t.Errorf("a membership lookup error must stop before the grant lookup, got %d grant calls", store.grantCalls)
			}
			if IsViewerEligibleForVisibleToUnlock(context.Background(), NewAccessController(store, 0), "did:test:viewer", flaggedRegular) {
				t.Errorf("%s lookup error must deny IsViewerEligibleForVisibleToUnlock", fail)
			}
		}
		store := newStore()
		store.user = nil
		if got := UnlockableContracts(context.Background(), NewAccessController(store, 0), "did:test:viewer", []string{flaggedRegular, flaggedAdmin}); len(got) != 0 {
			t.Errorf("unknown viewer (no users row) must deny, got %v", got)
		}
		if got := UnlockableContracts(context.Background(), NewAccessController(newStore(), 0), "", []string{flaggedRegular}); len(got) != 0 {
			t.Errorf("anonymous viewer must deny, got %v", got)
		}
		if got := UnlockableContracts(context.Background(), nil, "did:test:viewer", []string{flaggedRegular}); len(got) != 0 {
			t.Errorf("nil access controller must deny, got %v", got)
		}
	})
}
