package rbac

import (
	"context"
	"testing"
	"time"
)

// RD-1301: eth_getProof returns storageProof[].value for every requested key,
// so it is a raw storage read and must sit behind the same non-admin slot tier
// as eth_getStorageAt (RD-805).

const (
	rd1301Impl     = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	rd1301Diamond  = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"
	rd1301Ordinary = "0x1"
	rd1301Contract = "0xaaaa000000000000000000000000000000000001"
)

func TestExtractProofStorageKeys(t *testing.T) {
	tests := []struct {
		name   string
		params []any
		want   []string
		ok     bool
	}{
		{"one key", []any{rd1301Contract, []any{rd1301Impl}, "latest"}, []string{rd1301Impl}, true},
		{"several keys, order kept", []any{rd1301Contract, []any{rd1301Impl, rd1301Ordinary}}, []string{rd1301Impl, rd1301Ordinary}, true},
		{"zero keys is an account-only proof", []any{rd1301Contract, []any{}, "latest"}, []string{}, true},
		{"missing key list", []any{rd1301Contract}, nil, false},
		{"no params", []any{}, nil, false},
		{"nil params", nil, nil, false},
		{"null key list", []any{rd1301Contract, nil, "latest"}, nil, false},
		{"key list is a string", []any{rd1301Contract, rd1301Impl}, nil, false},
		{"key list is an object", []any{rd1301Contract, map[string]any{"0": rd1301Impl}}, nil, false},
		{"numeric key", []any{rd1301Contract, []any{float64(1)}}, nil, false},
		{"null key", []any{rd1301Contract, []any{nil}}, nil, false},
		{"nested list", []any{rd1301Contract, []any{[]any{rd1301Impl}}}, nil, false},
		{"one bad key poisons the list", []any{rd1301Contract, []any{rd1301Impl, true}}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractProofStorageKeys(tt.params)
			if ok != tt.ok {
				t.Fatalf("extractProofStorageKeys(%v) ok = %v, want %v", tt.params, ok, tt.ok)
			}
			if !ok {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("extractProofStorageKeys(%v) = %v, want %v", tt.params, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("extractProofStorageKeys(%v) = %v, want %v", tt.params, got, tt.want)
				}
			}
		})
	}
}

func TestValidateStorageReadAccess(t *testing.T) {
	c := &AccessController{}
	admin := &ContractAccess{Claims: []Claim{ClaimAdmin}}
	member := &ContractAccess{Claims: []Claim{}}
	deployOnly := &ContractAccess{Claims: []Claim{ClaimDeploy}}

	tests := []struct {
		name   string
		method string // raw method
		alias  string // AccessMethod (alias target); "" = none
		params []any
		access *ContractAccess
		denied bool
	}{
		// eth_getStorageAt keeps its RD-805 behaviour.
		{"storageAt member ordinary", "eth_getStorageAt", "", []any{rd1301Contract, rd1301Ordinary, "latest"}, member, true},
		{"storageAt member well-known", "eth_getStorageAt", "", []any{rd1301Contract, rd1301Impl, "latest"}, member, false},
		{"storageAt member missing slot", "eth_getStorageAt", "", []any{rd1301Contract}, member, true},
		{"storageAt admin ordinary", "eth_getStorageAt", "", []any{rd1301Contract, rd1301Ordinary, "latest"}, admin, false},

		// eth_getProof: every key must be a well-known slot for a non-admin.
		{"proof member ordinary", "eth_getProof", "", []any{rd1301Contract, []any{rd1301Ordinary}, "latest"}, member, true},
		{"proof member well-known", "eth_getProof", "", []any{rd1301Contract, []any{rd1301Impl, rd1301Diamond}, "latest"}, member, false},
		{"proof member zero keys", "eth_getProof", "", []any{rd1301Contract, []any{}, "latest"}, member, false},
		{"proof member mixed", "eth_getProof", "", []any{rd1301Contract, []any{rd1301Impl, rd1301Ordinary}, "latest"}, member, true},
		{"proof member malformed list", "eth_getProof", "", []any{rd1301Contract, rd1301Impl, "latest"}, member, true},
		{"proof member missing list", "eth_getProof", "", []any{rd1301Contract}, member, true},
		{"proof member empty-string key", "eth_getProof", "", []any{rd1301Contract, []any{""}}, member, true},
		{"proof deploy-claim ordinary", "eth_getProof", "", []any{rd1301Contract, []any{rd1301Ordinary}}, deployOnly, true},
		{"proof admin ordinary", "eth_getProof", "", []any{rd1301Contract, []any{rd1301Ordinary}, "latest"}, admin, false},

		// Aliases are judged by their access-control target.
		{"alias proof member ordinary", "linea_getProof", "eth_getProof", []any{rd1301Contract, []any{rd1301Ordinary}}, member, true},
		{"alias proof member well-known", "linea_getProof", "eth_getProof", []any{rd1301Contract, []any{rd1301Impl}}, member, false},
		{"alias storageAt member ordinary", "chain_getStorageAt", "eth_getStorageAt", []any{rd1301Contract, rd1301Ordinary}, member, true},

		// Methods that do not return raw storage are out of scope here.
		{"eth_call untouched", "eth_call", "", []any{map[string]any{"to": rd1301Contract}}, member, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AccessCheckRequest{Method: tt.method, AccessMethod: tt.alias, Params: tt.params, TargetAddress: rd1301Contract}
			res, handled := c.validateStorageReadAccess(req, tt.access)
			if handled != tt.denied {
				t.Fatalf("validateStorageReadAccess handled = %v, want denied = %v", handled, tt.denied)
			}
			if handled && (res == nil || res.Allowed || res.Reason != ErrContractAccessDenied) {
				t.Fatalf("denial must be the opaque contract-access denial, got %+v", res)
			}
		})
	}
}

// TestCheckAccess_AnonymousAliasHistoricalGuard pins that the anonymous
// historical-state guard is evaluated on the alias target: an operator who
// allowlists an alias of a state-reading method for anonymous callers must
// not open point-in-time reads through it.
func TestCheckAccess_AnonymousAliasHistoricalGuard(t *testing.T) {
	store := NewMockCrossOrgStore()
	store.groupAccess[AnonymousGroupID].AllowedMethods = append(store.groupAccess[AnonymousGroupID].AllowedMethods, "linea_getBalance")
	ac := NewAccessController(store, time.Minute)
	defer ac.Stop()

	req := func(block string) *AccessCheckRequest {
		return &AccessCheckRequest{
			Method:       "linea_getBalance",
			AccessMethod: "eth_getBalance",
			Params:       []any{rd1301Contract, block},
		}
	}

	res, err := ac.CheckAccess(context.Background(), req("latest"))
	if err != nil || !res.Allowed {
		t.Fatalf("precondition: the allowlisted alias at latest is allowed, got %+v err=%v", res, err)
	}
	res, err = ac.CheckAccess(context.Background(), req("0x10"))
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if res.Allowed {
		t.Fatalf("an anonymous alias of eth_getBalance at a block number must hit the historical-state guard")
	}
}

// TestCheckAccess_AuthenticatedAliasHistoricalGuard is the authenticated twin:
// a non-org-admin reading through an alias at a block number is denied just as
// the target method would be.
func TestCheckAccess_AuthenticatedAliasHistoricalGuard(t *testing.T) {
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)
	perms := store.cachedPermissions["user-a:org-a"]
	perms.AllowedMethods = append(perms.AllowedMethods, "eth_getProof", "linea_getProof")
	ac := NewAccessController(&orgAdminCheckingStore{MockCrossOrgStore: store}, time.Minute)
	defer ac.Stop()

	for _, tc := range []struct {
		method, alias string
	}{
		{"eth_getProof", ""},
		{"linea_getProof", "eth_getProof"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
				UserExternalID: "did:test:user-a",
				Method:         tc.method,
				AccessMethod:   tc.alias,
				Params:         []any{rd1301Contract, []any{rd1301Impl}, "0x10"},
				TargetAddress:  rd1301Contract,
			})
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			if res.Allowed {
				t.Fatalf("%s at a block number must be denied for a non-org-admin", tc.method)
			}
		})
	}
}

// orgAdminCheckingStore adds the production OrgAdminChecker extension (no user
// is an org admin) so the historical guard is live in the mock-store tests.
type orgAdminCheckingStore struct {
	*MockCrossOrgStore
}

func (s *orgAdminCheckingStore) IsOrgAdmin(ctx context.Context, userID string) (bool, []string, error) {
	return false, nil, nil
}
