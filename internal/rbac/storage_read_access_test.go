package rbac

import (
	"cmp"
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
		{"mixed string and non-string keys", []any{rd1301Contract, []any{rd1301Impl, true}}, nil, false},
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

// registerStorageReadAliases prepares the same exact alias registry used at
// startup, and restores it after the test.
func registerStorageReadAliases(t *testing.T, aliases map[string]string) {
	t.Helper()
	t.Cleanup(SnapshotMethodRegistriesForTest())
	names := make([]string, 0, len(aliases))
	for method := range aliases {
		names = append(names, method)
	}
	if err := RegisterExtraNamespaces(map[string][]string{"Storage": names}, aliases, nil); err != nil {
		t.Fatalf("register test aliases: %v", err)
	}
}

// Anonymous aliases at latest require authentication; historical requests
// retain the state restriction for both the alias and the built-in method.
func TestCheckAccess_AnonymousAliasHistoricalGuard(t *testing.T) {
	registerStorageReadAliases(t, map[string]string{"linea_getBalance": MethodGetBalance})
	store := NewMockCrossOrgStore()
	store.groupAccess[AnonymousGroupID].AllowedMethods = append(store.groupAccess[AnonymousGroupID].AllowedMethods, "linea_getBalance", MethodGetBalance)
	ac := NewAccessController(store, time.Minute)
	defer ac.Stop()

	check := func(method, alias, block string) *AccessCheckResult {
		res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
			Method: method, AccessMethod: alias, Params: []any{rd1301Contract, block},
		})
		if err != nil {
			t.Fatalf("CheckAccess: %v", err)
		}
		return res
	}
	if res := check(MethodGetBalance, "", "latest"); !res.Allowed {
		t.Fatalf("allowlisted catalog method at latest must be allowed: %+v", res)
	}
	if res := check(MethodGetBalance, "", "0x10"); res.Allowed || res.Reason != "historical state queries not permitted" {
		t.Fatalf("catalog historical query must be denied: %+v", res)
	}
	for _, block := range []string{"latest", "0x10"} {
		wantReason, wantAuth := "authentication required for this operation", true
		if block != "latest" {
			wantReason, wantAuth = "historical state queries not permitted", false
		}
		if res := check("linea_getBalance", MethodGetBalance, block); res.Allowed || res.AuthRequired != wantAuth || res.Reason != wantReason {
			t.Errorf("anonymous alias at %s must be denied with %q: %+v", block, wantReason, res)
		}
	}
}

// TestCheckAccess_AuthenticatedAliasHistoricalGuard is the authenticated twin:
// a non-org-admin reading through an alias at a block number is denied just as
// the target method would be.
func TestCheckAccess_AuthenticatedAliasHistoricalGuard(t *testing.T) {
	registerStorageReadAliases(t, map[string]string{"linea_getProof": MethodGetProof})
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
			check := func(block string) *AccessCheckResult {
				res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
					UserExternalID: "did:test:user-a",
					Method:         tc.method,
					AccessMethod:   tc.alias,
					Params:         []any{rd1301Contract, []any{rd1301Impl}, block},
					TargetAddress:  rd1301Contract,
				})
				if err != nil {
					t.Fatalf("CheckAccess: %v", err)
				}
				return res
			}
			if res := check("latest"); !res.Allowed {
				t.Fatalf("precondition: %s of a well-known slot at latest is allowed, got %+v", tc.method, res)
			}
			res := check("0x10")
			if res.Allowed {
				t.Fatalf("%s at a block number must be denied for a non-org-admin", tc.method)
			}
			if res.Reason != "historical state queries not permitted" {
				t.Fatalf("expected the historical-state denial, got reason %q", res.Reason)
			}
		})
	}
}

// TestCheckAccess_StorageReadWithoutTargetDenied pins the fail-closed branch
// for a storage read whose address param is missing or not a string: the
// contract and storage-slot checks key on the target address, so without one
// the request would otherwise be allowed and forwarded unchecked.
func TestCheckAccess_StorageReadWithoutTargetDenied(t *testing.T) {
	registerStorageReadAliases(t, map[string]string{"linea_getProof": MethodGetProof})
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)
	perms := store.cachedPermissions["user-a:org-a"]
	perms.AllowedMethods = append(perms.AllowedMethods, "eth_getProof", "linea_getProof")
	ac := NewAccessController(store, time.Minute)
	defer ac.Stop()

	for _, tc := range []struct {
		name, method, alias string
		params              []any
	}{
		{"getProof non-string address", "eth_getProof", "", []any{float64(1), []any{rd1301Impl}, "latest"}},
		{"getProof no params", "eth_getProof", "", []any{}},
		{"alias getProof non-string address", "linea_getProof", "eth_getProof", []any{nil, []any{}, "latest"}},
		{"getStorageAt non-string address", "eth_getStorageAt", "", []any{map[string]any{}, rd1301Impl, "latest"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
				UserExternalID: "did:test:user-a",
				Method:         tc.method,
				AccessMethod:   tc.alias,
				Params:         tc.params,
				TargetAddress:  GetTargetAddress(cmp.Or(tc.alias, tc.method), tc.params),
			})
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			if res.Allowed || res.Reason != ErrContractAccessDenied {
				t.Fatalf("a storage read without a target address must get the contract-access denial, got %+v", res)
			}
		})
	}
}

// TestCheckAccess_AnonymousStorageReadDenied pins that raw storage is never
// served to an anonymous caller, even when a super admin allowlists a storage
// method (or an alias of one) for the anonymous group: anonymous requests get
// no contract-level check, so the slot tier cannot apply there.
func TestCheckAccess_AnonymousStorageReadDenied(t *testing.T) {
	registerStorageReadAliases(t, map[string]string{"linea_getProof": MethodGetProof})
	store := NewMockCrossOrgStore()
	anon := store.groupAccess[AnonymousGroupID]
	anon.AllowedMethods = append(anon.AllowedMethods, "eth_getStorageAt", "eth_getProof", "linea_getProof")
	ac := NewAccessController(store, time.Minute)
	defer ac.Stop()

	res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{Method: "eth_blockNumber"})
	if err != nil || !res.Allowed {
		t.Fatalf("precondition: anonymous eth_blockNumber is allowed, got %+v err=%v", res, err)
	}
	for _, tc := range []struct {
		name, method, alias string
		params              []any
	}{
		{"getStorageAt well-known slot", "eth_getStorageAt", "", []any{rd1301Contract, rd1301Impl, "latest"}},
		{"getProof zero keys", "eth_getProof", "", []any{rd1301Contract, []any{}, "latest"}},
		{"alias getProof well-known key", "linea_getProof", "eth_getProof", []any{rd1301Contract, []any{rd1301Impl}, "latest"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
				Method: tc.method, AccessMethod: tc.alias, Params: tc.params, TargetAddress: rd1301Contract,
			})
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			wantReason := "storage reads require authentication"
			if tc.alias != "" {
				wantReason = "authentication required for this operation"
			}
			if res.Allowed || !res.AuthRequired || res.Reason != wantReason {
				t.Fatalf("anonymous storage request must be denied with %q, got %+v", wantReason, res)
			}
		})
	}
}

// Anonymous operator aliases require authentication. Catalog calls retain
// the creation restriction and ordinary-call positive control.
func TestCheckAccess_AnonymousAliasDeploymentDenied(t *testing.T) {
	registerStorageReadAliases(t, map[string]string{"linea_call": MethodCall, "linea_estimateGas": MethodEstimateGas})
	store := NewMockCrossOrgStore()
	anon := store.groupAccess[AnonymousGroupID]
	anon.AllowedMethods = append(anon.AllowedMethods, "linea_call", "linea_estimateGas", MethodEstimateGas)
	ac := NewAccessController(store, time.Minute)
	defer ac.Stop()

	create := []any{map[string]any{"from": rd1301Contract, "data": "0x6080"}}
	call := []any{map[string]any{"from": rd1301Contract, "to": rd1301Contract, "data": "0x6080"}}
	for _, tc := range []struct {
		name, method, alias, reason string
		params                      []any
		allowed                     bool
	}{
		{"call alias creation", "linea_call", MethodCall, "authentication required for this operation", create, false},
		{"estimate alias creation", "linea_estimateGas", MethodEstimateGas, "authentication required for this operation", create, false},
		{"ordinary operator alias", "linea_call", MethodCall, "authentication required for this operation", call, false},
		{"catalog creation", MethodEstimateGas, "", "deployment requires authentication", create, false},
		{"ordinary catalog call", MethodEstimateGas, "", "", call, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{Method: tc.method, AccessMethod: tc.alias, Params: tc.params})
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			if tc.allowed {
				if !res.Allowed {
					t.Fatalf("ordinary catalog call must be allowed: %+v", res)
				}
				return
			}
			if res.Allowed || !res.AuthRequired || res.Reason != tc.reason {
				t.Fatalf("anonymous request must be denied with %q, got %+v", tc.reason, res)
			}
		})
	}
}

// TestCheckAccess_BuiltinAliasKeyKeepsRawMethodChecks covers a standard
// method name used as an alias key (e.g. eth_getStorageAt → eth_call). Config
// loading refuses that (config.parseExplicitMethods); these rows set
// AccessMethod on the request directly, without config loading, to verify
// both request fields. The node executes
// the raw method (the body is forwarded verbatim), so every floor keyed on
// method semantics must hold for the raw method as well as for the alias
// target.
func TestCheckAccess_BuiltinAliasKeyKeepsRawMethodChecks(t *testing.T) {
	t.Run("anonymous", func(t *testing.T) {
		store := NewMockCrossOrgStore()
		anon := store.groupAccess[AnonymousGroupID]
		anon.AllowedMethods = append(anon.AllowedMethods, "eth_sendTransaction", "eth_getStorageAt", "eth_getBalance")
		ac := NewAccessController(store, time.Minute)
		defer ac.Stop()

		for _, tc := range []struct {
			name, method, alias, reason string
			params                      []any
		}{
			{"deployment", "eth_sendTransaction", "eth_call", "deployment requires authentication",
				[]any{map[string]any{"from": rd1301Contract, "data": "0x6080"}}},
			{"storage read", "eth_getStorageAt", "eth_blockNumber", "storage reads require authentication",
				[]any{rd1301Contract, rd1301Impl, "latest"}},
			{"historical state read", "eth_getBalance", "eth_blockNumber", "historical state queries not permitted",
				[]any{rd1301Contract, "0x10"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
					Method: tc.method, AccessMethod: tc.alias, Params: tc.params,
				})
				if err != nil {
					t.Fatalf("CheckAccess: %v", err)
				}
				if res.Allowed || res.Reason != tc.reason {
					t.Fatalf("expected %q, got %+v", tc.reason, res)
				}
			})
		}
	})

	for _, tc := range []struct {
		name, alias, reason string
		orgAdmin            bool // isolates the slot tier from the historical guard (a real org admin also holds the admin claim)
		params              []any
	}{
		// Target extracted per the alias (eth_call reads params[0].to) is empty.
		{"remapped to a call-shaped method", "eth_call", ErrContractAccessDenied, true,
			[]any{rd1301Contract, rd1301Ordinary}},
		// Target resolves, but the alias target is not a storage read.
		{"remapped to another address query", "eth_getBalance", ErrContractAccessDenied, true,
			[]any{rd1301Contract, rd1301Ordinary, "latest"}},
		{"remapped, at a block number", "eth_blockNumber", "historical state queries not permitted", false,
			[]any{rd1301Contract, rd1301Impl, "0x10"}},
		// Remapped to a basic address query, on an address no org owns: the
		// balance/nonce carve-out must not serve a raw storage read.
		{"remapped to a basic address query on an unregistered address", "eth_getBalance", ErrContractAccessDenied, true,
			[]any{"0x00000000000000000000000000000000000000ee", rd1301Ordinary, "latest"}},
	} {
		t.Run("authenticated "+tc.name, func(t *testing.T) {
			store := NewMockCrossOrgStore()
			setupCrossOrgTestScenario(store)
			ac := NewAccessController(&orgAdminCheckingStore{MockCrossOrgStore: store, orgAdmin: tc.orgAdmin}, time.Minute)
			defer ac.Stop()

			res, err := ac.CheckAccess(context.Background(), &AccessCheckRequest{
				UserExternalID: "did:test:user-a",
				Method:         MethodGetStorageAt,
				AccessMethod:   tc.alias,
				Params:         tc.params,
				TargetAddress:  GetTargetAddress(tc.alias, tc.params),
			})
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			if res.Allowed || res.Reason != tc.reason {
				t.Fatalf("eth_getStorageAt remapped to %s must keep the storage-read checks: want %q, got %+v", tc.alias, tc.reason, res)
			}
		})
	}
}

// Registration accepts catalog aliases in their canonical spelling. Config
// loading normalizes alias targets before passing them to this boundary.
func TestRegisterExtraNamespaces_RequiresCatalogAliasTargets(t *testing.T) {
	defer SnapshotMethodRegistriesForTest()()
	ExtraMethods = map[string]bool{}
	ExtraNamespaces = nil
	MethodAliases = map[string]string{}
	PassthroughMethods = map[string]bool{}

	err := RegisterExtraNamespaces(
		map[string][]string{"Linea": {"linea_getProof", "linea_getStorageAt"}},
		map[string]string{
			"linea_getProof":     MethodGetProof,
			"linea_getStorageAt": MethodGetStorageAt,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("canonical catalog aliases must register: %v", err)
	}

	if got := ResolveMethodAlias("linea_getProof"); got != MethodGetProof {
		t.Fatalf("eth_getProof target resolved to %q", got)
	}
	if got := ResolveMethodAlias("linea_getStorageAt"); got != MethodGetStorageAt {
		t.Fatalf("eth_getStorageAt target resolved to %q", got)
	}
	if err := RegisterExtraNamespaces(map[string][]string{"Linea": {"linea_custom"}}, map[string]string{"linea_custom": "vendor_somethingElse"}, nil); err == nil {
		t.Fatal("an unknown target must be refused")
	}
}

// orgAdminCheckingStore adds the production OrgAdminChecker extension so the
// historical guard is live in the mock-store tests; orgAdmin sets the answer
// for every user.
type orgAdminCheckingStore struct {
	*MockCrossOrgStore
	orgAdmin bool
}

func (s *orgAdminCheckingStore) IsOrgAdmin(ctx context.Context, userID string) (bool, []string, error) {
	return s.orgAdmin, nil, nil
}
