package rbac

import (
	"context"
	"strings"
	"testing"

	"privacy-proxy/internal/tracer"
)

// MockTraceStore implements the Store interface for trace validator tests.
type MockTraceStore struct {
	*MockStore
	sharedInfrastructure map[string]*SharedInfrastructure // address -> row (nil = not tagged)
	ownedAddresses       map[string]map[string]bool       // orgID -> address -> owned
	preregistered        map[string]map[string]bool       // orgID -> address -> pre-registered
}

func NewMockTraceStore() *MockTraceStore {
	return &MockTraceStore{
		MockStore:            NewMockStore(),
		sharedInfrastructure: make(map[string]*SharedInfrastructure),
		ownedAddresses:       make(map[string]map[string]bool),
		preregistered:        make(map[string]map[string]bool),
	}
}

// IsAddressPreregistered overrides the embedded MockStore stub (which always
// returns false) so RD-1053 pre-registration fallback tests can seed state.
func (m *MockTraceStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	addr := strings.ToLower(address)
	if orgAddrs, ok := m.preregistered[orgID]; ok {
		return orgAddrs[addr], nil
	}
	return false, nil
}

// AddPreregisteredAddress marks an address as a pending deployment for the
// org. Pre-registered addresses are also owned by the org (the real
// IsAddressOwnedByOrg UNIONs preregistered_addresses), so this seeds both.
func (m *MockTraceStore) AddPreregisteredAddress(orgID, address string) {
	addr := strings.ToLower(address)
	if m.preregistered[orgID] == nil {
		m.preregistered[orgID] = make(map[string]bool)
	}
	m.preregistered[orgID][addr] = true
	m.AddOwnedAddress(orgID, addr)
}

func (m *MockTraceStore) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) {
	addr := strings.ToLower(address)
	return m.sharedInfrastructure[addr] != nil, nil
}

func (m *MockTraceStore) GetSharedInfrastructure(ctx context.Context, address string) (*SharedInfrastructure, error) {
	addr := strings.ToLower(address)
	if row, ok := m.sharedInfrastructure[addr]; ok {
		return row, nil
	}
	return nil, nil
}

func (m *MockTraceStore) CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error {
	addr := strings.ToLower(infra.Address)
	// Copy to insulate test state from caller mutation.
	row := *infra
	row.Address = addr
	m.sharedInfrastructure[addr] = &row
	return nil
}

func (m *MockTraceStore) ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error) {
	return nil, nil
}

func (m *MockTraceStore) DeleteSharedInfrastructure(ctx context.Context, address string) error {
	addr := strings.ToLower(address)
	delete(m.sharedInfrastructure, addr)
	return nil
}

func (m *MockTraceStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	addr := strings.ToLower(address)
	if orgAddrs, ok := m.ownedAddresses[orgID]; ok {
		return orgAddrs[addr], nil
	}
	return false, nil
}

func (m *MockTraceStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	addr := strings.ToLower(address)
	for orgID, addrs := range m.ownedAddresses {
		if addrs[addr] {
			return orgID, nil
		}
	}
	return "", nil
}

func (m *MockTraceStore) GrantContractToDeployerGroup(ctx context.Context, orgID, contractID, deployerUserID string) error {
	return nil
}

func (m *MockTraceStore) AddSharedInfrastructure(address string) {
	addr := strings.ToLower(address)
	m.sharedInfrastructure[addr] = &SharedInfrastructure{Address: addr}
}

// AddSharedInfrastructureWithCodehash tags an address with a stored
// codehash so the M5 codehash-pin path can be exercised. Tests that
// want to assert mismatch behaviour set this to one value and inject a
// MockCodeHashFetcher returning a different value.
func (m *MockTraceStore) AddSharedInfrastructureWithCodehash(address, codehash string) {
	addr := strings.ToLower(address)
	h := codehash
	m.sharedInfrastructure[addr] = &SharedInfrastructure{Address: addr, Codehash: &h}
}

func (m *MockTraceStore) AddOwnedAddress(orgID, address string) {
	addr := strings.ToLower(address)
	if m.ownedAddresses[orgID] == nil {
		m.ownedAddresses[orgID] = make(map[string]bool)
	}
	m.ownedAddresses[orgID][addr] = true
}

// staticCodeHashFetcher is a CodeHashFetcher stub for M5 tests.
// Returns whatever the test injected for a given address; missing
// addresses return ("", nil) — the validator treats that as "no hash
// to compare against" which currently falls through to the legacy
// skip path. For the rotation-detection tests we inject a value that
// differs from the stored attestation.
type staticCodeHashFetcher struct {
	hashes map[string]string
}

func (s *staticCodeHashFetcher) GetCodeHash(ctx context.Context, address string) (string, error) {
	return s.hashes[strings.ToLower(address)], nil
}

// M6 (security audit follow-up to RD-915): DELEGATECALL into shared
// infrastructure must be denied even when the target is tagged.
// DELEGATECALL executes the callee's bytecode against the caller's
// storage; trusting any address based on a tag would let an operator-
// misconfigured proxy whose bytecode is rotated exfiltrate or
// impersonate caller storage. CALL and STATICCALL stay allowed.
func TestValidateTrace_M6_DelegateCallSharedInfraDenied(t *testing.T) {
	store := NewMockTraceStore()
	store.AddSharedInfrastructure("0xaaaa000000000000000000000000000000000000")
	validator := NewTraceValidator(store)

	cases := []struct {
		name       string
		callType   string
		wantAllow  bool
		wantReason DenialKind
	}{
		{"CALL allowed", "CALL", true, DenialKindNone},
		{"STATICCALL allowed", "STATICCALL", true, DenialKindNone},
		{"DELEGATECALL denied", "DELEGATECALL", false, DenialKindDelegateSharedInfra},
		{"CALLCODE denied", "CALLCODE", false, DenialKindDelegateSharedInfra},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trace := &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: tc.callType, To: "0xaaaa000000000000000000000000000000000000"},
				},
			}
			result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed != tc.wantAllow {
				t.Errorf("Allowed=%v, want %v (reason=%q kind=%q)", result.Allowed, tc.wantAllow, result.Reason, result.DenialKind)
			}
			if !tc.wantAllow && result.DenialKind != tc.wantReason {
				t.Errorf("DenialKind=%q, want %q", result.DenialKind, tc.wantReason)
			}
		})
	}
}

// M5 (security audit follow-up to RD-915): tagged shared
// infrastructure with a stored codehash must verify the current
// bytecode hash before skipping the trace. Pre-fix an operator who
// pointed a proxy at a tagged address could silently bypass the
// validator after an implementation rotation. The fix:
//   - codehash unset → keep the skip (back-compat).
//   - codehash set + match → keep the skip.
//   - codehash set + mismatch → deny.
//
// The fetcher is optional on the validator; when not set the check is
// disabled (back-compat for callers without node access).
func TestValidateTrace_M5_CodehashPin(t *testing.T) {
	const addr = "0xbbbb000000000000000000000000000000000000"
	const attested = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	const rotated = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	t.Run("no codehash stored → skip allowed (back-compat)", func(t *testing.T) {
		store := NewMockTraceStore()
		store.AddSharedInfrastructure(addr)
		v := NewTraceValidator(store)
		v.SetCodeHashFetcher(&staticCodeHashFetcher{hashes: map[string]string{addr: rotated}})
		trace := &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", To: addr}}}
		res, err := v.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
		if err != nil || !res.Allowed {
			t.Fatalf("legacy entry must still be allowed: err=%v allowed=%v", err, res.Allowed)
		}
	})

	t.Run("codehash matches → skip allowed", func(t *testing.T) {
		store := NewMockTraceStore()
		store.AddSharedInfrastructureWithCodehash(addr, attested)
		v := NewTraceValidator(store)
		v.SetCodeHashFetcher(&staticCodeHashFetcher{hashes: map[string]string{addr: attested}})
		trace := &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", To: addr}}}
		res, err := v.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
		if err != nil || !res.Allowed {
			t.Fatalf("matching codehash must be allowed: err=%v allowed=%v", err, res.Allowed)
		}
	})

	t.Run("codehash mismatch → denied with mismatch kind", func(t *testing.T) {
		store := NewMockTraceStore()
		store.AddSharedInfrastructureWithCodehash(addr, attested)
		v := NewTraceValidator(store)
		v.SetCodeHashFetcher(&staticCodeHashFetcher{hashes: map[string]string{addr: rotated}})
		trace := &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", To: addr}}}
		res, err := v.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("rotated bytecode must deny — operator's attestation no longer applies")
		}
		if res.DenialKind != DenialKindCodehashMismatch {
			t.Errorf("DenialKind=%q, want %q", res.DenialKind, DenialKindCodehashMismatch)
		}
	})

	t.Run("codehash match is case-insensitive", func(t *testing.T) {
		store := NewMockTraceStore()
		store.AddSharedInfrastructureWithCodehash(addr, strings.ToUpper(attested))
		v := NewTraceValidator(store)
		v.SetCodeHashFetcher(&staticCodeHashFetcher{hashes: map[string]string{addr: attested}})
		trace := &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", To: addr}}}
		res, err := v.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
		if err != nil || !res.Allowed {
			t.Fatalf("case-insensitive match must be allowed: err=%v allowed=%v", err, res.Allowed)
		}
	})
}

func TestValidateTrace_NilTrace(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected nil trace to be allowed")
	}
}

func TestValidateTrace_EmptyTrace(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected empty trace to be allowed")
	}
}

func TestValidateTrace_CreateDenied(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE", From: "0xsender", To: "0xnewcontract"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected CREATE to be denied")
	}
	if !strings.Contains(result.Reason, "deploy claim") {
		t.Errorf("expected reason to mention deploy claim, got: %s", result.Reason)
	}
}

func TestValidateTrace_Create2Denied(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate2: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE2", From: "0xsender", To: "0xnewcontract"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected CREATE2 to be denied")
	}
	if !strings.Contains(result.Reason, "deploy claim") {
		t.Errorf("expected reason to mention deploy claim, got: %s", result.Reason)
	}
}

func TestValidateTrace_PrecompileAllowed(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	// Trace calling precompile address 0x01 (ecrecover)
	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x0000000000000000000000000000000000000001"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected precompile call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_SharedInfrastructureAllowed(t *testing.T) {
	store := NewMockTraceStore()
	// Register Uniswap router as shared infrastructure
	store.AddSharedInfrastructure("0xe592427a0aece92de3edee1f18e0157c05861564")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xe592427a0aece92de3edee1f18e0157c05861564"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected shared infrastructure call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_OrgOwnedContractAllowed(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1234567890123456789012345678901234567890")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1234567890123456789012345678901234567890"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected org-owned contract call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_OtherOrgContractDenied(t *testing.T) {
	store := NewMockTraceStore()
	// Register contract as owned by org2 (not the user's org)
	store.AddOwnedAddress("org2", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}

	// User is member of org1, not org2
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected call to other org's contract to be denied")
	}
	if !strings.Contains(result.Reason, ErrContractAccessDenied) {
		t.Errorf("expected generic denial, got: %s", result.Reason)
	}
	if result.DeniedTarget != "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("expected DeniedTarget to be the denied address, got: %s", result.DeniedTarget)
	}
}

func TestValidateTrace_UnregisteredContractDenied(t *testing.T) {
	store := NewMockTraceStore()
	// Contract not registered to any org — private by default

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected unregistered contract call to be denied (private by default)")
	}
	if result.DeniedTarget != "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("expected DeniedTarget to be the unregistered address, got: %s", result.DeniedTarget)
	}
}

func TestValidateTrace_MultiOrgUserAllowed(t *testing.T) {
	store := NewMockTraceStore()
	// User is member of both org1 and org2
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddOwnedAddress("org2", "0x2222222222222222222222222222222222222222")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			{Type: "CALL", From: "0x1111", To: "0x2222222222222222222222222222222222222222"},
		},
	}

	// User is member of both orgs
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true, "org2": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected multi-org user to access both orgs' contracts, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_MixedTargets(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddSharedInfrastructure("0xcccccccccccccccccccccccccccccccccccccccc")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			// Org-owned contract
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			// Precompile
			{Type: "STATICCALL", From: "0x1111", To: "0x0000000000000000000000000000000000000002"},
			// Shared infrastructure
			{Type: "CALL", From: "0x1111", To: "0xcccccccccccccccccccccccccccccccccccccccc"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected mixed valid targets to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_MixedTargetsWithUnregistered(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddSharedInfrastructure("0xcccccccccccccccccccccccccccccccccccccccc")

	validator := NewTraceValidator(store)

	// Including an unregistered address should cause denial
	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			{Type: "STATICCALL", From: "0x1111", To: "0x0000000000000000000000000000000000000002"},
			{Type: "CALL", From: "0x1111", To: "0xcccccccccccccccccccccccccccccccccccccccc"},
			// Unregistered address — should trigger denial
			{Type: "DELEGATECALL", From: "0x1111", To: "0xdddddddddddddddddddddddddddddddddddddddd"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected trace with unregistered address to be denied (private by default)")
	}
}

func TestValidateTrace_DenyOnFirstViolation(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddOwnedAddress("org2", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // Other org

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			// First call is allowed
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			// Second call is to another org - should deny
			{Type: "CALL", From: "0x1111", To: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			// Third call would be allowed but we should never reach it
			{Type: "CALL", From: "0xaaaa", To: "0x0000000000000000000000000000000000000001"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected trace to be denied on first violation")
	}
	if result.DeniedTarget != "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("expected DeniedTarget to be the violating address, got: %s", result.DeniedTarget)
	}
}

func TestValidateTrace_AddressNormalization(t *testing.T) {
	store := NewMockTraceStore()
	// Register with lowercase
	store.AddOwnedAddress("org1", "0xabcdef1234567890abcdef1234567890abcdef12")

	validator := NewTraceValidator(store)

	// Trace uses uppercase
	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected address normalization to work, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_EmptyUserOrgs(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
		},
	}

	// User has no org memberships
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected user with no orgs to be denied access to org-owned contract")
	}
}

func TestValidateTrace_SkipsZeroAddress(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			// Zero address (e.g., from ETH transfer)
			{Type: "CALL", From: "0xsender", To: "0x0000000000000000000000000000000000000000"},
			// Empty address
			{Type: "CALL", From: "0xsender", To: ""},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected zero/empty addresses to be skipped, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_Create2AllowedWithDeployClaim(t *testing.T) {
	store := NewMockTraceStore()
	// Created address is public (not owned by any org)
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate2: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE2", From: "0xfactory", To: "0xnewcontract1234567890123456789012345678"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected CREATE2 with deploy claim to be allowed, got denied: %s", result.Reason)
	}
	if len(result.CreateTargets) != 1 {
		t.Fatalf("expected 1 CreateTarget, got %d", len(result.CreateTargets))
	}
	if result.CreateTargets[0].Type != "CREATE2" {
		t.Errorf("expected CreateTarget type CREATE2, got: %s", result.CreateTargets[0].Type)
	}
	if result.CreateTargets[0].Address != "0xnewcontract1234567890123456789012345678" {
		t.Errorf("expected CreateTarget address 0xnewcontract1234567890123456789012345678, got: %s", result.CreateTargets[0].Address)
	}
	if result.CreateTargets[0].From != "0xfactory" {
		t.Errorf("expected CreateTarget from 0xfactory, got: %s", result.CreateTargets[0].From)
	}
}

func TestValidateTrace_Create2DeniedCrossOrg(t *testing.T) {
	store := NewMockTraceStore()
	// The created address is already owned by org2
	store.AddOwnedAddress("org2", "0xnewcontract1234567890123456789012345678")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate2: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE2", From: "0xfactory", To: "0xnewcontract1234567890123456789012345678"},
		},
	}

	// User is org1, created address is owned by org2
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected CREATE2 to cross-org owned address to be denied")
	}
	if !strings.Contains(result.Reason, "contract access denied") {
		t.Errorf("expected generic denial, got: %s", result.Reason)
	}
	if result.DeniedTarget != "0xnewcontract1234567890123456789012345678" {
		t.Errorf("expected DeniedTarget to be the created address, got: %s", result.DeniedTarget)
	}
}

func TestValidateTrace_Create2DeniedWithoutDeployClaim(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate2: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE2", From: "0xfactory", To: "0xnewcontract1234567890123456789012345678"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected CREATE2 without deploy claim to be denied")
	}
	if !strings.Contains(result.Reason, "deploy claim") {
		t.Errorf("expected reason to mention deploy claim, got: %s", result.Reason)
	}
}

// TestValidateTrace_TableDriven provides comprehensive table-driven tests.
func TestValidateTrace_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		setupStore    func(*MockTraceStore)
		userOrgIDs    map[string]bool
		userHasDeploy bool
		trace         *tracer.TraceResult
		expectAllowed bool
		expectReason  string
		expectDenied  string
	}{
		{
			name:          "nil trace allowed",
			setupStore:    func(s *MockTraceStore) {},
			userOrgIDs:    map[string]bool{"org1": true},
			trace:         nil,
			expectAllowed: true,
		},
		{
			name:       "CREATE blocked without deploy claim",
			setupStore: func(s *MockTraceStore) {},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				HasCreate: true,
			},
			expectAllowed: false,
			expectReason:  "deploy claim",
		},
		{
			name:       "all precompiles allowed",
			setupStore: func(s *MockTraceStore) {},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: "CALL", To: "0x0000000000000000000000000000000000000001"},
					{Type: "STATICCALL", To: "0x0000000000000000000000000000000000000002"},
					{Type: "CALL", To: "0x0000000000000000000000000000000000000009"},
				},
			},
			expectAllowed: true,
		},
		{
			name: "shared infra allowed",
			setupStore: func(s *MockTraceStore) {
				s.AddSharedInfrastructure("0xsharedrouter")
			},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: "CALL", To: "0xsharedrouter"},
				},
			},
			expectAllowed: true,
		},
		{
			name: "cross-org isolation enforced",
			setupStore: func(s *MockTraceStore) {
				s.AddOwnedAddress("org2", "0xorg2contract")
			},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: "CALL", To: "0xorg2contract"},
				},
			},
			expectAllowed: false,
			expectReason:  ErrContractAccessDenied,
			expectDenied:  "0xorg2contract",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMockTraceStore()
			tt.setupStore(store)

			validator := NewTraceValidator(store)
			result, err := validator.ValidateTrace(context.Background(), tt.userOrgIDs, tt.trace, tt.userHasDeploy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				t.Errorf("Allowed = %v, want %v (reason: %s)", result.Allowed, tt.expectAllowed, result.Reason)
			}

			if tt.expectReason != "" && !strings.Contains(result.Reason, tt.expectReason) {
				t.Errorf("Reason = %q, want to contain %q", result.Reason, tt.expectReason)
			}

			if tt.expectDenied != "" && result.DeniedTarget != tt.expectDenied {
				t.Errorf("DeniedTarget = %q, want %q", result.DeniedTarget, tt.expectDenied)
			}
		})
	}
}

// RD-1053: intra-org contract-grant scoping. By default a frame into any
// contract owned by one of the caller's orgs is allowed (org is the isolation
// boundary). With WithIntraOrgGrantScoping the same-org "allow" is narrowed to
// contracts the caller actually has a grant for, mirroring the entry-point
// CheckAccess. Cross-org (2d) and unregistered (2e) denials are unaffected.
func TestValidateTrace_IntraOrgGrantScoping(t *testing.T) {
	const (
		granted      = "0xa111000000000000000000000000000000000000" // org1, in caller's grant set
		ungranted    = "0xb222000000000000000000000000000000000000" // org1, NOT in caller's grant set
		foreign      = "0xc333000000000000000000000000000000000000" // org2 (cross-org)
		unregistered = "0xd444000000000000000000000000000000000000" // owned by no org
	)

	newStore := func() *MockTraceStore {
		s := NewMockTraceStore()
		s.AddOwnedAddress("org1", granted)
		s.AddOwnedAddress("org1", ungranted)
		s.AddOwnedAddress("org2", foreign)
		return s
	}
	userOrgs := map[string]bool{"org1": true}
	grantSet := map[string]bool{granted: true}
	traceTo := func(addr string) *tracer.TraceResult {
		return &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", To: addr}}}
	}

	t.Run("scoping OFF: same-org ungranted frame is allowed (pre-RD-1053 behaviour)", func(t *testing.T) {
		v := NewTraceValidator(newStore())
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(ungranted), false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("without scoping, org-owned frame must be allowed; got deny kind=%q", res.DenialKind)
		}
	})

	t.Run("scoping ON: same-org ungranted frame is denied", func(t *testing.T) {
		v := NewTraceValidator(newStore())
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(ungranted), false,
			WithIntraOrgGrantScoping(grantSet))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("with scoping, same-org ungranted frame must be denied")
		}
		if res.DenialKind != DenialKindIntraOrgUngranted {
			t.Errorf("DenialKind = %q, want %q", res.DenialKind, DenialKindIntraOrgUngranted)
		}
		if res.DeniedTarget != ungranted {
			t.Errorf("DeniedTarget = %q, want %q", res.DeniedTarget, ungranted)
		}
	})

	t.Run("scoping ON: same-org granted frame is allowed", func(t *testing.T) {
		v := NewTraceValidator(newStore())
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(granted), false,
			WithIntraOrgGrantScoping(grantSet))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("granted same-org frame must be allowed; got deny kind=%q", res.DenialKind)
		}
	})

	t.Run("scoping ON: cross-org frame still denied as foreign_org (not intra-org)", func(t *testing.T) {
		v := NewTraceValidator(newStore())
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(foreign), false,
			WithIntraOrgGrantScoping(grantSet))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("cross-org frame must be denied")
		}
		if res.DenialKind != DenialKindForeignOrg {
			t.Errorf("DenialKind = %q, want %q (scoping must not reclassify cross-org)", res.DenialKind, DenialKindForeignOrg)
		}
	})

	t.Run("scoping ON: unregistered frame still denied as unregistered", func(t *testing.T) {
		v := NewTraceValidator(newStore())
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(unregistered), false,
			WithIntraOrgGrantScoping(grantSet))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("unregistered frame must be denied")
		}
		if res.DenialKind != DenialKindUnregistered {
			t.Errorf("DenialKind = %q, want %q", res.DenialKind, DenialKindUnregistered)
		}
	})

	t.Run("scoping ON: precompile and shared-infra frames remain allowed", func(t *testing.T) {
		s := newStore()
		const shared = "0xeeee000000000000000000000000000000000000"
		s.AddSharedInfrastructure(shared)
		v := NewTraceValidator(s)
		trace := &tracer.TraceResult{CallTargets: []tracer.CallTarget{
			{Type: "STATICCALL", To: "0x0000000000000000000000000000000000000001"}, // precompile
			{Type: "CALL", To: shared}, // globally shared
		}}
		res, err := v.ValidateTrace(context.Background(), userOrgs, trace, false,
			WithIntraOrgGrantScoping(grantSet))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("precompile/shared-infra frames must bypass grant scoping; got deny kind=%q target=%q", res.DenialKind, res.DeniedTarget)
		}
	})
}

// RD-1053 pre-registration fallback: a same-org PRE-REGISTERED (precomputed,
// not-yet-mined CREATE/CREATE2/CREATE3) address has no grant row yet, but a
// deploy-claim caller must still be able to touch it under strict scoping —
// otherwise a multi-contract deploy that references a precomputed sibling
// before it's mined would false-deny. A non-deployer is still denied (the
// address has no code; fail-closed). Mirrors the entry-point CheckAccess.
func TestValidateTrace_IntraOrgScoping_PreregisteredSibling(t *testing.T) {
	const prereg = "0xf00d000000000000000000000000000000000000" // org1, pre-registered, no grant
	userOrgs := map[string]bool{"org1": true}
	noGrants := map[string]bool{}
	traceTo := func(addr string) *tracer.TraceResult {
		return &tracer.TraceResult{CallTargets: []tracer.CallTarget{{Type: "CALL", To: addr}}}
	}

	t.Run("deploy-claim caller: pre-registered same-org frame allowed despite no grant", func(t *testing.T) {
		s := NewMockTraceStore()
		s.AddPreregisteredAddress("org1", prereg)
		v := NewTraceValidator(s)
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(prereg), true,
			WithIntraOrgGrantScoping(noGrants))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("deploy-claim caller must reach an in-flight pre-registered sibling; got deny kind=%q", res.DenialKind)
		}
	})

	t.Run("non-deployer: pre-registered same-org frame still denied", func(t *testing.T) {
		s := NewMockTraceStore()
		s.AddPreregisteredAddress("org1", prereg)
		v := NewTraceValidator(s)
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(prereg), false,
			WithIntraOrgGrantScoping(noGrants))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("non-deployer must not reach an ungranted address via the pre-reg fallback")
		}
		if res.DenialKind != DenialKindIntraOrgUngranted {
			t.Errorf("DenialKind = %q, want %q", res.DenialKind, DenialKindIntraOrgUngranted)
		}
	})

	t.Run("scoping OFF: pre-registered frame allowed regardless of claim", func(t *testing.T) {
		s := NewMockTraceStore()
		s.AddPreregisteredAddress("org1", prereg)
		v := NewTraceValidator(s)
		res, err := v.ValidateTrace(context.Background(), userOrgs, traceTo(prereg), false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("with scoping off, org-owned (incl. pre-registered) frame must be allowed")
		}
	})
}
