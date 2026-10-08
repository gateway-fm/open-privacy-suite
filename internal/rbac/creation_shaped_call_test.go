package rbac

import (
	"context"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/tracer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A call object without `to` makes the node execute `data` as
// contract-creation code, on eth_call and eth_estimateGas exactly as on
// eth_sendTransaction. These tests pin that every such shape is classified as
// a deployment (auth + deploy claim) and that target extraction agrees with
// the classification, so no shape ends up as "no target and no claim".

const creationInitcode = "0x6080604052348015600f57600080fd5b50"

func TestIsContractDeployment_CreationShapedCalls(t *testing.T) {
	for _, method := range []string{"eth_call", "eth_estimateGas", "eth_createAccessList", "eth_sendTransaction"} {
		cases := []struct {
			name   string
			params []any
			want   bool
		}{
			{"to missing", []any{map[string]any{"data": creationInitcode}}, true},
			{"to null", []any{map[string]any{"to": nil, "data": creationInitcode}}, true},
			{"to empty string", []any{map[string]any{"to": "", "data": creationInitcode}}, true},
			{"to 0x", []any{map[string]any{"to": "0x", "data": creationInitcode}}, true},
			{"to 0X padded", []any{map[string]any{"to": " 0X ", "data": creationInitcode}}, true},
			{"to whitespace", []any{map[string]any{"to": "  ", "data": creationInitcode}}, true},
			{"to number", []any{map[string]any{"to": 7, "data": creationInitcode}}, true},
			{"to object", []any{map[string]any{"to": map[string]any{}, "data": creationInitcode}}, true},
			{"to array", []any{map[string]any{"to": []any{"0x01"}, "data": creationInitcode}}, true},
			{"to bool", []any{map[string]any{"to": false, "data": creationInitcode}}, true},
			{"call object is a string", []any{"0xdeadbeef"}, true},
			{"call object is null", []any{nil}, true},
			// Geth matches call-object field names case-insensitively; a
			// case variant of to/data/input is read differently by the node
			// than by the proxy, so it is malformed.
			{"to case variant", []any{map[string]any{"To": "0x1111111111111111111111111111111111111111", "data": "0x"}}, true},
			{"data case variant", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "Data": "0x"}}, true},
			{"input case variant", []any{map[string]any{"INPUT": creationInitcode}}, true},
			{"from case variant", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "From": "0x2222222222222222222222222222222222222222"}}, true},
			{"value case variant", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "VALUE": "0x1"}}, true},
			// `to` set and a case-variant null `To`: Geth keeps the last key
			// and runs a creation while the proxy would see a target.
			{"to plus null To", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "To": nil, "data": creationInitcode}}, true},
			{"targeted data and input differ", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "data": "0x", "input": "0xa9059cbb"}}, true},
			{"targeted data and input equal", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "data": "0xA9059CBB", "input": "0xa9059cbb"}}, false},
			{"to address", []any{map[string]any{"to": "0x1111111111111111111111111111111111111111", "data": "0x"}}, false},
			{"to zero address", []any{map[string]any{"to": "0x0000000000000000000000000000000000000000"}}, false},
			{"no params", nil, false},
			{"empty params", []any{}, false},
		}
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				assert.Equal(t, tc.want, IsContractDeployment(method, tc.params))
				if tc.want {
					assert.Equal(t, ClaimDeploy, ClassifyOperation(method, tc.params))
				}
			})
		}
	}
}

func TestGetTargetAddress_CreationShapedCallsHaveNoTarget(t *testing.T) {
	for _, method := range []string{"eth_call", "eth_estimateGas", "eth_createAccessList"} {
		for _, to := range []any{nil, "", "0x", "0X", " 0x "} {
			params := []any{map[string]any{"to": to, "data": creationInitcode}}
			assert.Empty(t, GetTargetAddress(method, params), "%s to=%#v", method, to)
		}
		assert.Equal(t, "0xabcd", GetTargetAddress(method, []any{map[string]any{"to": "0xABCD"}}))
	}
}

// creationShapedGranted is an org-a contract the "callers" group holds a grant on.
const creationShapedGranted = "0x00000000000000000000000000000000000000aa"

// creationShapedStore builds org-a with two groups: "callers" (eth_call,
// eth_estimateGas and the linea_call alias allowed; no claims; a grant on
// creationShapedGranted) and "deployers" (same methods + the deploy claim).
func creationShapedStore() *MockCrossOrgStore {
	store := NewMockCrossOrgStore()
	store.organizations["org-a"] = &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	methods := []string{"eth_call", "eth_estimateGas", "eth_createAccessList", "eth_sendTransaction", "linea_call"}
	add := func(userID, did, groupID string, claims []Claim) {
		store.users[did] = &User{ID: userID, ExternalID: did, KYC: true}
		group := &Group{ID: groupID, OrgID: "org-a", Slug: groupID, Name: groupID}
		store.memberships[userID] = []*MembershipWithDetails{
			{Membership: &UserMembership{ID: "m-" + userID, UserID: userID, GroupID: groupID}, Group: group},
		}
		store.groupAccess[groupID] = &GroupAccess{ID: "ga-" + groupID, GroupID: groupID, AllowedMethods: methods, Claims: claims}
		store.cachedPermissions[userID+":org-a"] = &EffectivePermissions{
			ID: "p-" + userID, UserID: userID, OrgID: "org-a",
			AllowedMethods: methods, ContractAccess: map[string]ContractAccess{}, Claims: claims,
			ComputedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	add("u-caller", "did:test:caller", "callers", []Claim{})
	add("u-deployer", "did:test:deployer", "deployers", []Claim{ClaimDeploy})
	store.contractOwners[creationShapedGranted] = "org-a"
	store.registeredToAnyOrg[creationShapedGranted] = true
	store.addressOwnedByOrg[creationShapedGranted] = map[string]bool{"org-a": true}
	store.cachedPermissions["u-caller:org-a"].ContractAccess[creationShapedGranted] = ContractAccess{Claims: []Claim{}}
	return store
}

// accessRequestLikeProcess builds the request exactly as the /rpc processor
// does: alias-resolved AccessMethod, target + claim derived from params.
func accessRequestLikeProcess(did, method string, params []any) *AccessCheckRequest {
	accessMethod := ResolveMethodAlias(method)
	var required []Claim
	if c := ClassifyOperation(accessMethod, params); c != "" {
		required = []Claim{c}
	}
	return &AccessCheckRequest{
		UserExternalID: did, OrgID: "org-a", Method: method, AccessMethod: accessMethod,
		Params: params, TargetAddress: GetTargetAddress(accessMethod, params),
		FunctionSelector: GetFunctionSelector(accessMethod, params), RequiredClaims: required,
	}
}

func TestCheckAccess_CreationShapedCallRequiresDeployClaim(t *testing.T) {
	t.Cleanup(SnapshotMethodRegistriesForTest())
	MethodAliases["linea_call"] = "eth_call"
	ctrl := NewAccessController(creationShapedStore(), 5*time.Minute)
	ctx := context.Background()

	creation := []any{map[string]any{"data": creationInitcode}, "latest"}
	for _, method := range []string{"eth_call", "eth_estimateGas", "eth_createAccessList", "linea_call"} {
		t.Run(method+"/caller without deploy is denied", func(t *testing.T) {
			res, err := ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:caller", method, creation))
			require.NoError(t, err)
			assert.False(t, res.Allowed)
		})
		t.Run(method+"/deploy holder is allowed", func(t *testing.T) {
			res, err := ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:deployer", method, creation))
			require.NoError(t, err)
			assert.True(t, res.Allowed, res.Reason)
		})
	}

	t.Run("deploy holder with to 0x is treated as a deployment", func(t *testing.T) {
		res, err := ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:deployer", "eth_call",
			[]any{map[string]any{"to": "0x", "data": creationInitcode}}))
		require.NoError(t, err)
		assert.True(t, res.Allowed, res.Reason)
		res, err = ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:caller", "eth_call",
			[]any{map[string]any{"to": "0x", "data": creationInitcode}}))
		require.NoError(t, err)
		assert.False(t, res.Allowed)
	})

	// Malformed call objects are refused even for a deploy holder: the node
	// would reject or reinterpret them, so they are never forwarded.
	malformed := map[string][]any{
		"to number":      {map[string]any{"to": 7, "data": creationInitcode}},
		"to object":      {map[string]any{"to": map[string]any{"a": 1}, "data": creationInitcode}},
		"to array":       {map[string]any{"to": []any{}, "data": creationInitcode}},
		"to bool":        {map[string]any{"to": true, "data": creationInitcode}},
		"string call":    {"0xdeadbeef"},
		"null call":      {nil},
		"no bytecode":    {map[string]any{"data": "0x"}},
		"no bytecode 0X": {map[string]any{"data": " 0X "}},
		"empty bytecode": {map[string]any{}},
		// Nodes differ on which of data/input they run (Anvil runs input,
		// Geth rejects the pair); the checked code must be the executed code.
		"data and input differ": {map[string]any{"data": "0x", "input": creationInitcode}},
		"to case variant":       {map[string]any{"To": creationShapedGranted, "data": creationInitcode}},
		"data case variant":     {map[string]any{"data": creationInitcode, "DATA": "0x60"}},
	}
	for _, method := range []string{"eth_call", "eth_estimateGas", "eth_sendTransaction"} {
		for name, params := range malformed {
			t.Run(method+"/deploy holder malformed "+name, func(t *testing.T) {
				res, err := ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:deployer", method, params))
				require.NoError(t, err)
				assert.False(t, res.Allowed)
			})
		}
	}

	for name, params := range map[string][]any{
		"input only":               {map[string]any{"input": creationInitcode}},
		"data and input identical": {map[string]any{"data": creationInitcode, "input": strings.ToUpper(creationInitcode[:2]) + creationInitcode[2:]}},
	} {
		t.Run("deploy holder "+name, func(t *testing.T) {
			res, err := ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:deployer", "eth_call", params))
			require.NoError(t, err)
			assert.True(t, res.Allowed, res.Reason)
		})
	}

	// Shapes the node reads differently from the proxy are refused even when
	// the visible `to` is a contract the caller is granted.
	for name, params := range map[string][]any{
		"to plus null To":         {map[string]any{"to": creationShapedGranted, "To": nil, "data": creationInitcode}},
		"data and input differ":   {map[string]any{"to": creationShapedGranted, "data": "0x", "input": "0xa9059cbb"}},
		"from case variant spoof": {map[string]any{"to": creationShapedGranted, "From": "0x2222222222222222222222222222222222222222"}},
	} {
		t.Run("caller with grant, ambiguous "+name, func(t *testing.T) {
			res, err := ctrl.CheckAccess(ctx, accessRequestLikeProcess("did:test:caller", "eth_call", params))
			require.NoError(t, err)
			assert.False(t, res.Allowed)
		})
	}

	// /access/check takes a caller-built request: a stray target_address must
	// not divert a creation-shaped call away from the deployment rule.
	t.Run("access-check request with a stray target is still a deployment", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:caller", OrgID: "org-a", Method: "eth_call",
			Params:        creation,
			TargetAddress: creationShapedGranted,
		}
		res, err := ctrl.CheckAccess(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.Allowed)
	})
}

func TestCheckAccess_AnonymousCreationShapedCallDenied(t *testing.T) {
	t.Cleanup(SnapshotMethodRegistriesForTest())
	MethodAliases["linea_call"] = "eth_call"
	store := NewMockCrossOrgStore()
	store.groupAccess[AnonymousGroupID].AllowedMethods = append(
		store.groupAccess[AnonymousGroupID].AllowedMethods, "eth_call", "eth_estimateGas", "linea_call")
	ctrl := NewAccessController(store, 5*time.Minute)

	for _, method := range []string{"eth_call", "eth_estimateGas", "linea_call"} {
		t.Run(method, func(t *testing.T) {
			req := accessRequestLikeProcess("", method, []any{map[string]any{"data": creationInitcode}})
			res, err := ctrl.CheckAccess(context.Background(), req)
			require.NoError(t, err)
			assert.False(t, res.Allowed)
			assert.True(t, res.AuthRequired)
		})
	}
}

// Creation code may deploy contracts and then call them (a constructor that
// does `child = new Child(); child.init()`, a deployless read). Those
// callees run code the caller just supplied, and every frame they execute is
// validated in turn, so with WithCreatedContractsAsOwn a frame into a contract
// created earlier in the same trace is not refused as unregistered. A CREATE
// that failed (address collision: existing code) does not qualify.
func TestValidateTrace_CreatedContractsAsOwn(t *testing.T) {
	const (
		created = "0x00000000000000000000000000000000000000c1"
		child   = "0x00000000000000000000000000000000000000c2"
		foreign = "0x00000000000000000000000000000000000000f1"
	)
	store := NewMockTraceStore()
	store.AddOwnedAddress("org-b", foreign)
	validator := NewTraceValidator(store)
	ctx := context.Background()
	orgs := map[string]bool{"org-a": true}

	createAndCall := func(createErr string, calls ...tracer.CallTarget) *tracer.TraceResult {
		targets := []tracer.CallTarget{
			{Type: "CREATE", From: "0x0000000000000000000000000000000000000000", To: created, Depth: 0},
			{Type: "CREATE", From: created, To: child, Depth: 1, Error: createErr},
		}
		return &tracer.TraceResult{HasCreate: true, CallTargets: append(targets, calls...)}
	}
	callChild := tracer.CallTarget{Type: "CALL", From: created, To: child, Depth: 1}
	callSelf := tracer.CallTarget{Type: "STATICCALL", From: child, To: created, Depth: 2}

	res, err := validator.ValidateTrace(ctx, orgs, createAndCall("", callChild, callSelf), true, WithCreatedContractsAsOwn())
	require.NoError(t, err)
	assert.True(t, res.Allowed, res.Reason)

	res, err = validator.ValidateTrace(ctx, orgs, createAndCall("", callChild), true)
	require.NoError(t, err)
	assert.False(t, res.Allowed, "without the option a created callee stays unregistered")

	res, err = validator.ValidateTrace(ctx, orgs, createAndCall("contract address collision", callChild), true, WithCreatedContractsAsOwn())
	require.NoError(t, err)
	assert.False(t, res.Allowed, "a failed CREATE may point at existing code")

	res, err = validator.ValidateTrace(ctx, orgs, createAndCall("", callChild,
		tracer.CallTarget{Type: "STATICCALL", From: child, To: foreign, Depth: 2}), true, WithCreatedContractsAsOwn())
	require.NoError(t, err)
	assert.False(t, res.Allowed, "a created contract's own frames are still validated")
	assert.Equal(t, DenialKindForeignOrg, res.DenialKind)

	res, err = validator.ValidateTrace(ctx, orgs, createAndCall("", callChild), false, WithCreatedContractsAsOwn())
	require.NoError(t, err)
	assert.False(t, res.Allowed, "creation still needs the deploy claim")

	// A later creation cannot retrospectively authorize an earlier call.
	beforeCreate := &tracer.TraceResult{HasCreate: true, CallTargets: []tracer.CallTarget{
		{Type: "CREATE", To: created},
		callChild,
		{Type: "CREATE", From: created, To: child, Depth: 1},
	}}
	res, err = validator.ValidateTrace(ctx, orgs, beforeCreate, true, WithCreatedContractsAsOwn())
	require.NoError(t, err)
	assert.False(t, res.Allowed, "only contracts already created in execution order count as own")
	assert.Equal(t, DenialKindUnregistered, res.DenialKind)
}
