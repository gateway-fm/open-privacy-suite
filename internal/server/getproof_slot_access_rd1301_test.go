package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1301 — eth_getProof follows the non-admin storage-slot policy used by
// eth_getStorageAt (RD-805). These tests drive the full JSONRPCProcessor.Process
// path (alias resolution, CheckAccess, forwarding) against a counting upstream
// so denied requests are confirmed before forwarding.

// The four well-known infrastructure slots a non-admin may read.
const (
	rd1301ImplSlot    = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" // EIP-1967 implementation
	rd1301AdminSlot   = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103" // EIP-1967 admin
	rd1301BeaconSlot  = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50" // EIP-1967 beacon
	rd1301DiamondSlot = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c" // EIP-2535 diamond
	// An ordinary (business-data) slot a non-admin must not read.
	rd1301OrdinarySlot = "0x1"
	rd1301HistoricalBN = "0x10"
)

// rd1301ProofResponse models a compliant node: storageProof contains exactly
// the requested keys. An account-only proof has no storageProof entries.
func rd1301ProofResponse(body []byte) []byte {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	if req.Method == "eth_getStorageAt" || req.Method == "linea_getStorageAt" {
		return []byte(`{"jsonrpc":"2.0","id":1,"result":"0x2a"}`)
	}
	var address string
	var keys []string
	if len(req.Params) < 2 || json.Unmarshal(req.Params[0], &address) != nil || json.Unmarshal(req.Params[1], &keys) != nil {
		return nil
	}
	proofs := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		proofs = append(proofs, map[string]any{"key": key, "value": "0x2a", "proof": []string{}})
	}
	response, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{
			"address": address, "balance": "0x0", "nonce": "0x1",
			"codeHash":     "0x" + strings.Repeat("ab", 32),
			"storageHash":  "0x" + strings.Repeat("cd", 32),
			"accountProof": []string{}, "storageProof": proofs,
		},
	})
	return response
}

// countingUpstream counts requests and returns proofs for the requested keys.
type countingUpstream struct {
	srv   *httptest.Server
	count atomic.Int32
	mu    sync.Mutex
	last  []byte
}

func newCountingUpstream(t *testing.T) *countingUpstream {
	t.Helper()
	u := &countingUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.last = body
		u.mu.Unlock()
		u.count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rd1301ProofResponse(body))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *countingUpstream) lastBody() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last
}

// rd1301Methods is the allowlist every non-wildcard fixture group gets.
var rd1301Methods = []string{"eth_getProof", "linea_getProof", "eth_getStorageAt", "linea_getStorageAt"}

type rd1301Fixture struct {
	ts       *testServerRBAC
	proc     *JSONRPCProcessor
	upstream *countingUpstream

	contract    string // registered to org A, granted to the grant-holding groups
	deployed    string // registered to org A, deployed by deployerDID, no grant
	prereg      string // preregistered (planned deployment) for org A
	foreignAddr string // registered to org B

	memberDID        string // plain grant holder (no claims)
	contractAdminDID string // tier 3: admin claim + grant, not is_org_admin
	orgAdminDID      string // tier 2: is_org_admin of org A
	foreignAdminDID  string // tier 2 of org B, no relation to org A
	deployerDID      string // deployed `deployed`, no grant on it
	preregDID        string // deploy claim, reaches `prereg` via pre-registration
	starExpandedDID  string // group saved with "*" plus explicit linea_getProof
	literalStarDID   string // group stored with a literal "*" (batch-move new-group shape)
	splitAdminDID    string // admin claim in a group WITHOUT a grant + a plain grant from another group
}

// rd1301Group creates a group (optionally is_org_admin) with its access row
// and one member, returning the member's DID, user ID and the group ID.
func rd1301Group(t *testing.T, ts *testServerRBAC, orgID string, isOrgAdmin bool, claims []rbac.Claim, methods []string) (did, userID, groupID string) {
	t.Helper()
	ctx := context.Background()
	groupID = uuid.New().String()
	userID = uuid.New().String()
	did = "did:privado:rd1301-" + uuid.New().String()
	slug := "rd1301-" + groupID[:8]
	_, err := ts.db.Conn().ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, depth, is_org_admin)
		 VALUES ($1, $2, $3, $4, $5, 0, $6)`,
		groupID, orgID, slug, "RD-1301 group "+groupID[:8], slug, isOrgAdmin)
	require.NoError(t, err)
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: claims, AllowedMethods: methods,
	}))
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return did, userID, groupID
}

func rd1301Grant(t *testing.T, ts *testServerRBAC, contractID, groupID string) {
	t.Helper()
	require.NoError(t, ts.db.CreateContractGrant(context.Background(), &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID,
	}))
}

func rd1301Org(t *testing.T, ts *testServerRBAC, label string) string {
	t.Helper()
	orgID := uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(context.Background(), &rbac.Organization{
		ID: orgID, Slug: "rd1301-" + label + "-" + orgID[:8], Name: "RD-1301 " + label + " " + orgID[:8],
	}))
	return orgID
}

func rd1301Contract(t *testing.T, ts *testServerRBAC, orgID, addr string, deployer *string) string {
	t.Helper()
	id := uuid.New().String()
	require.NoError(t, ts.db.CreateContract(context.Background(), &rbac.Contract{
		ID: id, OrgID: orgID, Address: strings.ToLower(addr), Name: "C-" + addr[2:6], DeployedByUserID: deployer,
	}))
	return id
}

func setupRD1301(t *testing.T) *rd1301Fixture {
	t.Helper()
	ctx := context.Background()
	ts := setupTestServerForRBAC(t)
	up := newCountingUpstream(t)

	// Declare each proof/storage alias in the startup registry.
	withMethodAlias(t, "linea_getProof", "eth_getProof")
	rbac.MethodAliases["linea_getStorageAt"] = "eth_getStorageAt"
	rbac.ExtraMethods["linea_getProof"] = true
	rbac.ExtraMethods["linea_getStorageAt"] = true

	proc := NewJSONRPCProcessor(JSONRPCProcessorConfig{
		RBACAccessCtrl:     ts.rbacAccessCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              proxy.New(up.srv.URL),
		AccessLogger:       ts.db,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	})

	f := &rd1301Fixture{
		ts:          ts,
		proc:        proc,
		upstream:    up,
		contract:    fixedAddr(0xc1),
		deployed:    fixedAddr(0xc2),
		prereg:      fixedAddr(0xc3),
		foreignAddr: fixedAddr(0xf1),
	}

	orgA := rd1301Org(t, ts, "a")
	orgB := rd1301Org(t, ts, "b")
	contractID := rd1301Contract(t, ts, orgA, f.contract, nil)
	rd1301Contract(t, ts, orgB, f.foreignAddr, nil)
	require.NoError(t, ts.db.PreRegisterPlainCreate(ctx, orgA, f.prereg, "rd1301 planned deployment"))

	var groupID string
	f.memberDID, _, groupID = rd1301Group(t, ts, orgA, false, []rbac.Claim{}, rd1301Methods)
	rd1301Grant(t, ts, contractID, groupID)

	f.contractAdminDID, _, groupID = rd1301Group(t, ts, orgA, false, rbac.ExpandClaims([]rbac.Claim{rbac.ClaimAdmin}), rd1301Methods)
	rd1301Grant(t, ts, contractID, groupID)

	f.orgAdminDID, _, _ = rd1301Group(t, ts, orgA, true, []rbac.Claim{}, rd1301Methods)
	f.foreignAdminDID, _, _ = rd1301Group(t, ts, orgB, true, []rbac.Claim{}, rd1301Methods)

	var deployerUserID string
	f.deployerDID, deployerUserID, _ = rd1301Group(t, ts, orgA, false, []rbac.Claim{}, rd1301Methods)
	rd1301Contract(t, ts, orgA, f.deployed, &deployerUserID)

	f.preregDID, _, _ = rd1301Group(t, ts, orgA, false, rbac.ExpandClaims([]rbac.Claim{rbac.ClaimDeploy}), rd1301Methods)

	require.NotContains(t, rbac.ExpandWildcardMethods([]string{"*"}), "linea_getProof", "proof aliases require an explicit grant")
	expanded := rbac.ExpandWildcardMethods([]string{"*", "linea_getProof"})
	require.Contains(t, expanded, "linea_getProof", "the explicitly named proof alias is retained")
	f.starExpandedDID, _, groupID = rd1301Group(t, ts, orgA, false, []rbac.Claim{}, expanded)
	rd1301Grant(t, ts, contractID, groupID)

	f.literalStarDID, _, groupID = rd1301Group(t, ts, orgA, false, rbac.ExpandClaims([]rbac.Claim{rbac.ClaimDeploy}), []string{"*"})
	rd1301Grant(t, ts, contractID, groupID)

	// The admin claim is per contract: holding it in a group that has no
	// grant on the contract does not make a plain grant from another group an
	// admin grant.
	var splitUserID string
	f.splitAdminDID, splitUserID, groupID = rd1301Group(t, ts, orgA, false, []rbac.Claim{}, rd1301Methods)
	rd1301Grant(t, ts, contractID, groupID)
	_, _, adminGroupID := rd1301Group(t, ts, orgA, false, rbac.ExpandClaims([]rbac.Claim{rbac.ClaimAdmin}), rd1301Methods)
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: splitUserID, GroupID: adminGroupID, Source: rbac.MembershipSourceAdmin,
	}))

	return f
}

func rd1301Body(t *testing.T, method string, params []any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	return body
}

type rd1301Case struct {
	name    string
	did     string
	method  string
	params  []any
	bypass  bool // impersonation surface (view-as-user) re-resolves permissions
	allowed bool
}

func runRD1301Cases(t *testing.T, f *rd1301Fixture, cases []rd1301Case) {
	t.Helper()
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := rd1301Body(t, tc.method, tc.params)
			before := f.upstream.count.Load()
			res := f.proc.Process(ctx, &ProcessRequest{
				UserID: tc.did, Method: tc.method, Params: tc.params, Body: body, BypassPermsCache: tc.bypass,
			})
			reached := f.upstream.count.Load() - before
			if tc.allowed {
				require.Nil(t, res.Error, "expected the request to be allowed")
				assert.Equal(t, int32(1), reached, "an allowed request is forwarded exactly once")
				assert.Equal(t, body, f.upstream.lastBody(), "the node receives the validated body verbatim")
				assert.JSONEq(t, string(rd1301ProofResponse(body)), string(res.ResponseBody), "an allowed proof is returned unmodified")
				if tc.method == "eth_getProof" || tc.method == "linea_getProof" {
					var proof struct {
						Result struct {
							StorageProof []struct {
								Key string `json:"key"`
							} `json:"storageProof"`
						} `json:"result"`
					}
					require.NoError(t, json.Unmarshal(res.ResponseBody, &proof))
					requested := tc.params[1].([]any)
					require.Len(t, proof.Result.StorageProof, len(requested))
					for i, key := range requested {
						assert.Equal(t, key, proof.Result.StorageProof[i].Key)
					}
				}
				return
			}
			require.NotNil(t, res.Error, "expected an RBAC denial; a proof response would expose the slot value")
			assert.Equal(t, http.StatusNotFound, res.Error.StatusCode, "RBAC denials are opaque 404s")
			assert.Equal(t, "method not found", res.Error.Message, "denials must not say why")
			assert.Equal(t, int32(0), reached, "a denied request must never reach the upstream node")
		})
	}
}

func TestGetProofSlotPolicy_RD1301(t *testing.T) {
	f := setupRD1301(t)
	c := f.contract
	all4 := []any{rd1301ImplSlot, rd1301AdminSlot, rd1301BeaconSlot, rd1301DiamondSlot}

	runRD1301Cases(t, f, []rd1301Case{
		// eth_getStorageAt: the RD-805 tier the proof path must match.
		{name: "member getStorageAt ordinary slot denied", did: f.memberDID, method: "eth_getStorageAt",
			params: []any{c, rd1301OrdinarySlot, "latest"}},
		{name: "member getStorageAt well-known slot allowed", did: f.memberDID, method: "eth_getStorageAt",
			params: []any{c, rd1301ImplSlot, "latest"}, allowed: true},
		{name: "member getStorageAt non-string address denied", did: f.memberDID, method: "eth_getStorageAt",
			params: []any{float64(123), rd1301ImplSlot, "latest"}},
		{name: "contract admin getStorageAt ordinary slot allowed", did: f.contractAdminDID, method: "eth_getStorageAt",
			params: []any{c, rd1301OrdinarySlot, "latest"}, allowed: true},

		// Non-admin proofs: only the approved infrastructure slots.
		{name: "member getProof ordinary key denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "member getProof well-known key allowed", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}, allowed: true},
		{name: "member getProof all four well-known keys allowed", did: f.memberDID, method: "eth_getProof",
			params: []any{c, all4, "latest"}, allowed: true},
		{name: "member getProof zero keys (account proof) allowed", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{}, "latest"}, allowed: true},
		{name: "member getProof mixed well-known + ordinary keys denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot, rd1301OrdinarySlot}, "latest"}},
		{name: "member getProof ordinary key via impersonation denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}, bypass: true},

		// Malformed key lists and addresses fail closed.
		{name: "member getProof null keys denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, nil, "latest"}},
		{name: "member getProof keys as a string denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, rd1301ImplSlot, "latest"}},
		{name: "member getProof numeric key denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{float64(1)}, "latest"}},
		{name: "member getProof empty-string key denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{""}, "latest"}},
		{name: "member getProof nested key list denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{[]any{rd1301ImplSlot}}, "latest"}},
		{name: "member getProof object key denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{map[string]any{"key": rd1301ImplSlot}}, "latest"}},
		{name: "member getProof missing key list denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c}},
		{name: "member getProof non-string address denied", did: f.memberDID, method: "eth_getProof",
			params: []any{float64(123), []any{rd1301ImplSlot}, "latest"}},
		{name: "member getProof no params denied", did: f.memberDID, method: "eth_getProof",
			params: []any{}},

		// Aliases inherit the policy.
		{name: "member linea_getStorageAt alias ordinary slot denied", did: f.memberDID, method: "linea_getStorageAt",
			params: []any{c, rd1301OrdinarySlot, "latest"}},
		{name: "member linea_getStorageAt alias well-known slot allowed", did: f.memberDID, method: "linea_getStorageAt",
			params: []any{c, rd1301ImplSlot, "latest"}, allowed: true},
		{name: "member linea_getProof non-string address denied", did: f.memberDID, method: "linea_getProof",
			params: []any{nil, []any{}, "latest"}},
		{name: "member linea_getProof ordinary key denied", did: f.memberDID, method: "linea_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "member linea_getProof mixed keys denied", did: f.memberDID, method: "linea_getProof",
			params: []any{c, []any{rd1301ImplSlot, rd1301OrdinarySlot}, "latest"}},
		{name: "member linea_getProof well-known key allowed", did: f.memberDID, method: "linea_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}, allowed: true},
		{name: "member linea_getProof zero keys allowed", did: f.memberDID, method: "linea_getProof",
			params: []any{c, []any{}, "latest"}, allowed: true},

		// Every non-admin access path is non-admin for the slot policy.
		{name: "deployer (no grant) getProof ordinary key denied", did: f.deployerDID, method: "eth_getProof",
			params: []any{f.deployed, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "deployer (no grant) getProof well-known key allowed", did: f.deployerDID, method: "eth_getProof",
			params: []any{f.deployed, []any{rd1301ImplSlot}, "latest"}, allowed: true},
		{name: "deploy claim on pre-registered address getProof ordinary key denied", did: f.preregDID, method: "eth_getProof",
			params: []any{f.prereg, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "deploy claim on pre-registered address getProof well-known key allowed", did: f.preregDID, method: "eth_getProof",
			params: []any{f.prereg, []any{rd1301ImplSlot}, "latest"}, allowed: true},
		{name: "\"*\"-expanded group linea_getProof ordinary key denied", did: f.starExpandedDID, method: "linea_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "\"*\"-expanded group linea_getProof well-known key allowed", did: f.starExpandedDID, method: "linea_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}, allowed: true},
		{name: "literal \"*\" group getProof ordinary key denied", did: f.literalStarDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "literal \"*\" group getProof well-known key denied", did: f.literalStarDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}},
		{name: "admin claim without a grant + plain grant elsewhere getProof ordinary key denied", did: f.splitAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}},
		{name: "admin claim without a grant + plain grant elsewhere getProof well-known key allowed", did: f.splitAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}, allowed: true},

		// Admins keep the unrestricted same-org path.
		{name: "contract admin getProof ordinary key allowed", did: f.contractAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}, allowed: true},
		{name: "contract admin linea_getProof ordinary key allowed", did: f.contractAdminDID, method: "linea_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}, allowed: true},
		{name: "org admin getProof ordinary key allowed", did: f.orgAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, "latest"}, allowed: true},

		// Historical-state guard: only is_org_admin is exempt, and an alias
		// must not skip the guard its target method is subject to.
		{name: "member getProof well-known key at a block number denied", did: f.memberDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, rd1301HistoricalBN}},
		{name: "member linea_getProof well-known key at a block number denied", did: f.memberDID, method: "linea_getProof",
			params: []any{c, []any{rd1301ImplSlot}, rd1301HistoricalBN}},
		{name: "contract admin getProof at a block number denied", did: f.contractAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, rd1301HistoricalBN}},
		{name: "contract admin linea_getProof at a block number denied", did: f.contractAdminDID, method: "linea_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, rd1301HistoricalBN}},
		{name: "org admin getProof at a block number allowed", did: f.orgAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, rd1301HistoricalBN}, allowed: true},
		{name: "org admin linea_getProof at a block number allowed", did: f.orgAdminDID, method: "linea_getProof",
			params: []any{c, []any{rd1301OrdinarySlot}, rd1301HistoricalBN}, allowed: true},

		// Cross-org: an org admin of another org is denied, historical or not.
		{name: "foreign org admin getProof denied", did: f.foreignAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}},
		{name: "foreign org admin getProof at a block number denied", did: f.foreignAdminDID, method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, rd1301HistoricalBN}},
		{name: "member getProof on another org's contract denied", did: f.memberDID, method: "eth_getProof",
			params: []any{f.foreignAddr, []any{rd1301ImplSlot}, "latest"}},

		// Anonymous callers (default anonymous allowlist) are denied; an
		// allowlisted anonymous storage read is covered in internal/rbac.
		{name: "anonymous getProof denied", did: "", method: "eth_getProof",
			params: []any{c, []any{rd1301ImplSlot}, "latest"}},
	})
}

// TestHandleTestRequest_AliasResolvedLikeRPC_RD1301 pins that the admin
// test-request diagnostic evaluates a configured alias exactly as /rpc does.
// It forwards to the node, so an alias that skipped target extraction would
// skip the contract, cross-org and storage-slot checks there.
func TestHandleTestRequest_AliasResolvedLikeRPC_RD1301(t *testing.T) {
	f := setupRD1301(t)
	ctx := context.Background()

	// The synthetic dashboard identity, as a plain grant holder in the
	// contract's org.
	orgA, err := f.ts.db.GetContractOwnerOrgID(ctx, f.contract)
	require.NoError(t, err)
	contract, err := f.ts.db.GetContractByAddress(ctx, orgA, f.contract)
	require.NoError(t, err)
	require.NotNil(t, contract)
	groupID := uuid.New().String()
	userID := uuid.New().String()
	insertGroupRawSQL(t, ctx, f.ts.db, groupID, orgA,
		"rd1301-dash-"+groupID[:8], "RD-1301 dashboard "+groupID[:8], "rd1301-dash-"+groupID[:8])
	require.NoError(t, f.ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{}, AllowedMethods: rd1301Methods,
	}))
	require.NoError(t, f.ts.db.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: "test:dashboard", KYC: true}))
	require.NoError(t, f.ts.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	rd1301Grant(t, f.ts, contract.ID, groupID)

	f.ts.Server.proxy = proxy.New(f.upstream.srv.URL)
	router := gin.New()
	api := router.Group("/api/v1/admin")
	api.Use(f.ts.Server.localhostOnlyMiddleware())
	api.POST("/test-request", f.ts.Server.handleTestRequest)

	cases := []struct {
		name    string
		method  string
		params  []any
		allowed bool
	}{
		{"alias ordinary key on granted contract denied", "linea_getProof", []any{f.contract, []any{rd1301OrdinarySlot}, "latest"}, false},
		{"alias on another org's contract denied", "linea_getProof", []any{f.foreignAddr, []any{rd1301ImplSlot}, "latest"}, false},
		{"alias at a block number denied", "linea_getProof", []any{f.contract, []any{rd1301ImplSlot}, rd1301HistoricalBN}, false},
		{"direct ordinary key denied", "eth_getProof", []any{f.contract, []any{rd1301OrdinarySlot}, "latest"}, false},
		{"alias well-known key allowed", "linea_getProof", []any{f.contract, []any{rd1301ImplSlot}, "latest"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(apimodels.TestRequestInput{Method: tc.method, Params: tc.params})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/test-request", bytes.NewReader(payload))
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			before := f.upstream.count.Load()
			router.ServeHTTP(w, req)
			reached := f.upstream.count.Load() - before

			if tc.allowed {
				assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
				assert.Equal(t, int32(1), reached)
				return
			}
			assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, int32(0), reached, "a denied test request must never reach the upstream node")
		})
	}
}
