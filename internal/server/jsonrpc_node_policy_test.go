package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
)

const nodeRPCTarget = "0x2222222222222222222222222222222222222222"

type nodeRPCStore struct {
	rbac.Store // Unexpected legacy authorization calls deliberately panic.
	user       *rbac.User
	linked     []string
	methods    []string
}

func (s *nodeRPCStore) GetUserByExternalID(_ context.Context, did string) (*rbac.User, error) {
	if s.user.ExternalID == did {
		return s.user, nil
	}
	return nil, nil
}
func (s *nodeRPCStore) GetOrganization(_ context.Context, id string) (*rbac.Organization, error) {
	return &rbac.Organization{ID: id}, nil
}
func (s *nodeRPCStore) GetContractOwnerOrgID(context.Context, string) (string, error) {
	return "org-node", nil
}
func (s *nodeRPCStore) ListUserMembershipsWithDetails(context.Context, string) ([]*rbac.MembershipWithDetails, error) {
	return []*rbac.MembershipWithDetails{{Group: &rbac.Group{ID: "group-node", OrgID: "org-node"}}}, nil
}
func (s *nodeRPCStore) GetCachedPermissions(_ context.Context, user, org string) (*rbac.EffectivePermissions, error) {
	return &rbac.EffectivePermissions{UserID: user, OrgID: org, AllowedMethods: s.methods, ContractAccess: map[string]rbac.ContractAccess{}, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (s *nodeRPCStore) GetLinkedEthAddresses(context.Context, string) ([]string, error) {
	return s.linked, nil
}
func (s *nodeRPCStore) IsOrgAdmin(context.Context, string) (bool, []string, error) {
	return false, nil, nil
}

type nodeRPCLogger struct{ statuses []int }

func (l *nodeRPCLogger) LogAccess(_ context.Context, _, _ string, status int, _ string) error {
	l.statuses = append(l.statuses, status)
	return nil
}

type nodeRPCService struct {
	prepared      []NodeExecutionIdentityRequest
	requests      [][]byte
	submissions   []string
	err           error
	executionErr  error
	wrongHash     bool
	invalidResult bool
	metadata      []NodeSubmissionMetadata
}

func (n *nodeRPCService) PrepareIdentity(_ context.Context, r NodeExecutionIdentityRequest) ([]byte, error) {
	n.prepared = append(n.prepared, r)
	if n.err != nil {
		return nil, n.err
	}
	return []byte(`{"signed":"fixture"}`), nil
}
func (n *nodeRPCService) SubmitTransaction(_ context.Context, identity []byte, raw string, metadata NodeSubmissionMetadata) (nodepolicy.Submission, error) {
	n.metadata = append(n.metadata, metadata)
	n.submissions = append(n.submissions, raw)
	if n.executionErr != nil {
		return nodepolicy.Submission{}, n.executionErr
	}
	b, _ := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	var tx types.Transaction
	if err := tx.UnmarshalBinary(b); err != nil {
		return nodepolicy.Submission{}, err
	}
	hash := tx.Hash().Hex()
	if n.wrongHash {
		hash = common.Hash{}.Hex()
	}
	return nodepolicy.Submission{TransactionHash: hash, ContextID: "context-node", Status: "accepted"}, nil
}
func (n *nodeRPCService) Simulate(_ context.Context, identity, request []byte) (json.RawMessage, error) {
	n.requests = append(n.requests, append([]byte(nil), request...))
	if n.executionErr != nil {
		return nil, n.executionErr
	}
	if n.invalidResult {
		return json.RawMessage(`{"broken":`), nil
	}
	return json.RawMessage(`"0x1234"`), nil
}

func nodeRPCFixture(t *testing.T) (*JSONRPCProcessor, *nodeRPCStore, *nodeRPCService, string) {
	t.Helper()
	key, err := crypto.HexToECDSA(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	signer := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	to := common.HexToAddress(nodeRPCTarget)
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: 1, To: &to, Gas: 100000, GasPrice: big.NewInt(1), Data: []byte{0xde, 0xad, 0xbe, 0xef}}), types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	store := &nodeRPCStore{user: &rbac.User{ID: "principal-node", ExternalID: "did:test:node", KYC: true}, linked: []string{signer}, methods: []string{"eth_call", "eth_estimateGas", "debug_traceCall", "eth_sendTransaction"}}
	service := &nodeRPCService{}
	p := NewJSONRPCProcessor(JSONRPCProcessorConfig{RBACAccessCtrl: rbac.NewAccessController(store, time.Minute), NodeExecution: service, AccessLogger: &nodeRPCLogger{}, RateLimiter: &noopRateLimiter{}, ConcurrencyLimiter: middleware.NewConcurrencyLimiter(3, 0)})
	t.Cleanup(p.rbacAccessCtrl.Stop)
	return p, store, service, "0x" + hex.EncodeToString(b)
}

type nodeTraceLimiter struct {
	calls      int
	rps, daily int
}

func (l *nodeTraceLimiter) Stop() {}
func (l *nodeTraceLimiter) CheckAndIncrement(_ string, rps, daily *int) (bool, string) {
	l.calls++
	if rps != nil {
		l.rps = *rps
	}
	if daily != nil {
		l.daily = *daily
	}
	return false, "trace request limit reached"
}
func TestNodeExecutionTraceLimitPrecedesPrivateExecution(t *testing.T) {
	for _, absent := range []bool{false, true} {
		p, _, node, _ := nodeRPCFixture(t)
		limiter := &nodeTraceLimiter{}
		p.rateLimiter = limiter
		if absent {
			p.rateLimiter = nil
		}
		result := p.Process(context.Background(), nodeRPCRequest(t, "debug_traceCall", []any{map[string]any{"to": nodeRPCTarget}, "latest"}))
		want := 429
		if absent {
			want = 503
		}
		if result.Error == nil || result.Error.StatusCode != want || len(node.prepared) != 0 || len(node.requests) != 0 {
			t.Fatalf("trace bypassed limit: absent=%v result=%+v identity=%d calls=%d", absent, result, len(node.prepared), len(node.requests))
		}
		if !absent && (limiter.calls != 1 || limiter.rps != 1 || limiter.daily != 100) {
			t.Fatalf("wrong trace limits: %+v", limiter)
		}
	}
}

func nodeRPCRequest(t *testing.T, method string, params []any) *ProcessRequest {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 42, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	return &ProcessRequest{UserID: "did:test:node", Method: method, Params: params, Body: b}
}

func TestNodeExecutionRoutesActualSignedTransactionWithoutLegacyTrace(t *testing.T) {
	p, store, node, raw := nodeRPCFixture(t)
	result := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if result.Error != nil || result.StatusCode != 200 || len(node.submissions) != 1 {
		t.Fatalf("result=%+v submissions=%v", result, node.submissions)
	}
	i := node.prepared[0]
	if i.PrincipalID != store.user.ID || i.OrgID != "org-node" || i.Signer != store.linked[0] || i.Scope != "transaction" {
		t.Fatalf("wrong identity: %+v", i)
	}
	bytes, _ := hex.DecodeString(raw[2:])
	if i.BindingHash != crypto.Keccak256Hash(bytes).Hex() {
		t.Fatal("identity not bound to exact transaction")
	}
}

func TestNodeExecutionSimulationsBindExactNormalizedRequest(t *testing.T) {
	for _, method := range []string{"eth_call", "eth_estimateGas", "debug_traceCall"} {
		t.Run(method, func(t *testing.T) {
			p, store, node, _ := nodeRPCFixture(t)
			req := nodeRPCRequest(t, method, []any{map[string]any{"to": nodeRPCTarget, "data": "0xdeadbeef"}, "latest"})
			result := p.Process(context.Background(), req)
			if result.Error != nil || len(node.requests) != 1 {
				t.Fatalf("result=%+v requests=%d", result, len(node.requests))
			}
			identity := node.prepared[0]
			request, err := nodepolicy.ParseSimulation(node.requests[0], identity.BindingHash)
			if err != nil || identity.Scope != "simulation" || identity.Signer != store.linked[0] || request.Method != method {
				t.Fatalf("request=%+v identity=%+v err=%v", request, identity, err)
			}
			var rawParams []json.RawMessage
			if err := json.Unmarshal(request.Params, &rawParams); err != nil {
				t.Fatal(err)
			}
			var call map[string]any
			_ = json.Unmarshal(rawParams[0], &call)
			if call["from"] != store.linked[0] {
				t.Fatal("default signer not included in signed bytes")
			}
		})
	}
}

func TestNodeExecutionFailuresNeverFallBackToLegacyProxy(t *testing.T) {
	for _, name := range []string{"stale", "banned", "unlinked", "ambiguous-from", "method", "plain-send"} {
		t.Run(name, func(t *testing.T) {
			p, store, node, raw := nodeRPCFixture(t)
			method := "eth_sendRawTransaction"
			params := []any{raw}
			switch name {
			case "stale":
				node.err = nodepolicy.ErrSnapshotLag
			case "banned":
				store.user.Banned = true
			case "unlinked":
				store.linked = nil
			case "ambiguous-from":
				store.linked = append(store.linked, nodeRPCTarget)
				method = "eth_call"
				params = []any{map[string]any{"to": nodeRPCTarget}, "latest"}
			case "method":
				store.methods = nil
			case "plain-send":
				method = "eth_sendTransaction"
				params = []any{map[string]any{"from": store.linked[0], "to": nodeRPCTarget}}
			}
			result := p.Process(context.Background(), nodeRPCRequest(t, method, params))
			if result.Error == nil || len(node.submissions) != 0 || len(node.requests) != 0 {
				t.Fatalf("invalid request forwarded: %+v", result)
			}
		})
	}
}

func TestNodeExecutionServiceErrorsAreOpaque(t *testing.T) {
	p, _, node, raw := nodeRPCFixture(t)
	node.err = errors.New("private key details 0xdeadbeef")
	got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || strings.Contains(got.Error.Message, "private key") {
		t.Fatalf("unsafe error: %+v", got)
	}
}

func TestNodeExecutionRejectedDoesNotClaimMethodDenied(t *testing.T) {
	p, _, node, raw := nodeRPCFixture(t)
	node.executionErr = nodepolicy.ErrNodeRejected
	got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || got.Error.Reason != "node_rejected" || got.Error.Message != "request rejected by execution node" {
		t.Fatalf("misleading rejection: %+v", got.Error)
	}
}

func TestNodeExecutionUnsupportedMethodsNeverEnterLegacyTracePipeline(t *testing.T) {
	for _, method := range []string{"debug_traceTransaction", "eth_createAccessList"} {
		p, _, node, _ := nodeRPCFixture(t)
		got := p.Process(context.Background(), nodeRPCRequest(t, method, []any{}))
		if got.Error == nil || got.Error.StatusCode != 400 || got.Error.Message != "method is unavailable in Reth policy mode" || len(node.prepared) != 0 {
			t.Fatalf("unsupported method used fallback: %s %+v", method, got.Error)
		}
	}
}

func nodeRPCSign(t *testing.T, to *common.Address, data []byte, value int64) string {
	t.Helper()
	key, err := crypto.HexToECDSA(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: 7, To: to, Gas: 100000, GasPrice: big.NewInt(1), Data: data, Value: big.NewInt(value)}), types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return "0x" + hex.EncodeToString(b)
}

func TestNodeExecutionSharedSignerDoesNotMergePrincipals(t *testing.T) {
	var identities []NodeExecutionIdentityRequest
	for _, principal := range []string{"alice", "bob"} {
		p, store, node, raw := nodeRPCFixture(t)
		store.user.ID = principal
		store.user.ExternalID = "did:test:" + principal
		req := nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw})
		req.UserID = store.user.ExternalID
		if got := p.Process(context.Background(), req); got.Error != nil {
			t.Fatal(got.Error)
		}
		identities = append(identities, node.prepared[0])
	}
	if identities[0].Signer != identities[1].Signer || identities[0].PrincipalID == identities[1].PrincipalID {
		t.Fatalf("identity collapse: %+v", identities)
	}
}

func TestNodeExecutionCanonicalMethodsAndAliases(t *testing.T) {
	previous, existed := rbac.MethodAliases["linea_estimateGas"]
	rbac.MethodAliases["linea_estimateGas"] = "eth_estimateGas"
	t.Cleanup(func() {
		if existed {
			rbac.MethodAliases["linea_estimateGas"] = previous
		} else {
			delete(rbac.MethodAliases, "linea_estimateGas")
		}
	})
	for _, method := range []string{"ETH_CALL", "linea_estimateGas"} {
		t.Run(method, func(t *testing.T) {
			p, store, node, _ := nodeRPCFixture(t)
			// Chain aliases are still explicitly controlled by the original
			// method allowlist, while their signed node request is canonical.
			store.methods = append(store.methods, method)
			got := p.Process(context.Background(), nodeRPCRequest(t, method, []any{map[string]any{"to": nodeRPCTarget}, "latest"}))
			if got.Error != nil || len(node.requests) != 1 {
				t.Fatalf("alias %s: %+v", method, got)
			}
			request, err := nodepolicy.ParseSimulation(node.requests[0], node.prepared[0].BindingHash)
			if err != nil || request.Method != rbac.ResolveMethodAlias(rbac.CanonicalizeMethod(method)) {
				t.Fatalf("wrong alias binding: %+v %v", request, err)
			}
		})
	}
}

func TestNodeExecutionNodeRejectionAndMalformedRepliesFailClosed(t *testing.T) {
	for _, name := range []string{"transaction-denied", "simulation-denied", "wrong-hash", "invalid-result"} {
		t.Run(name, func(t *testing.T) {
			p, _, node, raw := nodeRPCFixture(t)
			method, params := "eth_sendRawTransaction", []any{raw}
			if name == "simulation-denied" || name == "invalid-result" {
				method, params = "eth_call", []any{map[string]any{"to": nodeRPCTarget}}
			}
			if strings.HasSuffix(name, "denied") {
				node.executionErr = nodepolicy.ErrNodeRejected
			}
			node.wrongHash = name == "wrong-hash"
			node.invalidResult = name == "invalid-result"
			got := p.Process(context.Background(), nodeRPCRequest(t, method, params))
			if got.Error == nil {
				t.Fatalf("accepted invalid execution: %+v", got)
			}
			want := 503
			if node.executionErr != nil {
				want = 403
			}
			if got.Error.StatusCode != want {
				t.Fatalf("status=%d want=%d", got.Error.StatusCode, want)
			}
		})
	}
}

func TestNodeExecutionConcurrencyAndCircuitLimits(t *testing.T) {
	p, store, node, raw := nodeRPCFixture(t)
	p.concurrencyLimiter = middleware.NewConcurrencyLimiter(1, 0)
	p.concurrencyLimiter.TryAcquire(store.user.ExternalID)
	got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || got.Error.StatusCode != 429 || len(node.prepared) != 0 {
		t.Fatalf("concurrency not enforced: %+v", got)
	}
	p.concurrencyLimiter.Release(store.user.ExternalID)
	p.circuitBreaker = middleware.NewCircuitBreaker()
	p.defaultRPCAPIKey = "test-key"
	p.circuitBreaker.Trip("test-key")
	got = p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || got.Error.StatusCode != 429 || len(node.prepared) != 0 {
		t.Fatalf("circuit not enforced: %+v", got)
	}
	p.circuitBreaker.Reset("test-key")
	node.err = nodepolicy.ErrSnapshotLag
	got = p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || !p.concurrencyLimiter.TryAcquire(store.user.ExternalID) {
		t.Fatal("failure leaked concurrency slot")
	}
	p.concurrencyLimiter.Release(store.user.ExternalID)
}

type nodeRPCComplianceStore struct {
	compliance.Store
	org string
}

func (s *nodeRPCComplianceStore) GetComplianceConfig(_ context.Context, org string) (*compliance.ComplianceConfig, error) {
	s.org = org
	return nil, errors.New("private compliance database unavailable")
}
func TestNodeExecutionComplianceFailurePreventsSubmission(t *testing.T) {
	p, _, node, _ := nodeRPCFixture(t)
	store := &nodeRPCComplianceStore{}
	p.complianceChecker = compliance.NewChecker(store, time.Minute, time.Minute)
	target := common.HexToAddress(nodeRPCTarget)
	raw := nodeRPCSign(t, &target, nil, 123)
	got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || got.Error.StatusCode != 500 || store.org != "org-node" || len(node.prepared) != 0 || strings.Contains(got.Error.Message, "database") {
		t.Fatalf("compliance bypass: %+v org=%s", got, store.org)
	}
}

type nodeRPCVisibility struct {
	stubTxVisibilityProvider
	hash, sender, org string
	dids              []string
}

func (v *nodeRPCVisibility) SaveTxVisibility(context.Context, string, []string, string, string) error {
	panic("must use outbox")
}
func (v *nodeRPCVisibility) EnqueuePendingTxVisibility(_ context.Context, hash string, dids []string, sender, org string) error {
	v.hash, v.sender, v.org, v.dids = hash, sender, org, append([]string(nil), dids...)
	return nil
}
func TestNodeExecutionHandsVisibilityToDurableSubmission(t *testing.T) {
	p, store, node, raw := nodeRPCFixture(t)
	visibility := &nodeRPCVisibility{}
	p.txVisibilityStore = visibility
	kicked := false
	p.visibilityKick = func() { kicked = true }
	req := nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw, map[string]any{"visibleTo": []any{"did:test:bob"}}})
	var env map[string]any
	if err := json.Unmarshal(req.Body, &env); err != nil {
		t.Fatal(err)
	}
	env["privateFor"] = []string{"did:test:alice", "did:test:bob"}
	req.Body, _ = json.Marshal(env)
	got := p.Process(context.Background(), req)
	if got.Error != nil || len(node.metadata) != 1 || node.metadata[0].SenderDID != store.user.ExternalID || len(node.metadata[0].VisibleTo) != 2 || visibility.hash != "" || kicked {
		t.Fatalf("visibility missing: %+v %+v", got, visibility)
	}
	if strings.Contains(string(req.Body), "visibleTo") || strings.Contains(string(req.Body), "privateFor") || len(req.Params) != 1 {
		t.Fatal("privacy metadata not stripped")
	}
	visibility.hash = ""
	node.executionErr = nodepolicy.ErrNodeRejected
	got = p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw, map[string]any{"visibleTo": []any{"did:test:bob"}}}))
	if got.Error == nil || visibility.hash != "" {
		t.Fatal("visibility persisted for rejected transaction")
	}
}

func TestNodeExecutionLeavesCreateRegistrationToCanonicalReconciliation(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		p, _, node, _ := nodeRPCFixture(t)
		raw := nodeRPCSign(t, nil, []byte{0x60, 0x00, 0x60, 0x00, 0xf3}, 0)
		if rejected {
			node.executionErr = nodepolicy.ErrNodeRejected
		}
		got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
		if rejected {
			if got.Error == nil || p.rbacAccessCtrl.PendingDeploymentCount() != 0 {
				t.Fatal("rejected deployment tracked")
			}
			continue
		}
		if got.Error != nil {
			t.Fatal(got.Error)
		}
		if p.rbacAccessCtrl.PendingDeploymentCount() != 0 || len(node.metadata) != 1 {
			t.Fatal("node CREATE used legacy transient registration")
		}
	}
}
