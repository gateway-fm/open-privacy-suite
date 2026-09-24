package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	privacyredis "privacy-proxy/internal/redis"
	"privacy-proxy/internal/tracer"
)

// startPreflightTestRedis starts a password-protected Redis (production refuses
// one without a password) and returns its URL.
func startPreflightTestRedis(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	const password = "preflight-limit-test-only"
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			Cmd:          []string{"redis-server", "--requirepass", password},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)
	return fmt.Sprintf("redis://:%s@%s/0", password, net.JoinHostPort(host, port.Port()))
}

// preflightNode stands in for the node that runs the approval preflight. It
// answers the chain and head lookups a preflight starts with, refuses the
// simulation itself (debug_traceCall on Reth, ops_prepareApproval on Besu),
// and counts both every request and every simulation it was asked to run.
type preflightNode struct {
	url         string
	requests    atomic.Int64
	simulations atomic.Int64
}

func startPreflightNode(t *testing.T) *preflightNode {
	t.Helper()
	node := &preflightNode{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node.requests.Add(1)
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if len(request.ID) == 0 {
			request.ID = json.RawMessage("1")
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "eth_chainId":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x7a69"}`, request.ID)
		case "eth_getHeaderByNumber":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"hash":"0x%s"}}`, request.ID, strings.Repeat("11", 32))
		default:
			if request.Method == "debug_traceCall" || request.Method == "ops_prepareApproval" {
				node.simulations.Add(1)
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"test node refuses to simulate"}}`, request.ID)
		}
	}))
	t.Cleanup(server.Close)
	node.url = server.URL
	return node
}

// startApprovalSink runs a stand-in block producer: it confirms every batch and
// answers Status for chain 31337 trusting the key id "default", so an approvals
// service delivering to it counts as ready.
func startApprovalSink(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}))
	approvalpb.RegisterApprovalDeliveryServer(server, approvalSink{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}

type approvalSink struct {
	approvalpb.UnimplementedApprovalDeliveryServer
}

func (approvalSink) Deliver(context.Context, *approvalpb.DeliverRequest) (*approvalpb.DeliverResponse, error) {
	return &approvalpb.DeliverResponse{BootId: "sink", Stored: 1}, nil
}

func (approvalSink) Status(context.Context, *approvalpb.StatusRequest) (*approvalpb.StatusResponse, error) {
	return &approvalpb.StatusResponse{BootId: "sink", ChainId: 31337, TrustedKeyIds: []string{"default"},
		MaxTtlMs: 3_600_000, Capacity: 100_000, WaitMs: 5_000}, nil
}

// isolateApprovalEnv pins every setting the approvals service and the preflight
// limit read, so a developer's environment cannot change the test.
func isolateApprovalEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"OPS_APPROVAL_NODE", "OPS_APPROVAL_HASH_MODE", "OPS_APPROVAL_KEY_ID", "OPS_APPROVAL_TTL",
		"OPS_APPROVAL_MAX_BATCH", "OPS_APPROVAL_HOPS_FILE", "OPS_APPROVAL_HOPS_LIMIT",
		preflightRateEnv, preflightBurstEnv,
	} {
		t.Setenv(name, "")
	}
}

// newApprovalInstance builds one OPS instance's JSON-RPC processor with signed
// approvals on, the way the server wires it — its own access controller,
// tracer and approvals service, sharing the database and the node with every
// other instance — but without the preflight limit, which the caller installs.
func newApprovalInstance(t *testing.T, ts *testServerRBAC, nodeURL, sink string) *JSONRPCProcessor {
	t.Helper()
	access := rbac.NewAccessController(ts.db, 5*time.Minute)
	t.Cleanup(access.Stop)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: nodeURL, Enabled: true, Timeout: 5 * time.Second})
	t.Cleanup(rt.Stop)
	p := NewJSONRPCProcessorWithTracing(access, &noopRateLimiter{}, proxy.New(nodeURL), ts.db, rt,
		rbac.NewTraceValidator(ts.db), NewCircuitBreaker(), NewConcurrencyLimiter(50, 0), "")
	approvals, err := nodeapproval.New(nodeURL, sink, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	t.Cleanup(approvals.Close)
	require.Eventually(t, approvals.Accepting, 5*time.Second, 10*time.Millisecond, "the stand-in producer never became ready")
	p.nodeApprovals = approvals
	return p
}

// connectPreflightRedis opens a Redis client the way the server does.
func connectPreflightRedis(t *testing.T, redisURL string) *privacyredis.Client {
	t.Helper()
	client, err := privacyredis.NewClient(redisURL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// approvalSenders sets up two members of one group, both allowed to send
// transactions to contract, and returns their DIDs and the organization.
func approvalSenders(t *testing.T, ts *testServerRBAC, contract string) (alice, bob, org string) {
	t.Helper()
	ctx := context.Background()
	alice, org, groupID, contractID := callerSameOrgWithGroup(t, ctx, ts, contract)
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: contractID, GroupID: groupID}))
	bobID := uuid.New().String()
	bob = "did:privado:member-" + uuid.New().String()
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: bobID, ExternalID: bob}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: bobID, GroupID: groupID, Source: rbac.MembershipSourceAdmin}))
	_, err := ts.db.Conn().ExecContext(ctx, "UPDATE group_access SET allowed_methods=ARRAY['eth_sendTransaction'] WHERE group_id=$1", groupID)
	require.NoError(t, err)
	_, err = ts.db.Conn().ExecContext(ctx, "UPDATE users SET kyc=true")
	require.NoError(t, err)
	return alice, bob, org
}

// accessLogEntry is what the access-log writer was given for one request.
type accessLogEntry struct {
	status       int
	orgID        string
	denialReason string
}

// accessLogRecorder is the access-log writer of a test processor; it keeps
// every entry instead of writing it to the audit database.
type accessLogRecorder struct {
	mu      sync.Mutex
	entries []accessLogEntry
}

func (r *accessLogRecorder) record(status int, orgID, denialReason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, accessLogEntry{status: status, orgID: orgID, denialReason: denialReason})
}

func (r *accessLogRecorder) last() (accessLogEntry, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return accessLogEntry{}, 0
	}
	return r.entries[len(r.entries)-1], len(r.entries)
}

func (r *accessLogRecorder) LogAccessChained(_ context.Context, _ db.RBACAuditChain, _, _ string, status int, _, _ string, _ []byte, _ *int, orgID, denialReason string) (int64, time.Time, string, error) {
	r.record(status, orgID, denialReason)
	return 1, time.Now(), "hash", nil
}

func (r *accessLogRecorder) LogAccessEnhanced(_ context.Context, _, _ string, status int, _, _ string, _ []byte, _ *int, orgID, denialReason string) (int64, time.Time, error) {
	r.record(status, orgID, denialReason)
	return 1, time.Now(), nil
}

func (r *accessLogRecorder) UpdateAccessLogHash(context.Context, int64, string) error { return nil }

// recordAccessLog routes p's access-log writes to a recorder.
func recordAccessLog(p *JSONRPCProcessor) *accessLogRecorder {
	recorder := &accessLogRecorder{}
	p.SetEnhancedAudit(recorder, audit.NewHashChain(""), nil, false)
	return recorder
}

// sendRaw submits raw as principal through the processor's entry point and
// reports what the node was asked meanwhile.
func sendRaw(t *testing.T, p *JSONRPCProcessor, node *preflightNode, org, raw, principal string) (req *ProcessRequest, result *ProcessResult, requests, simulations int64) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []any{raw}})
	require.NoError(t, err)
	req = &ProcessRequest{UserID: principal, OrgID: org, Method: "eth_sendRawTransaction", Params: []any{raw}, Body: body, ClientIP: "127.0.0.1"}
	requestsBefore, simulationsBefore := node.requests.Load(), node.simulations.Load()
	result = p.Process(context.Background(), req)
	return req, result, node.requests.Load() - requestsBefore, node.simulations.Load() - simulationsBefore
}

// signedContractCall returns a signed EIP-155 raw transaction calling `to`.
func signedContractCall(t *testing.T, to string) string {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	target := common.HexToAddress(to)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      100_000,
		To:       &target,
		Data:     []byte{0xd0, 0x9d, 0xe0, 0x8a},
	})
	signed, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(31337)), key)
	require.NoError(t, err)
	raw, err := signed.MarshalBinary()
	require.NoError(t, err)
	return "0x" + hex.EncodeToString(raw)
}

// Two OPS instances on one Redis share each principal's preflight budget. A
// principal over it is refused before any simulation — the node sees nothing —
// while another principal keeps its own full budget.
func TestApprovalPreflightLimit_SharedAcrossInstances(t *testing.T) {
	isolateApprovalEnv(t)
	// Two preflights per principal, then one per 1000 s: nothing refills while
	// the test runs.
	t.Setenv(preflightRateEnv, "0.001")
	t.Setenv(preflightBurstEnv, "2")

	ts := setupTestServerForRBAC(t)
	contract := "0x0000000000000000000000000000000000001100"
	alice, bob, org := approvalSenders(t, ts, contract)
	node := startPreflightNode(t)
	sink := startApprovalSink(t)
	redisURL := startPreflightTestRedis(t)
	first := newApprovalInstance(t, ts, node.url, sink)
	require.NoError(t, first.configurePreflightLimit(connectPreflightRedis(t, redisURL)))
	second := newApprovalInstance(t, ts, node.url, sink)
	require.NoError(t, second.configurePreflightLimit(connectPreflightRedis(t, redisURL)))
	accessLogs := map[*JSONRPCProcessor]*accessLogRecorder{first: recordAccessLog(first), second: recordAccessLog(second)}
	raw := signedContractCall(t, contract)

	admitted := func(p *JSONRPCProcessor, principal, step string) {
		t.Helper()
		_, result, _, simulations := sendRaw(t, p, node, org, raw, principal)
		require.NotNil(t, result.Error, step)
		require.NotEqual(t, http.StatusTooManyRequests, result.Error.StatusCode, "%s: must not be rate limited: %+v", step, result.Error)
		// The test node refuses to simulate, so an admitted call ends as an
		// unavailable preflight — after the node was asked to run it.
		require.Equal(t, ReasonTracingUnavailable, result.Error.Reason, "%s: %+v", step, result.Error)
		require.Positive(t, simulations, "%s: an admitted call has the node simulate the transaction", step)
	}
	limited := func(p *JSONRPCProcessor, principal, step string) {
		t.Helper()
		_, loggedBefore := accessLogs[p].last()
		req, result, requests, _ := sendRaw(t, p, node, org, raw, principal)
		require.NotNil(t, result.Error, step)
		require.Equal(t, http.StatusTooManyRequests, result.Error.StatusCode, "%s: %+v", step, result.Error)
		require.Equal(t, "rate limit exceeded (requests per second)", result.Error.Message, step)
		require.Equal(t, ReasonRateLimited, result.Error.Reason, step)
		require.Equal(t, ReasonRateLimited, req.denialReason, "%s: verbose errors carry the reason", step)
		require.Zero(t, requests, "%s: a limited call must not reach the node at all", step)
		entry, logged := accessLogs[p].last()
		require.Equal(t, loggedBefore+1, logged, "%s: the refusal is written to the access log once", step)
		require.Equal(t, accessLogEntry{status: http.StatusTooManyRequests, orgID: org, denialReason: ReasonRateLimited}, entry,
			"%s: logged as a 429 with its reason, in the caller's organization", step)
	}

	admitted(first, alice, "alice's 1st preflight, instance 1")
	admitted(second, alice, "alice's 2nd preflight, instance 2")
	// Each instance has seen only one of alice's preflights; a per-instance
	// limit of two would still admit both of these.
	limited(first, alice, "alice's 3rd preflight, instance 1")
	limited(second, alice, "alice's 4th preflight, instance 2")
	admitted(second, bob, "bob's 1st preflight, instance 2")
	admitted(first, bob, "bob's 2nd preflight, instance 1")
	limited(first, bob, "bob's 3rd preflight, instance 1")
}

// A processor with signed approvals on whose limit was never installed refuses
// to simulate at all, rather than simulating without a bound.
func TestApprovalPreflightLimit_RefusesWhenNotConfigured(t *testing.T) {
	isolateApprovalEnv(t)
	ts := setupTestServerForRBAC(t)
	contract := "0x0000000000000000000000000000000000001100"
	alice, _, org := approvalSenders(t, ts, contract)
	node := startPreflightNode(t)
	p := newApprovalInstance(t, ts, node.url, startApprovalSink(t))

	req, result, requests, _ := sendRaw(t, p, node, org, signedContractCall(t, contract), alice)
	require.NotNil(t, result.Error)
	require.Equal(t, http.StatusForbidden, result.Error.StatusCode, "%+v", result.Error)
	require.Equal(t, "signed preflight unavailable or unsupported transaction", result.Error.Message)
	require.Equal(t, ReasonTracingUnavailable, req.denialReason)
	require.Zero(t, requests, "nothing reaches the node")
}
