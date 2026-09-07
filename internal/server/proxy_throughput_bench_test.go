package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"
)

// PROXY THROUGHPUT BENCHMARK (RD-1112). Measures the OPEN PRIVACY SUITE's own
// per-request cost end-to-end — decode + ecrecover + RBAC access check + audit
// + forward — with the Ethereum node MOCKED (instant canned responses), so the
// number reflects the proxy, not node execution. b.RunParallel simulates
// concurrent load; middleware.NewConcurrencyLimiter(50, 0) mirrors the per-user cap, so keep
// -cpu <= 50 for single-user runs (seed more users to exceed it).
//
// CI: run on a LINUX runner against a real Postgres for representative fsync
// semantics (a macOS dev box uses F_FULLFSYNC and is NOT representative):
//
//	PROXY_BENCH_DSN=postgres://user:pass@pg:5432/privacy_proxy?sslmode=disable \
//	  go test -run '^$' -bench BenchmarkProxyValueTransfer -benchmem -cpu 8,32 ./internal/server/
//
// Compare SyncAudit vs AsyncAudit, and track across commits with benchstat to
// see whether a change made the proxy faster or slower.
func proxyBenchDSN(b *testing.B) string {
	dsn := os.Getenv("PROXY_BENCH_DSN")
	if dsn == "" {
		b.Skip("set PROXY_BENCH_DSN to a real migrated Postgres (Linux in CI) to run the proxy throughput benchmark")
	}
	return dsn
}

// mockNode is an instant-response Ethereum node stub: it executes no EVM, so
// the benchmark measures only the proxy.
func mockNode(tb testing.TB) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result any
		switch req.Method {
		case "eth_chainId":
			result = "0x7a69" // 31337
		case "eth_getCode":
			result = "0x" // recipient is an EOA → tiered tracing skips tracing
		case "eth_sendRawTransaction":
			result = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
		case "net_version":
			result = "31337"
		case "eth_blockNumber", "eth_gasPrice":
			result = "0x1"
		default:
			result = "0x0"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// seedPermittedUser inserts an org + group + group_access (allowing
// eth_sendRawTransaction, admin claim) + user + membership, returning the DID.
func seedPermittedUser(tb testing.TB, ctx context.Context, database *db.DB) string {
	tb.Helper()
	orgID := uuid.New().String()
	groupID := uuid.New().String()
	userID := uuid.New().String()
	did := "did:bench:" + uuid.New().String()

	must := func(err error) {
		if err != nil {
			tb.Fatalf("seed: %v", err)
		}
	}
	must(database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "bench-" + orgID[:8], Name: "Bench Org"}))
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, depth, is_org_admin) VALUES ($1,$2,$3,$4,$5,0,false)`,
		groupID, orgID, "g-"+groupID[:8], "Bench Grp", "g-"+groupID[:8])
	must(err)
	// eth_sendRawTransaction is classified to RBAC as eth_sendTransaction
	// (jsonrpc_processor.go), so the allowlist must contain eth_sendTransaction.
	must(database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID,
		Claims:         []rbac.Claim{rbac.ClaimAdmin},
		AllowedMethods: []string{"eth_sendTransaction", "eth_sendRawTransaction"},
	}))
	// KYC must be true — CheckAccess denies non-KYC'd users unconditionally.
	must(database.CreateUser(ctx, &rbac.User{ID: userID, ExternalID: did, KYC: true}))
	must(database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return did
}

// signedValueTransfer returns a signed EOA→EOA raw tx (hex) + the JSON-RPC body.
// Each call uses a fresh key, so the recovered from-address is unique — letting
// callers seed many distinct senders (open-loop multi-user load).
func signedValueTransfer(tb testing.TB) (rawHex string, body []byte) {
	tb.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		tb.Fatal(err)
	}
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tx := types.NewTransaction(0, to, big.NewInt(1), 21000, big.NewInt(1_000_000_000), nil)
	signed, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(31337)), key)
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	rawHex = "0x" + hex.EncodeToString(raw)
	body, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "eth_sendRawTransaction", "params": []string{rawHex}, "id": 1})
	return rawHex, body
}

func benchProcessor(b *testing.B, async bool) (*JSONRPCProcessor, string, *ProcessRequest, func()) {
	dsn := proxyBenchDSN(b)
	database, err := db.New(dsn)
	if err != nil {
		b.Fatalf("db: %v", err)
	}
	if err := db.ResetTestDatabase(database); err != nil {
		b.Fatalf("reset: %v", err)
	}
	ctx := context.Background()
	did := seedPermittedUser(b, ctx, database)

	node := mockNode(b)
	rbacCtrl := rbac.NewAccessController(database, 5*time.Minute)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: node.URL, Enabled: true, TieredEnabled: true, Timeout: 5 * time.Second})
	tv := rbac.NewTraceValidator(database)
	procCfg := JSONRPCProcessorConfig{
		RBACAccessCtrl:     rbacCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              proxy.New(node.URL),
		AccessLogger:       database,
		RuntimeTracer:      rt,
		TraceValidator:     tv,
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	}
	var buf *buffer.Buffer
	if async {
		buf, err = buffer.Open(b.TempDir())
		if err != nil {
			b.Fatalf("buffer: %v", err)
		}
		procCfg.AuditBuffer = buf
	} else {
		seed, _ := database.GetLatestAccessLogHash(ctx)
		procCfg.EnhancedAuditLogger = database
		procCfg.HashChain = audit.NewHashChain(seed)
	}
	proc := NewJSONRPCProcessor(procCfg)

	rawHex, body := signedValueTransfer(b)
	req := &ProcessRequest{UserID: did, Method: "eth_sendRawTransaction", Params: []any{rawHex}, Body: body, ClientIP: "127.0.0.1"}

	// Warm the perms cache so we measure the steady-state hot path.
	if res := proc.Process(ctx, req); res.StatusCode != http.StatusOK {
		detail := ""
		if res.Error != nil {
			detail = fmt.Sprintf(" err.status=%d err.msg=%q", res.Error.StatusCode, res.Error.Message)
		}
		b.Fatalf("warmup request not allowed: status=%d%s body=%s", res.StatusCode, detail, string(res.ResponseBody))
	}

	cleanup := func() {
		rt.Stop()
		rbacCtrl.Stop()
		if buf != nil {
			_ = buf.Close()
		}
		_ = database.Close()
	}
	return proc, did, req, cleanup
}

func benchProxyValueTransfer(b *testing.B, async bool) {
	proc, _, req, cleanup := benchProcessor(b, async)
	defer cleanup()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if res := proc.Process(ctx, req); res.StatusCode != http.StatusOK {
				b.Errorf("status=%d", res.StatusCode)
				return
			}
		}
	})
}

// BenchmarkProxyValueTransferSyncAudit — full proxy hot path with the legacy
// synchronous audit chain write.
func BenchmarkProxyValueTransferSyncAudit(b *testing.B) { benchProxyValueTransfer(b, false) }

// BenchmarkProxyValueTransferAsyncAudit — full proxy hot path with the RD-1112
// async durable buffer.
func BenchmarkProxyValueTransferAsyncAudit(b *testing.B) { benchProxyValueTransfer(b, true) }
