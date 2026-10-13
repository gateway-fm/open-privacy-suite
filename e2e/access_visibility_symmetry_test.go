package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestAccessVisibilitySymmetry enforces the RD-849 invariant: for every
// (viewer, address) pair, the RPC access layer and the explorer visibility
// layer must agree. If CheckAccess allows a viewer to reach an address, the
// same viewer must see that address as VisibilityFull in GetBatchVisibility.
// If CheckAccess denies, visibility must be anything other than Full (Hidden
// or Redacted). Any asymmetry is a bug — historically we had tier 3 admin
// claim users with RPC access to all org contracts but only Redacted/Hidden
// visibility. This test exists to prevent regression to that state.
//
// The invariant is checked under both read profiles (RD-1299). The profile
// governs transaction, receipt and event reads, never grant-based access: a
// real server running each profile must answer eth_call for every case
// exactly as the access table says, the same under strict as under standard.
// Under strict the test also bounds the explorer list allowlist: it may
// contain only the viewer's own linked addresses and approved disclosure-grant
// addresses, never an address the viewer sees through a contract grant or an
// admin role.
func TestAccessVisibilitySymmetry(t *testing.T) {
	ctx := context.Background()

	dbURL, dbCleanup := db.SetupTestContainer(t)
	t.Cleanup(dbCleanup)

	// One real server per read profile, on the fixture database. Built before
	// the reset below so their migrations run first; started after seeding.
	// Both write access-log rows to the same database with separate in-memory
	// audit chains; the chain is not verified in this test.
	requireSymmetryNode(t)
	profiles := []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict}
	servers := make(map[rbac.ReadProfile]*server.Server, len(profiles))
	for _, p := range profiles {
		servers[p] = newSymmetryServer(t, dbURL, p)
	}

	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	// --- Fixture: two orgs, various user configurations, two contracts per org.
	//
	//   orgA
	//     grantedGroup (claims: []) with grant on contractA1
	//     adminGroup   (claims: [admin])  — tier 3, no grants
	//     deployGroup  (claims: [deploy]) — tier 3, no grants
	//     orgAdminGroup (is_org_admin: true)
	//   orgB
	//     readerGroup (claims: []) with grant on contractB1
	//   Contracts
	//     contractA1 (orgA) — granted to grantedGroup
	//     contractA2 (orgA) — no grants (only org admin should see)
	//     contractB1 (orgB) — granted to orgB readerGroup
	//     contractB2 (orgB) — no grants (no one in orgA should see)
	orgAID := uuid.New().String()
	orgBID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgAID, Slug: "sym-a", Name: "Sym A", Settings: map[string]any{}}))
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgBID, Slug: "sym-b", Name: "Sym B", Settings: map[string]any{}}))

	grantedGID := createGroup(t, database, orgAID, "sym-a-granted", nil, false)
	adminGID := createGroup(t, database, orgAID, "sym-a-tier3-admin", []rbac.Claim{rbac.ClaimAdmin}, false)
	deployGID := createGroup(t, database, orgAID, "sym-a-tier3-deploy", []rbac.Claim{rbac.ClaimDeploy}, false)
	orgAdminGID := createGroup(t, database, orgAID, "sym-a-org-admin", nil, true)
	readerBGID := createGroup(t, database, orgBID, "sym-b-reader", nil, false)

	contractA1 := "0x1111111111111111111111111111111111111111"
	contractA2 := "0x2222222222222222222222222222222222222222"
	contractB1 := "0x3333333333333333333333333333333333333333"
	contractB2 := "0x4444444444444444444444444444444444444444"
	contractA1ID := createContract(t, database, orgAID, contractA1, "ContractA1")
	_ = createContract(t, database, orgAID, contractA2, "ContractA2")
	contractB1ID := createContract(t, database, orgBID, contractB1, "ContractB1")
	_ = createContract(t, database, orgBID, contractB2, "ContractB2")

	// Grants: grantedGroup → A1, readerBGroup → B1. No grants on A2 or B2.
	createGrant(t, database, contractA1ID, grantedGID)
	createGrant(t, database, contractB1ID, readerBGID)

	// Users: one per role. grantedUser is in grantedGroup; t3AdminUser in adminGroup; etc.
	// Each gets `eth_call` in AllowedMethods so the method allowlist doesn't
	// confound the access check.
	grantedUser := createUserInGroup(t, database, "did:sym:granted", grantedGID)
	t3AdminUser := createUserInGroup(t, database, "did:sym:t3admin", adminGID)
	t3DeployUser := createUserInGroup(t, database, "did:sym:t3deploy", deployGID)
	orgAdminUser := createUserInGroup(t, database, "did:sym:orgadmin", orgAdminGID)
	crossOrgUser := createUserInGroup(t, database, "did:sym:crossorg", readerBGID)

	_ = grantedUser
	_ = t3AdminUser
	_ = t3DeployUser
	_ = orgAdminUser
	_ = crossOrgUser

	// Another user's wallet (an orgB member). Org admins manage contracts, not
	// user wallets: this EOA is private to the orgA admin on both layers, and
	// stays [PRIVATE] on an explorer row kept by the transfer-participant union
	// (RD-1316, checked after the table).
	foreignEOA := "0x5555555555555555555555555555555555555555"
	createUserInGroup(t, database, "did:sym:orgb-wallet", readerBGID)
	require.NoError(t, database.SystemLinkEthAddress(ctx, "did:sym:orgb-wallet", foreignEOA))

	// Add eth_call to every group's AllowedMethods so method allowlist never blocks.
	for _, gid := range []string{grantedGID, adminGID, deployGID, orgAdminGID, readerBGID} {
		attachAllowedMethods(t, database, gid, []string{"eth_call", "eth_getBalance", "eth_getCode"})
	}

	// Linked EOAs (one per viewer) and one approved disclosure grant, so the
	// strict allowlist bound below is checked against non-empty own and grant
	// sets. The disclosure subject is an orgA member with no contract grant;
	// the granted user holds an approved disclosure grant on the subject.
	subjectGID := createGroup(t, database, orgAID, "sym-a-subject", nil, false)
	subjectUser := createUserInGroup(t, database, "did:sym:subject", subjectGID)
	ownAddrs := map[string]string{
		"did:sym:granted":  "0xa000000000000000000000000000000000000001",
		"did:sym:t3admin":  "0xa000000000000000000000000000000000000002",
		"did:sym:t3deploy": "0xa000000000000000000000000000000000000003",
		"did:sym:orgadmin": "0xa000000000000000000000000000000000000004",
		"did:sym:crossorg": "0xa000000000000000000000000000000000000005",
		"did:sym:subject":  "0xa000000000000000000000000000000000000006",
	}
	for did, addr := range ownAddrs {
		require.NoError(t, database.SystemLinkEthAddress(ctx, did, addr))
	}
	createApprovedDisclosureGrant(t, database, orgAID, "did:sym:granted", subjectUser)
	disclosedAddrs := map[string][]string{
		"did:sym:granted": {ownAddrs["did:sym:subject"]},
	}

	controller := rbac.NewAccessController(database, 1*time.Minute)

	type tc struct {
		name        string
		viewerDID   string
		contract    string
		wantAllowed bool // expected CheckAccess outcome + expected VisibilityFull
	}

	cases := []tc{
		// Granted user on granted contract: both allow + Full.
		{"granted user → granted own-org contract", "did:sym:granted", contractA1, true},
		// Granted user on non-granted own-org contract: both deny + non-Full.
		{"granted user → non-granted own-org contract", "did:sym:granted", contractA2, false},
		// Tier 3 admin claim, no grant: both deny + non-Full. (RD-849 regression scenario.)
		{"tier 3 admin → granted own-org contract (no grant for admin group)", "did:sym:t3admin", contractA1, false},
		{"tier 3 admin → non-granted own-org contract", "did:sym:t3admin", contractA2, false},
		// Tier 3 deploy claim, no grant: both deny + non-Full.
		{"tier 3 deploy → granted own-org contract (no grant for deploy group)", "did:sym:t3deploy", contractA1, false},
		{"tier 3 deploy → non-granted own-org contract", "did:sym:t3deploy", contractA2, false},
		// Tier 2 org admin: both allow + Full on every org contract.
		{"org admin → granted own-org contract", "did:sym:orgadmin", contractA1, true},
		{"org admin → non-granted own-org contract", "did:sym:orgadmin", contractA2, true},
		// Cross-org: both deny + non-Full on the other org's contracts.
		{"orgB user → orgA granted contract", "did:sym:crossorg", contractA1, false},
		{"orgB user → orgA non-granted contract", "did:sym:crossorg", contractA2, false},
		{"orgA tier 3 admin → orgB contract", "did:sym:t3admin", contractB1, false},
		{"orgA tier 3 admin → orgB non-granted contract", "did:sym:t3admin", contractB2, false},
		// Org admin vs another user's wallet: both deny + non-Full (§2.1).
		{"org admin → another user's EOA", "did:sym:orgadmin", foreignEOA, false},
	}

	// Start the servers on the seeded database and mint each viewer's JWT with
	// the servers' signing secret (no login flow, so no login side effects).
	urls := make(map[rbac.ReadProfile]string, len(profiles))
	for _, p := range profiles {
		urls[p] = runSymmetryServer(t, servers[p])
	}
	jwtService, err := auth.NewJWTService(symmetryJWTSecret, symmetryJWTRefreshSecret, 30*time.Minute, time.Hour)
	require.NoError(t, err)
	jwts := make(map[string]string, len(cases))
	for _, c := range cases {
		if _, ok := jwts[c.viewerDID]; !ok {
			jwts[c.viewerDID], err = jwtService.IssueAccessToken(c.viewerDID, true)
			require.NoError(t, err)
		}
	}

	// The same table, with the same expectations, under each read profile: the
	// server running that profile must answer eth_call as the table says.
	for _, profile := range profiles {
		for _, c := range cases {
			t.Run(profile.String()+"/"+c.name, func(t *testing.T) {
				// RPC-layer check.
				accessResult, err := controller.CheckAccess(ctx, &rbac.AccessCheckRequest{
					UserExternalID: c.viewerDID,
					Method:         "eth_call",
					Params:         []any{map[string]any{"to": c.contract, "data": "0x"}, "latest"},
					TargetAddress:  c.contract,
				})
				require.NoError(t, err)

				// Explorer visibility check.
				visMap, err := database.GetBatchVisibility(ctx, c.viewerDID, []string{strings.ToLower(c.contract)})
				require.NoError(t, err)
				visFull := visMap[strings.ToLower(c.contract)] == explorer.VisibilityFull

				if c.wantAllowed {
					require.True(t, accessResult.Allowed, "expected RPC access allowed, got denied: %s", accessResult.Reason)
					require.True(t, visFull, "expected visibility Full when RPC access is allowed — symmetry violation")
				} else {
					require.False(t, accessResult.Allowed, "expected RPC access denied, got allowed")
					require.False(t, visFull, "expected visibility not-Full when RPC access is denied — symmetry violation")
				}

				// The symmetry assertion itself — flags any future asymmetry regardless of expectation.
				require.Equal(t, c.wantAllowed, accessResult.Allowed && visFull,
					"access/visibility mismatch: access.Allowed=%v, visibilityFull=%v", accessResult.Allowed, visFull)

				// The server running this read profile answers the same:
				// a result when access is allowed, the opaque RBAC denial
				// (404 "method not found") otherwise — not some other error.
				status, result, body := symmetryEthCall(t, urls[profile], jwts[c.viewerDID], c.contract)
				if c.wantAllowed {
					require.Equal(t, http.StatusOK, status, "%s server: eth_call must be allowed; response %s", profile, body)
					require.NotEmpty(t, result, "%s server: eth_call must return a result; response %s", profile, body)
				} else {
					require.Equal(t, http.StatusNotFound, status, "%s server: eth_call must be denied by RBAC; response %s", profile, body)
					require.JSONEq(t, `{"error":"method not found"}`, body, "%s server: eth_call denial", profile)
				}
			})
		}
	}

	// RD-1316: a tx from that wallet (here to an orgB contract the admin cannot
	// see) that the transfer-participant union keeps for the org admin — passed
	// in directly as VisibleTxHashes — still renders the wallet [PRIVATE],
	// matching the RPC denial above. Only a genuine visibleTo listing reveals.
	// The union is a standard-profile rule; strict has no union.
	t.Run("org admin → another user's EOA on a transfer-linked row", func(t *testing.T) {
		const hash = "0x5555000000000000000000000000000000000000000000000000000000000001"
		to := contractB2
		engine := explorer.NewRedactionEngine(nil, database, rbac.ReadProfileStandard)
		got, err := engine.RedactTransactions(ctx, []explorer.Transaction{{Hash: hash, From: foreignEOA, To: &to, Value: "5"}},
			"did:sym:orgadmin", explorer.RedactOpts{VisibleTxHashes: map[string]bool{hash: true}, ViewerIsAdmin: true})
		require.NoError(t, err)
		require.Len(t, got, 1, "the union keeps the row")
		require.Equal(t, "[PRIVATE]", got[0].From, "the explorer must not reveal what the RPC layer denies")
		require.NotContains(t, got[0].AddressMetadata, foreignEOA, "no addressMetadata key for the private wallet")
	})

	// Disclosure grants (RD-1353): a Full grant over a user is an input of the
	// shared read decision, so for a transaction that user sent the JSON-RPC
	// read and the explorer agree — under both profiles, on a real server and
	// a real mined transaction. Only an active Full grant opens it; a
	// pseudonymous grant keeps its explorer-only lens (the subject is never
	// Full there), and an expired or revoked grant opens nothing anywhere.
	t.Run("disclosure grant viewers: JSON-RPC tx read agrees with explorer visibility", func(t *testing.T) {
		const (
			grantSubjectEOA = "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f" // anvil account 8
			grantPeerEOA    = "0x14dc79964da2c08b23698b3d3cc7ca32193d9955" // anvil account 7
		)
		subject := createUserInGroup(t, database, "did:sym:grant_subject", subjectGID)
		require.NoError(t, database.SystemLinkEthAddress(ctx, "did:sym:grant_subject", grantSubjectEOA))
		auditorGID := createGroup(t, database, orgAID, "sym-a-auditors", nil, false)
		attachAllowedMethods(t, database, auditorGID, []string{"eth_getTransactionByHash"})
		viewers := []struct {
			did, level string
			expires    time.Time
			revoked    bool
			admits     bool
		}{
			{"did:sym:auditor_full", "full", time.Now().Add(24 * time.Hour), false, true},
			{"did:sym:auditor_pseudo", "pseudonymous", time.Now().Add(24 * time.Hour), false, false},
			{"did:sym:auditor_expired", "full", time.Now().Add(-time.Minute), false, false},
			{"did:sym:auditor_revoked", "full", time.Now().Add(24 * time.Hour), true, false},
		}
		for _, v := range viewers {
			createUserInGroup(t, database, v.did, auditorGID)
			createDisclosureGrant(t, database, orgAID, v.did, subject, v.level, v.expires, v.revoked)
			jwts[v.did], err = jwtService.IssueAccessToken(v.did, true)
			require.NoError(t, err)
		}

		// The subject sends a transaction straight to the node.
		raw, err := symmetryNodeRPC(t, "eth_sendTransaction", []any{map[string]any{"from": grantSubjectEOA, "to": grantPeerEOA, "value": "0x1"}})
		require.NoError(t, err)
		var txHash string
		require.NoError(t, json.Unmarshal(raw, &txHash))
		require.Eventually(t, func() bool {
			r, err := symmetryNodeRPC(t, "eth_getTransactionReceipt", []any{txHash})
			return err == nil && string(r) != "null"
		}, 10*time.Second, 100*time.Millisecond, "the subject's transaction is mined")

		peer := grantPeerEOA
		for _, profile := range profiles {
			engine := explorer.NewRedactionEngine(nil, database, profile)
			engine.SetDisclosureGrantResolver(database)
			for _, v := range viewers {
				t.Run(profile.String()+"/"+v.did, func(t *testing.T) {
					vis, err := database.GetBatchVisibility(ctx, v.did, []string{grantSubjectEOA})
					require.NoError(t, err)
					explorerFull := vis[grantSubjectEOA] == explorer.VisibilityFull
					rows, err := engine.RedactTransactions(ctx, []explorer.Transaction{{Hash: txHash, From: grantSubjectEOA, To: &peer, Value: "1"}}, v.did)
					require.NoError(t, err)
					explorerReveals := len(rows) == 1 && strings.EqualFold(rows[0].From, grantSubjectEOA)

					status, result, body := symmetryRPC(t, urls[profile], jwts[v.did], "eth_getTransactionByHash", []any{txHash})
					require.Equal(t, http.StatusOK, status, "%s server: %s", profile, body)
					rpcAdmits := result != ""

					require.Equal(t, v.admits, rpcAdmits, "%s server: JSON-RPC admission for %s; response %s", profile, v.did, body)
					require.Equal(t, v.admits, explorerFull, "explorer visibility of the subject for %s", v.did)
					require.Equal(t, v.admits, explorerReveals, "explorer row for %s: %+v", v.did, rows)
					if rpcAdmits {
						require.Contains(t, strings.ToLower(result), grantSubjectEOA, "the RPC tx carries the subject")
					} else {
						require.NotContains(t, strings.ToLower(body), grantSubjectEOA[2:], "a refused read never names the subject")
					}
				})
			}
		}
	})

	// Strict explorer allowlist bound: the SQL-level allowlist that lists,
	// counts and stats use under strict holds only the viewer's own linked
	// addresses and approved disclosure-grant addresses. Grant- or
	// admin-driven Full visibility (contractA1 for the granted user, every
	// orgA contract for the org admin) must stay out.
	t.Run("strict/explorer allowlist is own plus disclosure-grant addresses", func(t *testing.T) {
		registered, err := database.GetAllRegisteredAddresses(ctx)
		require.NoError(t, err)
		linked, err := database.GetAllLinkedEOAAddresses(ctx)
		require.NoError(t, err)
		universe := append(append([]string{}, registered...), linked...)

		viewers := []string{"did:sym:granted", "did:sym:t3admin", "did:sym:t3deploy", "did:sym:orgadmin", "did:sym:crossorg", "did:sym:subject", ""}
		for _, did := range viewers {
			bound := map[string]bool{}
			if own, ok := ownAddrs[did]; ok {
				bound[strings.ToLower(own)] = true
			}
			for _, a := range disclosedAddrs[did] {
				bound[strings.ToLower(a)] = true
			}

			detailed, err := database.GetBatchVisibilityDetailed(ctx, did, universe)
			require.NoError(t, err)
			allow := explorer.StrictAllowlist(detailed)

			got := map[string]bool{}
			for _, a := range allow {
				a = strings.ToLower(a)
				got[a] = true
				require.True(t, bound[a], "viewer %q: strict allowlist entry %s is neither an own address nor a disclosure-grant address (allowlist %v)", did, a, allow)
			}
			// Not vacuous: own and disclosure-grant addresses are listed.
			for a := range bound {
				require.True(t, got[a], "viewer %q: strict allowlist is missing %s (allowlist %v)", did, a, allow)
			}
			for _, contract := range []string{contractA1, contractA2, contractB1, contractB2} {
				require.False(t, got[strings.ToLower(contract)], "viewer %q: contract %s must not be on the strict allowlist", did, contract)
			}
		}
	})
}

// --- Helpers (keep local to this file — small and clear) ---

// Test-only signing secrets for the symmetry servers; the test mints its
// viewers' JWTs with them.
const (
	symmetryJWTSecret        = "symmetry-test-access-secret"
	symmetryJWTRefreshSecret = "symmetry-test-refresh-secret"
)

// newSymmetryServer builds the real server with the given read profile on
// dbURL (running its migrations), forwarding to the e2e node. Mock login is
// off: the test mints JWTs directly, so no login side effect touches the
// fixture.
func newSymmetryServer(t *testing.T, dbURL string, profile rbac.ReadProfile) *server.Server {
	t.Helper()
	cfg := &config.Config{
		ReadProfile:           profile,
		NodeURL:               e2eNodeURL(),
		DatabaseURL:           dbURL,
		AuditDatabaseURL:      dbURL,
		AuditAdminDatabaseURL: dbURL,
		PrivadoRPCURL:         "https://rpc-mainnet.privado.id",
		IPFSGateway:           "https://ipfs-proxy-cache.privado.id",
		JWTSecret:             symmetryJWTSecret,
		JWTRefreshSecret:      symmetryJWTRefreshSecret,
		VerifierID:            "did:privado:verifier:test",
		BaseURL:               "http://127.0.0.1",
		Environment:           "development",
		DisableCoinGecko:      true,
	}
	srv, err := server.NewWithVerifier(cfg, &mockPrivadoVerifier{})
	require.NoError(t, err)
	t.Cleanup(srv.Stop)
	return srv
}

// runSymmetryServer serves srv on a free loopback port until the test ends
// and returns its base URL once /health answers.
func runSymmetryServer(t *testing.T, srv *server.Server) string {
	t.Helper()
	addrs := make(chan string, 1)
	httpServer := &http.Server{
		Addr:              "127.0.0.1:0",
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext: func(l net.Listener) context.Context {
			addrs <- l.Addr().String()
			return context.Background()
		},
	}
	// Registered before the server starts, so a listener that binds after a
	// startup timeout is still shut down.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	})
	runErr := make(chan error, 1)
	go func() { runErr <- srv.RunWithServer(httpServer) }()
	var addr string
	select {
	case addr = <-addrs:
	case err := <-runErr:
		t.Fatalf("symmetry server exited before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the symmetry server listener")
	}
	baseURL := "http://" + addr
	client := &http.Client{Timeout: time.Second}
	for i := 0; ; i++ {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return baseURL
			}
		}
		require.Less(t, i, 50, "symmetry server did not become healthy")
		time.Sleep(100 * time.Millisecond)
	}
}

// symmetryEthCall sends eth_call to contract as the JWT's viewer and returns
// the HTTP status, the JSON-RPC result (empty on an error or a null result)
// and the raw response body.
func symmetryEthCall(t *testing.T, baseURL, jwt, contract string) (int, string, string) {
	t.Helper()
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_call",
		"params": []any{map[string]any{"to": contract, "data": "0x"}, "latest"},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &env), "eth_call response is not JSON: %s", raw)
	result := ""
	if len(env.Error) == 0 && string(env.Result) != "null" {
		result = string(env.Result)
	}
	return resp.StatusCode, result, string(raw)
}

// symmetryRPC sends one JSON-RPC request as the JWT's viewer and returns the
// HTTP status, the JSON-RPC result (empty on an error or a null result) and the
// raw response body.
func symmetryRPC(t *testing.T, baseURL, jwt, method string, params []any) (int, string, string) {
	t.Helper()
	reqBody, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &env), "%s response is not JSON: %s", method, raw)
	result := ""
	if len(env.Error) == 0 && len(env.Result) > 0 && string(env.Result) != "null" {
		result = string(env.Result)
	}
	return resp.StatusCode, result, string(raw)
}

// symmetryNodeRPC sends one JSON-RPC request straight to the e2e node.
func symmetryNodeRPC(t *testing.T, method string, params []any) (json.RawMessage, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(e2eNodeURL(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, errors.New(out.Error.Message)
	}
	return out.Result, nil
}

// requireSymmetryNode fails fast, with a clear cause, when the e2e node the
// symmetry servers forward eth_call to is not reachable.
func requireSymmetryNode(t *testing.T) {
	t.Helper()
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(e2eNodeURL(), "application/json", bytes.NewReader(body))
	require.NoError(t, err, "TestAccessVisibilitySymmetry needs the e2e node at %s (set E2E_NODE_URL)", e2eNodeURL())
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "e2e node at %s did not answer eth_chainId", e2eNodeURL())
}

func createGroup(t *testing.T, database *db.DB, orgID, slug string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: gid, OrgID: orgID, Slug: slug, Name: slug, Depth: 0, Path: slug, IsOrgAdmin: isOrgAdmin,
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{}, Claims: claims,
	}))
	return gid
}

func createUserInGroup(t *testing.T, database *db.DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: uid, ExternalID: did, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: uid, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return uid
}

func createContract(t *testing.T, database *db.DB, orgID, address, name string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: strings.ToLower(address), Name: name, Metadata: map[string]any{},
	}))
	return cid
}

func createGrant(t *testing.T, database *db.DB, contractID, groupID string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, Functions: nil,
	}))
}

// createApprovedDisclosureGrant records an approved disclosure request by
// requesterDID on targetUserID in orgID and an active grant for it.
func createApprovedDisclosureGrant(t *testing.T, database *db.DB, orgID, requesterDID, targetUserID string) {
	t.Helper()
	ctx := context.Background()
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		 VALUES ($1, $2, $3, $4, '{}', 'symmetry fixture', 'approved', NOW())`,
		requestID, requesterDID, targetUserID, orgID)
	require.NoError(t, err)
	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at)
		 VALUES ($1, $2, $3, '{}', NOW(), NOW() + INTERVAL '1 day')`,
		grantID, requestID, "symmetry-fixture-"+grantID)
	require.NoError(t, err)
}

// createDisclosureGrant records an approved disclosure request by requesterDID
// on targetUserID in orgID at the given level, and its grant (expiring at
// expires; revoked when revoked is set).
func createDisclosureGrant(t *testing.T, database *db.DB, orgID, requesterDID, targetUserID, level string, expires time.Time, revoked bool) {
	t.Helper()
	ctx := context.Background()
	scope := `{"disclosure_level":"` + level + `"}`
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests (id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, 'symmetry fixture', 'approved', NOW())`,
		requestID, requesterDID, targetUserID, orgID, scope)
	require.NoError(t, err)
	var revokedAt any
	if revoked {
		revokedAt = time.Now().Add(-time.Minute)
	}
	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants (id, request_id, grant_token_hash, scope, granted_at, expires_at, revoked_at)
		 VALUES ($1, $2, $3, $4::jsonb, NOW() - INTERVAL '1 hour', $5, $6)`,
		grantID, requestID, "symmetry-fixture-"+grantID, scope, expires, revokedAt)
	require.NoError(t, err)
}

func attachAllowedMethods(t *testing.T, database *db.DB, groupID string, methods []string) {
	t.Helper()
	ctx := context.Background()
	gas, err := database.GetGroupAccess(ctx, groupID)
	require.NoError(t, err)
	require.NotNil(t, gas)
	gas.AllowedMethods = methods
	require.NoError(t, database.UpdateGroupAccess(ctx, gas))
}
