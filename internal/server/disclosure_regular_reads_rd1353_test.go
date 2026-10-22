package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Adding a disclosure grant must leave the same viewer's ordinary Explorer
// responses unchanged, including address probes and paginated/count surfaces.
func TestRegularExplorerIgnoresDisclosureGrantsRD1353(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, level := range []disclosure.DisclosureLevel{disclosure.DisclosureFull, disclosure.DisclosurePseudonymous, disclosure.DisclosureRedacted} {
			t.Run(profile.String()+"/"+string(level), func(t *testing.T) {
				srv, database, conn := setupTestServerForExplorerTransactions(t)
				srv.config.ReadProfile = profile
				srv.explorerRedactor = explorer.NewRedactionEngine(srv.explorerStore, database, profile)
				_, err := conn.ExecContext(context.Background(), explorerCoherenceExtraSchema)
				require.NoError(t, err)
				_, err = conn.ExecContext(context.Background(), addressStatsSchema)
				require.NoError(t, err)
				const viewer = "did:rd1353:viewer"
				const subject = "did:rd1353:subject"
				const subjectAddr = "0x1353000000000000000000000000000000000001"
				const privateAddr = "0x1353000000000000000000000000000000000002"
				const ownAddr = "0x1353000000000000000000000000000000000003"
				const hash = "0x1353000000000000000000000000000000000000000000000000000000000001"
				const ownHash = "0x1353000000000000000000000000000000000000000000000000000000000002"
				createTestUserForExplorer(t, database, viewer)
				linkEthAddressToUser(t, database, viewer, ownAddr)
				subjectID := createTestUserForExplorer(t, database, subject)
				linkEthAddressToUser(t, database, subject, subjectAddr)
				// Grant creation also provisions org membership. Provision it
				// before the baseline so the grant is the only changed authority.
				ensureDefaultOrgMembership(t, database, viewer)
				block := seedExplorerBlock(t, conn)
				seedExplorerTransaction(t, conn, block, hash, subjectAddr, privateAddr)
				seedExplorerTransaction(t, conn, block, ownHash, ownAddr, privateAddr)
				_, err = conn.Exec(`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number) VALUES ($1, 0, $2, $3, $4, 7, $5)`, hash, privateAddr, privateAddr, subjectAddr, block)
				require.NoError(t, err)
				router := gin.New()
				group := router.Group("/api/v1/explorer")
				group.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, database))
				srv.bindExplorerEndpoints(group)
				get := func(path string) *httptest.ResponseRecorder {
					t.Helper()
					req := httptest.NewRequest(http.MethodGet, "/api/v1/explorer"+path, nil)
					addBearerToken(t, req, srv, viewer)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)
					require.Less(t, w.Code, 500, "%s: %s", path, w.Body.String())
					return w
				}
				paths := []string{"/transactions", "/transactions/paginated", "/transactions/" + hash, "/transactions/" + ownHash,
					"/transactions/" + hash + "/transfers", "/transactions/" + hash + "/internal", "/transactions/" + hash + "/logs", "/transfers", "/logs",
					fmt.Sprintf("/blocks/%d/transactions", block), "/addresses/" + subjectAddr + "/stats", "/addresses/" + subjectAddr + "/transactions",
					"/addresses/" + subjectAddr + "/transfers", "/addresses/" + subjectAddr + "/internal", "/addresses/" + subjectAddr + "/logs", "/addresses/" + subjectAddr + "/is-contract"}
				before := make(map[string]*httptest.ResponseRecorder)
				for _, path := range paths {
					before[path] = get(path)
				}
				require.Equal(t, http.StatusOK, before["/transactions/"+ownHash].Code, "own transaction remains readable")
				require.Equal(t, http.StatusNotFound, before["/transactions/"+hash].Code)
				createDisclosureGrantWithLevel(t, database, viewer, subjectID, level, time.Now().Add(time.Hour))
				for _, path := range paths {
					after := get(path)
					require.Equal(t, before[path].Code, after.Code, path)
					require.JSONEq(t, before[path].Body.String(), after.Body.String(), path)
				}
				probe := get("/addresses/" + privateAddr + "/stats")
				require.Equal(t, http.StatusNotFound, probe.Code)
				require.JSONEq(t, before["/addresses/"+subjectAddr+"/stats"].Body.String(), probe.Body.String(), "a disclosed address must not create an address probe")
			})
		}
	}
}

func TestRegularRPCIgnoresDisclosureGrantsRD1353(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		for _, level := range []string{"full", "pseudonymous", "redacted"} {
			t.Run(profile.String()+"/"+level, func(t *testing.T) {
				f := setupDRFFixture(t)
				f.proc.readProfile = profile
				ctx := context.Background()
				const subjectDID = "did:rd1353:rpc-subject"
				const subjectAddr = "0x1353000000000000000000000000000000000001"
				const ownHash = "0x1353000000000000000000000000000000000000000000000000000000000001"
				const privateHash = "0x1353000000000000000000000000000000000000000000000000000000000002"
				subjectID := drCreateUserInGroup(t, f.ts.db, subjectDID, f.memberGroup)
				require.NoError(t, f.ts.db.SystemLinkEthAddress(ctx, subjectDID, subjectAddr))
				f.txByHash[ownHash] = drfTx(drfMemberEOA, drfContractO, ownHash)
				f.txByHash[privateHash] = drfTx(subjectAddr, drfOtherEOA, privateHash)
				log := drfTransferLog(drfContractO, drfMemberEOA, subjectAddr, ownHash, "0x0")
				receipt := func(hash, from, to string, logs []any) []byte {
					return drfEnvelope(t, map[string]any{"transactionHash": hash, "from": from, "to": to, "status": "0x1", "gasUsed": "0x5208", "cumulativeGasUsed": "0x5208", "effectiveGasPrice": "0x1", "contractAddress": nil, "logsBloom": "0x" + strings.Repeat("0", 512), "logs": logs})
				}
				cases := []struct {
					method string
					params []any
					body   []byte
				}{
					{rbac.MethodGetTransactionByHash, []any{ownHash}, drfEnvelope(t, f.txByHash[ownHash])},
					{rbac.MethodGetTransactionByHash, []any{privateHash}, drfEnvelope(t, f.txByHash[privateHash])},
					{rbac.MethodGetTransactionReceipt, []any{ownHash}, receipt(ownHash, drfMemberEOA, drfContractO, []any{log})},
					{rbac.MethodGetTransactionReceipt, []any{privateHash}, receipt(privateHash, subjectAddr, drfOtherEOA, nil)},
					{rbac.MethodGetLogs, []any{map[string]any{"address": drfContractO, "fromBlock": "0x1", "toBlock": "0x1"}}, drfEnvelope(t, []any{log})},
				}
				before := make([][]byte, len(cases))
				for i, c := range cases {
					before[i] = f.production(t, c.method, c.params, c.body)
				}
				require.JSONEq(t, "null", string(drfResult(t, before[1])))
				require.JSONEq(t, "null", string(drfResult(t, before[3])))
				require.Contains(t, string(before[4]), bare(drfMemberEOA), "the own indexed log is admitted")
				require.NotContains(t, string(before[4]), bare(subjectAddr), "the embedded subject is private")
				requestID := uuid.New().String()
				scope := `{"disclosure_level":"` + level + `"}`
				_, err := f.ts.db.Conn().ExecContext(ctx, `INSERT INTO disclosure_requests (id,requester_did,target_user_id,org_id,scope,reason,status,requested_at) VALUES ($1,$2,$3,$4,$5::jsonb,'rd1353','approved',NOW())`, requestID, drfMemberDID, subjectID, f.orgO, scope)
				require.NoError(t, err)
				_, err = f.ts.db.Conn().ExecContext(ctx, `INSERT INTO disclosure_grants (id,request_id,grant_token_hash,scope,granted_at,expires_at) VALUES ($1,$2,'rd1353-rpc',$3::jsonb,NOW(),NOW()+interval '1 day')`, uuid.New().String(), requestID, scope)
				require.NoError(t, err)
				for i, c := range cases {
					after := f.production(t, c.method, c.params, c.body)
					require.JSONEq(t, string(before[i]), string(after), c.method)
				}
			})
		}
	}
}

// Chain identifiers are not UUIDs. Preserve them in audit metadata while the
// UUID resource_id stays NULL, so admin audit views actually record an entry.
func TestAdminUserTxAuditUsesMetadataForChainTargetsRD1353(t *testing.T) {
	srv, database := setupTestServerForExplorer(t)
	for _, target := range []string{"0x" + strings.Repeat("a", 64), "0x" + strings.Repeat("b", 40), "1234"} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/transactions", nil)
		srv.auditAdminUserTxView(c, "did:rd1353:admin", "transactions", target, &explorer.RedactStats{AdminUserTxsRevealed: 1})
		var count int
		err := database.Conn().QueryRow(`SELECT COUNT(*) FROM rbac_audit_log WHERE actor_external_id='did:rd1353:admin' AND resource_type=$1 AND resource_id IS NULL AND new_value::jsonb->>'target'=$2`, rbac.ResourceTypeExplorerUserTxs, target).Scan(&count)
		require.NoError(t, err)
		require.Equal(t, 1, count, "audit target %s", target)
	}
}
