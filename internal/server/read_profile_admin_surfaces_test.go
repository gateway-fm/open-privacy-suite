package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1299: under the strict read profile an administrator's authority never
// becomes read access to a member's chain data. The dry-run refuses read
// methods before anything is forwarded (and audits the refusal); a simulated
// send still returns the permission verdict but no trace or logs.

func TestReadProfile_Strict_DryRunReadMethodsRefused(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			f := setupDryRunFixture(t)
			f.srv.config.ReadProfile = profile
			ctx := context.Background()
			gid := uuid.New().String()
			require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{ID: gid, OrgID: f.orgID, Slug: "dr-reader", Name: "dr-reader", Path: "dr-reader"}))
			require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
				ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_getTransactionByHash", "eth_getLogs", "eth_getTransactionReceipt", "eth_call"},
			}))
			readerDID := "did:dr:reader-" + profile.String()
			drCreateUserInGroup(t, f.srv.db, readerDID, gid)

			var forwarded atomic.Int32
			stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				forwarded.Add(1)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
			}))
			t.Cleanup(stub.Close)
			f.srv.proxy = proxy.New(stub.URL)

			for _, m := range []string{"eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getLogs"} {
				w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, map[string]any{
					"user_did": readerDID,
					"rpc":      map[string]any{"method": m, "params": []any{"0x" + "11"}},
				})
				if profile.Strict() {
					assert.Equal(t, http.StatusForbidden, w.Code, "%s: %s", m, w.Body.String())
				} else {
					assert.Equal(t, http.StatusOK, w.Code, "%s: %s", m, w.Body.String())
				}
			}
			if profile.Strict() {
				assert.Zero(t, forwarded.Load(), "a refused read must not reach the node")
				var n int
				require.NoError(t, f.srv.db.Conn().QueryRowContext(ctx,
					`SELECT COUNT(*) FROM impersonation_log WHERE actor_did = $1 AND impersonated_did = $2 AND decision = 'deny' AND reason = 'strict_read_profile'`,
					f.adminDID, readerDID).Scan(&n))
				assert.Equal(t, 3, n, "every refusal is audited")
			} else {
				assert.Equal(t, int32(3), forwarded.Load())
			}
		})
	}
}

func TestReadProfile_Strict_DryRunSendReturnsVerdictOnly(t *testing.T) {
	f := setupDryRunFixture(t)
	f.srv.config.ReadProfile = rbac.ReadProfileStrict
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, f.srv.db.CreateGroup(ctx, &rbac.Group{ID: gid, OrgID: f.orgID, Slug: "dr-sender", Name: "dr-sender", Path: "dr-sender"}))
	require.NoError(t, f.srv.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	senderDID := "did:dr:strict-sender"
	drCreateUserInGroup(t, f.srv.db, senderDID, gid)
	target := "0x6666666666666666666666666666666666666661"
	cid := drCreateContract(t, f.srv.db, f.orgID, target, "DRStrictTarget")
	require.NoError(t, f.srv.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: cid, GroupID: gid}))

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
			"type": "CALL", "from": "0x0000000000000000000000000000000000000000", "to": target,
			"logs": []any{map[string]any{"address": target, "topics": []string{"0x" + "ab"}, "data": "0x"}},
		}})
	}))
	t.Cleanup(stub.Close)
	f.srv.proxy = proxy.New(stub.URL)

	w := dryRunPost(t, f.srv, f.orgID, "jwt_admin", f.adminDID, map[string]any{
		"user_did": senderDID,
		"rpc":      apimodels.DryRunRPCBlock{Method: "eth_sendTransaction", Params: []any{map[string]any{"to": target, "data": "0x"}}},
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp dryRunResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "allow", resp.Decision)
	assert.Empty(t, resp.Trace, "strict: no trace output")
	assert.Empty(t, resp.LogsEmitted, "strict: no emitted logs")
	assert.Empty(t, resp.LogsVisibleToUser, "strict: no per-user logs")
	assert.Empty(t, resp.Response)
}

// View as user under strict: every explorer and RPC data surface of the
// impersonation tree is refused after the tier-2 gate (so the attempt is still
// audited); under standard the same request is served.
func TestReadProfile_Strict_ViewAsRefused(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			f := setupImpersonationFixture(t)
			f.srv.config.ReadProfile = profile
			w := impersonationGET(t, f.srv,
				impersonatePath(f.userDID, f.orgID, "/api/v1/explorer/chain-id"),
				"jwt_admin", f.adminDID, []string{f.orgID})
			if !profile.Strict() {
				assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
				return
			}
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), "chain_id")
			var decision, reason string
			require.NoError(t, f.srv.db.Conn().QueryRowContext(context.Background(), `
				SELECT decision, COALESCE(reason, '') FROM impersonation_log
				WHERE actor_did = $1 AND impersonated_did = $2
				ORDER BY created_at DESC LIMIT 1`, f.adminDID, f.userDID).Scan(&decision, &reason))
			assert.Equal(t, "deny", decision)

			// The RPC mount is refused too.
			w = impersonationGET(t, f.srv, impersonatePath(f.userDID, f.orgID, "/rpc"), "jwt_admin", f.adminDID, []string{f.orgID})
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		})
	}
}
