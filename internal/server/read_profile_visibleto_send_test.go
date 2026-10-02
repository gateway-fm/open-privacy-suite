package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1299: under the strict read profile visibleTo grants nothing, so a send
// that supplies one is refused with 400 before it is forwarded or stored —
// the sender learns the share did not happen, and no tx_visible_to row exists
// that a later profile change could re-activate. Standard is unchanged.
func TestReadProfile_Strict_SendWithVisibleToRejected(t *testing.T) {
	ts := setupTestServerForRBAC(t)
	ctx := context.Background()
	orgID := uuid.New().String()
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "vts-" + orgID[:8], Name: "VTS", Settings: map[string]any{}}))
	gid := uuid.New().String()
	require.NoError(t, ts.db.CreateGroup(ctx, &rbac.Group{ID: gid, OrgID: orgID, Slug: "vts-senders", Name: "vts-senders", Path: "vts-senders"}))
	require.NoError(t, ts.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_sendTransaction"},
	}))
	const senderDID = "did:test:vts:sender"
	const listedDID = "did:test:vts:listed"
	sender := "0x5e0de00000000000000000000000000000000001"
	contract := "0xc0a7ac7000000000000000000000000000000001"
	cid := uuid.New().String()
	require.NoError(t, ts.db.CreateContract(ctx, &rbac.Contract{ID: cid, OrgID: orgID, Address: contract, Name: "VTS", Metadata: map[string]any{}}))
	require.NoError(t, ts.db.CreateContractGrant(ctx, &rbac.ContractGrant{ID: uuid.New().String(), ContractID: cid, GroupID: gid}))
	uid := uuid.New().String()
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: uid, ExternalID: senderDID, KYC: true, Metadata: map[string]any{}}))
	require.NoError(t, ts.db.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: uid, GroupID: gid, Source: rbac.MembershipSourceAdmin}))
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, senderDID, sender))
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{ID: uuid.New().String(), ExternalID: listedDID, KYC: true, Metadata: map[string]any{}}))

	txHash := "0x" + "7e" + "00000000000000000000000000000000000000000000000000000000000000"
	var forwarded atomic.Int32
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + txHash + `"}`))
	}))
	t.Cleanup(stub.Close)

	// The compliance check runs after tracing; a strict refusal must come
	// before both, so a refused send costs neither (counted via the store).
	compStore := &countingComplianceStore{}
	sendWith := func(profile rbac.ReadProfile, shape func(env, txObj map[string]any)) (*ProcessResult, int32) {
		p := NewJSONRPCProcessor(JSONRPCProcessorConfig{
			RBACAccessCtrl:     ts.rbacAccessCtrl,
			RateLimiter:        &noopRateLimiter{},
			Proxy:              proxy.New(stub.URL),
			AccessLogger:       ts.db,
			CircuitBreaker:     middleware.NewCircuitBreaker(),
			ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
			TxVisibilityStore:  ts.db,
			ComplianceChecker:  compliance.NewChecker(compStore, time.Hour, time.Hour),
			ReadProfile:        profile,
		})
		txObj := map[string]any{"from": sender, "to": contract, "data": "0xa9059cbb", "value": "0x1"}
		env := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction", "params": []any{txObj}}
		if shape != nil {
			shape(env, txObj)
		}
		body, err := json.Marshal(env)
		require.NoError(t, err)
		method, params, perr := ParseAndValidateBody(body)
		require.Nil(t, perr)
		before := forwarded.Load()
		res := p.Process(ctx, &ProcessRequest{UserID: senderDID, OrgID: orgID, Method: method, Params: params, Body: body})
		return res, forwarded.Load() - before
	}
	send := func(profile rbac.ReadProfile, withVisibleTo bool) (*ProcessResult, int32) {
		if !withVisibleTo {
			return sendWith(profile, nil)
		}
		return sendWith(profile, func(env, _ map[string]any) { env["visibleTo"] = []string{listedDID} })
	}

	t.Run("strict rejects a supplied visibleTo", func(t *testing.T) {
		compStore.reset()
		res, fwd := send(rbac.ReadProfileStrict, true)
		require.NotNil(t, res.Error, "expected a 400")
		assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
		assert.Zero(t, fwd, "the tx must not be forwarded")
		assert.Zero(t, compStore.load(), "refused before the compliance check")
		var n int
		require.NoError(t, ts.db.Conn().QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_tx_visibility`).Scan(&n))
		assert.Zero(t, n, "no visibleTo row is stored")
	})
	// Presence is what is refused, whatever the entries: an empty list, an
	// entry that does not resolve, the privateFor alias and the tx-object form.
	for name, shape := range map[string]func(env, txObj map[string]any){
		"empty top-level list":    func(env, _ map[string]any) { env["visibleTo"] = []string{} },
		"unresolvable entry":      func(env, _ map[string]any) { env["visibleTo"] = []string{"not-a-did"} },
		"privateFor alias":        func(env, _ map[string]any) { env["privateFor"] = []string{listedDID} },
		"tx-object visibleTo":     func(_, txObj map[string]any) { txObj["visibleTo"] = []string{listedDID} },
		"tx-object empty list":    func(_, txObj map[string]any) { txObj["visibleTo"] = []string{} },
		"tx-object non-list type": func(_, txObj map[string]any) { txObj["visibleTo"] = "did:test:vts:listed" },
	} {
		t.Run("strict rejects "+name, func(t *testing.T) {
			res, fwd := sendWith(rbac.ReadProfileStrict, shape)
			require.NotNil(t, res.Error, "expected a 400")
			assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
			assert.Equal(t, "visibleTo is not supported on this network", res.Error.Message)
			assert.Zero(t, fwd, "the tx must not be forwarded")
		})
	}
	t.Run("strict forwards a send without visibleTo", func(t *testing.T) {
		compStore.reset()
		res, fwd := send(rbac.ReadProfileStrict, false)
		require.Nil(t, res.Error, "%+v", res.Error)
		assert.Equal(t, int32(1), fwd)
		assert.NotZero(t, compStore.load(), "control: the compliance check runs for an accepted send")
	})
	t.Run("standard accepts visibleTo", func(t *testing.T) {
		res, fwd := send(rbac.ReadProfileStandard, true)
		require.Nil(t, res.Error, "%+v", res.Error)
		assert.Equal(t, int32(1), fwd)
	})
}

// countingComplianceStore reports compliance as disabled and counts how often
// the checker consulted it (one call per checked value transfer).
type countingComplianceStore struct {
	compliance.Store
	calls atomic.Int32
}

func (c *countingComplianceStore) GetComplianceConfig(context.Context, string) (*compliance.ComplianceConfig, error) {
	c.calls.Add(1)
	return nil, nil
}

func (c *countingComplianceStore) reset()      { c.calls.Store(0) }
func (c *countingComplianceStore) load() int32 { return c.calls.Load() }
