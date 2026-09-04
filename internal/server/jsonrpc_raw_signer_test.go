package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/tracer"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The raw-transaction signer gate (processRawTransaction) binds the recovered
// signer to the authenticated DID before tracing or forwarding. These tests
// exercise the processor path directly — the policy-check unlinked-sender test
// goes through a separate helper and does not pin the live boundary.

// setupRawSignerProcessor wires a JSONRPCProcessor whose tracer points at an
// httptest node that returns a single same-org CALL frame, so a fully
// authorized, signer-linked raw transaction can complete end to end.
func setupRawSignerProcessor(t *testing.T, targetAddr string) (*JSONRPCProcessor, *testServerRBAC) {
	t.Helper()
	ts := setupTestServerForRBAC(t)

	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "debug_traceCall":
			var tx map[string]any
			if len(req.Params) > 0 {
				_ = json.Unmarshal(req.Params[0], &tx)
			}
			from, _ := tx["from"].(string)
			to, _ := tx["to"].(string)
			frame := map[string]any{"type": "CALL", "from": from, "to": to}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": frame})
		default:
			// Forwarding (eth_sendRawTransaction) and any other call: echo a hash.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": "0x" + hex.EncodeToString(common.HexToHash("0x01").Bytes()),
			})
		}
	}))
	t.Cleanup(node.Close)

	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: node.URL, Enabled: true})
	t.Cleanup(rt.Stop)

	proc := NewJSONRPCProcessorWithTracing(
		ts.rbacAccessCtrl,
		&noopRateLimiter{},
		proxy.New(node.URL),
		ts.db,
		rt,
		rbac.NewTraceValidator(ts.db),
		NewCircuitBreaker(),
		NewConcurrencyLimiter(50, 0),
		"",
	)
	return proc, ts
}

// signRawTxToTarget returns a signed legacy transaction from a fresh key whose
// derived address is returned alongside, targeting an empty-data contract call.
func signRawTxToTarget(t *testing.T, targetAddr string) (rawHex, fromAddr string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	to := common.HexToAddress(targetAddr)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      100_000,
		To:       &to,
		Value:    big.NewInt(0),
		Data:     []byte{0x70, 0xa0, 0x82, 0x31}, // balanceOf selector shape
	})
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1)), key)
	require.NoError(t, err)
	rawBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)
	return "0x" + hex.EncodeToString(rawBytes), crypto.PubkeyToAddress(key.PublicKey).Hex()
}

// seedRawSignerUser seeds an org whose group allows eth_sendTransaction and
// grants it on the target contract, with one KYC'd member.
func seedRawSignerUser(t *testing.T, ctx context.Context, database *db.DB, targetAddr string) string {
	t.Helper()
	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "rawsigner-" + orgID[:8], Name: "Raw Signer Org", Settings: map[string]any{},
	}))
	groupID := drCreateGroup(t, database, orgID, "rawsigner-grp-"+groupIDSuffix(), nil, false)
	// The group must allow eth_sendTransaction (the RBAC classification used
	// for raw transactions) and hold a grant on the traced target.
	_, err := database.Conn().ExecContext(ctx,
		`UPDATE group_access SET allowed_methods = allowed_methods || $1::text[] WHERE group_id = $2`,
		[]string{"eth_sendTransaction", "eth_sendRawTransaction"}, groupID,
	)
	require.NoError(t, err)
	contractID := drCreateContract(t, database, orgID, targetAddr, "RawSignerTarget")
	drCreateGrant(t, database, contractID, groupID)
	did := "did:rawsigner:" + uuid.New().String()
	drCreateUserInGroup(t, database, did, groupID)
	return did
}

func groupIDSuffix() string { return uuid.New().String()[:8] }

func TestRawTxSignerGate_LinkedSignerAllowed(t *testing.T) {
	ctx := context.Background()
	targetAddr := "0xAC0000000000000000000000000000000000beef"
	proc, ts := setupRawSignerProcessor(t, targetAddr)
	did := seedRawSignerUser(t, ctx, ts.db, targetAddr)

	rawHex, from := signRawTxToTarget(t, targetAddr)
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, did, from))

	res := proc.Process(ctx, &ProcessRequest{
		UserID:   did,
		Method:   "eth_sendRawTransaction",
		Params:   []any{rawHex},
		ClientIP: "127.0.0.1",
	})
	require.NotNil(t, res)
	assert.Nil(t, res.Error, "linked signer must pass the gate; got %+v", res.Error)
	assert.NotEmpty(t, res.ResponseBody, "linked signer must reach forwarding")
}

func TestRawTxSignerGate_UnlinkedSignerDenied(t *testing.T) {
	ctx := context.Background()
	targetAddr := "0xAC0000000000000000000000000000000000beef"
	proc, ts := setupRawSignerProcessor(t, targetAddr)
	did := seedRawSignerUser(t, ctx, ts.db, targetAddr)

	// The signer key is fresh and never linked to the DID.
	rawHex, _ := signRawTxToTarget(t, targetAddr)

	res := proc.Process(ctx, &ProcessRequest{
		UserID:   did,
		Method:   "eth_sendRawTransaction",
		Params:   []any{rawHex},
		ClientIP: "127.0.0.1",
	})
	require.NotNil(t, res)
	require.NotNil(t, res.Error, "unlinked signer must be denied")
	assert.Equal(t, http.StatusBadRequest, res.Error.StatusCode)
	assert.Equal(t, ReasonSenderNotLinked, res.Error.Reason)
	assert.Contains(t, res.Error.Message, "not linked")
}

func TestRawTxSignerGate_LinkStoreErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	targetAddr := "0xAC0000000000000000000000000000000000beef"
	proc, ts := setupRawSignerProcessor(t, targetAddr)
	did := seedRawSignerUser(t, ctx, ts.db, targetAddr)

	rawHex, from := signRawTxToTarget(t, targetAddr)
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, did, from))

	// Break the link store: dropping the table makes GetLinkedEthAddresses
	// fail, and the gate must fail closed rather than forward.
	_, err := ts.db.Conn().ExecContext(ctx, `ALTER TABLE eth_address_links RENAME TO eth_address_links_broken`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = ts.db.Conn().ExecContext(context.Background(), `ALTER TABLE eth_address_links_broken RENAME TO eth_address_links`)
	})

	res := proc.Process(ctx, &ProcessRequest{
		UserID:   did,
		Method:   "eth_sendRawTransaction",
		Params:   []any{rawHex},
		ClientIP: "127.0.0.1",
	})
	require.NotNil(t, res)
	require.NotNil(t, res.Error, "link-store error must fail closed")
	assert.Equal(t, http.StatusForbidden, res.Error.StatusCode)
	assert.Equal(t, ReasonTracingUnavailable, res.Error.Reason)
	assert.Contains(t, res.Error.Message, "failed to verify sender identity")
}
