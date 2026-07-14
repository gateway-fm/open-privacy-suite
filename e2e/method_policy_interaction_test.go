//go:build mockauth

package e2e

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// These tests lock the *interaction* between method policies (RD-1206) and the
// pre-existing access/redaction rules: a policy must only NARROW — it must never
// change how the contract grant, the method allowlist, or event-log redaction
// behave. If it did, adding a policy would silently break existing privacy
// rules, which is the opposite of the design intent.

type mpPersona struct{ did, addr, token string }

func mpDeployAndProvision(t *testing.T, srv interface{ DB() *db.DB }, serverURL string, allowedMethods []string) (database *db.DB, orgID, contractAddr, abiJSON string, parsed abi.ABI, personas map[string]*mpPersona) {
	t.Helper()
	database = srv.DB()
	ctx := context.Background()

	abiJSON = mustReadTestdata(t, "PaymentRegistry.abi.json")
	bytecode := strings.TrimSpace(mustReadTestdata(t, "PaymentRegistry.bin"))
	var err error
	parsed, err = abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	contractAddr = deployToAnvilDirect(t, anvilAccount0, bytecode)

	orgID = uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{ID: orgID, Slug: "mpi-" + orgID[:8], Name: "MPI", Settings: map[string]any{}}))
	groupID := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{ID: groupID, OrgID: orgID, Slug: "g", Name: "payment"}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID, Claims: []rbac.Claim{}, AllowedMethods: allowedMethods,
	}))

	personas = map[string]*mpPersona{
		"alice": {did: "did:test:alice", addr: anvilAccount0},
		"bob":   {did: "did:test:bob", addr: anvilAccount1},
		"diana": {did: "did:test:diana", addr: anvilAccount3},
	}
	for _, p := range personas {
		u := &rbac.User{ID: uuid.New().String(), ExternalID: p.did, KYC: true}
		require.NoError(t, database.CreateUser(ctx, u))
		require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.New().String(), UserID: u.ID, GroupID: groupID}))
		require.NoError(t, database.SystemLinkEthAddress(ctx, p.did, p.addr))
		p.token = getJWTToken(t, serverURL, p.did)
	}

	// register the contract; the caller sets the grant/policy/event-rules it needs.
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: uuid.New().String(), OrgID: orgID, Address: strings.ToLower(contractAddr), Name: "PaymentRegistry", ABI: abiJSON, Metadata: map[string]any{},
	}))
	return database, orgID, contractAddr, abiJSON, parsed, personas
}

func mpContractID(t *testing.T, database *db.DB, contractAddr string) string {
	t.Helper()
	c, err := database.GetContractByAddressGlobal(context.Background(), strings.ToLower(contractAddr))
	require.NoError(t, err)
	require.NotNil(t, c)
	return c.ID
}

// Interaction 1: a contract with NO method policy behaves exactly as before —
// the coarse contract grant governs, so ANY granted group member (even a
// non-party) can read getPaymentInfo. This proves the feature is opt-in and
// leaves unconfigured contracts untouched.
func TestMethodPolicy_NoPolicyPassthrough_E2E(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	database, orgID, contractAddr, abiJSON, parsed, personas := mpDeployAndProvision(t, srv, serverURL,
		[]string{"eth_call", "eth_sendTransaction", "eth_getTransactionReceipt"})
	_ = abiJSON

	// grant the whole group, NO method policy configured.
	require.NoError(t, database.CreateContractGrant(context.Background(), &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: mpContractID(t, database, contractAddr), GroupID: mustGroupID(t, database, orgID),
	}))

	createData, err := parsed.Pack("createPayment", "PAY-NP", common.HexToAddress(personas["bob"].addr), big.NewInt(1000))
	require.NoError(t, err)
	txHash := sendTxWithVisibleTo(t, serverURL, orgID, personas["alice"].token, map[string]any{
		"from": personas["alice"].addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(createData), "gas": "0x100000",
	}, nil)
	require.Equal(t, "0x1", waitForReceipt(t, serverURL, orgID, personas["alice"].token, txHash)["status"])

	readData, _ := parsed.Pack("getPaymentInfo", "PAY-NP")
	readHex := "0x" + common.Bytes2Hex(readData)
	call := func(p *mpPersona) map[string]any {
		return jsonRPCCall(t, serverURL, orgID, p.token, "eth_call",
			[]any{map[string]any{"from": p.addr, "to": contractAddr, "data": readHex}, "latest"})
	}
	// Without a policy, BOTH the payer and a granted NON-party read the record —
	// the pre-feature coarse-grant behavior, unchanged.
	require.Nil(t, call(personas["alice"])["error"], "payer must read (no policy)")
	dianaResp := call(personas["diana"])
	require.Nil(t, dianaResp["error"], "granted non-party must read when NO policy is set (coarse grant unchanged)")
	require.NotEqual(t, "0x", dianaResp["result"], "non-party should get real data (no gating)")
}

// Interaction 2: with a method policy on the getter AND event rules on the
// grant, event-log redaction is UNAFFECTED by the policy — getLogs still
// filters by the event rules (payee sees their PaymentCreated, non-party does
// not), exactly as it would with no policy — while the getter is separately
// narrowed. The two layers coexist; the policy does not touch getLogs.
func TestMethodPolicy_DoesNotAffectEventLogs_E2E(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	database, orgID, contractAddr, abiJSON, parsed, personas := mpDeployAndProvision(t, srv, serverURL,
		[]string{"eth_call", "eth_sendTransaction", "eth_getTransactionReceipt", "eth_getLogs"})
	_ = abiJSON
	ctx := context.Background()
	cID := mpContractID(t, database, contractAddr)

	// PaymentCreated(bytes32 paymentKey, string paymentIdentifier, address payer, address payee)
	topic0 := crypto.Keccak256Hash([]byte("PaymentCreated(bytes32,string,address,address)")).Hex()
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: cID, GroupID: mustGroupID(t, database, orgID),
		EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{{
			Topic0: topic0, Name: "PaymentCreated",
			ParamRules: []rbac.ParamRule{{Index: 2, MustBe: "self"}, {Index: 3, MustBe: "self"}},
		}}},
	}))
	// PaymentCreated has a non-indexed dynamic `string` → allow it through M15.
	require.NoError(t, database.UpdateContractEventsAllowDynamicPayload(ctx, cID, true))
	// The method policy on the getter (does NOT touch events).
	require.NoError(t, database.UpdateContractMethodPolicies(ctx, cID, []byte(partiorMethodPolicy)))

	// alice (payer) creates a payment to bob (payee).
	createData, _ := parsed.Pack("createPayment", "PAY-EV", common.HexToAddress(personas["bob"].addr), big.NewInt(2000))
	txHash := sendTxWithVisibleTo(t, serverURL, orgID, personas["alice"].token, map[string]any{
		"from": personas["alice"].addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(createData), "gas": "0x100000",
	}, nil)
	require.Equal(t, "0x1", waitForReceipt(t, serverURL, orgID, personas["alice"].token, txHash)["status"])
	waitForCapture(t, database, orgID, strings.ToLower(contractAddr), "payment", "PAY-EV")

	getLogs := func(p *mpPersona) []any {
		resp := jsonRPCCall(t, serverURL, orgID, p.token, "eth_getLogs",
			[]any{map[string]any{"address": contractAddr, "topics": []any{topic0}, "fromBlock": "0x0", "toBlock": "latest"}})
		require.Nil(t, resp["error"], "getLogs error for %s: %v", p.did, resp["error"])
		if arr, ok := resp["result"].([]any); ok {
			return arr
		}
		return nil
	}

	// getLogs is governed by the EVENT RULES, not the method policy: the payee
	// sees the PaymentCreated log; the granted non-party does not. This is
	// identical to the behavior without a method policy — the policy left the
	// event-redaction layer untouched.
	require.Len(t, getLogs(personas["bob"]), 1, "payee must see PaymentCreated via event rules despite the method policy")
	require.Len(t, getLogs(personas["diana"]), 0, "non-party must NOT see PaymentCreated (event rule), unaffected by the policy")

	// Meanwhile the getter IS narrowed by the method policy: the non-party is
	// denied getPaymentInfo even though the same grant lets them call getLogs.
	readData, _ := parsed.Pack("getPaymentInfo", "PAY-EV")
	dianaGet := jsonRPCCall(t, serverURL, orgID, personas["diana"].token, "eth_call",
		[]any{map[string]any{"from": personas["diana"].addr, "to": contractAddr, "data": "0x" + common.Bytes2Hex(readData)}, "latest"})
	require.NotNil(t, dianaGet["error"], "non-party must be denied getPaymentInfo by the method policy")
}

func mustGroupID(t *testing.T, database *db.DB, orgID string) string {
	t.Helper()
	groups, err := database.ListGroups(context.Background(), orgID)
	require.NoError(t, err)
	require.NotEmpty(t, groups)
	return groups[0].ID
}
