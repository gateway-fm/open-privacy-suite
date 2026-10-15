package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storageAccessTestSetup holds IDs created during test setup.
type storageAccessTestSetup struct {
	orgID        string
	readGroupID  string
	adminGroupID string
	readUserDID  string
	adminUserDID string
	contractAddr string

	// Cross-org isolation
	orgBID      string
	orgBGroupID string
	orgBUserDID string
}

// setupStorageAccessTest creates the full RBAC hierarchy for tiered storage access testing:
//
//	Org A:
//	  - readGroup (read+write claims) -> readUser
//	  - adminGroup (admin claim) -> adminUser
//	  - contract registered with grants for both groups
//	Org B:
//	  - orgBGroup (read+write+admin claims) -> orgBUser
//	  (no grant on Org A's contract)
func setupStorageAccessTest(t *testing.T, database *db.DB) *storageAccessTestSetup {
	t.Helper()
	ctx := context.Background()

	setup := &storageAccessTestSetup{
		orgID:        uuid.New().String(),
		readGroupID:  uuid.New().String(),
		adminGroupID: uuid.New().String(),
		readUserDID:  "did:privado:storage_read_user",
		adminUserDID: "did:privado:storage_admin_user",
		contractAddr: "0x7777777777777777777777777777777777777777",
		orgBID:       uuid.New().String(),
		orgBGroupID:  uuid.New().String(),
		orgBUserDID:  "did:privado:storage_orgb_user",
	}

	// --- Org A ---

	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: setup.orgID, Slug: "storage-test-org-a", Name: "Storage Test Org A", Settings: map[string]any{},
	}))

	// Read group (read+write claims)
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: setup.readGroupID, OrgID: setup.orgID, Slug: "storage-read-group",
		Name: "Storage Read Group", Depth: 0, Path: "storage-read-group",
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: setup.readGroupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId", "eth_getStorageAt", "eth_getProof", "eth_getCode"},
		Claims:         []rbac.Claim{},
	}))

	// Admin group (admin claim — implies read+write)
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: setup.adminGroupID, OrgID: setup.orgID, Slug: "storage-admin-group",
		Name: "Storage Admin Group", Depth: 0, Path: "storage-admin-group",
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: setup.adminGroupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId", "eth_getStorageAt", "eth_getProof", "eth_getCode"},
		Claims:         rbac.ExpandClaims([]rbac.Claim{rbac.ClaimAdmin}), // admin implies read+write+deploy+upgrade
	}))

	// Read user
	readUserID := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: readUserID, ExternalID: setup.readUserDID, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: readUserID, GroupID: setup.readGroupID, Source: rbac.MembershipSourceAdmin,
	}))

	// Admin user
	adminUserID := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: adminUserID, ExternalID: setup.adminUserDID, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: adminUserID, GroupID: setup.adminGroupID, Source: rbac.MembershipSourceAdmin,
	}))

	// Contract registered under Org A
	contractID := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: contractID, OrgID: setup.orgID, Address: strings.ToLower(setup.contractAddr),
		Name: "Storage Test Contract", Metadata: map[string]any{},
	}))

	// Grant: read group -> contract (read claim inherited from group access)
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: setup.readGroupID,
	}))

	// Grant: admin group -> contract (admin claim inherited from group access)
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: setup.adminGroupID,
	}))

	// --- Org B (cross-org isolation) ---

	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: setup.orgBID, Slug: "storage-test-org-b", Name: "Storage Test Org B", Settings: map[string]any{},
	}))
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: setup.orgBGroupID, OrgID: setup.orgBID, Slug: "storage-orgb-group",
		Name: "Storage OrgB Group", Depth: 0, Path: "storage-orgb-group",
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: setup.orgBGroupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId", "eth_getStorageAt", "eth_getProof", "eth_getCode"},
		Claims:         rbac.ExpandClaims([]rbac.Claim{rbac.ClaimAdmin}), // admin implies read+write+deploy+upgrade
	}))
	orgBUserID := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: orgBUserID, ExternalID: setup.orgBUserDID, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: orgBUserID, GroupID: setup.orgBGroupID, Source: rbac.MembershipSourceAdmin,
	}))
	// Note: no contract grant for Org B on Org A's contract

	return setup
}

// buildGetStorageAtBody builds a JSON-RPC eth_getStorageAt request body.
func buildGetStorageAtBody(contractAddr, slot string) []byte {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getStorageAt",
		"params":  []any{contractAddr, slot, "latest"},
		"id":      1,
	}
	body, _ := json.Marshal(reqBody)
	return body
}

// TestE2E_TieredStorageAccess tests the tiered eth_getStorageAt access control.
//
// Admin users can read any storage slot on a granted contract. Read-only users can
// only read well-known infrastructure slots (EIP-1967, EIP-2535). Arbitrary slot
// enumeration is denied for non-admin users. Cross-org and unauthenticated access
// is always denied.
func TestE2E_TieredStorageAccess(t *testing.T) {
	t.Run("admin reads arbitrary storage slot", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_admin_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.adminUserDID)

		// Arbitrary slot (not well-known) — admin should be allowed
		body := buildGetStorageAtBody(setup.contractAddr, "0x0000000000000000000000000000000000000000000000000000000000000000")
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		// Admin should pass RBAC. Accept 200 (node answered) or 502 (node not running).
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
			"admin reading arbitrary slot should not be denied; got: %s", string(respBody))
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"expected 200 or 502, got %d: %s", resp.StatusCode, string(respBody))
	})

	t.Run("read user reads EIP-1967 implementation slot", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_read_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.readUserDID)

		// EIP-1967 implementation slot — well-known, should be allowed for read users
		eip1967ImplSlot := "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
		body := buildGetStorageAtBody(setup.contractAddr, eip1967ImplSlot)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
			"read user reading EIP-1967 implementation slot should not be denied; got: %s", string(respBody))
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"expected 200 or 502, got %d: %s", resp.StatusCode, string(respBody))
	})

	t.Run("read user reads arbitrary slot DENIED", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_read_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.readUserDID)

		// Slot 0x0 — arbitrary, not well-known
		body := buildGetStorageAtBody(setup.contractAddr, "0x0000000000000000000000000000000000000000000000000000000000000000")
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"read user reading arbitrary slot should be denied with opaque 404; got: %s", string(respBody))
		assertOpaqueErrorBody(t, respBody, "storage", "slot", "denied")
	})

	t.Run("unauthenticated user denied", func(t *testing.T) {
		_, serverURL, cleanup := setupE2E(t)
		defer cleanup()

		contractAddr := "0x7777777777777777777777777777777777777777"
		eip1967ImplSlot := "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
		body := buildGetStorageAtBody(contractAddr, eip1967ImplSlot)

		// Send request without Authorization header
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest("POST", serverURL+"/", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"unauthenticated user should be denied with opaque 404; got: %s", string(respBody))
	})

	t.Run("cross-org user denied", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_orgb_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.orgBUserDID)

		// Org B user tries to read Org A's contract — even a well-known slot should be denied
		eip1967ImplSlot := "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
		body := buildGetStorageAtBody(setup.contractAddr, eip1967ImplSlot)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"cross-org user should be denied access to another org's contract; got: %s", string(respBody))
		assertOpaqueErrorBody(t, respBody, "cross-org", "org b")
	})

	// --- Security-focused subtests ---

	t.Run("SECURITY: read user cannot enumerate slots", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_read_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.readUserDID)

		// Try to enumerate slots 0x0 through 0x4 — all should be denied
		for i := 0; i <= 4; i++ {
			slot := fmt.Sprintf("0x%064x", i)
			t.Run(fmt.Sprintf("slot_%d", i), func(t *testing.T) {
				body := buildGetStorageAtBody(setup.contractAddr, slot)
				resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

				assert.Equal(t, http.StatusNotFound, resp.StatusCode,
					"read user enumerating slot %d should be denied; got: %s", i, string(respBody))
				assertOpaqueErrorBody(t, respBody, "storage", "slot")
			})
		}
	})

	t.Run("SECURITY: read user denied on Diamond slot off-by-one", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_read_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.readUserDID)

		// Diamond slot: 0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c
		// Off-by-one: change last hex digit c -> d
		offByOneSlot := "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131d"
		body := buildGetStorageAtBody(setup.contractAddr, offByOneSlot)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"read user with off-by-one Diamond slot should be denied; got: %s", string(respBody))
		assertOpaqueErrorBody(t, respBody, "storage", "slot")
	})
}

// buildGetProofBody builds a JSON-RPC eth_getProof request body.
func buildGetProofBody(contractAddr string, keys []string) []byte {
	storageKeys := make([]any, 0, len(keys))
	for _, k := range keys {
		storageKeys = append(storageKeys, k)
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_getProof",
		"params":  []any{contractAddr, storageKeys, "latest"},
		"id":      1,
	})
	return body
}

// TestE2E_TieredStorageAccess_GetProof pins that eth_getProof sits behind the
// same storage-slot tier as eth_getStorageAt. A proof returns
// storageProof[].value for every requested key, so a non-admin may only prove
// the well-known infrastructure slots; an ordinary or mixed key list is denied
// with the opaque 404 before it reaches the node.
func TestE2E_TieredStorageAccess_GetProof(t *testing.T) {
	const (
		implSlot     = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
		ordinarySlot = "0x0000000000000000000000000000000000000000000000000000000000000000"
	)

	t.Run("read user", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_read_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.readUserDID)

		for _, tc := range []struct {
			name string
			keys []string
		}{
			{"ordinary key DENIED", []string{ordinarySlot}},
			{"well-known + ordinary keys DENIED", []string{implSlot, ordinarySlot}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resp, respBody := doRPCRequest(t, serverURL, accessToken, buildGetProofBody(setup.contractAddr, tc.keys))
				assert.Equal(t, http.StatusNotFound, resp.StatusCode,
					"a non-admin proof of an ordinary slot must be denied with the opaque 404; got: %s", string(respBody))
				assertOpaqueErrorBody(t, respBody, "storage", "slot", "proof", "denied")
			})
		}

		for _, tc := range []struct {
			name string
			keys []string
		}{
			{"EIP-1967 implementation key allowed", []string{implSlot}},
			{"zero keys (account proof) allowed", []string{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resp, respBody := doRPCRequest(t, serverURL, accessToken, buildGetProofBody(setup.contractAddr, tc.keys))
				assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
					"a non-admin proof of well-known slots only must not be denied; got: %s", string(respBody))
				assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
					"expected 200 or 502, got %d: %s", resp.StatusCode, string(respBody))
			})
		}
	})

	t.Run("admin proves an ordinary key", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_admin_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.adminUserDID)

		resp, respBody := doRPCRequest(t, serverURL, accessToken, buildGetProofBody(setup.contractAddr, []string{ordinarySlot}))
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
			"an admin proof of an ordinary slot on a granted contract must not be denied; got: %s", string(respBody))
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
			"expected 200 or 502, got %d: %s", resp.StatusCode, string(respBody))
	})

	t.Run("cross-org user DENIED", func(t *testing.T) {
		mockVerifier := &mockPrivadoVerifier{userDID: "did:privado:storage_orgb_user"}
		srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
		defer cleanup()

		setup := setupStorageAccessTest(t, srv.DB())
		accessToken := getJWTToken(t, serverURL, setup.orgBUserDID)

		resp, respBody := doRPCRequest(t, serverURL, accessToken, buildGetProofBody(setup.contractAddr, []string{implSlot}))
		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"another org's user must be denied a proof even of a well-known slot; got: %s", string(respBody))
		assertOpaqueErrorBody(t, respBody, "cross-org", "org b")
	})
}
