package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/db"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test addresses and DIDs for E2E tests
const (
	e2eViewerWallet  = "0x1111111111111111111111111111111111111111"
	e2eTargetAddress = "0x2222222222222222222222222222222222222222"
	e2ePublicAddress = "0x3333333333333333333333333333333333333333"
	e2eUnknownWallet = "0x4444444444444444444444444444444444444444"
	e2eViewerDID     = "did:privado:e2e_viewer"
	e2eTargetDID     = "did:privado:e2e_target"
)

// explorerTestSetup creates the necessary test data for explorer E2E tests
type explorerTestSetup struct {
	viewerUserID string
	targetUserID string
}

func setupExplorerTestData(t *testing.T, database *db.DB) *explorerTestSetup {
	ctx := context.Background()
	setup := &explorerTestSetup{}

	// Create default organization
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, _ = database.Conn().ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}') ON CONFLICT (id) DO NOTHING",
		defaultOrgID, "default", "Default Organization")

	// Create viewer user
	setup.viewerUserID = uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, true, false, '{}')",
		setup.viewerUserID, e2eViewerDID)
	require.NoError(t, err)

	// Create target user
	setup.targetUserID = uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, true, false, '{}')",
		setup.targetUserID, e2eTargetDID)
	require.NoError(t, err)

	return setup
}

func linkAddressForE2E(t *testing.T, database *db.DB, did, address string) {
	err := database.LinkEthAddress(context.Background(), did, address, "test-sig", "test-hash-"+address)
	require.NoError(t, err)
}

func createDisclosureGrantForE2E(t *testing.T, database *db.DB, requesterDID, targetUserID string, expiresAt time.Time) string {
	ctx := context.Background()

	// Create disclosure request
	requestID := uuid.New().String()
	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_requests
		(id, requester_did, target_user_id, org_id, scope, reason, status, requested_at)
		VALUES ($1, $2, $3, '00000000-0000-0000-0000-000000000001', '{}', 'E2E test grant', 'approved', NOW())`,
		requestID, requesterDID, targetUserID)
	require.NoError(t, err)

	// Create grant
	grantID := uuid.New().String()
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO disclosure_grants
		(id, request_id, grant_token_hash, scope, granted_at, expires_at)
		VALUES ($1, $2, $3, '{}', NOW(), $4)`,
		grantID, requestID, "e2e-test-hash-"+grantID, expiresAt)
	require.NoError(t, err)

	return grantID
}

// ============================================================================
// E2E Test: Viewable Addresses
// ============================================================================

func TestE2E_Explorer_ViewableAddresses(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link addresses
	linkAddressForE2E(t, database, e2eViewerDID, e2eViewerWallet)
	linkAddressForE2E(t, database, e2eTargetDID, e2eTargetAddress)

	// Create grant
	createDisclosureGrantForE2E(t, database, e2eViewerDID, setup.targetUserID, time.Now().Add(24*time.Hour))

	client := &http.Client{Timeout: 5 * time.Second}

	// RD-1164 #7: identity comes from the validated JWT, not a ?wallet= lookup
	// (the wallet param is only echoed as ViewerWallet). Authenticate as the viewer.
	token := getJWTToken(t, serverURL, e2eViewerDID)
	req, _ := http.NewRequest("GET", serverURL+"/api/v1/explorer/viewable-addresses?wallet="+e2eViewerWallet, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result apimodels.ViewableAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, e2eViewerWallet, result.ViewerWallet)
	assert.Equal(t, e2eViewerDID, result.ViewerDID)
	assert.Len(t, result.OwnAddresses, 1)
	assert.Equal(t, e2eViewerWallet, result.OwnAddresses[0].Address)
	assert.Len(t, result.DisclosedAddresses, 1)
	assert.Equal(t, e2eTargetAddress, result.DisclosedAddresses[0].Address)
	assert.Equal(t, e2eTargetDID, result.DisclosedAddresses[0].OwnerDID)
}

// ============================================================================
// E2E Test: Anonymous Viewer
// ============================================================================

func TestE2E_Explorer_AnonymousViewer(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	client := &http.Client{Timeout: 5 * time.Second}

	// Anonymous wallet (not linked to any DID)
	req, _ := http.NewRequest("GET", serverURL+"/api/v1/explorer/viewable-addresses?wallet="+e2eUnknownWallet, nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result apimodels.ViewableAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, e2eUnknownWallet, result.ViewerWallet)
	assert.Empty(t, result.ViewerDID)
	assert.Empty(t, result.OwnAddresses)
	assert.Empty(t, result.DisclosedAddresses)
}

// ============================================================================
// E2E Test: Multiple Addresses Per User
// ============================================================================

func TestE2E_Explorer_MultipleAddressesPerUser(t *testing.T) {
	mockVerifier := &mockPrivadoVerifier{userDID: e2eViewerDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	database := srv.DB()
	setup := setupExplorerTestData(t, database)

	// Link multiple addresses to viewer
	addresses := []string{
		"0xaaaa111111111111111111111111111111111111",
		"0xaaaa222222222222222222222222222222222222",
		"0xaaaa333333333333333333333333333333333333",
	}

	for _, addr := range addresses {
		linkAddressForE2E(t, database, e2eViewerDID, addr)
	}

	// Link multiple addresses to target
	targetAddresses := []string{
		"0xbbbb111111111111111111111111111111111111",
		"0xbbbb222222222222222222222222222222222222",
	}

	for _, addr := range targetAddresses {
		linkAddressForE2E(t, database, e2eTargetDID, addr)
	}

	// Create grant
	createDisclosureGrantForE2E(t, database, e2eViewerDID, setup.targetUserID, time.Now().Add(24*time.Hour))

	client := &http.Client{Timeout: 5 * time.Second}

	// RD-1164 #7: authenticate as the viewer; identity is JWT-based now, not ?wallet=.
	token := getJWTToken(t, serverURL, e2eViewerDID)
	req, _ := http.NewRequest("GET", serverURL+"/api/v1/explorer/viewable-addresses?wallet="+addresses[0], nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var result apimodels.ViewableAddressesResponse
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Len(t, result.OwnAddresses, 3)
	assert.Len(t, result.DisclosedAddresses, 2)

	// Verify all own addresses are present
	ownAddressMap := make(map[string]bool)
	for _, a := range result.OwnAddresses {
		ownAddressMap[a.Address] = true
	}
	for _, addr := range addresses {
		assert.True(t, ownAddressMap[addr], "Expected address %s to be in own addresses", addr)
	}

	// Verify all disclosed addresses are present
	disclosedAddressMap := make(map[string]bool)
	for _, a := range result.DisclosedAddresses {
		disclosedAddressMap[a.Address] = true
	}
	for _, addr := range targetAddresses {
		assert.True(t, disclosedAddressMap[addr], "Expected address %s to be in disclosed addresses", addr)
	}
}
