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
	"privacy-proxy/internal/server"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// visibleToTestSetup holds IDs created during test setup.
type visibleToTestSetup struct {
	orgID         string
	groupID       string
	senderUserID  string
	senderDID     string
	viewerUserID  string
	viewerDID     string
	contractAddr  string
	senderAddr    string
	viewerAddr    string
}

// setupVisibleToTest creates the full RBAC hierarchy for testing visibleTo:
// org -> group -> sender user + viewer user -> contract with event rules -> grants.
func setupVisibleToTest(t *testing.T, database *db.DB) *visibleToTestSetup {
	t.Helper()
	ctx := context.Background()

	setup := &visibleToTestSetup{
		orgID:        uuid.New().String(),
		groupID:      uuid.New().String(),
		senderDID:    "did:privado:log_vis_sender",
		viewerDID:    "did:privado:log_vis_viewer",
		contractAddr: "0x6666666666666666666666666666666666666666",
		senderAddr:   "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		viewerAddr:   "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	// 1. Create organization
	org := &rbac.Organization{
		ID:       setup.orgID,
		Slug:     "log-vis-test-org",
		Name:     "Log Visibility Test Org",
		Settings: map[string]any{},
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	// 2. Create group with read+write claims
	group := &rbac.Group{
		ID:    setup.groupID,
		OrgID: setup.orgID,
		Slug:  "log-vis-group",
		Name:  "Log Visibility Group",
	}
	require.NoError(t, database.CreateGroup(ctx, group))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        setup.groupID,
		Claims:         []rbac.Claim{},
		AllowedMethods: []string{},
	}))

	// 3. Create sender user
	senderUser := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: setup.senderDID,
	}
	require.NoError(t, database.CreateUser(ctx, senderUser))
	setup.senderUserID = senderUser.ID
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  senderUser.ID,
		GroupID: setup.groupID,
	}))
	require.NoError(t, database.SystemLinkEthAddress(ctx, setup.senderDID, setup.senderAddr))

	// 4. Create viewer user
	viewerUser := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: setup.viewerDID,
	}
	require.NoError(t, database.CreateUser(ctx, viewerUser))
	setup.viewerUserID = viewerUser.ID
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  viewerUser.ID,
		GroupID: setup.groupID,
	}))
	require.NoError(t, database.SystemLinkEthAddress(ctx, setup.viewerDID, setup.viewerAddr))

	// 5. Create contract with event rules (Transfer with must_be=self on from param)
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	now := time.Now()
	contract := &rbac.Contract{
		ID:         uuid.New().String(),
		OrgID:      setup.orgID,
		Address:    setup.contractAddr,
		Name:       "Log Vis Test Token",
		DeployedAt: &now,
	}
	require.NoError(t, database.CreateContract(ctx, contract))

	// 6. Create grant with event rules
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    setup.groupID,
		EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
			{
				Topic0: transferTopic0,
				Name:   "Transfer",
				ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "self"},
				},
			},
		}},
	}))

	return setup
}

// TestVisibleToE2E_SaveAndQuery tests that visibleTo rules are stored
// and queried correctly at the database level.
func TestVisibleToE2E_SaveAndQuery(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	database, err := db.New(dbURL)
	require.NoError(t, err)
	defer database.Close()

	ctx := context.Background()
	setup := setupVisibleToTest(t, database)

	txHash := "0xfeedface0000000000000000000000000000000000000000000000000000abcd"

	// Save a visibleTo rule
	err = database.SaveTxVisibility(ctx, txHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID)
	require.NoError(t, err)

	// Query single
	dids, err := database.GetTxVisibility(ctx, txHash)
	require.NoError(t, err)
	assert.Equal(t, []string{setup.viewerDID}, dids)

	// Query batch
	batch, err := database.GetBatchTxVisibility(ctx, []string{txHash, "0xnonexistent"})
	require.NoError(t, err)
	assert.Len(t, batch, 1)
	assert.Equal(t, []string{setup.viewerDID}, batch[strings.ToLower(txHash)])

	// Verify the viewer DID is listed but unlisted user is not
	assert.Contains(t, dids, setup.viewerDID)
	assert.NotContains(t, dids, setup.senderDID)
}

// TestVisibleToE2E_FilterIntegration tests that the event filter uses
// visibleTo to extend access when param rules fail.
func TestVisibleToE2E_FilterIntegration(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	database, err := db.New(dbURL)
	require.NoError(t, err)
	defer database.Close()

	ctx := context.Background()
	setup := setupVisibleToTest(t, database)

	txHash := "0xfeedface0000000000000000000000000000000000000000000000000000def0"

	// Save visibleTo for viewer
	err = database.SaveTxVisibility(ctx, txHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID)
	require.NoError(t, err)

	// Query permissions for viewer (resolve effective permissions)
	// We build a minimal EffectivePermissions manually since we're testing
	// the filter, not the full permission resolver.
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	senderTopic := "0x000000000000000000000000" + setup.senderAddr[2:]

	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			setup.contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	// Build log entry: Transfer event where from = sender (not viewer)
	logJSON := fmt.Sprintf(`{"address":"%s","topics":["%s","%s"],"data":"0x","transactionHash":"%s"}`,
		setup.contractAddr, transferTopic0, senderTopic, txHash)
	logs := []json.RawMessage{json.RawMessage(logJSON)}

	// Build visibility context
	visibility, err := database.GetBatchTxVisibility(ctx, []string{txHash})
	require.NoError(t, err)

	visCtx := &rbac.TxVisibilityContext{
		ViewerDID:    setup.viewerDID,
		TxVisibility: visibility,
	}

	// Viewer without visibleTo: should not see the log (not "self")
	resultWithout := rbac.FilterEventLogs(logs, perms, []string{setup.viewerAddr}, nil, nil, nil)
	assert.Len(t, resultWithout, 0, "viewer should not see log without visibleTo")

	// Viewer with visibleTo: should see the log
	resultWith := rbac.FilterEventLogs(logs, perms, []string{setup.viewerAddr}, nil, visCtx, nil)
	assert.Len(t, resultWith, 1, "viewer should see log with visibleTo")

	// Unlisted user with visibleTo context: should NOT see the log
	unlistedVisCtx := &rbac.TxVisibilityContext{
		ViewerDID:    "did:privado:unlisted",
		TxVisibility: visibility,
	}
	resultUnlisted := rbac.FilterEventLogs(logs, perms, []string{"0xcccccccccccccccccccccccccccccccccccccccc"}, nil, unlistedVisCtx, nil)
	assert.Len(t, resultUnlisted, 0, "unlisted user should not see log even with visCtx")
}

// TestVisibleToE2E_TxNotVisibleToListedDID verifies the critical security
// property: visibleTo grants access to LOGS ONLY via JSON-RPC, not the
// transaction receipt. The viewer (settlement bank) should see event logs via
// eth_getLogs but NOT the transaction via eth_getTransactionReceipt — because
// they are not a participant in the from/to fields of the receipt.
func TestVisibleToE2E_TxNotVisibleToListedDID(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	database, err := db.New(dbURL)
	require.NoError(t, err)
	defer database.Close()

	ctx := context.Background()
	setup := setupVisibleToTest(t, database)

	txHash := "0xfeedface0000000000000000000000000000000000000000000000000000aa01"
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	senderTopic := "0x000000000000000000000000" + setup.senderAddr[2:]

	// Save visibleTo rule: viewer DID can see logs from this tx.
	err = database.SaveTxVisibility(ctx, txHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID)
	require.NoError(t, err)

	// Build effective permissions for the viewer.
	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			setup.contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	// Build visibility context from DB.
	visibility, err := database.GetBatchTxVisibility(ctx, []string{txHash})
	require.NoError(t, err)
	visCtx := &rbac.TxVisibilityContext{
		ViewerDID:    setup.viewerDID,
		TxVisibility: visibility,
	}

	// --- Test FilterReceiptLogsWithEventRules ---
	// Build a fake receipt where from=senderAddr, to=contractAddr.
	// The viewer (0xBBB) is NOT a participant (not from, not to).
	receiptBody := buildReceiptResponse(t, setup.senderAddr, setup.contractAddr, txHash, transferTopic0, senderTopic)

	receiptResult := server.FilterReceiptLogsWithEventRules(
		rbac.ReadProfileStandard,
		receiptBody,
		[]string{setup.viewerAddr}, // viewer's addresses
		perms,
		nil,    // no ABI provider
		visCtx, // has visibleTo
		nil,    // no admin map (admin bypass tested elsewhere)
	)

	// Viewer is NOT a from/to participant but IS in visibleTo — receipt is
	// returned (visibleTo bypasses the participant gate for receipts).
	var receiptResp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(receiptResult, &receiptResp))
	assert.NotEqual(t, "null", string(receiptResp.Result),
		"visibleTo viewer should receive receipt even without being a from/to participant")

	// --- Test FilterLogsWithEventRules (eth_getLogs path) ---
	// Build a fake eth_getLogs response with the same Transfer log.
	logsBody := buildLogsResponse(t, setup.contractAddr, txHash, transferTopic0, senderTopic)

	// Viewer WITH visibleTo: should see the log via eth_getLogs.
	logsResult := server.FilterLogsWithEventRules(
		logsBody,
		[]string{setup.viewerAddr},
		perms,
		nil,
		visCtx,
	nil,
	)

	var logsResp struct {
		Result []json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(logsResult, &logsResp))
	assert.Len(t, logsResp.Result, 1,
		"viewer should see log via eth_getLogs because their DID is in visibleTo")
}

// TestVisibleToE2E_GetLogsWithVisibleTo tests the full filter pipeline for
// eth_getLogs: listed DID sees logs, unlisted DID does not.
func TestVisibleToE2E_GetLogsWithVisibleTo(t *testing.T) {
	dbURL, cleanup := db.SetupTestContainer(t)
	defer cleanup()

	database, err := db.New(dbURL)
	require.NoError(t, err)
	defer database.Close()

	ctx := context.Background()
	setup := setupVisibleToTest(t, database)

	txHash := "0xfeedface0000000000000000000000000000000000000000000000000000bb02"
	transferTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	senderTopic := "0x000000000000000000000000" + setup.senderAddr[2:]

	// Save visibleTo for viewer.
	err = database.SaveTxVisibility(ctx, txHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID)
	require.NoError(t, err)

	// Build permissions for viewer with Transfer event rule (must_be=self on from).
	perms := &rbac.EffectivePermissions{
		ContractAccess: map[string]rbac.ContractAccess{
			setup.contractAddr: {
				Claims: []rbac.Claim{},
				EventRules: &rbac.EventRulesField{Rules: []rbac.EventRule{
					{
						Topic0: transferTopic0,
						Name:   "Transfer",
						ParamRules: []rbac.ParamRule{
							{Index: 0, MustBe: "self"},
						},
					},
				}},
			},
		},
	}

	// Build mock eth_getLogs response with a Transfer log where topic1 = sender address.
	logsBody := buildLogsResponse(t, setup.contractAddr, txHash, transferTopic0, senderTopic)

	// Viewer with visibleTo context: should see the log.
	visibility, err := database.GetBatchTxVisibility(ctx, []string{txHash})
	require.NoError(t, err)

	viewerVisCtx := &rbac.TxVisibilityContext{
		ViewerDID:    setup.viewerDID,
		TxVisibility: visibility,
	}

	resultListed := server.FilterLogsWithEventRules(
		logsBody,
		[]string{setup.viewerAddr},
		perms,
		nil,
		viewerVisCtx,
	nil,
	)
	var listedResp struct {
		Result []json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(resultListed, &listedResp))
	assert.Len(t, listedResp.Result, 1,
		"listed viewer DID should see the log via visibleTo")

	// Unlisted DID: should NOT see the log even though visibility data exists.
	unlistedVisCtx := &rbac.TxVisibilityContext{
		ViewerDID:    "did:privado:unlisted_stranger",
		TxVisibility: visibility,
	}
	unlistedAddr := "0xcccccccccccccccccccccccccccccccccccccccc"

	resultUnlisted := server.FilterLogsWithEventRules(
		logsBody,
		[]string{unlistedAddr},
		perms,
		nil,
		unlistedVisCtx,
	nil,
	)
	var unlistedResp struct {
		Result []json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(resultUnlisted, &unlistedResp))
	assert.Len(t, unlistedResp.Result, 0,
		"unlisted DID should not see the log — visibleTo only applies to listed DIDs")

	// No visCtx at all: should also NOT see the log (backward compat).
	resultNone := server.FilterLogsWithEventRules(
		logsBody,
		[]string{setup.viewerAddr},
		perms,
		nil,
		nil, // no visCtx
		nil, // no admin map
	)
	var noneResp struct {
		Result []json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(resultNone, &noneResp))
	assert.Len(t, noneResp.Result, 0,
		"viewer without visCtx should not see the log (param rule self check fails)")
}

// buildReceiptResponse constructs a JSON-RPC response body for eth_getTransactionReceipt.
func buildReceiptResponse(t *testing.T, from, to, txHash, topic0, topic1 string) []byte {
	t.Helper()
	receipt := map[string]any{
		"from":            from,
		"to":              to,
		"status":          "0x1",
		"gasUsed":         "0x5208",
		"blockHash":       "0x0000000000000000000000000000000000000000000000000000000000000001",
		"blockNumber":     "0x1",
		"transactionHash": txHash,
		"logsBloom":       "0x" + strings.Repeat("0", 512),
		"logs": []map[string]any{
			{
				"address":          to,
				"topics":           []string{topic0, topic1},
				"data":             "0x",
				"transactionHash":  txHash,
				"logIndex":         "0x0",
				"blockNumber":      "0x1",
				"transactionIndex": "0x0",
			},
		},
	}
	receiptJSON, err := json.Marshal(receipt)
	require.NoError(t, err)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  json.RawMessage(receiptJSON),
	}
	body, err := json.Marshal(resp)
	require.NoError(t, err)
	return body
}

// buildLogsResponse constructs a JSON-RPC response body for eth_getLogs.
func buildLogsResponse(t *testing.T, contractAddr, txHash, topic0, topic1 string) []byte {
	t.Helper()
	logs := []map[string]any{
		{
			"address":          contractAddr,
			"topics":           []string{topic0, topic1},
			"data":             "0x",
			"transactionHash":  txHash,
			"logIndex":         "0x0",
			"blockNumber":      "0x1",
			"transactionIndex": "0x0",
		},
	}
	logsJSON, err := json.Marshal(logs)
	require.NoError(t, err)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  json.RawMessage(logsJSON),
	}
	body, err := json.Marshal(resp)
	require.NoError(t, err)
	return body
}

// rpcCall is a helper for tests that makes a JSON-RPC call.
func rpcCall(t *testing.T, url string, method string, params []any, headers map[string]string) (int, json.RawMessage) {
	t.Helper()
	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, json.RawMessage(respBody)
}
