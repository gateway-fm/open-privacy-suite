package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the visibleTo fallback for transaction-object RPCs:
//
//   - eth_getTransactionByHash (bug: extractor silently failed on tx body)
//   - eth_getTransactionByBlockHashAndIndex (gap: no visibleTo fallback at all)
//   - eth_getTransactionByBlockNumberAndIndex (gap: no visibleTo fallback at all)
//
// They exercise the full applyResponseFilter path with a real DB, real
// AccessController, and a real txVisibilityStore. A listed viewer (not a from/to
// participant) must receive the full tx body; an unlisted viewer must see null.

const (
	visTxBuilderTxHash        = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	visTxBuilderSenderAddr    = "0x1111111111111111111111111111111111111111"
	visTxBuilderReceiverAddr  = "0x2222222222222222222222222222222222222222"
	visTxBuilderBystanderAddr = "0x3333333333333333333333333333333333333333"
)

// buildTransactionByHashResponse builds a JSON-RPC response for eth_getTransactionByHash.
// Uses the canonical Ethereum field "hash" (not "transactionHash" — receipts use that).
func buildTransactionByHashResponse(t *testing.T, hash, from, to string) []byte {
	t.Helper()
	tx := map[string]any{
		"hash":             hash,
		"from":             from,
		"to":               to,
		"blockHash":        "0x0000000000000000000000000000000000000000000000000000000000000001",
		"blockNumber":      "0x1",
		"transactionIndex": "0x0",
		"value":            "0x0",
		"gas":              "0x5208",
		"gasPrice":         "0x1",
		"input":            "0x",
		"nonce":            "0x0",
		"v":                "0x0",
		"r":                "0x0",
		"s":                "0x0",
	}
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  tx,
	}
	out, err := json.Marshal(body)
	require.NoError(t, err)
	return out
}

// visTxTestSetup is a minimal RBAC setup for the visibleTo tx-by-hash tests.
type visTxTestSetup struct {
	orgID     string
	senderDID string
	viewerDID string
	// The viewer has a linked address that is NOT from/to of the tx, forcing the
	// filter to fall back to the visibleTo gate.
	viewerAddr string
}

// setupVisTxTest creates an org, a sender DID, and a viewer DID with a linked
// address that is NOT a participant in the test tx. This lets us verify that
// visibleTo genuinely widens access past the from/to participant check.
func setupVisTxTest(t *testing.T, ts *testServerRBAC) *visTxTestSetup {
	t.Helper()
	ctx := context.Background()

	setup := &visTxTestSetup{
		orgID:      uuid.New().String(),
		senderDID:  "did:privado:tx_sender_" + uuid.New().String()[:8],
		viewerDID:  "did:privado:tx_viewer_" + uuid.New().String()[:8],
		viewerAddr: visTxBuilderBystanderAddr, // not from, not to
	}

	// Create org
	require.NoError(t, ts.db.CreateOrganization(ctx, &rbac.Organization{
		ID:   setup.orgID,
		Slug: "tx-vis-test-" + uuid.New().String()[:8],
		Name: "Tx Vis Test Org",
	}))

	// Create viewer user + link an address that is NOT a tx participant.
	// (applyResponseFilter reads linked addresses before falling through to visibleTo.)
	viewer := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: setup.viewerDID,
	}
	require.NoError(t, ts.db.CreateUser(ctx, viewer))
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, setup.viewerDID, setup.viewerAddr))

	// Save visibleTo: sender lists viewerDID as allowed to see the tx.
	require.NoError(t, ts.db.SaveTxVisibility(ctx, visTxBuilderTxHash, []string{setup.viewerDID}, setup.senderDID, setup.orgID))

	return setup
}

func TestApplyResponseFilter_GetTransactionByHash_ListedDIDSeesFullTx(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	proc.txVisibilityStore = ts.db

	setup := setupVisTxTest(t, ts)

	body := buildTransactionByHashResponse(t, visTxBuilderTxHash, visTxBuilderSenderAddr, visTxBuilderReceiverAddr)
	req := &ProcessRequest{
		Method: rbac.MethodGetTransactionByHash,
		UserID: setup.viewerDID,
		Body:   body,
	}

	out := proc.applyResponseFilter(context.Background(), req, nil, body)

	// Listed viewer gets the full tx body (not null) via the visibleTo fallback.
	assertResultNotNull(t, out, "listed viewer should receive full tx via visibleTo")
	assertHashInResult(t, out, visTxBuilderTxHash)
}

func TestApplyResponseFilter_GetTransactionByHash_UnlistedDIDGetsNull(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	proc.txVisibilityStore = ts.db

	_ = setupVisTxTest(t, ts)

	// Create an unlisted user whose DID is NOT in visibleTo for this tx.
	unlistedDID := "did:privado:stranger_" + uuid.New().String()[:8]
	require.NoError(t, ts.db.CreateUser(context.Background(), &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: unlistedDID,
	}))
	require.NoError(t, ts.db.SystemLinkEthAddress(context.Background(), unlistedDID, "0x4444444444444444444444444444444444444444"))

	body := buildTransactionByHashResponse(t, visTxBuilderTxHash, visTxBuilderSenderAddr, visTxBuilderReceiverAddr)
	req := &ProcessRequest{
		Method: rbac.MethodGetTransactionByHash,
		UserID: unlistedDID,
		Body:   body,
	}

	out := proc.applyResponseFilter(context.Background(), req, nil, body)

	// Unlisted viewer with non-participant address → null.
	assertResultIsNull(t, out, "unlisted viewer should see null (no visibleTo entry)")
}

func TestApplyResponseFilter_GetTransactionByHash_ParticipantStillWorks(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	proc.txVisibilityStore = ts.db

	// A user whose linked address IS the tx sender — should get the tx via the
	// normal participant path, independent of visibleTo.
	ctx := context.Background()
	participantDID := "did:privado:participant_" + uuid.New().String()[:8]
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: participantDID,
	}))
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, participantDID, visTxBuilderSenderAddr))

	body := buildTransactionByHashResponse(t, visTxBuilderTxHash, visTxBuilderSenderAddr, visTxBuilderReceiverAddr)
	req := &ProcessRequest{
		Method: rbac.MethodGetTransactionByHash,
		UserID: participantDID,
		Body:   body,
	}

	out := proc.applyResponseFilter(ctx, req, nil, body)

	assertResultNotNull(t, out, "participant should always see tx (visibleTo-independent)")
	assertHashInResult(t, out, visTxBuilderTxHash)
}

func TestApplyResponseFilter_GetTransactionByBlockHashAndIndex_ListedDIDSeesFullTx(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	proc.txVisibilityStore = ts.db

	setup := setupVisTxTest(t, ts)

	body := buildTransactionByHashResponse(t, visTxBuilderTxHash, visTxBuilderSenderAddr, visTxBuilderReceiverAddr)
	req := &ProcessRequest{
		Method: rbac.MethodGetTransactionByBlockHashAndIndex,
		UserID: setup.viewerDID,
		Body:   body,
	}

	out := proc.applyResponseFilter(context.Background(), req, nil, body)

	// Before this PR, ByBlockHashAndIndex had no visibleTo fallback — listed DID got null.
	assertResultNotNull(t, out, "listed viewer should receive full tx via visibleTo on ByBlockHashAndIndex")
	assertHashInResult(t, out, visTxBuilderTxHash)
}

func TestApplyResponseFilter_GetTransactionByBlockNumberAndIndex_ListedDIDSeesFullTx(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	proc.txVisibilityStore = ts.db

	setup := setupVisTxTest(t, ts)

	body := buildTransactionByHashResponse(t, visTxBuilderTxHash, visTxBuilderSenderAddr, visTxBuilderReceiverAddr)
	req := &ProcessRequest{
		Method: rbac.MethodGetTransactionByBlockNumberAndIndex,
		UserID: setup.viewerDID,
		Body:   body,
	}

	out := proc.applyResponseFilter(context.Background(), req, nil, body)

	assertResultNotNull(t, out, "listed viewer should receive full tx via visibleTo on ByBlockNumberAndIndex")
	assertHashInResult(t, out, visTxBuilderTxHash)
}

func TestApplyResponseFilter_GetTransactionByBlockHashAndIndex_UnlistedDIDGetsNull(t *testing.T) {
	proc, ts := setupProcessorWithoutTracing(t)
	proc.txVisibilityStore = ts.db

	_ = setupVisTxTest(t, ts)

	ctx := context.Background()
	unlistedDID := "did:privado:stranger_" + uuid.New().String()[:8]
	require.NoError(t, ts.db.CreateUser(ctx, &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: unlistedDID,
	}))
	require.NoError(t, ts.db.SystemLinkEthAddress(ctx, unlistedDID, "0x4444444444444444444444444444444444444444"))

	body := buildTransactionByHashResponse(t, visTxBuilderTxHash, visTxBuilderSenderAddr, visTxBuilderReceiverAddr)
	req := &ProcessRequest{
		Method: rbac.MethodGetTransactionByBlockHashAndIndex,
		UserID: unlistedDID,
		Body:   body,
	}

	out := proc.applyResponseFilter(ctx, req, nil, body)

	assertResultIsNull(t, out, "unlisted viewer should see null on ByBlockHashAndIndex")
}

// -- helpers --------------------------------------------------------------

func assertResultNotNull(t *testing.T, body []byte, msg string) {
	t.Helper()
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &resp), "invalid response body: %s", string(body))
	assert.NotEqual(t, "null", string(resp.Result), msg+" — got: %s", string(body))
}

func assertResultIsNull(t *testing.T, body []byte, msg string) {
	t.Helper()
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &resp), "invalid response body: %s", string(body))
	assert.Equal(t, "null", string(resp.Result), msg+" — got: %s", string(body))
}

func assertHashInResult(t *testing.T, body []byte, wantHash string) {
	t.Helper()
	if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(wantHash)) {
		t.Errorf("expected hash %q in response, got: %s", wantHash, string(body))
	}
}
