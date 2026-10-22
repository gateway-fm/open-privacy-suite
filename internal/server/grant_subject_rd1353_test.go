package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/explorer"

	"github.com/stretchr/testify/require"
)

// The production indexer includes parent transactions when an address occurs
// only in a Transfer event. The local SQL address feed includes only tx.from/to,
// so reproduce that production behavior explicitly at the backend boundary.
type grantTransferParentBackendRD1353 struct {
	explorer.ExplorerBackend
	parent explorer.Transaction
	calls  int
}

func (b *grantTransferParentBackendRD1353) GetTransactionsByAddress(ctx context.Context, address string, limit int, page explorer.AddressPage) ([]explorer.Transaction, string, error) {
	b.calls++
	if page.Cursor == "" {
		return []explorer.Transaction{b.parent}, "after-transfer-parent", nil
	}
	if page.Cursor == "after-transfer-parent" {
		return b.ExplorerBackend.GetTransactionsByAddress(ctx, address, limit, explorer.AddressPage{})
	}
	return b.ExplorerBackend.GetTransactionsByAddress(ctx, address, limit, page)
}

func TestGrantAPI_TransferOnlyParentsDoNotDiscloseTransactions_RD1353(t *testing.T) {
	f := newRD1353Fixture(t)
	block := rd1353SeedBlockAt(t, f.conn, time.Now().Unix())
	directHash := rd1353SeedTx(t, f.conn, block, 0, testTargetAddress, rd1353Counterparty)
	parentHash := rd1353SeedTx(t, f.conn, block, 1, rd1353Other, rd1353Counterparty)
	parent, err := f.srv.explorerStore.GetTransaction(context.Background(), parentHash)
	require.NoError(t, err)
	require.NotNil(t, parent)
	backend := &grantTransferParentBackendRD1353{ExplorerBackend: f.srv.explorerStore, parent: *parent}
	f.srv.explorerStore = backend
	grantID, addressID := f.grant(t, `{"disclosure_level":"full","addresses":["`+rd1353Counterparty+`"]}`)

	w := rd1353Get(t, f.router, f.srv, testViewerDID,
		"/api/v1/explorer/grant/"+grantID+"/"+addressID+"/transactions?limit=1")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var response apimodels.GrantTransactionsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Len(t, response.Transactions, 1)
	require.NotNil(t, response.Transactions[0].TxHash)
	require.Equal(t, directHash, *response.Transactions[0].TxHash,
		"the feed must skip transfer-only parents and continue to a subject transaction")
	require.Equal(t, "out", response.Transactions[0].Direction)
	require.Empty(t, response.NextCursor)
	require.Equal(t, 2, backend.calls, "the scanner must advance past the skipped row")
	require.NotContains(t, w.Body.String(), parentHash)
	require.NotContains(t, w.Body.String(), rd1353Other)
	require.Equal(t, http.StatusOK, f.detail(t, testViewerDID, grantID, addressID, directHash).Code)
	require.Equal(t, http.StatusNotFound, f.detail(t, testViewerDID, grantID, addressID, parentHash).Code)
}
