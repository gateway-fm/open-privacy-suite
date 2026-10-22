package server

import (
	"net/http"
	"strings"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/disclosure"

	"github.com/gin-gonic/gin"
)

// getGrantTransaction serves only a Full grant's in-scope transaction.
//
// @Summary      Grant-scoped transaction detail
// @Description  Returns a transaction involving the disclosed address within an active Full grant's consented date and address scope. The authenticated requester must remain a member of the grant's organization. Pseudonymous and redacted grants, a transaction outside scope, and View-as return 404. Transactions require transaction_history or full_disclosure permission. The access is audited. Private network only; not reachable through public ingress.
// @Tags         Explorer
// @Produce      json
// @Security     BearerAuth
// @Param        grant_id path string true "Disclosure grant ID"
// @Param        address_id path string true "Opaque address identifier from viewable-addresses"
// @Param        tx_hash path string true "Transaction hash (0x-prefixed, 32 bytes)"
// @Success      200 {object} apimodels.GrantTransactionDetail
// @Failure      400 {object} apimodels.APIError "invalid transaction hash"
// @Failure      401 {object} apimodels.APIError "authentication required"
// @Failure      403 {object} apimodels.APIError "inactive grant or transaction history not permitted"
// @Failure      404 {object} apimodels.APIError "grant or transaction not available"
// @Failure      500 {object} apimodels.APIError "lookup failed"
// @Router       /api/v1/explorer/grant/{grant_id}/{address_id}/transactions/{tx_hash} [get]
func (s *Server) getGrantTransaction(c *gin.Context) {
	gw, ok := s.explorerGrant(c, false)
	if !ok {
		return
	}
	// A hash lookup at a lower disclosure level would confirm ownership of a
	// known transaction, even if the payload were subsequently redacted.
	if gw.Grant.Scope.EffectiveLevel() != disclosure.DisclosureFull {
		respondNotFound(c, "transaction not found")
		return
	}
	if !gw.Grant.Scope.AllowsTransactionHistory() {
		respondForbidden(c, "grant scope does not include transaction_history")
		return
	}
	hash := c.Param("tx_hash")
	if !isTxHash(hash) {
		respondBadRequest(c, "invalid transaction hash")
		return
	}
	address, err := s.grantSubjectAddress(c.Request.Context(), gw, c.Param("address_id"))
	if err != nil {
		respondInternalError(c, "failed to resolve address")
		return
	}
	if address == "" {
		respondNotFound(c, "transaction not found")
		return
	}
	if s.explorerStore == nil {
		respondInternalError(c, "explorer store not configured")
		return
	}
	tx, err := s.explorerStore.GetTransaction(c.Request.Context(), strings.ToLower(hash))
	if err != nil {
		respondInternalError(c, "failed to get transaction")
		return
	}
	if tx == nil || (!strings.EqualFold(tx.From, address) && (!tx.HasRecipient() || !strings.EqualFold(*tx.To, address))) {
		respondNotFound(c, "transaction not found")
		return
	}
	if err := s.grantTxTimestamp(c.Request.Context(), tx); err != nil {
		respondInternalErrorAndLog(c, "failed to get transaction time", "disclosure: transaction block lookup failed", "err", err)
		return
	}
	to := ""
	if tx.HasRecipient() {
		to = *tx.To
	}
	if !gw.Grant.Scope.CoversTransaction(tx.From, to, int64(tx.BlockTimestamp)) {
		respondNotFound(c, "transaction not found")
		return
	}
	response := apimodels.GrantTransactionDetail{
		TxHash: tx.Hash, BlockNumber: tx.BlockNumber, BlockTimestamp: tx.BlockTimestamp,
		TxIndex: tx.TxIndex, Direction: grantTxDirection(*tx, address), From: tx.From, To: to,
		Value: string(tx.Value), GasUsed: tx.GasUsed, GasPrice: tx.GasPrice, GasLimit: tx.GasLimit,
		MaxFeePerGas: tx.MaxFeePerGas, MaxPriorityFeePerGas: tx.MaxPriorityFeePerGas,
		Nonce: tx.Nonce, TxType: tx.TxType, InputData: tx.InputData, Status: tx.Status,
		Error: tx.Error, RevertReason: tx.RevertReason, DisclosureLevel: "full",
	}
	if tx.ContractAddress != nil {
		response.ContractAddress = *tx.ContractAddress
	}
	s.recordGrantRead(c, gw.Grant.ID, disclosure.ActionViewTransaction, disclosure.ResourceTransactions, 1)
	c.JSON(http.StatusOK, response)
}
