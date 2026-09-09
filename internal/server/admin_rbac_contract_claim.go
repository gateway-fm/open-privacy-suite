package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// claimUnregisteredContract allows an org admin to claim a contract that exists
// on-chain but is not registered to any org. Requires proof of deployment.
// POST /orgs/:org_id/contracts/claim
//
// @Summary      Claim an unregistered contract (proof of deployment)
// @Description  Registers an on-chain contract to the organization when the caller proves deployment: the deployment transaction's receipt must name the claimed address, and the deployer address must be linked to a member of the claiming org. Fail-closed: every verification failure (already registered, unknown tx, receipt mismatch, deployer not in org, no bytecode) returns the same opaque 400 "contract registration failed" so the endpoint cannot be used as an existence or ownership oracle.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "organization ID"
// @Param        request body apimodels.ContractClaimRequest true "claimed address and deployment tx hash"
// @Success      201 {object} apimodels.ContractClaimResponse
// @Failure      400 {object} apimodels.APIError "invalid input, or opaque verification failure"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/claim [post]
func (s *Server) claimUnregisteredContract(c *gin.Context) {
	if denyOperatorOrgScoped(c) { // RD-1173: operator token must not register contracts into a tenant org
		return
	}
	orgID := c.Param("org_id")

	var input struct {
		Address          string `json:"address" binding:"required"`
		Name             string `json:"name"`
		DeploymentTxHash string `json:"deployment_tx_hash" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address and deployment_tx_hash are required"})
		return
	}

	if !auth.IsValidAddress(input.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Ethereum address format"})
		return
	}

	normalizedAddr := strings.ToLower(input.Address)

	// Validate tx hash format (0x-prefixed, 66 chars total)
	txHash := strings.ToLower(input.DeploymentTxHash)
	if len(txHash) != 66 || !strings.HasPrefix(txHash, "0x") {
		slog.Warn("contract claim: invalid tx hash format",
			"address", normalizedAddr, "tx_hash", input.DeploymentTxHash, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	// Check if already registered to any org
	ownerOrgID, err := s.db.GetContractOwnerOrgID(c.Request.Context(), normalizedAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	if ownerOrgID != "" {
		slog.Warn("contract claim: address already registered",
			"address", normalizedAddr, "owner_org", ownerOrgID, "claiming_org", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	// Verify the deployment tx receipt on chain
	receipt, err := s.fetchTransactionReceipt(txHash)
	if err != nil {
		slog.Warn("contract claim: failed to fetch tx receipt",
			"address", normalizedAddr, "tx_hash", txHash, "org_id", orgID, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}
	if receipt == nil {
		slog.Warn("contract claim: tx receipt not found",
			"address", normalizedAddr, "tx_hash", txHash, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	// Verify the receipt's contractAddress matches the claimed address
	receiptAddr, ok := receipt["contractAddress"].(string)
	if !ok || strings.ToLower(receiptAddr) != normalizedAddr {
		slog.Warn("contract claim: receipt contractAddress mismatch",
			"address", normalizedAddr, "receipt_address", receiptAddr, "tx_hash", txHash, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	// Verify the deployer belongs to the claiming org.
	// Without this check, any org that knows a tx hash could claim another org's contract.
	deployerAddr, ok := receipt["from"].(string)
	if !ok || deployerAddr == "" {
		slog.Warn("contract claim: receipt missing from address",
			"address", normalizedAddr, "tx_hash", txHash, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}
	deployerDID, err := s.db.GetDIDByEthAddress(c.Request.Context(), strings.ToLower(deployerAddr))
	if err != nil || deployerDID == "" {
		slog.Warn("contract claim: deployer address not linked to any user",
			"address", normalizedAddr, "deployer", deployerAddr, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}
	// Check if the deployer's user is a member of the claiming org
	deployerInOrg, err := s.db.IsUserInOrg(c.Request.Context(), deployerDID, orgID)
	if err != nil || !deployerInOrg {
		slog.Warn("contract claim: deployer is not a member of claiming org",
			"address", normalizedAddr, "deployer", deployerAddr, "deployer_did", deployerDID, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	// Verify the address has bytecode on chain
	code, err := s.getContractCode(normalizedAddr)
	if err != nil {
		slog.Warn("contract claim: failed to check on-chain code",
			"address", normalizedAddr, "org_id", orgID, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}
	if code == "" || code == "0x" {
		slog.Warn("contract claim: no bytecode at address",
			"address", normalizedAddr, "org_id", orgID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	// All checks passed — register the contract
	name := input.Name
	if name == "" {
		name = "Contract " + normalizedAddr[:10]
	}

	contract := &rbac.Contract{
		ID:      uuid.New().String(),
		OrgID:   orgID,
		Address: normalizedAddr,
		Name:    name,
	}
	if err := s.db.CreateContract(c.Request.Context(), contract); err != nil {
		slog.Warn("contract claim: failed to create contract",
			"address", normalizedAddr, "org_id", orgID, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract registration failed"})
		return
	}

	slog.Info("contract claimed via proof-of-deployment",
		"address", normalizedAddr, "org_id", orgID, "tx_hash", txHash)

	c.JSON(http.StatusCreated, gin.H{
		"id":      contract.ID,
		"address": normalizedAddr,
		"name":    name,
		"org_id":  orgID,
	})
}

// fetchTransactionReceipt makes an eth_getTransactionReceipt RPC call.
// Returns the receipt as a map, or nil if the receipt is not found.
func (s *Server) fetchTransactionReceipt(txHash string) (map[string]any, error) {
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getTransactionReceipt",
		Params:  []interface{}{txHash},
		ID:      1,
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, err
	}

	respBody, statusCode, err := s.proxy.Forward(reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("RPC request failed with status %d", statusCode)
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Receipt can be null for pending/unknown txs
	if string(rpcResp.Result) == "null" || len(rpcResp.Result) == 0 {
		return nil, nil
	}

	var receipt map[string]any
	if err := json.Unmarshal(rpcResp.Result, &receipt); err != nil {
		return nil, err
	}

	return receipt, nil
}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
