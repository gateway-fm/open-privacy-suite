package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/rbac"
)

// Anvil default account 0
// NOTE: These are well-known Anvil/Hardhat default test accounts -- NOT real secrets.
// See https://book.getfoundry.sh/reference/anvil/
// This code is gated behind IsProduction() == false and never runs in production.
const anvilAccount0Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

// sendRPCRequest sends a JSON-RPC request to the configured node.
func (s *Server) sendRPCRequest(ctx context.Context, reqBody map[string]interface{}) (map[string]interface{}, error) {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.NodeURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// DemoERC20InitCode is the deployment bytecode for a simple ERC20 token contract.
// The token has name "DemoToken", symbol "DEMO", 18 decimals, and mints 1_000_000e18 to the deployer.
const DemoERC20InitCode = "0x608060405234801561000f575f80fd5b505f69d3c21bcecceda10000009050805f803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2081905550806002819055503373ffffffffffffffffffffffffffffffffffffffff165f73ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516100c391906100e9565b60405180910390a350610102565b5f819050919050565b6100e3816100d1565b82525050565b5f6020820190506100fc5f8301846100da565b92915050565b610da98061010f5f395ff3fe608060405234801561000f575f80fd5b5060043610610091575f3560e01c8063313ce56711610064578063313ce5671461013157806370a082311461014f57806395d89b411461017f578063a9059cbb1461019d578063dd62ed3e146101cd57610091565b806306fdde0314610095578063095ea7b3146100b357806318160ddd146100e357806323b872dd14610101575b5f80fd5b61009d6101fd565b6040516100aa9190610971565b60405180910390f35b6100cd60048036038101906100c89190610a22565b610236565b6040516100da9190610a7a565b60405180910390f35b6100eb610323565b6040516100f89190610aa2565b60405180910390f35b61011b60048036038101906101169190610abb565b610329565b6040516101289190610a7a565b60405180910390f35b610139610674565b6040516101469190610b26565b60405180910390f35b61016960048036038101906101649190610b3f565b610679565b6040516101769190610aa2565b60405180910390f35b61018761068d565b6040516101949190610971565b60405180910390f35b6101b760048036038101906101b29190610a22565b6106c6565b6040516101c49190610a7a565b60405180910390f35b6101e760048036038101906101e29190610b6a565b6108c7565b6040516101f49190610aa2565b60405180910390f35b6040518060400160405280600981526020017f44656d6f546f6b656e000000000000000000000000000000000000000000000081525081565b5f8160015f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516103119190610aa2565b60405180910390a36001905092915050565b60025481565b5f8160015f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205410156103e5576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103dc90610bf2565b60405180910390fd5b815f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20541015610464576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161045b90610c5a565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16036104d2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104c990610cc2565b60405180910390fd5b8160015f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546105599190610d0d565b92505081905550815f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546105ab9190610d0d565b92505081905550815f808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546105fd9190610d40565b925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516106619190610aa2565b60405180910390a3600190509392505050565b601281565b5f602052805f5260405f205f915090505481565b6040518060400160405280600481526020017f44454d4f0000000000000000000000000000000000000000000000000000000081525081565b5f815f803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20541015610746576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161073d90610c5a565b60405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16036107b4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107ab90610cc2565b60405180910390fd5b815f803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546107ff9190610d0d565b92505081905550815f808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546108519190610d40565b925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516108b59190610aa2565b60405180910390a36001905092915050565b6001602052815f5260405f20602052805f5260405f205f91509150505481565b5f81519050919050565b5f82825260208201905092915050565b5f5b8381101561091e578082015181840152602081019050610903565b5f8484015250505050565b5f601f19601f8301169050919050565b5f610943826108e7565b61094d81856108f1565b935061095d818560208601610901565b61096681610929565b840191505092915050565b5f6020820190508181035f8301526109898184610939565b905092915050565b5f80fd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6109be82610995565b9050919050565b6109ce816109b4565b81146109d8575f80fd5b50565b5f813590506109e9816109c5565b92915050565b5f819050919050565b610a01816109ef565b8114610a0b575f80fd5b50565b5f81359050610a1c816109f8565b92915050565b5f8060408385031215610a3857610a37610991565b5b5f610a45858286016109db565b9250506020610a5685828601610a0e565b9150509250929050565b5f8115159050919050565b610a7481610a60565b82525050565b5f602082019050610a8d5f830184610a6b565b92915050565b610a9c816109ef565b82525050565b5f602082019050610ab55f830184610a93565b92915050565b5f805f60608486031215610ad257610ad1610991565b5b5f610adf868287016109db565b9350506020610af0868287016109db565b9250506040610b0186828701610a0e565b9150509250925092565b5f60ff82169050919050565b610b2081610b0b565b82525050565b5f602082019050610b395f830184610b17565b92915050565b5f60208284031215610b5457610b53610991565b5b5f610b61848285016109db565b91505092915050565b5f8060408385031215610b8057610b7f610991565b5b5f610b8d858286016109db565b9250506020610b9e858286016109db565b9150509250929050565b7f696e73756666696369656e7420616c6c6f77616e6365000000000000000000005f82015250565b5f610bdc6016836108f1565b9150610be782610ba8565b602082019050919050565b5f6020820190508181035f830152610c0981610bd0565b9050919050565b7f696e73756666696369656e742062616c616e63650000000000000000000000005f82015250565b5f610c446014836108f1565b9150610c4f82610c10565b602082019050919050565b5f6020820190508181035f830152610c7181610c38565b9050919050565b7f7472616e7366657220746f207a65726f206164647265737300000000000000005f82015250565b5f610cac6018836108f1565b9150610cb782610c78565b602082019050919050565b5f6020820190508181035f830152610cd981610ca0565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610d17826109ef565b9150610d22836109ef565b9250828203905081811115610d3a57610d39610ce0565b5b92915050565b5f610d4a826109ef565b9150610d55836109ef565b9250828201905080821115610d6d57610d6c610ce0565b5b9291505056fea264697066735822122051ff8f9884990f47a020aab14bf90acce68db2d2c155d19626eba9ffd4ea8b5364736f6c63430008140033"

// DemoERC20ABI is the ABI for the DemoERC20 token contract.
const DemoERC20ABI = `[{"type":"constructor","inputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"allowance","inputs":[{"name":"","type":"address","internalType":"address"},{"name":"","type":"address","internalType":"address"}],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"approve","inputs":[{"name":"spender","type":"address","internalType":"address"},{"name":"amount","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"},{"type":"function","name":"balanceOf","inputs":[{"name":"","type":"address","internalType":"address"}],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"decimals","inputs":[],"outputs":[{"name":"","type":"uint8","internalType":"uint8"}],"stateMutability":"view"},{"type":"function","name":"name","inputs":[],"outputs":[{"name":"","type":"string","internalType":"string"}],"stateMutability":"view"},{"type":"function","name":"symbol","inputs":[],"outputs":[{"name":"","type":"string","internalType":"string"}],"stateMutability":"view"},{"type":"function","name":"totalSupply","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address","internalType":"address"},{"name":"amount","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"},{"type":"function","name":"transferFrom","inputs":[{"name":"from","type":"address","internalType":"address"},{"name":"to","type":"address","internalType":"address"},{"name":"amount","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"","type":"bool","internalType":"bool"}],"stateMutability":"nonpayable"},{"type":"event","name":"Approval","inputs":[{"name":"owner","type":"address","indexed":true,"internalType":"address"},{"name":"spender","type":"address","indexed":true,"internalType":"address"},{"name":"value","type":"uint256","indexed":false,"internalType":"uint256"}],"anonymous":false},{"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true,"internalType":"address"},{"name":"to","type":"address","indexed":true,"internalType":"address"},{"name":"value","type":"uint256","indexed":false,"internalType":"uint256"}],"anonymous":false}]`

// handleDeployDemoERC20 deploys a DemoERC20 token contract in dev mode.
// Optionally registers it to an organization if org_id is provided.
//
// @Summary      Deploy a demo ERC-20 token (dev only)
// @Description  Deploys a DemoToken (DEMO) ERC-20 contract via the configured node and returns its address and transaction hash. Self-gated to non-production builds: returns 403 when running in production. Optionally registers the deployed contract to an organization (and grants it to the deployer's group) when org_id is supplied. Requires an admin token and a private-network source address.
// @Tags         Admin: ops
// @Accept       json
// @Produce      json
// @Param        request body apimodels.DeployDemoERC20Request false "optional org to register the contract to, and contract name"
// @Success      200 {object} apimodels.DeployDemoERC20Response
// @Failure      400 {object} apimodels.APIError "invalid request body"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "not available in production, or source address not on the private network"
// @Failure      404 {object} apimodels.APIError "organization not found"
// @Failure      500 {object} apimodels.APIError "deployment failed"
// @Security     AdminToken
// @Router       /api/v1/admin/dev/deploy-demo-erc20 [post]
func (s *Server) handleDeployDemoERC20(c *gin.Context) {
	// Only allow in non-production
	if s.config.IsProduction() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this endpoint is only available in development mode"})
		return
	}

	ctx := c.Request.Context()

	// Optionally bind JSON body (request may have no body at all)
	var req apimodels.DeployDemoERC20Request
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			respondBadRequestAndLog(c, "invalid request body",
				"dev_deploy_demo: invalid body", "err", err)
			return
		}
	}

	// Default name
	name := req.Name
	if name == "" {
		name = "DemoERC20"
	}

	// Get current gas price
	gasPriceResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_gasPrice",
		"params":  []interface{}{},
		"id":      1,
	})
	if err != nil {
		respondInternalErrorAndLog(c, "failed to get gas price",
			"dev_deploy_demo: eth_gasPrice failed", "err", err)
		return
	}
	gasPrice := gasPriceResp["result"].(string)

	// Estimate gas
	estimateResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_estimateGas",
		"params": []interface{}{
			map[string]interface{}{
				"from": anvilAccount0Address,
				"data": DemoERC20InitCode,
			},
		},
		"id": 1,
	})
	if err != nil {
		respondInternalErrorAndLog(c, "failed to estimate gas",
			"dev_deploy_demo: eth_estimateGas failed", "err", err)
		return
	}
	gasLimit := estimateResp["result"].(string)

	// Send the deployment transaction
	txResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendTransaction",
		"params": []interface{}{
			map[string]interface{}{
				"from":     anvilAccount0Address,
				"data":     DemoERC20InitCode,
				"gas":      gasLimit,
				"gasPrice": gasPrice,
			},
		},
		"id": 1,
	})
	if err != nil {
		respondInternalErrorAndLog(c, "failed to send deployment transaction",
			"dev_deploy_demo: eth_sendTransaction failed", "err", err)
		return
	}

	if txResp["error"] != nil {
		errData, _ := json.Marshal(txResp["error"])
		// errData is upstream node error verbatim — keep it out of the
		// wire response. RD-934.
		slog.Error("dev_deploy_demo: deployment transaction failed",
			"upstream_error", string(errData))
		respondInternalError(c, "deployment transaction failed")
		return
	}

	txHash, ok := txResp["result"].(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid transaction hash response"})
		return
	}

	// Poll for transaction receipt (up to 30 seconds)
	var contractAddress string
	for i := 0; i < 30; i++ {
		receiptResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "eth_getTransactionReceipt",
			"params":  []interface{}{txHash},
			"id":      1,
		})
		if err != nil {
			respondInternalErrorAndLog(c, "failed to get transaction receipt",
				"dev_deploy_demo: eth_getTransactionReceipt failed",
				"tx_hash", txHash, "err", err)
			return
		}

		if receiptResp["result"] != nil {
			receipt, ok := receiptResp["result"].(map[string]interface{})
			if ok && receipt["contractAddress"] != nil {
				contractAddress, _ = receipt["contractAddress"].(string)
				break
			}
		}

		time.Sleep(1 * time.Second)
	}

	if contractAddress == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "deployment transaction did not produce a contract address"})
		return
	}

	contractAddress = strings.ToLower(contractAddress)

	// If org_id is provided, register the contract to that org
	registered := false
	if req.OrgID != "" {
		// Verify org exists
		org, err := s.db.GetOrganization(ctx, req.OrgID)
		if err != nil {
			respondInternalErrorAndLog(c, "failed to look up organization",
				"dev_deploy_demo: GetOrganization failed",
				"org_id", req.OrgID, "err", err)
			return
		}
		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
			return
		}

		contract := &rbac.Contract{
			ID:       uuid.New().String(),
			OrgID:    req.OrgID,
			Address:  contractAddress,
			Name:     name,
			ABI:      DemoERC20ABI,
			Metadata: map[string]any{"source": "dev-deploy"},
		}

		if err := s.db.CreateContract(ctx, contract); err != nil {
			respondInternalErrorAndLog(c, "failed to register contract",
				"dev_deploy_demo: CreateContract failed",
				"org_id", req.OrgID, "address", contract.Address, "err", err)
			return
		}
		registered = true

		// Grant contract to deployer's existing deploy group (best-effort, non-fatal)
		if subject, exists := c.Get("admin_subject"); exists {
			if userDID, ok := subject.(string); ok && userDID != "" {
				if user, err := s.db.GetUserByExternalID(ctx, userDID); err == nil && user != nil {
					if err := s.db.GrantContractToDeployerGroup(ctx, req.OrgID, contract.ID, user.ID); err != nil {
						fmt.Printf("warning: failed to grant contract to deployer group: %v\n", err)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, apimodels.DeployDemoERC20Response{
		Address:    contractAddress,
		TxHash:     txHash,
		Registered: registered,
		Name:       name,
	})
}
