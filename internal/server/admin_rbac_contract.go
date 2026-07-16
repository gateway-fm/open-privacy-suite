package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
)

// Contract handlers

// listContracts returns a paginated, optionally filtered list of the
// organization's registered contracts.
//
// @Summary      List contracts
// @Description  Lists the contracts registered to the organization, most recent first, with an optional case-insensitive search over name/address and a created-at date window. Scoped to {org_id}; a tier-2 admin only sees their own org's contracts.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        limit query int false "Max rows to return (default 50)"
// @Param        offset query int false "Rows to skip for pagination (default 0)"
// @Param        search query string false "Case-insensitive filter over contract name or address"
// @Param        created_after query string false "Only contracts created on or after this ISO 8601 date"
// @Param        created_before query string false "Only contracts created before this ISO 8601 date"
// @Success      200 {object} contractListResponse
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts [get]
func (s *Server) listContracts(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	limit, offset := parsePaginationParams(c, 50)

	filter := db.ContractListFilter{
		Search:        c.Query("search"),
		CreatedAfter:  c.Query("created_after"),
		CreatedBefore: c.Query("created_before"),
	}

	contracts, total, err := s.db.ListContractsFiltered(c.Request.Context(), orgID, limit, offset, filter)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list contracts",
			"admin_rbac_contract: ListContractsFiltered failed", "org_id", orgID, "err", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": contracts, "total": total, "limit": limit, "offset": offset})
}

// createContract registers a new contract in the organization.
//
// @Summary      Create a contract
// @Description  Registers a contract (address plus optional name and metadata) in the organization. The address is validated and stored lowercase. Scoped to {org_id}; the restricted operator token is rejected because per-org contract management is the org admin's job.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        request body contractCreateRequest true "contract to create"
// @Success      201 {object} rbac.Contract
// @Failure      400 {object} APIError "invalid body or invalid Ethereum address format"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      409 {object} APIError "a contract with this address already exists in the organization"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts [post]
func (s *Server) createContract(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job; the
	// super-admin token is platform/bootstrap only.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	var input struct {
		Address  string         `json:"address" binding:"required"`
		Name     string         `json:"name"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid createContract body", "org_id", orgID, "err", err)
		return
	}

	// Validate Ethereum address format
	if !auth.IsValidAddress(input.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Ethereum address format"})
		return
	}

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgID,
		Address:  strings.ToLower(input.Address),
		Name:     input.Name,
		Metadata: input.Metadata,
	}
	if contract.Metadata == nil {
		contract.Metadata = make(map[string]any)
	}

	if err := s.db.CreateContract(c.Request.Context(), contract); err != nil {
		// Check for unique constraint violation (duplicate address in org)
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "contract with this address already exists in this organization"})
			return
		}
		respondInternalErrorAndLog(c, "failed to create contract",
			"admin_rbac_contract: CreateContract failed",
			"org_id", orgID, "address", contract.Address, "err", err)
		return
	}

	c.JSON(http.StatusCreated, contract)
}

// getContract returns a single contract by address within the organization.
//
// @Summary      Get a contract
// @Description  Returns one contract by its address within the organization. Scoped to {org_id}; a tier-2 admin can only read their own org's contracts.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} rbac.Contract
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address} [get]
func (s *Server) getContract(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (getContract)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}
	c.JSON(http.StatusOK, contract)
}

// updateContract updates a contract's name and/or metadata.
//
// @Summary      Update a contract
// @Description  Updates the name and/or metadata of a contract; omitted fields are left unchanged. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body contractUpdateRequest true "fields to update"
// @Success      200 {object} rbac.Contract
// @Failure      400 {object} APIError "invalid request body"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address} [put]
func (s *Server) updateContract(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (updateContract)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		Name     *string        `json:"name"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid updateContract body",
			"org_id", orgID, "address", address, "err", err)
		return
	}

	if input.Name != nil {
		contract.Name = *input.Name
	}
	if input.Metadata != nil {
		contract.Metadata = input.Metadata
	}

	if err := s.db.UpdateContract(c.Request.Context(), contract); err != nil {
		respondInternalErrorAndLog(c, "failed to update contract",
			"admin_rbac_contract: UpdateContract failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	c.JSON(http.StatusOK, contract)
}

// deleteContract removes a contract and invalidates the org's RBAC cache.
//
// @Summary      Delete a contract
// @Description  Deletes a contract from the organization and invalidates the org's permission cache (its grants may affect many groups). Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} APIMessage "contract deleted"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address} [delete]
func (s *Server) deleteContract(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (deleteContract)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	// Invalidate cache for the entire org (grants may affect many groups)
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	if err := s.db.DeleteContract(c.Request.Context(), contract.ID); err != nil {
		respondInternalErrorAndLog(c, "failed to delete contract",
			"admin_rbac_contract: DeleteContract failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "contract deleted"})
}

// updateContractABI updates the ABI for a contract.
// PUT /orgs/:org_id/contracts/:address/abi
//
// @Summary      Set a contract's ABI
// @Description  Stores the contract's ABI (used for function-level access control and event redaction). The ABI must be a valid JSON array. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body contractABIUpdateRequest true "ABI JSON array"
// @Success      200 {object} rbac.Contract
// @Failure      400 {object} APIError "invalid body, or ABI is not a valid JSON array"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/abi [put]
func (s *Server) updateContractABI(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (updateContractABI)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		ABI string `json:"abi" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid updateContractABI body",
			"contract_id", contract.ID, "err", err)
		return
	}

	// Validate ABI is a valid JSON array
	if input.ABI != "" && !strings.HasPrefix(strings.TrimSpace(input.ABI), "[") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "abi must be a valid JSON array"})
		return
	}

	// Validate it's valid JSON
	var abiItems []json.RawMessage
	if err := json.Unmarshal([]byte(input.ABI), &abiItems); err != nil {
		respondBadRequestAndLog(c, "abi must be valid JSON",
			"admin_rbac_contract: ABI JSON unmarshal failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	// RD-1206 (H2): if a method policy is configured, the new ABI must still
	// satisfy it. A gated reader whose selector/signature no longer resolves
	// against the ABI fails OPEN at the gate (it looks "not gated" and the
	// response is served unfiltered), so a breaking ABI change would silently
	// disable per-record read gating. Re-validate and reject; the policy must be
	// updated or cleared (same tier) first.
	if len(contract.MethodPolicies) > 0 {
		doc, perr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies)
		if perr != nil {
			respondBadRequestAndLog(c, "contract has a method policy that cannot be re-validated against the new ABI; clear the method policy first",
				"admin_rbac_contract: stored method policy unreadable on ABI update",
				"contract_id", contract.ID, "err", perr)
			return
		}
		if reason := doc.ValidateForClient(input.ABI); reason != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "this ABI change would disable the configured method policy (" + reason + "); update or clear the method policy first"})
			return
		}
	}

	if err := s.db.UpdateContractABI(c.Request.Context(), contract.ID, input.ABI); err != nil {
		respondInternalErrorAndLog(c, "failed to update contract ABI",
			"admin_rbac_contract: UpdateContractABI failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	// Return updated contract
	contract.ABI = input.ABI
	c.JSON(http.StatusOK, contract)
}

// updateContractAllowVisibleToUnlock toggles the per-contract opt-in
// flag for the RD-874 visibleTo unlock semantic. Admin-only — the
// caller must already be an admin for the contract's owning org
// (enforced by the route's middleware chain alongside the other admin
// endpoints in this file).
//
// Body: {"allow_visibleto_unlock": true|false}
//
// PUT /orgs/:org_id/contracts/:address/visibleto-unlock
//
// Security note: setting this to true means any tx sender on this
// contract can grant per-event visibility to any DID they list in
// `visibleTo` (scoped to that one tx, gated by the viewer being in
// some non-system group with a contract_grant). See decisions.md §12
// for the full bypass surface (event_rules, param_rules,
// deny-when-no-ABI gate are all bypassed for unlocked viewers on the
// matching tx). Operators should review their grants before flipping.
//
// @Summary      Toggle a contract's visibleTo-unlock flag
// @Description  Enables or disables the RD-874 per-contract opt-in that lets a tx sender grant per-event visibility to DIDs listed in the transaction's visibleTo. Enabling it widens who can see events on this contract, so review grants first. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body contractVisibleToUnlockRequest true "flag value"
// @Success      200 {object} rbac.Contract
// @Failure      400 {object} APIError "invalid body, or allow_visibleto_unlock is missing"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/visibleto-unlock [put]
func (s *Server) updateContractAllowVisibleToUnlock(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (updateContractAllowVisibleToUnlock)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		AllowVisibleToUnlock *bool `json:"allow_visibleto_unlock" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid updateContractAllowVisibleToUnlock body",
			"contract_id", contract.ID, "err", err)
		return
	}
	if input.AllowVisibleToUnlock == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "allow_visibleto_unlock is required"})
		return
	}

	if err := s.db.UpdateContractAllowVisibleToUnlock(c.Request.Context(), contract.ID, *input.AllowVisibleToUnlock); err != nil {
		respondInternalErrorAndLog(c, "failed to update flag",
			"admin_rbac_contract: UpdateContractAllowVisibleToUnlock failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	// Invalidate the org's permission cache so the new flag takes effect
	// on the next request — the resolver caches contract records along
	// with grants. Same pattern as other contract-mutating endpoints.
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)
	}

	contract.AllowVisibleToUnlock = *input.AllowVisibleToUnlock
	c.JSON(http.StatusOK, contract)
}

// updateContractEventsAllowDynamicPayload toggles the per-contract
// M15 opt-out for the dynamic-payload event drop gate (security audit
// follow-up to RD-915).
//
// Body: {"events_allow_dynamic_payload": true|false}
//
// PUT /orgs/:org_id/contracts/:address/events-allow-dynamic-payload
//
// **Super-admin only** (X-Admin-Token). Tier-2 / tier-3 org admins
// cannot flip this flag — it weakens a privacy default in a way that
// affects every viewer of every event on the contract, and is not a
// per-grant decision. Operating procedure: super-admin reviews the
// contract's event ABI and confirms that its dynamic non-indexed
// params cannot carry foreign-org address material before opting it
// out. Default FALSE (close-by-default).
//
// Security: flipping to TRUE causes RedactLogs and FilterEventLogs to
// pass dynamic-payload events through to non-Full viewers WITHOUT
// scanning the payload for embedded private addresses. This is correct
// for standard ERC-20 / ERC-721 contracts whose `string symbol`,
// `string name`, or `bytes` metadata fields are static text — and
// unsafe for bridge / forwarder / smart-wallet contracts that encode
// foreign-org addresses inside `bytes` payloads. The pre-M15 default
// (this flag effectively always true) is what the audit classified as
// a leak.
//
// Audit-logged at ResourceTypeContract; the entry stores the before
// and after state so ISO 27001 A.8.16 evidence is complete.
//
// @Summary      Toggle a contract's dynamic-payload event flag
// @Description  Enables or disables the M15 opt-out that lets events with dynamic non-indexed payloads pass through to non-Full viewers without scanning for embedded foreign-org addresses. Default false (close-by-default). Super-admin token only — tier-2/3 org admins cannot flip it; the change is audit-logged with before/after state.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body contractEventsAllowDynamicPayloadRequest true "flag value"
// @Success      200 {object} rbac.Contract
// @Failure      400 {object} APIError "invalid address, invalid body, or events_allow_dynamic_payload is missing"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "super-admin token required"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/events-allow-dynamic-payload [put]
func (s *Server) updateContractEventsAllowDynamicPayload(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	if !auth.IsValidAddress(address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Ethereum address format"})
		return
	}

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		slog.Error("update events_allow_dynamic_payload: db read failed", "org", orgID, "addr", address, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read contract"})
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		EventsAllowDynamicPayload *bool `json:"events_allow_dynamic_payload"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid updateContractEventsAllowDynamicPayload body",
			"contract_id", contract.ID, "err", err)
		return
	}
	if input.EventsAllowDynamicPayload == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "events_allow_dynamic_payload is required"})
		return
	}

	before := contract.EventsAllowDynamicPayload
	if err := s.db.UpdateContractEventsAllowDynamicPayload(c.Request.Context(), contract.ID, *input.EventsAllowDynamicPayload); err != nil {
		slog.Error("update events_allow_dynamic_payload: db write failed", "org", orgID, "addr", address, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update contract"})
		return
	}

	// Invalidate org cache so the new flag takes effect on the next
	// request. The resolver caches contract records along with grants;
	// same pattern as updateContractAllowVisibleToUnlock.
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)
	}

	s.recordAuditActionScoped(c, rbac.AuditActionUpdate, rbac.ResourceTypeContract, contract.ID, contract.Name, orgID,
		map[string]any{
			"events_allow_dynamic_payload": before,
		},
		map[string]any{
			"events_allow_dynamic_payload": *input.EventsAllowDynamicPayload,
			"address":                      contract.Address,
		})

	contract.EventsAllowDynamicPayload = *input.EventsAllowDynamicPayload
	c.JSON(http.StatusOK, contract)
}

// getContractMethodPolicies returns the contract's configured method access
// policy document (RD-1206), or null when none is set.
//
// @Summary      Get a contract's method access policies
// @Description  Returns the per-record method access policy document (RD-1206) configured on the contract, or null when unset. Scoped to {org_id}; the restricted operator token is rejected (tenant read).
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} contractMethodPoliciesResponse
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/method-policies [get]
func (s *Server) getContractMethodPolicies(c *gin.Context) {
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")
	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (getContractMethodPolicies)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}
	c.JSON(http.StatusOK, contractMethodPoliciesResponse{MethodPolicies: contract.MethodPolicies})
}

// updateContractMethodPolicies sets or clears the per-record method access
// policy document (RD-1206). Send method_policies:null to clear.
//
// PUT /orgs/:org_id/contracts/:address/method-policies
//
// **Tier-2 org-admin** (org-scoped JWT; the restricted operator token is
// rejected). A method policy is per-contract, per-org configuration — the same
// scope as the contract's grants, groups, ABI and the RD-874 visibleto-unlock
// toggle, all of which the org admin already owns. It only ever NARROWS an
// already-permitted read and fails closed, so a malformed policy denies rather
// than leaks. The policy is validated against the contract's registered ABI on
// write, so a policy can never validate here and then misbehave at read time;
// and updateContractABI re-validates any configured policy against a new ABI so
// an ABI change cannot silently disable the gate. Audit-logged with before/after
// state.
//
// @Summary      Set a contract's method access policies
// @Description  Sets or clears (method_policies:null) the per-record method access policy (RD-1206), gating record-reader eth_calls to a record's stakeholders. Validated against the contract's registered ABI. Tier-2 org-admin (the restricted operator token is rejected) — it is per-contract, per-org configuration that only narrows reads; the change is audit-logged with before/after state.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body contractMethodPoliciesRequest true "policy document, or null to clear"
// @Success      200 {object} rbac.Contract
// @Failure      400 {object} APIError "invalid body, policy fails ABI validation, or no ABI registered"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage tenant data, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/method-policies [put]
func (s *Server) updateContractMethodPolicies(c *gin.Context) {
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (updateContractMethodPolicies)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input contractMethodPoliciesRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid updateContractMethodPolicies body",
			"contract_id", contract.ID, "err", err)
		return
	}

	var toStore []byte
	clearing := len(input.MethodPolicies) == 0 || string(input.MethodPolicies) == "null"
	if !clearing {
		if contract.ABI == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "register the contract ABI before setting method policies"})
			return
		}
		doc, perr := rbac.ParseMethodPolicyDocument(input.MethodPolicies)
		if perr != nil {
			// Generic client message (avoid echoing raw JSON-parser output);
			// the detail is logged for operator diagnostics (RD-934).
			respondBadRequestAndLog(c, "malformed method policy document",
				"admin_rbac_contract: method policy parse failed",
				"contract_id", contract.ID, "err", perr)
			return
		}
		// ValidateForClient returns a curated, ABI-derived reason (safe to
		// surface — see its doc); the sanitization boundary lives in rbac.
		if reason := doc.ValidateForClient(contract.ABI); reason != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "method policy failed ABI validation: " + reason})
			return
		}
		toStore = input.MethodPolicies
	}

	if err := s.db.UpdateContractMethodPolicies(c.Request.Context(), contract.ID, toStore); err != nil {
		respondInternalErrorAndLog(c, "failed to update method policies",
			"admin_rbac_contract: UpdateContractMethodPolicies failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)
	}

	// Audit with full before/after policy JSON — the change-management artifact
	// for a security-relevant read-enforcement config.
	s.recordAuditActionScoped(c, rbac.AuditActionUpdate, rbac.ResourceTypeContract, contract.ID, contract.Name, orgID,
		map[string]any{"method_policies": rawOrNull(contract.MethodPolicies)},
		map[string]any{"method_policies": rawOrNull(toStore), "address": contract.Address})

	contract.MethodPolicies = toStore
	c.JSON(http.StatusOK, contract)
}

// rawOrNull renders raw JSON for the audit log, or nil when empty.
func rawOrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return json.RawMessage(b)
}

// simulateContractMethodPolicy answers "would this caller be allowed to read
// this record via this method?" from the stored captures (RD-1206). It performs
// NO node call — the return-address resolver is not simulated; when the reader
// has a return rule and the capture side denies, the result is
// "indeterminate_return_source" so a capture-side deny is never mistaken for an
// authoritative deny.
//
// **Tier-2 org-admin** (the restricted operator token is rejected) — it
// discloses the record's captured admit-set (stakeholder DIDs/addresses) and is
// a per-caller allow/deny oracle over the org's own contract, the same tenant-read
// tier as GET method-policies. Org-scoped by the path org_id (never a global
// address lookup); opaque 404 for a missing or other-org contract (no cross-org
// existence probe). Audit-logged.
//
// @Summary      Simulate a method access policy decision
// @Description  Evaluates the capture side of a contract's method policy for a given caller + record, returning allow / deny / indeterminate_return_source plus the record's captured admit-set. No node call; the live return-address resolver is not simulated. Supply `captured` (field→values) to dry-run against HYPOTHETICAL parties instead of a live record — validating a policy before any record exists (record_key then optional). Tier-2 org-admin (the restricted operator token is rejected); org-scoped; audit-logged.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body methodPolicySimulateRequest true "caller + record to simulate"
// @Success      200 {object} methodPolicySimulateResponse
// @Failure      400 {object} APIError "invalid body, or no policy configured"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/method-policies/simulate [post]
func (s *Server) simulateContractMethodPolicy(c *gin.Context) {
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	// Org-scoped lookup (never GetContractByAddressGlobal): a missing or
	// other-org contract returns the same opaque 404 — no cross-org probe.
	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (simulateContractMethodPolicy)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}
	if len(contract.MethodPolicies) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no method policy configured for this contract"})
		return
	}

	var input methodPolicySimulateRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid simulateContractMethodPolicy body",
			"contract_id", contract.ID, "err", err)
		return
	}
	if input.Method == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "method is required"})
		return
	}
	if input.RecordKey == "" && len(input.Captured) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "record_key (live) or captured (what-if) is required"})
		return
	}

	doc, perr := rbac.ParseMethodPolicyDocument(contract.MethodPolicies)
	if perr != nil {
		respondInternalErrorAndLog(c, "stored policy is unreadable",
			"admin_rbac_contract: stored method policy failed to parse (simulate)",
			"contract_id", contract.ID, "err", perr)
		return
	}

	caller := rbac.NewCallerIdentity(input.CallerDID, input.CallerETH)
	var capturedRows []rbac.CapturedField
	// What-if mode (admin supplies `captured`): evaluate against hypothetical
	// parties with NO DB read, so a policy can be validated before any record is
	// created. Live mode: load the record's real captured rows.
	whatIf := len(input.Captured) > 0
	res, gated, serr := doc.SimulateReader(input.Method, caller, func(recordType string) ([]rbac.CapturedField, error) {
		if whatIf {
			capturedRows = hypotheticalCaptures(input.Captured)
			return capturedRows, nil
		}
		rows, e := s.db.GetRecordCaptures(c.Request.Context(), contract.OrgID, contract.Address, recordType, input.RecordKey)
		capturedRows = rows
		return rows, e
	})
	if serr != nil {
		respondInternalErrorAndLog(c, "failed to load captures",
			"admin_rbac_contract: GetRecordCaptures failed (simulate)",
			"contract_id", contract.ID, "err", serr)
		return
	}
	if !gated {
		c.JSON(http.StatusBadRequest, gin.H{"error": "method is not a gated reader in this contract's policy"})
		return
	}

	result := "deny"
	note := ""
	switch {
	case res.Poisoned:
		result, note = "deny", "record key is poisoned (conflicting set-once captures) — all reads denied"
	case res.Allow:
		result = "allow"
	case res.HasReturnSource:
		result = "indeterminate_return_source"
		note = "capture side denies, but this reader has a return-address rule; the live getPaymentInfo return could additionally admit this caller (not simulated)"
	}

	captured := map[string][]string{}
	for _, cf := range capturedRows {
		captured[cf.Field] = append(captured[cf.Field], cf.Value)
	}

	// Audit the simulation (it surfaces stakeholder identities) — log the query,
	// not the admit-set, so the harvest is itself auditable.
	s.recordAuditActionScoped(c, rbac.AuditActionAccess, rbac.ResourceTypeContract, contract.ID, contract.Name, orgID,
		nil,
		map[string]any{"simulate": true, "what_if": whatIf, "method": input.Method, "record_key": input.RecordKey, "caller_did": input.CallerDID, "result": result})

	c.JSON(http.StatusOK, methodPolicySimulateResponse{
		Result:          result,
		RecordType:      res.RecordType,
		MatchedRule:     res.MatchedRule,
		HasReturnSource: res.HasReturnSource,
		Poisoned:        res.Poisoned,
		Captured:        captured,
		Note:            note,
	})
}

// hypotheticalCaptures turns an admin-supplied {field: [values]} map into
// capture rows for the what-if simulator. Merge is "union" so multiple values
// per field never trip set-once poisoning (a what-if run tests "given these
// parties, who is admitted?", not accumulation semantics).
func hypotheticalCaptures(m map[string][]string) []rbac.CapturedField {
	var out []rbac.CapturedField
	for field, vals := range m {
		for _, v := range vals {
			out = append(out, rbac.CapturedField{Field: field, Value: v, Merge: "union"})
		}
	}
	return out
}

// listContractEvents parses the stored ABI and returns the list of events with
// their topic0 hashes and parameter info. Used by the UI to show a human-readable
// event picker for configuring event rules.
// GET /orgs/:org_id/contracts/:address/events
//
// @Summary      List a contract's events
// @Description  Parses the contract's resolved ABI and returns its events with topic0 hashes and parameter info, for building event-rule configurations. Returns an empty list with a message when no ABI is registered. Scoped to {org_id}; a tier-2 admin can only read their own org's contracts.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} contractEventsResponse
// @Failure      400 {object} APIError "the stored ABI could not be parsed"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/events [get]
func (s *Server) listContractEvents(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (listContractEvents)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	abiJSON := resolveContractABI(contract)
	if abiJSON == "" {
		c.JSON(http.StatusOK, gin.H{"events": []rbac.EventSignature{}, "message": "no ABI registered"})
		return
	}

	events, err := rbac.ExtractEventSignatures(abiJSON)
	if err != nil {
		respondBadRequestAndLog(c, "failed to parse ABI",
			"admin_rbac_contract: ExtractEventSignatures failed",
			"contract_id", contract.ID, "err", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

// ContractSyncStatus represents the on-chain status of a contract
type ContractSyncStatus struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Status  string `json:"status"` // "exists", "missing", "error"
	Error   string `json:"error,omitempty"`
}

// checkContractsOnChain checks all contracts against the chain and returns their status.
// POST /orgs/:org_id/contracts/sync-check
//
// @Summary      Check contracts against the chain
// @Description  Runs eth_getCode for every registered contract in the organization and buckets them as existing, missing, or errored (RPC failure). Read-only reconciliation helper. Scoped to {org_id}.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Success      200 {object} contractSyncCheckResponse
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "caller is out of org scope"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/sync-check [post]
func (s *Server) checkContractsOnChain(c *gin.Context) {
	if denyOperatorTenantRead(c) { // RD-1173: operator token must not read tenant contract inventory
		return
	}
	orgID := c.Param("org_id")

	contracts, err := s.db.ListContracts(c.Request.Context(), orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list contracts",
			"admin_rbac_contract: ListContracts failed (checkContractsOnChain)",
			"org_id", orgID, "err", err)
		return
	}

	if len(contracts) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"total":    0,
			"existing": []ContractSyncStatus{},
			"missing":  []ContractSyncStatus{},
			"errors":   []ContractSyncStatus{},
		})
		return
	}

	var existing, missing, errors []ContractSyncStatus

	for _, contract := range contracts {
		status := ContractSyncStatus{
			ID:      contract.ID,
			Address: contract.Address,
			Name:    contract.Name,
		}

		// Make eth_getCode RPC call
		code, err := s.getContractCode(contract.Address)
		if err != nil {
			// RPC error - could be chain unavailable. Opaque status to the
			// client; raw chain/RPC error stays in slog. (RD-1178 / RD-934)
			slog.Warn("admin_rbac_contract: getContractCode failed (checkContractsOnChain)",
				"org_id", orgID, "contract_id", contract.ID, "err", err)
			status.Status = "error"
			status.Error = "chain unavailable"
			errors = append(errors, status)
			continue
		}

		// Check if contract exists on chain
		// eth_getCode returns "0x" for addresses with no code
		if code == "0x" || code == "" {
			status.Status = "missing"
			missing = append(missing, status)
		} else {
			status.Status = "exists"
			existing = append(existing, status)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":    len(contracts),
		"existing": existing,
		"missing":  missing,
		"errors":   errors,
	})
}

// deleteStaleContracts deletes contracts that are confirmed to be missing on-chain.
// POST /orgs/:org_id/contracts/sync-delete
//
// @Summary      Delete stale (missing) contracts
// @Description  Deletes the given contracts only after re-verifying each still belongs to the organization and is still absent on-chain; contracts that now exist, belong elsewhere, or error are skipped with a reason. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        request body contractSyncDeleteRequest true "contract IDs to delete"
// @Success      200 {object} contractSyncDeleteResponse
// @Failure      400 {object} APIError "invalid body, or no contract IDs provided"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/sync-delete [post]
func (s *Server) deleteStaleContracts(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	var input struct {
		ContractIDs []string `json:"contract_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid deleteStaleContracts body",
			"org_id", orgID, "err", err)
		return
	}

	if len(input.ContractIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no contract IDs provided"})
		return
	}

	// Verify all contracts belong to this org and re-check they're still missing
	var deleted []string
	var skipped []struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}

	for _, contractID := range input.ContractIDs {
		contract, err := s.db.GetContract(c.Request.Context(), contractID)
		if err != nil {
			slog.Warn("sync-delete: contract lookup failed", "contract_id", contractID, "err", err) // RD-1178: don't echo raw err
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "lookup failed"})
			continue
		}
		// RD-1180: "not found" and "belongs to another org" return the SAME
		// opaque reason so the by-ID skipped list can't be used as a
		// cross-tenant existence oracle.
		if contract == nil || contract.OrgID != orgID {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "not eligible for deletion"})
			continue
		}

		// Re-verify the contract is still missing on-chain (safety check)
		code, err := s.getContractCode(contract.Address)
		if err != nil {
			slog.Warn("sync-delete: on-chain code check failed", "contract_id", contractID, "err", err) // RD-1178
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "chain check failed"})
			continue
		}
		if code != "0x" && code != "" {
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "contract now exists on chain"})
			continue
		}

		// Delete the contract
		if err := s.db.DeleteContract(c.Request.Context(), contractID); err != nil {
			slog.Warn("sync-delete: delete failed", "contract_id", contractID, "err", err) // RD-1178: don't echo raw err
			skipped = append(skipped, struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			}{contractID, "delete failed"})
			continue
		}

		deleted = append(deleted, contract.Address)
	}

	// Invalidate cache for the org if any contracts were deleted
	if len(deleted) > 0 {
		s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)
	}

	c.JSON(http.StatusOK, gin.H{
		"deleted_count":     len(deleted),
		"deleted_addresses": deleted,
		"skipped":           skipped,
	})
}

// getContractCode makes an eth_getCode RPC call to check if a contract exists on-chain.
// Returns the code hex string, or an error if the RPC call fails.
func (s *Server) getContractCode(address string) (string, error) {
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getCode",
		Params:  []interface{}{address, "latest"},
		ID:      1,
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", err
	}

	respBody, statusCode, err := s.proxy.Forward(reqBody)
	if err != nil {
		return "", err
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("RPC request failed with status %d", statusCode)
	}

	var rpcResp proxy.JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", err
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Result should be a hex string
	code, ok := rpcResp.Result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected response type from eth_getCode")
	}

	return code, nil
}

// resolveContractABI is a thin wrapper around rbac.ResolveContractABI kept
// for call-site readability in this file. The single source of truth for
// "what ABI applies to this contract" lives in the rbac package.
func resolveContractABI(contract *rbac.Contract) string {
	return rbac.ResolveContractABI(contract)
}

// noABIForEventRulesErrorMessage is returned by the grant create/update
// handlers (RD-875) when an admin tries to save event_rules other than
// explicit deny on a contract with no resolvable ABI. The runtime log filter
// would deny the contract anyway because non-indexed address parameters in
// event data cannot be decoded — surfacing the error at save time avoids
// silent no-op rules.
const noABIForEventRulesErrorMessage = "cannot save event_rules: contract has no ABI registered. Upload an ABI for the contract or set its metadata token_type to a known value (\"ERC20\" or \"ERC721\") to use the built-in ABI registry. Without an ABI, log redaction cannot decode non-indexed address parameters and event visibility is denied at runtime regardless of the rules below."

// validateEventRulesWithABI validates event rules against a contract ABI.
// If abiJSON is empty, validation is skipped (returns ""). Otherwise:
//
//   - **Topic0 must match an event declared by the ABI.** This is the
//     allowlist-integrity gate: a rule whose topic0 isn't in the ABI is
//     either a typo, a stale demo seed, or a copy-paste from a different
//     contract — all three would silently never fire and pollute the
//     audit surface. Reject at save time. (Decision: no legitimate
//     "topic0 not in ABI" case for the privacy product.)
//
//   - Per-rule param_rules are checked:
//
//   - index must be within the event's input count
//
//   - "self" constraints must target an address-typed parameter
//
//   - hex value constraints must have the correct byte length for the param type
//
// Returns a descriptive error message, or "" if valid.
func validateEventRulesWithABI(rules []rbac.EventRule, abiJSON string) string {
	if abiJSON == "" {
		return ""
	}

	events, err := rbac.ExtractEventSignatures(abiJSON)
	if err != nil {
		// ABI is unparseable — skip validation rather than blocking saves.
		// Topic0 vs ABI checks share the same fall-through: if we can't
		// parse the ABI we can't compare topics either.
		return ""
	}

	// Build lookup: topic0 -> EventSignature
	eventByTopic := make(map[string]*rbac.EventSignature, len(events))
	for i := range events {
		eventByTopic[strings.ToLower(events[i].Topic0)] = &events[i]
	}

	for _, rule := range rules {
		ev, ok := eventByTopic[strings.ToLower(rule.Topic0)]
		if !ok {
			// Topic0 not in the contract's ABI. Reject the save — every
			// rule must correspond to an event the ABI declares, otherwise
			// it's dead config. Surface the available topics in the error
			// so admins can copy-paste the correct value.
			available := make([]string, 0, len(events))
			for i := range events {
				available = append(available, fmt.Sprintf("%s (%s)", events[i].Topic0, events[i].Name))
			}
			return fmt.Sprintf(
				"event rule topic0 %s does not match any event in the contract's ABI; available events: [%s]",
				rule.Topic0,
				strings.Join(available, ", "),
			)
		}

		if len(rule.ParamRules) == 0 {
			continue
		}

		for _, pr := range rule.ParamRules {
			if pr.Index < 0 || pr.Index >= len(ev.Inputs) {
				return fmt.Sprintf(
					"event %s: param_rule index %d out of bounds (event has %d inputs)",
					ev.Name, pr.Index, len(ev.Inputs),
				)
			}

			paramType := ev.Inputs[pr.Index].Type

			switch {
			case pr.MustBe == "self":
				// "self" constraint only makes sense for address parameters.
				if paramType != "address" {
					return fmt.Sprintf(
						"event %s: param_rule index %d has must_be=\"self\" but parameter type is %s, not address",
						ev.Name, pr.Index, paramType,
					)
				}

			case strings.HasPrefix(pr.MustBe, "0x"):
				// Hex value constraint — validate byte length matches the param type.
				hexStr := strings.TrimPrefix(pr.MustBe, "0x")
				decoded, decErr := hex.DecodeString(hexStr)
				if decErr != nil {
					return fmt.Sprintf(
						"event %s: param_rule index %d has invalid hex value: %s",
						ev.Name, pr.Index, pr.MustBe,
					)
				}

				expectedLen := expectedByteLength(paramType)
				if expectedLen > 0 && len(decoded) != expectedLen {
					return fmt.Sprintf(
						"event %s: param_rule index %d has hex value of %d bytes but %s requires %d bytes",
						ev.Name, pr.Index, len(decoded), paramType, expectedLen,
					)
				}
			}
		}
	}

	return ""
}

// rejectCustomParamRulesWithoutABI checks if any event rules contain custom hex
// param constraints (must_be != "self") when no ABI is available. Without ABI,
// we cannot validate byte length/type, and the rule will silently fail at runtime.
func rejectCustomParamRulesWithoutABI(rules []rbac.EventRule, abiJSON string) string {
	if abiJSON != "" {
		return "" // ABI available — full validation handled by validateEventRulesWithABI
	}
	for _, rule := range rules {
		for _, pr := range rule.ParamRules {
			if pr.MustBe != "self" && strings.HasPrefix(pr.MustBe, "0x") {
				return fmt.Sprintf(
					"event %s: custom param constraints require a contract ABI — upload one or set token_type for built-in ABI fallback",
					rule.Name,
				)
			}
		}
	}
	return ""
}

// expectedByteLength returns the expected byte length for common ABI types used
// in param_rule hex value validation. Returns 0 for types where length is variable
// or unknown (which means length validation is skipped).
func expectedByteLength(abiType string) int {
	switch {
	case abiType == "address":
		return 20
	case abiType == "bool":
		return 32 // ABI-encoded bool is 32 bytes
	case strings.HasPrefix(abiType, "uint") || strings.HasPrefix(abiType, "int"):
		return 32
	case strings.HasPrefix(abiType, "bytes32"):
		return 32
	case abiType == "bytes20":
		return 20
	default:
		return 0
	}
}

// addressOrgResolver is the minimal interface needed by validateCrossOrgParamRules
// to check whether a hex address belongs to a given organization.
// rbac.Store (and *db.DB) satisfy this interface.
type addressOrgResolver interface {
	GetContractOwnerOrgID(ctx context.Context, address string) (string, error)
	GetOrgIDsForEthAddress(ctx context.Context, address string) ([]string, error)
}

// validateCrossOrgParamRules checks that custom hex addresses in event param rules
// do not cross organization boundaries. For each param rule with a custom hex value
// on an address-type parameter, this validates that the address belongs to the same
// organization as the grant being created/updated.
//
// Fail-closed: addresses not registered to any org (contracts, preregistered, or
// linked EOAs) are rejected. Only addresses verifiably belonging to the grant's org
// are allowed.
//
// Requires ABI to determine parameter types — if no ABI is available, custom hex
// param rules are already rejected by rejectCustomParamRulesWithoutABI.
func validateCrossOrgParamRules(ctx context.Context, store addressOrgResolver, orgID string, rules []rbac.EventRule, abiJSON string) string {
	if abiJSON == "" {
		return "" // No ABI = custom hex already rejected upstream
	}

	events, err := rbac.ExtractEventSignatures(abiJSON)
	if err != nil {
		return "" // Unparseable ABI — skip (matches validateEventRulesWithABI behavior)
	}

	eventByTopic := make(map[string]*rbac.EventSignature, len(events))
	for i := range events {
		eventByTopic[strings.ToLower(events[i].Topic0)] = &events[i]
	}

	for _, rule := range rules {
		for _, pr := range rule.ParamRules {
			if !strings.HasPrefix(pr.MustBe, "0x") {
				continue // "self" constraints don't reference external addresses
			}

			// Only validate address-type parameters for cross-org boundaries.
			// Non-address types (uint256, bytes32, etc.) don't represent org entities.
			ev, ok := eventByTopic[strings.ToLower(rule.Topic0)]
			if !ok {
				continue // Event not in ABI — can't determine param types
			}
			if pr.Index < 0 || pr.Index >= len(ev.Inputs) {
				continue // Out of bounds — caught by validateEventRulesWithABI
			}
			if ev.Inputs[pr.Index].Type != "address" {
				continue // Not an address param — no cross-org concern
			}

			hexAddr := pr.MustBe

			// Check 1: Is this address a contract or preregistered address?
			contractOrgID, err := store.GetContractOwnerOrgID(ctx, hexAddr)
			if err != nil {
				return fmt.Sprintf("event %s: failed to validate cross-org boundary for param %d", rule.Name, pr.Index)
			}
			if contractOrgID != "" {
				if contractOrgID == orgID {
					continue // Same org — allowed
				}
				return fmt.Sprintf(
					"event %s: param_rule[%d] references an address belonging to a different organization",
					rule.Name, pr.Index,
				)
			}

			// Check 2: Is this address an EOA linked to a user?
			eoaOrgIDs, err := store.GetOrgIDsForEthAddress(ctx, hexAddr)
			if err != nil {
				return fmt.Sprintf("event %s: failed to validate cross-org boundary for param %d", rule.Name, pr.Index)
			}
			if len(eoaOrgIDs) > 0 {
				found := false
				for _, eid := range eoaOrgIDs {
					if eid == orgID {
						found = true
						break
					}
				}
				if found {
					continue // Address owner is in this org — allowed
				}
				return fmt.Sprintf(
					"event %s: param_rule[%d] references an address belonging to a different organization",
					rule.Name, pr.Index,
				)
			}

			// Check 3: Address not registered anywhere — fail closed.
			// Unregistered addresses cannot be verified as belonging to this org.
			return fmt.Sprintf(
				"event %s: param_rule[%d] references an unregistered address; only addresses belonging to this organization are allowed",
				rule.Name, pr.Index,
			)
		}
	}

	return ""
}

// autoAddSelfConstraints adds "self" param rules for all address-type parameters
// in event rules that don't already have an explicit constraint. This ensures
// that by default, users only see events where they are a party (fail-closed).
// The admin can remove self constraints via a subsequent update if broader access is needed.
func autoAddSelfConstraints(rules []rbac.EventRule, abiJSON string) []rbac.EventRule {
	if len(rules) == 0 || abiJSON == "" {
		return rules
	}

	sigs, err := rbac.ExtractEventSignatures(abiJSON)
	if err != nil || len(sigs) == 0 {
		return rules
	}

	// Build topic0 -> signature map
	sigMap := make(map[string]rbac.EventSignature)
	for _, sig := range sigs {
		sigMap[strings.ToLower(sig.Topic0)] = sig
	}

	for i := range rules {
		sig, ok := sigMap[strings.ToLower(rules[i].Topic0)]
		if !ok {
			continue
		}

		// Build set of already-constrained param indexes
		constrained := make(map[int]bool)
		for _, pr := range rules[i].ParamRules {
			constrained[pr.Index] = true
		}

		// Add self for unconstrained address params
		for j, input := range sig.Inputs {
			if input.Type == "address" && !constrained[j] {
				rules[i].ParamRules = append(rules[i].ParamRules, rbac.ParamRule{
					Index:  j,
					MustBe: "self",
				})
			}
		}
	}

	return rules
}

// Contract Grant handlers

// listContractGrants lists all grants attached to a contract.
//
// @Summary      List contract grants
// @Description  Lists the group grants attached to a contract (each links a group to the contract with optional function and event-rule restrictions). Scoped to {org_id}; a tier-2 admin can only read their own org's contracts.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {array} rbac.ContractGrant
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/grants [get]
func (s *Server) listContractGrants(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (listContractGrants)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	grants, err := s.db.ListContractGrantsByContract(c.Request.Context(), contract.ID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to list grants",
			"admin_rbac_contract: ListContractGrantsByContract failed",
			"contract_id", contract.ID, "err", err)
		return
	}
	c.JSON(http.StatusOK, grants)
}

// createContractGrant grants a group access to a contract.
//
// @Summary      Create a contract grant
// @Description  Grants a group access to the contract, optionally restricting functions and event visibility. Non-deny event_rules require a resolvable ABI, and any custom hex address in an address-typed param rule must belong to this organization (cross-org references are rejected). Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body contractGrantCreateRequest true "grant to create"
// @Success      201 {object} rbac.ContractGrant
// @Failure      400 {object} APIError "invalid body, invalid event rules, or event_rules set without a resolvable ABI"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org grants, caller is out of org scope, or a param rule references a cross-org / unregistered address"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/grants [post]
func (s *Server) createContractGrant(c *gin.Context) {
	// RD-1107: granting per-org contract access is the org admin's job; the
	// super-admin token is platform/bootstrap only.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (createContractGrant)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	var input struct {
		GroupID    string                `json:"group_id" binding:"required"`
		Functions  []rbac.FunctionRule   `json:"functions"`   // nil = all functions
		EventRules *rbac.EventRulesField `json:"event_rules"` // nil = deny, "*" = wildcard, [...] = allowlist
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid createContractGrant body",
			"contract_id", contract.ID, "err", err)
		return
	}

	// RD-875: any non-deny event_rules require a resolvable ABI (custom upload
	// or metadata.token_type matching the built-in registry). Without one, the
	// runtime log filter denies the contract regardless of these rules because
	// non-indexed address parameters in event data cannot be redacted. Reject
	// up-front rather than letting admins configure rules that look permissive
	// but won't fire (closes decisions.md §2 G5).
	if input.EventRules != nil && !input.EventRules.IsDeny() {
		if resolveContractABI(contract) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": noABIForEventRulesErrorMessage})
			return
		}
	}

	// Validate event rules if provided and not wildcard
	if input.EventRules != nil && !input.EventRules.IsWildcard() {
		rules := input.EventRules.GetRules()
		if len(rules) > 0 {
			if errMsg := validateEventRules(rules); errMsg != "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
				return
			}

			// Validate param_rules against ABI if available
			abiJSON := resolveContractABI(contract)
			if errMsg := validateEventRulesWithABI(rules, abiJSON); errMsg != "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
				return
			}

			// Reject custom hex param rules if no ABI is available
			if errMsg := rejectCustomParamRulesWithoutABI(rules, abiJSON); errMsg != "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
				return
			}

			// Enforce cross-org boundaries: custom hex addresses in address-type
			// params must belong to the same org as the grant.
			if errMsg := validateCrossOrgParamRules(c.Request.Context(), s.db, orgID, rules, abiJSON); errMsg != "" {
				c.JSON(http.StatusForbidden, gin.H{"error": errMsg})
				return
			}
		}
	}

	// Verify group exists and belongs to the same org
	group, err := s.db.GetGroup(c.Request.Context(), input.GroupID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read group",
			"admin_rbac_contract: GetGroup failed (createContractGrant)",
			"group_id", input.GroupID, "err", err)
		return
	}
	if group == nil || group.OrgID != orgID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "group not found or belongs to different organization"})
		return
	}

	grant := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contract.ID,
		GroupID:    input.GroupID,
		Functions:  input.Functions,
		EventRules: input.EventRules,
	}

	if err := s.db.CreateContractGrant(c.Request.Context(), grant); err != nil {
		respondInternalErrorAndLog(c, "failed to create grant",
			"admin_rbac_contract: CreateContractGrant failed",
			"contract_id", contract.ID, "group_id", input.GroupID, "err", err)
		return
	}

	// Invalidate cache for the group
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), input.GroupID)

	c.JSON(http.StatusCreated, grant)
}

// updateContractGrant updates the function and/or event rules of a grant.
//
// @Summary      Update a contract grant
// @Description  Updates a grant's function and/or event rules. An absent key means no change; an explicit null clears it; event_rules also accepts "*" (all events). Non-deny event_rules require a resolvable ABI, and custom hex address param rules must stay within this organization. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        group_id path string true "Group ID the grant belongs to"
// @Param        request body contractGrantUpdateRequest true "fields to update"
// @Success      200 {object} rbac.ContractGrant
// @Failure      400 {object} APIError "invalid body, invalid functions/event_rules, or event_rules set without a resolvable ABI"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org grants, caller is out of org scope, or a param rule references a cross-org / unregistered address"
// @Failure      404 {object} APIError "contract or grant not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/grants/{group_id} [put]
func (s *Server) updateContractGrant(c *gin.Context) {
	// RD-1107: per-org contract grants are the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")
	groupID := c.Param("group_id")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (updateContractGrant)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	grant, err := s.db.GetContractGrantByContractAndGroup(c.Request.Context(), contract.ID, groupID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read grant",
			"admin_rbac_contract: GetContractGrantByContractAndGroup failed",
			"contract_id", contract.ID, "group_id", groupID, "err", err)
		return
	}
	if grant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
		return
	}

	var input struct {
		Functions  json.RawMessage `json:"functions"`
		EventRules json.RawMessage `json:"event_rules"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid updateContractGrant body",
			"contract_id", contract.ID, "group_id", groupID, "err", err)
		return
	}

	// input.Functions is nil when the key is absent from the JSON body (no change).
	// input.Functions is "null" when explicitly set to null (all functions allowed).
	// input.Functions is "[...]" when set to an array of function rules.
	if input.Functions != nil {
		if string(input.Functions) == "null" {
			grant.Functions = nil
		} else {
			var rules []rbac.FunctionRule
			if err := json.Unmarshal(input.Functions, &rules); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid functions format"})
				return
			}
			grant.Functions = rules
		}
	}

	// Same pattern for event_rules, but also handle "*" wildcard string.
	if input.EventRules != nil {
		if string(input.EventRules) == "null" {
			grant.EventRules = nil
		} else {
			// Try to unmarshal as EventRulesField (handles "*", null, and arrays).
			var erf rbac.EventRulesField
			if err := json.Unmarshal(input.EventRules, &erf); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event_rules format: must be \"*\", null, or an array"})
				return
			}

			// RD-875: any non-deny event_rules require a resolvable ABI. See the
			// create handler for the rationale; same gate, same error message.
			if !erf.IsDeny() {
				if resolveContractABI(contract) == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": noABIForEventRulesErrorMessage})
					return
				}
			}

			if erf.IsWildcard() {
				grant.EventRules = &erf
			} else if erf.IsDeny() {
				grant.EventRules = nil
			} else {
				rules := erf.GetRules()

				// Validate topic0 hashes and param rules
				if errMsg := validateEventRules(rules); errMsg != "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
					return
				}

				// Validate param_rules against ABI if available
				abiJSON := resolveContractABI(contract)
				if errMsg := validateEventRulesWithABI(rules, abiJSON); errMsg != "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
					return
				}

				// Reject custom hex param rules if no ABI is available
				if errMsg := rejectCustomParamRulesWithoutABI(rules, abiJSON); errMsg != "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
					return
				}

				// Enforce cross-org boundaries: custom hex addresses in address-type
				// params must belong to the same org as the grant.
				if errMsg := validateCrossOrgParamRules(c.Request.Context(), s.db, orgID, rules, abiJSON); errMsg != "" {
					c.JSON(http.StatusForbidden, gin.H{"error": errMsg})
					return
				}

				// NOTE: autoAddSelfConstraints is not called on create or update.
				// The frontend pre-populates defaults from default_param_rules;
				// the admin's explicit choices are authoritative.

				grant.EventRules = &rbac.EventRulesField{Rules: rules}
			}
		}
	}

	if err := s.db.UpdateContractGrant(c.Request.Context(), grant); err != nil {
		respondInternalErrorAndLog(c, "failed to update grant",
			"admin_rbac_contract: UpdateContractGrant failed",
			"grant_id", grant.ID, "err", err)
		return
	}

	// Invalidate cache for the group
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	c.JSON(http.StatusOK, grant)
}

// lookupContractByAddress looks up a contract by address globally and returns
// lookupContractByAddress is a cross-org lookup used during the
// claim-unregistered-contract flow ("is this contract already
// registered to some org?"). Audit H2: pre-fix this returned the
// full contract record + owning organization + every grant's
// group+access (allowed_methods, claims, rate limits) for any
// address — a topology-mapping oracle for any tier-2 admin.
//
// Now: JWT admins receive only a minimal {address, registered}
// payload when the contract is owned by an org outside their
// scope. Super-admin and JWT admins of the owning org receive the
// full payload.
// GET /contracts/by-address/:address
//
// @Summary      Look up a contract by address (cross-org)
// @Description  Resolves a contract by address across all organizations, for the claim-unregistered-contract flow. The super-admin and a JWT admin of the owning org receive the full contract, organization, and grant topology; a JWT admin outside the owning org's scope receives only {address, registered} (audit H2). Not readable with the restricted operator token.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} contractLookupFullResponse "full payload for super-admin / owning-org admin; out-of-scope JWT admins receive contractLookupMinimalResponse instead"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data"
// @Failure      404 {object} APIError "contract not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/contracts/by-address/{address} [get]
func (s *Server) lookupContractByAddress(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	address := c.Param("address")

	contract, err := s.db.GetContractByAddressGlobal(c.Request.Context(), address)
	if err != nil {
		slog.Error("lookup contract: db read failed", "address", address, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up contract"})
		return
	}
	if contract == nil {
		// Match the not-found error shape regardless of caller.
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	// Audit H2: minimal response for callers outside the owning org's
	// scope. They learn only whether the address is registered (which
	// they need for the claim-unregistered flow); they do NOT learn
	// which org owns it or any of its grant topology.
	if c.GetString("auth_method") == "jwt_admin" && !inScope(c, contract.OrgID) {
		c.JSON(http.StatusOK, gin.H{
			"address":    contract.Address,
			"registered": true,
		})
		return
	}

	// Get the organization
	org, err := s.db.GetOrganization(c.Request.Context(), contract.OrgID)
	if err != nil {
		slog.Error("lookup contract: org read failed", "org_id", contract.OrgID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up contract"})
		return
	}

	// Get grants for this contract
	grants, err := s.db.ListContractGrantsByContract(c.Request.Context(), contract.ID)
	if err != nil {
		slog.Error("lookup contract: grants read failed", "contract_id", contract.ID, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up contract"})
		return
	}

	// Build grants with group+access info
	type grantInfo struct {
		Grant  *rbac.ContractGrant `json:"grant"`
		Group  *rbac.Group         `json:"group"`
		Access *rbac.GroupAccess   `json:"access"`
	}

	grantInfos := make([]grantInfo, 0, len(grants))
	for _, grant := range grants {
		group, err := s.db.GetGroup(c.Request.Context(), grant.GroupID)
		if err != nil || group == nil {
			continue
		}
		access, _ := s.db.GetGroupAccess(c.Request.Context(), grant.GroupID)
		grantInfos = append(grantInfos, grantInfo{
			Grant:  grant,
			Group:  group,
			Access: access,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"contract":     contract,
		"organization": org,
		"grants":       grantInfos,
	})
}

// getContractGrantSummary returns grant counts and group names for all contracts in an org.
// GET /orgs/:org_id/contracts/grant-summary
//
// @Summary      Get contract grant summary
// @Description  Returns, keyed by contract ID, the grant count and assigned group names for each of the organization's contracts that has at least one grant. Scoped to {org_id}; a tier-2 admin can only read their own org.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Success      200 {object} map[string]rbac.ContractGrantSummary "grant summary keyed by contract ID"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot read tenant data, or caller is out of org scope"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/grant-summary [get]
func (s *Server) getContractGrantSummary(c *gin.Context) {
	// RD-1132: tenant-confidential read — not readable with the operator token.
	if denyOperatorTenantRead(c) {
		return
	}
	orgID := c.Param("org_id")
	summary, err := s.db.GetContractGrantSummary(c.Request.Context(), orgID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read grant summary",
			"admin_rbac_contract: GetContractGrantSummary failed",
			"org_id", orgID, "err", err)
		return
	}
	c.JSON(http.StatusOK, summary)
}

// deleteContractGrant removes a group's grant on a contract.
//
// @Summary      Delete a contract grant
// @Description  Removes a group's grant on the contract and invalidates that group's permission cache. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        group_id path string true "Group ID the grant belongs to"
// @Success      200 {object} APIMessage "grant deleted"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org grants, or caller is out of org scope"
// @Failure      404 {object} APIError "contract or grant not found"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/{address}/grants/{group_id} [delete]
func (s *Server) deleteContractGrant(c *gin.Context) {
	// RD-1107: per-org contract grants are the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")
	address := c.Param("address")
	groupID := c.Param("group_id")

	contract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read contract",
			"admin_rbac_contract: GetContractByAddress failed (deleteContractGrant)",
			"org_id", orgID, "address", address, "err", err)
		return
	}
	if contract == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "contract not found"})
		return
	}

	grant, err := s.db.GetContractGrantByContractAndGroup(c.Request.Context(), contract.ID, groupID)
	if err != nil {
		respondInternalErrorAndLog(c, "failed to read grant",
			"admin_rbac_contract: GetContractGrantByContractAndGroup failed (deleteContractGrant)",
			"contract_id", contract.ID, "group_id", groupID, "err", err)
		return
	}
	if grant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
		return
	}

	// Invalidate cache before deleting
	s.rbacAccessCtrl.InvalidateGroup(c.Request.Context(), groupID)

	if err := s.db.DeleteContractGrant(c.Request.Context(), grant.ID); err != nil {
		respondInternalErrorAndLog(c, "failed to delete grant",
			"admin_rbac_contract: DeleteContractGrant failed",
			"grant_id", grant.ID, "err", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "grant deleted"})
}

// validateEventRules validates a slice of EventRules: topic0 format and param
// rule must_be values. Returns an error message or "" if valid.
func validateEventRules(rules []rbac.EventRule) string {
	for _, rule := range rules {
		if !rbac.IsValidTopic0(rule.Topic0) {
			return fmt.Sprintf("invalid topic0 hash: %s", rule.Topic0)
		}
		for _, pr := range rule.ParamRules {
			if errMsg := rbac.ValidateParamRuleMustBe(pr.MustBe); errMsg != "" {
				return fmt.Sprintf("event %s param[%d]: %s", rule.Name, pr.Index, errMsg)
			}
		}
	}
	return ""
}

// batchMoveContracts moves contracts from auto-created groups to a target group.
// POST /orgs/:org_id/contracts/batch-move
//
// @Summary      Batch-move contracts to a group
// @Description  Moves up to 200 contracts to an existing group or a newly created one (grant them to the target, drop their grants to auto-created source groups, optionally delete emptied source groups). All contracts must belong to the organization. Scoped to {org_id}; the restricted operator token is rejected.
// @Tags         Admin: RBAC
// @Accept       json
// @Produce      json
// @Param        org_id path string true "Organization ID"
// @Param        request body contractBatchMoveRequest true "move request (provide exactly one of target_group_id or new_group)"
// @Success      200 {object} contractBatchMoveResponse
// @Failure      400 {object} APIError "invalid body, too many contract IDs, missing/ambiguous target, or a contract/group not in this org"
// @Failure      401 {object} APIError "missing or invalid admin token"
// @Failure      403 {object} APIError "operator token cannot manage per-org contracts, or caller is out of org scope"
// @Failure      500 {object} APIError
// @Security     AdminToken
// @Router       /api/v1/admin/orgs/{org_id}/contracts/batch-move [post]
func (s *Server) batchMoveContracts(c *gin.Context) {
	// RD-1107: per-org contract management is the org admin's job.
	if denyOperatorOrgScoped(c) {
		return
	}
	orgID := c.Param("org_id")

	var input struct {
		ContractIDs   []string `json:"contract_ids" binding:"required"`
		TargetGroupID string   `json:"target_group_id"`
		NewGroup      *struct {
			Slug string `json:"slug" binding:"required"`
			Name string `json:"name" binding:"required"`
		} `json:"new_group"`
		DeleteEmptyAutoGroups bool `json:"delete_empty_auto_groups"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondBadRequestAndLog(c, "invalid request body",
			"admin_rbac_contract: invalid batchMoveContracts body",
			"org_id", orgID, "err", err)
		return
	}

	if len(input.ContractIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "contract_ids is required"})
		return
	}
	if len(input.ContractIDs) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many contract_ids (max 200)"})
		return
	}
	if input.TargetGroupID == "" && input.NewGroup == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "either target_group_id or new_group is required"})
		return
	}
	if input.TargetGroupID != "" && input.NewGroup != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot specify both target_group_id and new_group"})
		return
	}

	type moveResult struct {
		TargetGroupID   string   `json:"target_group_id"`
		MovedCount      int      `json:"moved_count"`
		DeletedGroupIDs []string `json:"deleted_group_ids,omitempty"`
	}

	var result moveResult

	err := s.db.WithTx(c.Request.Context(), func(tx *db.Tx) error {
		ctx := c.Request.Context()

		// Resolve target group
		targetGroupID := input.TargetGroupID
		if input.NewGroup != nil {
			// Create new group inline with deploy claims
			newGroup := &rbac.Group{
				ID:    uuid.New().String(),
				OrgID: orgID,
				Slug:  input.NewGroup.Slug,
				Name:  input.NewGroup.Name,
				Depth: 0,
				Path:  input.NewGroup.Slug,
			}
			if err := tx.CreateGroup(ctx, newGroup); err != nil {
				if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
					return fmt.Errorf("group with slug '%s' already exists", input.NewGroup.Slug)
				}
				return fmt.Errorf("failed to create group: %w", err)
			}
			// Create group access with deploy claims
			claims := rbac.ExpandClaims([]rbac.Claim{rbac.ClaimDeploy})
			if err := tx.CreateGroupAccess(ctx, &rbac.GroupAccess{
				ID:             uuid.New().String(),
				GroupID:        newGroup.ID,
				AllowedMethods: []string{"*"},
				Claims:         claims,
			}); err != nil {
				return fmt.Errorf("failed to create group access: %w", err)
			}
			targetGroupID = newGroup.ID
		} else {
			// Verify target group exists and belongs to org
			group, err := tx.GetGroup(ctx, targetGroupID)
			if err != nil {
				return fmt.Errorf("failed to get target group: %w", err)
			}
			if group == nil || group.OrgID != orgID {
				return fmt.Errorf("target group not found in this organization")
			}
		}

		result.TargetGroupID = targetGroupID

		// Verify all contracts belong to this org
		contracts, err := tx.GetContractsByIDs(ctx, input.ContractIDs)
		if err != nil {
			return fmt.Errorf("failed to get contracts: %w", err)
		}
		for _, cid := range input.ContractIDs {
			contract, ok := contracts[cid]
			if !ok {
				return fmt.Errorf("contract %s not found", cid)
			}
			if contract.OrgID != orgID {
				return fmt.Errorf("contract %s does not belong to this organization", cid)
			}
		}

		// Collect auto-created source group IDs across selected contracts
		autoGroupIDs, err := tx.GetAutoCreatedGroupIDsForContracts(ctx, input.ContractIDs)
		if err != nil {
			return fmt.Errorf("failed to get auto-created groups: %w", err)
		}

		// For each contract: create grant to target, remove grants to auto-created groups
		for _, cid := range input.ContractIDs {
			// Create grant to target group (ignore if already exists)
			if err := tx.CreateContractGrantIfNotExists(ctx, &rbac.ContractGrant{
				ID:         uuid.New().String(),
				ContractID: cid,
				GroupID:    targetGroupID,
			}); err != nil {
				return fmt.Errorf("failed to create grant for contract %s: %w", cid, err)
			}

			// Delete only grants to auto-created source groups (preserves manual grants)
			if err := tx.DeleteContractGrantsByContractAndGroups(ctx, cid, autoGroupIDs); err != nil {
				return fmt.Errorf("failed to remove auto grants for contract %s: %w", cid, err)
			}

			result.MovedCount++
		}

		// Optionally delete empty auto-created groups
		if input.DeleteEmptyAutoGroups && len(autoGroupIDs) > 0 {
			for _, gid := range autoGroupIDs {
				count, err := tx.CountContractGrantsByGroup(ctx, gid)
				if err != nil {
					return fmt.Errorf("failed to count grants for group %s: %w", gid, err)
				}
				if count == 0 {
					if err := tx.DeleteGroupWithDependenciesTx(ctx, gid); err != nil {
						return fmt.Errorf("failed to delete empty group %s: %w", gid, err)
					}
					result.DeletedGroupIDs = append(result.DeletedGroupIDs, gid)
				}
			}
		}

		// Invalidate DB cache for all users in the org (must happen inside the tx
		// so rollback also rolls back the cache delete).
		if err := tx.InvalidateCacheForOrg(ctx, orgID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}

		return nil
	})

	if err != nil {
		// Distinguish validation errors from internal errors
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "does not belong") {
			respondBadRequestAndLog(c, "batch move failed: invalid request",
				"admin_rbac_contract: batchMoveContracts validation",
				"org_id", orgID, "err", err)
			return
		}
		respondInternalErrorAndLog(c, "batch move failed",
			"admin_rbac_contract: batchMoveContracts internal error",
			"org_id", orgID, "err", err)
		return
	}

	// Tx committed — drop the in-memory cache for this org so live requests
	// see the new grant layout immediately (no TTL wait).
	s.rbacAccessCtrl.InvalidateOrg(c.Request.Context(), orgID)

	c.JSON(http.StatusOK, result)
}
