package server

// Spec-only response models (RD-1166) for the contract / grant / ABI /
// event-toggle handlers (admin_rbac_contract.go), the shared-infrastructure
// handlers (admin_shared_infra.go), and the Azure-tenant handlers
// (admin_rbac_azure_tenant.go).
//
// These mirror the gin.H / anonymous wire shapes those handlers emit so the
// swaggo @Success annotations have a concrete Go type to reference. Handlers
// that marshal a real struct (rbac.Contract, rbac.ContractGrant,
// rbac.SharedInfrastructure, db.AllowedAzureTenant, …) reference that struct
// directly and are intentionally NOT duplicated here. These types are never
// constructed at runtime — annotation references only.

import (
	"encoding/json"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// contractListResponse is the GET /orgs/{org_id}/contracts body: a page of
// contracts plus the echoed pagination window.
type contractListResponse struct {
	Data   []rbac.Contract `json:"data"`
	Total  int             `json:"total" example:"42"`
	Limit  int             `json:"limit" example:"50"`
	Offset int             `json:"offset" example:"0"`
}

// contractEventsResponse is the GET /orgs/{org_id}/contracts/{address}/events
// body. Events is empty and Message is set ("no ABI registered") when the
// contract has no resolvable ABI; otherwise Message is omitted.
type contractEventsResponse struct {
	Events  []rbac.EventSignature `json:"events"`
	Message string                `json:"message,omitempty" example:"no ABI registered"`
}

// contractSyncCheckResponse is the POST /orgs/{org_id}/contracts/sync-check
// body: every registered contract bucketed by its on-chain presence.
type contractSyncCheckResponse struct {
	Total    int                  `json:"total" example:"3"`
	Existing []ContractSyncStatus `json:"existing"`
	Missing  []ContractSyncStatus `json:"missing"`
	Errors   []ContractSyncStatus `json:"errors"`
}

// contractSyncDeleteSkipped is one entry in the "skipped" list of the
// sync-delete response: a contract that was not deleted, with the reason.
type contractSyncDeleteSkipped struct {
	ID     string `json:"id" example:"6f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"`
	Reason string `json:"reason" example:"contract now exists on chain"`
}

// contractSyncDeleteResponse is the POST /orgs/{org_id}/contracts/sync-delete
// body: which stale contracts were removed and which were skipped (and why).
type contractSyncDeleteResponse struct {
	DeletedCount     int                         `json:"deleted_count" example:"1"`
	DeletedAddresses []string                    `json:"deleted_addresses"`
	Skipped          []contractSyncDeleteSkipped `json:"skipped"`
}

// contractBatchMoveResponse is the POST /orgs/{org_id}/contracts/batch-move
// body: the resolved target group, how many contracts were moved, and any
// emptied auto-created groups that were deleted.
type contractBatchMoveResponse struct {
	TargetGroupID   string   `json:"target_group_id" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	MovedCount      int      `json:"moved_count" example:"5"`
	DeletedGroupIDs []string `json:"deleted_group_ids,omitempty"`
}

// contractLookupMinimalResponse is the reduced GET
// /contracts/by-address/{address} body returned to a JWT admin whose scope
// does not include the owning org: it reveals only that the address is
// registered, never which org owns it or its grant topology (audit H2).
type contractLookupMinimalResponse struct {
	Address    string `json:"address" example:"0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"`
	Registered bool   `json:"registered" example:"true"`
}

// contractLookupGrantInfo is one contract grant enriched with its group and
// group-access records, as returned inside the full contract-lookup body.
type contractLookupGrantInfo struct {
	Grant  *rbac.ContractGrant `json:"grant"`
	Group  *rbac.Group         `json:"group"`
	Access *rbac.GroupAccess   `json:"access"`
}

// contractLookupFullResponse is the full GET /contracts/by-address/{address}
// body returned to the super-admin or to a JWT admin of the owning org: the
// contract, its organization, and every grant with group + access detail.
type contractLookupFullResponse struct {
	Contract     *rbac.Contract            `json:"contract"`
	Organization *rbac.Organization        `json:"organization"`
	Grants       []contractLookupGrantInfo `json:"grants"`
}

// sharedInfraListResponse is the GET /shared-infrastructure body: the full
// fleet-level shared-infrastructure allowlist.
type sharedInfraListResponse struct {
	Data []rbac.SharedInfrastructure `json:"data"`
}

// azureTenantListResponse is the GET /azure-tenants body: the full Azure AD
// tenant allowlist.
type azureTenantListResponse struct {
	Data []db.AllowedAzureTenant `json:"data"`
}

// --- Request bodies (mirror the anonymous ShouldBindJSON structs) ---

// contractCreateRequest is the POST /orgs/{org_id}/contracts body.
type contractCreateRequest struct {
	Address  string         `json:"address" binding:"required" example:"0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"`
	Name     string         `json:"name" example:"Uniswap Token"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// contractUpdateRequest is the PUT /orgs/{org_id}/contracts/{address} body.
// Fields are optional; omitted fields are left unchanged.
type contractUpdateRequest struct {
	Name     *string        `json:"name" example:"Renamed contract"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// contractABIUpdateRequest is the PUT /orgs/{org_id}/contracts/{address}/abi
// body. The ABI must be a JSON array string.
type contractABIUpdateRequest struct {
	ABI string `json:"abi" binding:"required" example:"[{\"type\":\"event\",\"name\":\"Transfer\",\"inputs\":[]}]"`
}

// contractVisibleToUnlockRequest is the PUT
// /orgs/{org_id}/contracts/{address}/visibleto-unlock body.
type contractVisibleToUnlockRequest struct {
	AllowVisibleToUnlock *bool `json:"allow_visibleto_unlock" binding:"required" example:"false"`
}

// contractEventsAllowDynamicPayloadRequest is the PUT
// /orgs/{org_id}/contracts/{address}/events-allow-dynamic-payload body.
type contractEventsAllowDynamicPayloadRequest struct {
	EventsAllowDynamicPayload *bool `json:"events_allow_dynamic_payload" example:"false"`
}

// contractMethodPoliciesRequest is the PUT
// /orgs/{org_id}/contracts/{address}/method-policies body (RD-1206). The
// method_policies object is a per-record access policy validated against the
// contract's registered ABI; send null to clear it (feature off).
type contractMethodPoliciesRequest struct {
	MethodPolicies json.RawMessage `json:"method_policies" swaggertype:"object"`
}

// contractMethodPoliciesResponse is the GET
// /orgs/{org_id}/contracts/{address}/method-policies body: the currently
// configured policy document, or null when none is set.
type contractMethodPoliciesResponse struct {
	MethodPolicies json.RawMessage `json:"method_policies" swaggertype:"object"`
}

// contractSyncDeleteRequest is the POST
// /orgs/{org_id}/contracts/sync-delete body: the contracts to re-check and
// delete if still missing on-chain.
type contractSyncDeleteRequest struct {
	ContractIDs []string `json:"contract_ids" binding:"required"`
}

// contractGrantCreateRequest is the POST
// /orgs/{org_id}/contracts/{address}/grants body. Functions nil means all
// functions; event_rules is null (deny), "*" (all events), or an allowlist.
type contractGrantCreateRequest struct {
	GroupID    string                `json:"group_id" binding:"required" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	Functions  []rbac.FunctionRule   `json:"functions,omitempty"`
	EventRules *rbac.EventRulesField `json:"event_rules"`
}

// contractGrantUpdateRequest is the PUT
// /orgs/{org_id}/contracts/{address}/grants/{group_id} body. An absent key
// means "no change"; an explicit null clears the field. functions is an array
// of function rules; event_rules is "*", null, or an array of event rules.
type contractGrantUpdateRequest struct {
	Functions  []rbac.FunctionRule   `json:"functions,omitempty"`
	EventRules *rbac.EventRulesField `json:"event_rules"`
}

// contractBatchMoveNewGroup is the optional inline group-creation block of the
// batch-move request.
type contractBatchMoveNewGroup struct {
	Slug string `json:"slug" binding:"required" example:"engineering"`
	Name string `json:"name" binding:"required" example:"Engineering"`
}

// contractBatchMoveRequest is the POST /orgs/{org_id}/contracts/batch-move
// body. Provide exactly one of target_group_id or new_group.
type contractBatchMoveRequest struct {
	ContractIDs           []string                   `json:"contract_ids" binding:"required"`
	TargetGroupID         string                     `json:"target_group_id,omitempty" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	NewGroup              *contractBatchMoveNewGroup `json:"new_group,omitempty"`
	DeleteEmptyAutoGroups bool                       `json:"delete_empty_auto_groups" example:"false"`
}

// azureTenantCreateRequest is the POST /azure-tenants body.
type azureTenantCreateRequest struct {
	TenantID       string  `json:"tenant_id" binding:"required" example:"11111111-2222-3333-4444-555555555555"`
	Label          string  `json:"label" example:"Contoso"`
	DefaultOrgID   *string `json:"default_org_id,omitempty"`
	DefaultGroupID *string `json:"default_group_id,omitempty"`
	AutoProvision  *bool   `json:"auto_provision,omitempty" example:"true"`
}

// azureTenantUpdateRequest is the PUT /azure-tenants/{id} body. All fields are
// optional; omitted fields are left unchanged.
type azureTenantUpdateRequest struct {
	TenantID       *string `json:"tenant_id,omitempty" example:"11111111-2222-3333-4444-555555555555"`
	Label          *string `json:"label,omitempty" example:"Contoso"`
	DefaultOrgID   *string `json:"default_org_id,omitempty"`
	DefaultGroupID *string `json:"default_group_id,omitempty"`
	AutoProvision  *bool   `json:"auto_provision,omitempty" example:"true"`
}

// contractClaimRequest is the POST /orgs/{org_id}/contracts/claim body.
type contractClaimRequest struct {
	Address          string `json:"address" binding:"required" example:"0x0000000000000000000000000000000000000001"`
	Name             string `json:"name" example:"My Token"`
	DeploymentTxHash string `json:"deployment_tx_hash" binding:"required" example:"0x0000000000000000000000000000000000000000000000000000000000000001"`
}

// contractClaimResponse is the 201 body of a successful contract claim.
type contractClaimResponse struct {
	ID      string `json:"id" example:"11111111-2222-3333-4444-555555555555"`
	Address string `json:"address" example:"0x0000000000000000000000000000000000000001"`
	Name    string `json:"name" example:"My Token"`
	OrgID   string `json:"org_id" example:"11111111-2222-3333-4444-555555555555"`
}
