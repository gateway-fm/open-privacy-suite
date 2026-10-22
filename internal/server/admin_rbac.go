package server

import (
	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/configuration"
)

// registerRBACRoutes registers RBAC admin API endpoints.
func (s *Server) registerRBACRoutes(api *gin.RouterGroup) {
	s.registerConfigurationRoutes(api)
	groupsWriter := s.configurationWriterGuard(configuration.Groups)
	registryWriter := s.configurationWriterGuard(configuration.ContractRegistry)
	executionWriter := s.configurationWriterGuard(configuration.ExecutionRules)
	// Organizations
	api.GET("/orgs", s.listOrganizations)
	api.POST("/orgs", s.createOrganization)
	api.GET("/orgs/:org_id", s.getOrganization)
	api.PUT("/orgs/:org_id", s.updateOrganization)
	api.DELETE("/orgs/:org_id", s.deleteOrganization)

	// Groups
	api.GET("/orgs/:org_id/groups", s.listGroups)
	api.POST("/orgs/:org_id/groups", groupsWriter, s.createGroup)
	api.GET("/orgs/:org_id/groups/:group_id", s.getGroup)
	api.PUT("/orgs/:org_id/groups/:group_id", groupsWriter, s.updateGroup)
	api.DELETE("/orgs/:org_id/groups/:group_id", groupsWriter, s.deleteGroup)

	// Group Access (replaces old permissions and roles)
	api.GET("/orgs/:org_id/groups/:group_id/access", s.getGroupAccess)
	api.PUT("/orgs/:org_id/groups/:group_id/access", groupsWriter, s.setGroupAccess)
	api.PUT("/orgs/:org_id/groups/:group_id/rpc-credential", s.rotateGroupRPCCredential)

	// Contracts
	api.GET("/orgs/:org_id/contracts", s.listContracts)
	api.POST("/orgs/:org_id/contracts", registryWriter, s.createContract)
	api.POST("/orgs/:org_id/contracts/claim", registryWriter, s.claimUnregisteredContract)
	api.GET("/orgs/:org_id/contracts/:address", s.getContract)
	api.PUT("/orgs/:org_id/contracts/:address", registryWriter, s.updateContract)
	api.DELETE("/orgs/:org_id/contracts/:address", registryWriter, s.deleteContract)
	api.PUT("/orgs/:org_id/contracts/:address/abi", registryWriter, s.updateContractABI)
	api.PUT("/orgs/:org_id/contracts/:address/visibleto-unlock", registryWriter, s.updateContractAllowVisibleToUnlock)
	api.PUT("/orgs/:org_id/contracts/:address/events-allow-dynamic-payload", registryWriter, s.updateContractEventsAllowDynamicPayload)
	api.GET("/orgs/:org_id/contracts/:address/events", s.listContractEvents)

	// RD-872: admin dry-run / impersonation. Tier-2 admin of :org_id
	// only; super-admin tokens are rejected inside the handler. See
	// admin_dry_run.go for threat-model rationale.
	api.POST("/orgs/:org_id/dry-run", s.handleDryRun)

	api.POST("/orgs/:org_id/contracts/sync-check", s.checkContractsOnChain)
	api.POST("/orgs/:org_id/contracts/sync-delete", registryWriter, s.deleteStaleContracts)
	api.GET("/orgs/:org_id/contracts/grant-summary", s.getContractGrantSummary)

	// Batch operations
	api.POST("/orgs/:org_id/contracts/batch-move", registryWriter, s.batchMoveContracts)
	api.POST("/orgs/:org_id/groups/batch-delete", groupsWriter, s.batchDeleteGroups)
	api.POST("/orgs/:org_id/groups/batch-delete-preview", s.batchDeletePreview)

	// Contract Grants
	api.GET("/orgs/:org_id/contracts/:address/grants", s.listContractGrants)
	// A grant row is owned by two streams: claims/event rules by the registry,
	// function rules by execution-rules. Either active stream closes the row's
	// legacy writers (the contract_grants trigger enforces the same split).
	api.POST("/orgs/:org_id/contracts/:address/grants", registryWriter, executionWriter, s.createContractGrant)
	api.PUT("/orgs/:org_id/contracts/:address/grants/:group_id", registryWriter, executionWriter, s.updateContractGrant)
	api.DELETE("/orgs/:org_id/contracts/:address/grants/:group_id", registryWriter, executionWriter, s.deleteContractGrant)

	// Execution policies (RD-1287). A policy restricts what a group may
	// execute; it never grants anything. Submitting compiles and stores a
	// draft that enforces nothing, and a separate activation puts it in
	// force, so a person reviews the exact artifact before it decides.
	api.GET("/orgs/:org_id/execution-policy/context", s.getExecutionPolicyContext)
	api.GET("/orgs/:org_id/execution-policy/revisions", s.listExecutionPolicyRevisions)
	api.POST("/orgs/:org_id/execution-policy/revisions", executionWriter, s.submitExecutionPolicy)
	api.GET("/orgs/:org_id/execution-policy/revisions/:revision_id", s.getExecutionPolicyRevision)
	api.POST("/orgs/:org_id/execution-policy/revisions/:revision_id/activate", executionWriter, s.activateExecutionPolicyRevision)
	api.POST("/orgs/:org_id/execution-policy/revisions/:revision_id/withdraw", executionWriter, s.withdrawExecutionPolicyRevision)
	api.POST("/orgs/:org_id/execution-policy/revisions/:revision_id/simulate", s.simulateExecutionPolicy)

	// Contract lookup (cross-org)
	api.GET("/contracts/by-address/:address", s.lookupContractByAddress)

	// Users
	api.GET("/users", s.listRBACUsers)
	api.GET("/users/:user_id", s.getRBACUser)
	api.PUT("/users/:user_id", s.updateRBACUser)
	api.DELETE("/users/:user_id", s.deleteRBACUser)
	api.GET("/users/:user_id/linked-addresses", s.getUserLinkedAddresses)

	// Memberships
	api.GET("/users/:user_id/memberships", s.listUserMemberships)
	api.POST("/users/:user_id/memberships", s.createUserMembership)
	api.DELETE("/users/:user_id/memberships/:membership_id", s.deleteUserMembership)

	// RD-945: tier-2 onboard-by-DID. Lets a full-admin of :org_id pull a
	// known DID into their own org without a super-admin handoff. Same
	// cross-org gate as createUserMembership; calls EnsureUserExists so
	// not-yet-seen DIDs are provisioned on first onboarding.
	api.POST("/orgs/:org_id/memberships/by-did", s.createMembershipByDID)
	// RD-1182: symmetric removal-by-DID — lets the operator token complete the
	// org-admin lifecycle (mint + remove) without a tenant-confidential read.
	api.DELETE("/orgs/:org_id/memberships/by-did", s.deleteMembershipByDID)

	// Audit Logs
	api.GET("/audit-logs", s.listAuditLogs)

	// Sessions
	api.GET("/sessions", s.listSessions)
	api.DELETE("/sessions/:session_id", s.deleteSession)

	// Azure AD Tenant Allowlist
	api.GET("/azure-tenants", s.listAzureTenants)
	api.POST("/azure-tenants", s.configurationWriterGuard(configuration.Platform), s.createAzureTenant)
	api.GET("/azure-tenants/:id", s.getAzureTenant)
	api.PUT("/azure-tenants/:id", s.configurationWriterGuard(configuration.Platform), s.updateAzureTenant)
	api.DELETE("/azure-tenants/:id", s.configurationWriterGuard(configuration.Platform), s.deleteAzureTenant)

	// shared_infrastructure (KD-1, follow-up to M5 / RD-915).
	// Super-admin only; the table is not org-scoped, every mutation
	// changes cluster-wide trust policy.
	s.registerSharedInfraRoutes(api)

	// Debugging
	api.GET("/users/:user_id/effective-permissions", s.getEffectivePermissions)
	api.POST("/access/check", s.checkAccessAPI)
	api.GET("/cache/stats", s.getCacheStats)
}
