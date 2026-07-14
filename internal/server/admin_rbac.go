package server

import (
	"github.com/gin-gonic/gin"
)

// registerRBACRoutes registers RBAC admin API endpoints.
func (s *Server) registerRBACRoutes(api *gin.RouterGroup) {
	// Organizations
	api.GET("/orgs", s.listOrganizations)
	api.POST("/orgs", s.createOrganization)
	api.GET("/orgs/:org_id", s.getOrganization)
	api.PUT("/orgs/:org_id", s.updateOrganization)
	api.DELETE("/orgs/:org_id", s.deleteOrganization)

	// Groups
	api.GET("/orgs/:org_id/groups", s.listGroups)
	api.POST("/orgs/:org_id/groups", s.createGroup)
	api.GET("/orgs/:org_id/groups/:group_id", s.getGroup)
	api.PUT("/orgs/:org_id/groups/:group_id", s.updateGroup)
	api.DELETE("/orgs/:org_id/groups/:group_id", s.deleteGroup)

	// Group Access (replaces old permissions and roles)
	api.GET("/orgs/:org_id/groups/:group_id/access", s.getGroupAccess)
	api.PUT("/orgs/:org_id/groups/:group_id/access", s.setGroupAccess)

	// Contracts
	api.GET("/orgs/:org_id/contracts", s.listContracts)
	api.POST("/orgs/:org_id/contracts", s.createContract)
	api.POST("/orgs/:org_id/contracts/claim", s.claimUnregisteredContract)
	api.GET("/orgs/:org_id/contracts/:address", s.getContract)
	api.PUT("/orgs/:org_id/contracts/:address", s.updateContract)
	api.DELETE("/orgs/:org_id/contracts/:address", s.deleteContract)
	api.PUT("/orgs/:org_id/contracts/:address/abi", s.updateContractABI)
	api.PUT("/orgs/:org_id/contracts/:address/visibleto-unlock", s.updateContractAllowVisibleToUnlock)
	api.PUT("/orgs/:org_id/contracts/:address/events-allow-dynamic-payload", s.updateContractEventsAllowDynamicPayload)
	api.GET("/orgs/:org_id/contracts/:address/method-policies", s.getContractMethodPolicies)
	api.PUT("/orgs/:org_id/contracts/:address/method-policies", s.updateContractMethodPolicies)
	api.GET("/orgs/:org_id/contracts/:address/events", s.listContractEvents)

	// RD-872: admin dry-run / impersonation. Tier-2 admin of :org_id
	// only; super-admin tokens are rejected inside the handler. See
	// admin_dry_run.go for threat-model rationale.
	api.POST("/orgs/:org_id/dry-run", s.handleDryRun)
	api.POST("/orgs/:org_id/contracts/sync-check", s.checkContractsOnChain)
	api.POST("/orgs/:org_id/contracts/sync-delete", s.deleteStaleContracts)
	api.GET("/orgs/:org_id/contracts/grant-summary", s.getContractGrantSummary)

	// Batch operations
	api.POST("/orgs/:org_id/contracts/batch-move", s.batchMoveContracts)
	api.POST("/orgs/:org_id/groups/batch-delete", s.batchDeleteGroups)
	api.POST("/orgs/:org_id/groups/batch-delete-preview", s.batchDeletePreview)

	// Contract Grants
	api.GET("/orgs/:org_id/contracts/:address/grants", s.listContractGrants)
	api.POST("/orgs/:org_id/contracts/:address/grants", s.createContractGrant)
	api.PUT("/orgs/:org_id/contracts/:address/grants/:group_id", s.updateContractGrant)
	api.DELETE("/orgs/:org_id/contracts/:address/grants/:group_id", s.deleteContractGrant)

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

	// Audit Logs
	api.GET("/audit-logs", s.listAuditLogs)

	// Sessions
	api.GET("/sessions", s.listSessions)
	api.DELETE("/sessions/:session_id", s.deleteSession)

	// Azure AD Tenant Allowlist
	api.GET("/azure-tenants", s.listAzureTenants)
	api.POST("/azure-tenants", s.createAzureTenant)
	api.GET("/azure-tenants/:id", s.getAzureTenant)
	api.PUT("/azure-tenants/:id", s.updateAzureTenant)
	api.DELETE("/azure-tenants/:id", s.deleteAzureTenant)

	// shared_infrastructure (KD-1, follow-up to M5 / RD-915).
	// Super-admin only; the table is not org-scoped, every mutation
	// changes cluster-wide trust policy.
	s.registerSharedInfraRoutes(api)

	// Debugging
	api.GET("/users/:user_id/effective-permissions", s.getEffectivePermissions)
	api.POST("/access/check", s.checkAccessAPI)
	api.GET("/cache/stats", s.getCacheStats)
}
