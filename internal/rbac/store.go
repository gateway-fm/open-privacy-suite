package rbac

import (
	"context"
)

// Store defines the interface for RBAC data operations.
type Store interface {
	// Organization operations
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	ListOrganizations(ctx context.Context) ([]*Organization, error)
	ListOrganizationsPaginated(ctx context.Context, limit, offset int) ([]*Organization, int, error)
	DeleteOrganization(ctx context.Context, id string) error

	// Group operations
	CreateGroup(ctx context.Context, group *Group) error
	GetGroup(ctx context.Context, id string) (*Group, error)
	GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error)
	UpdateGroup(ctx context.Context, group *Group) error
	ListGroups(ctx context.Context, orgID string) ([]*Group, error)
	ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Group, int, error) // Returns groups, total count
	ListGroupsWithAccessPaginated(ctx context.Context, orgID string, limit, offset int) ([]*GroupWithAccess, int, error)
	ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error)
	GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) // Returns groups from root to the specified group
	DeleteGroup(ctx context.Context, id string) error

	// Group Access operations (replaces roles.allow_methods and group_permissions)
	CreateGroupAccess(ctx context.Context, access *GroupAccess) error
	GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error)
	GetGroupAccessBatch(ctx context.Context, groupIDs []string) (map[string]*GroupAccess, error)
	UpdateGroupAccess(ctx context.Context, access *GroupAccess) error
	DeleteGroupAccess(ctx context.Context, groupID string) error

	// Contract operations
	CreateContract(ctx context.Context, contract *Contract) error
	GetContract(ctx context.Context, id string) (*Contract, error)
	GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error)
	GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error)
	// GetContractByAddressGlobal looks up a contract by address across all organizations.
	// Used for ABI lookups during event log filtering where the org context is not always known.
	GetContractByAddressGlobal(ctx context.Context, address string) (*Contract, error)
	UpdateContract(ctx context.Context, contract *Contract) error
	ListContracts(ctx context.Context, orgID string) ([]*Contract, error)
	ListContractsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Contract, int, error) // Returns contracts, total count
	DeleteContract(ctx context.Context, id string) error
	// IsContractRegisteredToAnyOrg checks if a contract address is registered in ANY organization.
	// This is used for cross-org isolation: if a contract is registered to any org but the user
	// doesn't have explicit access to it, they should be denied access (not fall back to default_claims).
	IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error)
	// IsAddressOwnedByOrg checks if a contract address belongs to the given organization.
	// This is used for deployment validation to ensure contracts only call addresses owned by the org.
	IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error)
	// GetContractOwnerOrgID returns the org ID that owns a contract address.
	// Returns empty string if the contract is not registered to any organization (public contract).
	// This is used for multi-org user support to determine which org context to use.
	GetContractOwnerOrgID(ctx context.Context, address string) (string, error)
	// GetContractDeployerByAddress returns the user ID that deployed a contract at the given address.
	// Returns nil if the contract is not found or has no deployer recorded.
	// This is used for deployer auto-grant: the user who deployed a contract automatically gets read+write access.
	GetContractDeployerByAddress(ctx context.Context, address string) (*string, error)

	// Contract Grant operations
	CreateContractGrant(ctx context.Context, grant *ContractGrant) error
	GetContractGrant(ctx context.Context, id string) (*ContractGrant, error)
	GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*ContractGrant, error)
	UpdateContractGrant(ctx context.Context, grant *ContractGrant) error
	ListContractGrantsByContract(ctx context.Context, contractID string) ([]*ContractGrant, error)
	ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error)
	ListContractGrantsBatch(ctx context.Context, groupIDs []string) (map[string][]*ContractGrant, error)
	ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error)
	DeleteContractGrant(ctx context.Context, id string) error
	GetContractGrantSummary(ctx context.Context, orgID string) (map[string]*ContractGrantSummary, error)

	// Deployer contract grant operations
	// GrantContractToDeployerGroup finds the deployer's existing group with
	// the deploy claim in the given org and adds a contract_grant to it.
	GrantContractToDeployerGroup(ctx context.Context, orgID, contractID, deployerUserID string) error

	// ETH Address operations (for parameter constraint enforcement)
	GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error)
	SystemLinkEthAddress(ctx context.Context, did, ethAddress string) error
	// GetOrgIDsForEthAddress returns all organization IDs that the owner of a given
	// ETH address belongs to. This resolves via eth_address_links → users → memberships → groups.
	// Returns nil if the address is not linked to any user. Used for cross-org boundary
	// enforcement on custom hex addresses in param rules.
	GetOrgIDsForEthAddress(ctx context.Context, address string) ([]string, error)

	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByExternalID(ctx context.Context, externalID string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	ListUsersPaginated(ctx context.Context, limit, offset int) ([]*User, int, error)
	DeleteUser(ctx context.Context, id string) error

	// Membership operations
	CreateMembership(ctx context.Context, membership *UserMembership) error
	GetMembership(ctx context.Context, id string) (*UserMembership, error)
	GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error)
	UpdateMembership(ctx context.Context, membership *UserMembership) error
	ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error)
	ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error)
	ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error)
	// ListActiveUserMembershipsWithDetails excludes expired memberships. Use it
	// for authorization and trace validation; ListUserMembershipsWithDetails
	// stays complete for the admin membership listing.
	ListActiveUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error)
	ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error)
	DeleteMembership(ctx context.Context, id string) error
	DeleteExpiredMemberships(ctx context.Context) (int64, error)

	// Effective Permissions Cache operations
	GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error)
	SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error
	InvalidateCacheForUser(ctx context.Context, userID string) error
	InvalidateCacheForOrg(ctx context.Context, orgID string) error
	InvalidateCacheForGroup(ctx context.Context, groupID string) error
	CleanupExpiredCache(ctx context.Context) (int64, error)

	// Audit Log operations
	CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error
	ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error)
	ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error)

	// Preregistered Address operations (used by plain CREATE pre-reg flow)
	IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error)
	MarkAddressUsed(ctx context.Context, address string) error
	// PreRegisterPlainCreate inserts a temporary preregistered_addresses row for a plain
	// CREATE deployment before the tx is forwarded, closing the cross-org race window.
	// factory and salt are NULL (not applicable for plain CREATE).
	PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error
	// DeletePreregisteredAddressByAddress removes a preregistered_addresses row by address
	// (without org filter, since addresses are unique). Used to clean up plain CREATE
	// pre-registrations when the tx is rejected or reverts.
	DeletePreregisteredAddressByAddress(ctx context.Context, address string) error

	// Shared infrastructure operations (for runtime tracing)
	// These contracts are globally accessible (e.g., Uniswap router) and do not require org ownership.
	IsSharedInfrastructure(ctx context.Context, address string) (bool, error)
	CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error
	ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error)
	DeleteSharedInfrastructure(ctx context.Context, address string) error
}

// OrgAdminChecker is an optional extension implemented by the
// production DB layer (db.DB.IsOrgAdmin). Used by AccessController to
// determine whether a JWT-authenticated user has org-admin status for
// the historical-state guard (M9). Returns (isAdmin, orgIDs, err) so
// the implementation can also surface the admin's org list, though
// the access controller only consumes the boolean.
type OrgAdminChecker interface {
	IsOrgAdmin(ctx context.Context, userID string) (bool, []string, error)
}

// AuditAction constants for audit logging.
const (
	AuditActionCreate = "create"
	AuditActionUpdate = "update"
	AuditActionDelete = "delete"
	AuditActionAssign = "assign"
	AuditActionRevoke = "revoke"
	// AuditActionAccess records a read/access event (as opposed to a mutation),
	// e.g. an org admin exercising elevated transaction visibility.
	AuditActionAccess = "access"
)

// ResourceType constants for audit logging.
const (
	ResourceTypeOrganization         = "organization"
	ResourceTypeGroup                = "group"
	ResourceTypeUser                 = "user"
	ResourceTypeMembership           = "membership"
	ResourceTypeContract             = "contract"
	ResourceTypeGrant                = "grant"
	ResourceTypeAccess               = "access"
	ResourceTypePreregisteredAddress = "preregistered_address"
	// ResourceTypeExplorerUserTxs is the audit resource for an org admin's
	// elevated view of user↔user transactions (ORG_ADMIN_VIEW_USER_TXS).
	ResourceTypeExplorerUserTxs = "explorer_user_txs"

	// Compliance / disclosure / SSO surfaces — audit-log every mutation
	// for ISO 27001 A.5.25 / A.8.16 evidence (see security audit M2).
	ResourceTypeCompliance        = "compliance"
	ResourceTypeTokenPrice        = "token_price"
	ResourceTypeSanction          = "sanction"
	ResourceTypeTravelRule        = "travel_rule_record"
	ResourceTypeAddressThreshold  = "address_threshold"
	ResourceTypeBaseCurrency      = "base_currency"
	ResourceTypeAzureTenant       = "azure_tenant"
	ResourceTypeSharedInfra       = "shared_infrastructure"
	ResourceTypeDisclosureRequest = "disclosure_request"
	ResourceTypeDisclosureGrant   = "disclosure_grant"
	ResourceTypeSession           = "session"
)
