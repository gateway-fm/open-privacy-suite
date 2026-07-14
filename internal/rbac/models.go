// Package rbac provides role-based access control for the privacy proxy.
package rbac

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"privacy-proxy/internal/evm/precompile"
)

// Claim represents a permission claim type for contract access.
type Claim string

const (
	ClaimAdmin   Claim = "admin"   // Full control — implies deploy + upgrade
	ClaimUpgrade Claim = "upgrade" // Can upgrade proxy contracts
	ClaimDeploy  Claim = "deploy"  // Can deploy new contracts (contract creation transactions)
)

// AllClaims returns all valid claims.
func AllClaims() []Claim {
	return []Claim{ClaimAdmin, ClaimUpgrade, ClaimDeploy}
}

// claimImplications defines which claims each claim implies.
// admin implies deploy+upgrade. Read/write access is determined by the method
// allowlist, not by claims — those are operational gates only.
var claimImplications = map[Claim][]Claim{
	ClaimAdmin:   {ClaimDeploy, ClaimUpgrade},
	ClaimDeploy:  {},
	ClaimUpgrade: {},
}

// ExpandClaims expands claims according to the hierarchy:
//   - admin → deploy, upgrade
//
// Read/write are not claim-gated; the method allowlist is the source of truth.
// Returns a deduplicated, sorted slice.
func ExpandClaims(claims []Claim) []Claim {
	set := make(map[Claim]bool, len(claims))
	for _, c := range claims {
		set[c] = true
		for _, implied := range claimImplications[c] {
			set[implied] = true
		}
	}

	result := make([]Claim, 0, len(set))
	for c := range set {
		result = append(result, c)
	}
	slices.SortFunc(result, func(a, b Claim) int {
		return strings.Compare(string(a), string(b))
	})
	return result
}

// MembershipSource indicates how a user obtained membership in a group.
type MembershipSource string

const (
	MembershipSourceAdmin      MembershipSource = "admin"
	MembershipSourceZKAttested MembershipSource = "zk_attested"
)

// Default IDs for seeded data (matching database migrations).
const (
	// DefaultOrgID is the ID of the default organization created on first run.
	DefaultOrgID = "00000000-0000-0000-0000-000000000001"
	// DefaultGroupID is the ID of the default group that new users are added to.
	DefaultGroupID = "00000000-0000-0000-0000-000000000001"
	// AnonymousOrgID is the ID of the system org that holds the anonymous group
	// (RD-870). Seeded by migration 044 with is_system=true; identity-immutable.
	AnonymousOrgID = "00000000-0000-0000-0000-000000000002"
	// AnonymousGroupID is the group whose group_access row supplies the
	// allowed_methods + claims applied to no-JWT (anonymous) requests in
	// internal/rbac/access.go. Edit via super-admin (X-Admin-Token) only.
	AnonymousGroupID = "00000000-0000-0000-0000-000000000002"
)

// Organization represents a top-level tenant.
type Organization struct {
	ID        string         `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Settings  map[string]any `json:"settings"`
	IsSystem  bool           `json:"is_system"` // Seeded, identity-immutable rows (e.g. anonymous, RD-870)
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type AuditRecord struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	ActorID   string    `json:"actor_id"`  // User or API Key ID
	Action    string    `json:"action"`    // e.g., "create", "update", "delete"
	Resource  string    `json:"resource"`  // The type of resource (e.g., "ContractGrant")
	TargetID  string    `json:"target_id"` // GroupID, UserID, ContractID depending on resource
	Details   any       `json:"details"`   // The actual object changes
	Timestamp time.Time `json:"timestamp"`
}

// Group represents a hierarchical permission container within an organization.
// Note: Permissions come from GroupAccess and ContractGrants, not roles.
type Group struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"org_id"`
	ParentID           *string   `json:"parent_id,omitempty"`
	Slug               string    `json:"slug"`
	Name               string    `json:"name"`
	Description        string    `json:"description,omitempty"`
	Depth              int       `json:"depth"`
	Path               string    `json:"path"`                  // Materialized path (e.g., "root.engineering.devops")
	IsOrgAdmin         bool      `json:"is_org_admin"`          // If true, members get all claims on all contracts in the org
	IsOrgReadonlyAdmin bool      `json:"is_org_readonly_admin"` // If true, members can read all admin endpoints in the org but cannot mutate (RD-866)
	IsSystem           bool      `json:"is_system"`             // Seeded, identity-immutable rows (e.g. anonymous, RD-870)
	AutoCreated        bool      `json:"auto_created"`          // Deprecated: always false for new groups. Column retained in DB for expand-only migration policy.
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Contract represents a first-class contract resource.
// "Ownership" is claims-based - a group with 'admin' claim is considered the owner.
type Contract struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"org_id"`
	Address          string         `json:"address"` // lowercase 0x-prefixed
	Name             string         `json:"name,omitempty"`
	ABI              string         `json:"abi,omitempty"` // Contract ABI JSON for function-level access control
	DeployedByUserID *string        `json:"deployed_by_user_id,omitempty"`
	DeployedAt       *time.Time     `json:"deployed_at,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	// AllowVisibleToUnlock: when true, per-tx visibleTo lists act as a
	// per-event opt-in unlock for eligible viewers (RD-874). False
	// preserves the pre-RD-874 additive-only behaviour. Admin-only via
	// the dedicated PATCH endpoint; never settable by sendTransaction
	// or by non-admin contract create/update calls.
	AllowVisibleToUnlock bool `json:"allow_visibleto_unlock"`

	// EventsAllowDynamicPayload: when true, RedactLogs /
	// FilterEventLogs pass through events with dynamic non-indexed
	// parameters (`bytes`, `string`, dynamic arrays / structs)
	// without dropping for non-Full viewers (M15 opt-out, security
	// audit follow-up to RD-915). Default false — close-by-default
	// behaviour: events whose payload could embed foreign-org
	// addresses are dropped for any viewer who didn't earn Full
	// visibility via admin claim, participant override, or
	// visibleTo unlock. Admin-only via the dedicated PUT endpoint.
	EventsAllowDynamicPayload bool `json:"events_allow_dynamic_payload"`

	// MethodPolicies is the raw per-contract method-access policy document
	// (RD-1206; contracts.method_policies JSONB). Nil when unset (feature off
	// for the contract). Kept raw here — the request path parses it via
	// ParseMethodPolicyDocument and fails closed on a parse error, so a
	// corrupt policy denies only that contract's gated reads rather than
	// breaking every contract load.
	MethodPolicies json.RawMessage `json:"method_policies,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FunctionRule describes access to a single contract function selector,
// with optional parameter-level constraints.
type FunctionRule struct {
	Selector   string      `json:"selector"`
	ParamRules []ParamRule `json:"param_rules,omitempty"`
}

// ParamRule constrains a single ABI parameter of a function call or event.
type ParamRule struct {
	Index  int    `json:"index"`   // ABI parameter position (0-based)
	MustBe string `json:"must_be"` // "self" (caller's address) or "0x..." (literal hex value)
}

// EventRule describes access to a single event (identified by topic0 hash),
// with optional parameter-level constraints.
type EventRule struct {
	Topic0     string      `json:"topic0"`                // keccak256(EventName(paramTypes)) — 32-byte hex with 0x prefix
	Name       string      `json:"name"`                  // human-readable event name, from ABI
	ParamRules []ParamRule `json:"param_rules,omitempty"` // optional "self" constraints (reuse existing ParamRule)
}

// EventRulesField represents event access configuration for a contract grant.
// Three states:
//   - Wildcard ("*" in JSON) = all events visible
//   - Deny (null or [] in JSON) = no events visible (fail-closed)
//   - Allowlist ([{...}] in JSON) = only listed events visible
type EventRulesField struct {
	Wildcard bool        // true when the JSON value is the string "*"
	Rules    []EventRule // allowlist rules; only meaningful when Wildcard is false
}

// IsWildcard returns true if all events are visible (wildcard mode).
func (f EventRulesField) IsWildcard() bool { return f.Wildcard }

// IsDeny returns true if no events are visible (deny mode).
func (f EventRulesField) IsDeny() bool { return !f.Wildcard && len(f.Rules) == 0 }

// GetRules returns the allowlist rules. Returns nil for wildcard or deny states.
func (f EventRulesField) GetRules() []EventRule {
	if f.Wildcard {
		return nil
	}
	return f.Rules
}

// MarshalJSON encodes the EventRulesField to JSON:
//   - Wildcard → "*" (quoted string)
//   - Deny (nil/empty rules) → null
//   - Allowlist → JSON array of EventRule
func (f EventRulesField) MarshalJSON() ([]byte, error) {
	if f.Wildcard {
		return json.Marshal("*")
	}
	if len(f.Rules) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(f.Rules)
}

// UnmarshalJSON decodes JSON into EventRulesField:
//   - "*" string → Wildcard=true
//   - null → Wildcard=false, Rules=nil (deny)
//   - [] → Wildcard=false, Rules=nil (deny)
//   - [{...}] → Wildcard=false, Rules=parsed
func (f *EventRulesField) UnmarshalJSON(data []byte) error {
	// Handle null
	if string(data) == "null" {
		f.Wildcard = false
		f.Rules = nil
		return nil
	}

	// Try string first (for "*")
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "*" {
			f.Wildcard = true
			f.Rules = nil
			return nil
		}
		return fmt.Errorf("invalid event_rules string: %q (only \"*\" is supported)", s)
	}

	// Try array
	var rules []EventRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("event_rules must be \"*\", null, or an array: %w", err)
	}

	f.Wildcard = false
	if len(rules) == 0 {
		f.Rules = nil // empty array = deny (same as null)
	} else {
		f.Rules = rules
	}
	return nil
}

// ContractGrant links a group to a contract, enabling access.
// The group's claims (from GroupAccess) apply to this contract.
// Functions can optionally restrict which contract functions are accessible.
// EventRules can optionally restrict which event logs are visible.
// Claims are inherited from the group's GroupAccess.claims - grants just link groups to contracts.
type ContractGrant struct {
	ID         string           `json:"id"`
	ContractID string           `json:"contract_id"`
	GroupID    string           `json:"group_id"`
	Functions  []FunctionRule   `json:"functions,omitempty"` // nil = all functions, or structured rules with optional param constraints
	EventRules *EventRulesField `json:"event_rules"`         // nil = deny, wildcard = all events, allowlist = specific events
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

// GroupAccess represents RPC method permissions and rate limits for a group.
// AllowedMethods controls which RPC methods the group can call (the method allowlist).
// Claims are operational gates: only deploy, upgrade, and admin are meaningful.
// Read/write access is determined by AllowedMethods, not claims.
type GroupAccess struct {
	ID             string    `json:"id"`
	GroupID        string    `json:"group_id"`
	AllowedMethods []string  `json:"allowed_methods"`
	Claims         []Claim   `json:"claims"`                // Operational claims: deploy, upgrade, admin
	RPCAPIKey      *string   `json:"rpc_api_key,omitempty"` // API key for upstream RPC proxy authentication
	VerboseErrors  bool      `json:"verbose_errors"`        // RD-1137 Part A: members get curated reason codes on the wire for denials
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	// Computed fields (not stored in DB, populated by handlers for child groups)
	EffectiveClaims  []Claim `json:"effective_claims,omitempty"`
	NarrowedByParent bool    `json:"narrowed_by_parent,omitempty"`
}

// User represents a user in the RBAC system.
type User struct {
	ID           string         `json:"id"`
	ExternalID   string         `json:"external_id"` // User's DID
	KYC          bool           `json:"kyc"`
	Banned       bool           `json:"banned"`
	Note         string         `json:"note,omitempty"`
	AuthTenantID *string        `json:"auth_tenant_id,omitempty"` // Azure AD tenant ID (nil for Privado users)
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// UserMembership links a user to a group.
// Note: No role_id - permissions come from group's access settings.
type UserMembership struct {
	ID              string           `json:"id"`
	UserID          string           `json:"user_id"`
	GroupID         string           `json:"group_id"`
	Source          MembershipSource `json:"source"`
	ZKCredentialRef string           `json:"zk_credential_ref,omitempty"`
	ExpiresAt       *time.Time       `json:"expires_at,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// ContractAccess represents access permissions for a specific contract.
type ContractAccess struct {
	Claims     []Claim          `json:"claims"`
	Functions  []FunctionRule   `json:"functions,omitempty"` // nil = all functions allowed
	EventRules *EventRulesField `json:"event_rules"`         // nil = deny, wildcard = all events, allowlist = specific events
}

// EffectivePermissions represents the computed permissions for a user in an organization.
// Claims are the user's capabilities from their group memberships.
// ContractAccess maps registered contract addresses to their access settings.
type EffectivePermissions struct {
	ID             string                    `json:"id"`
	UserID         string                    `json:"user_id"`
	OrgID          string                    `json:"org_id"`
	AllowedMethods []string                  `json:"allowed_methods"`
	ContractAccess map[string]ContractAccess `json:"contract_access"` // address -> access
	Claims         []Claim                   `json:"claims"`          // User's capabilities from groups
	RPCAPIKey      string                    `json:"-"`               // Per-group upstream RPC API key (excluded from JSON — sensitive)
	ComputedAt     time.Time                 `json:"computed_at"`
	ExpiresAt      time.Time                 `json:"expires_at"`
}

// AuditLogEntry represents an entry in the RBAC audit log.
type AuditLogEntry struct {
	ID              int64          `json:"id"`
	ActorID         *string        `json:"actor_id,omitempty"`
	ActorExternalID string         `json:"actor_external_id,omitempty"`
	Action          string         `json:"action"` // create, update, delete, assign, revoke
	ResourceType    string         `json:"resource_type"`
	ResourceID      *string        `json:"resource_id,omitempty"`
	ResourceName    string         `json:"resource_name,omitempty"`
	OrgID           *string        `json:"org_id,omitempty"` // parent org of the affected resource (audit H1 — used for cross-org scoping of the list endpoint)
	OldValue        map[string]any `json:"old_value,omitempty"`
	NewValue        map[string]any `json:"new_value,omitempty"`
	IPAddress       string         `json:"ip_address,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

// AccessCheckRequest represents a request to check access permissions.
type AccessCheckRequest struct {
	UserExternalID   string  `json:"user_external_id"`
	OrgSlug          string  `json:"org_slug,omitempty"`          // Optional org slug (deprecated, use OrgID)
	OrgID            string  `json:"org_id,omitempty"`            // Optional org ID for explicit org selection
	Method           string  `json:"method"`                      // Original JSON-RPC method name (used for RBAC allowlist)
	AccessMethod     string  `json:"-"`                           // Resolved method for access control (alias target). Empty = same as Method.
	Params           []any   `json:"params,omitempty"`            // JSON-RPC params for Multicall detection
	TargetAddress    string  `json:"target_address,omitempty"`    // Target address (contract or EOA)
	FunctionSelector string  `json:"function_selector,omitempty"` // First 4 bytes of calldata (e.g., "0xa9059cbb")
	Calldata         []byte  `json:"-"`                           // Raw calldata bytes for parameter validation (not serialized)
	RequiredClaims   []Claim `json:"required_claims,omitempty"`
	// BypassCache, when true, forces CheckAccess to skip the in-memory
	// permissions cache and re-resolve from the underlying store. Used by
	// the RD-928 impersonation surface so a tier-2 admin browsing as user
	// X never sees a stale snapshot of X's perms held by the AccessController.
	// Does not propagate to the resolver's DB cache (5-min TTL); RD-956
	// covers the full fix.
	BypassCache bool `json:"-"`
}

// EffectiveMethod returns the method name to use for access control decisions.
// Returns AccessMethod if set (for aliased chain-specific methods like linea_estimateGas
// → eth_estimateGas), otherwise returns Method.
func (r *AccessCheckRequest) EffectiveMethod() string {
	if r.AccessMethod != "" {
		return r.AccessMethod
	}
	return r.Method
}

// AccessCheckResult represents the result of an access check.
//
// SECURITY (RD-934): The Reason field is an OPERATOR-ONLY diagnostic.
// It is populated with the specific cause of a denial (cardinality of
// org memberships, missing claim names, target-org context, etc.) so
// admins can debug RBAC failures from the access log. It MUST NOT be
// echoed verbatim in a client-facing response body — doing so leaks
// structural information about the caller's account (number of orgs,
// claim presence/absence, existence of resources) that an attacker can
// chain. Past leaks of this class: RD-916, RD-942, RD-944.
//
// The /rpc wire path strips this field automatically (jsonrpc_processor
// returns a fixed "method not found" regardless of Reason). The admin
// `test-request` endpoint is the only intentional surface that returns
// it, and only to localhost + X-Admin-Token callers. Anything else
// that consumes this field should slog it for the operator and
// respond with a generic opaque message to the client.
type AccessCheckResult struct {
	Allowed      bool    `json:"allowed"`
	AuthRequired bool    `json:"auth_required,omitempty"` // True when denial is due to missing authentication (401 vs 403)
	Reason       string  `json:"reason,omitempty"`
	OrgID        string  `json:"org_id,omitempty"`  // Resolved organization ID
	UserID       string  `json:"user_id,omitempty"` // Internal user ID (UUID)
	RPCAPIKey    string  `json:"-"`                 // API key for upstream RPC proxy (excluded from JSON — sensitive)
	Claims       []Claim `json:"claims,omitempty"`
}

// GroupWithAccess combines a Group with its access settings.
type GroupWithAccess struct {
	Group  *Group       `json:"group"`
	Access *GroupAccess `json:"access"`
}

// UserWithMemberships combines a User with their group memberships.
type UserWithMemberships struct {
	User        *User             `json:"user"`
	Memberships []*UserMembership `json:"memberships"`
}

// MembershipWithDetails includes membership with group information.
type MembershipWithDetails struct {
	Membership *UserMembership `json:"membership"`
	Group      *Group          `json:"group"`
}

// ContractWithGrants combines a Contract with its grants.
type ContractWithGrants struct {
	Contract *Contract        `json:"contract"`
	Grants   []*ContractGrant `json:"grants"`
}

// ContractGrantWithGroup includes grant with group details.
type ContractGrantWithGroup struct {
	Grant *ContractGrant `json:"grant"`
	Group *Group         `json:"group"`
}

// GroupSummary is a lightweight representation of a group for summary responses.
type GroupSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserGroupMembership is a per-user membership summary surfaced by the
// users list. It is intentionally narrower than MembershipWithDetails:
// only the fields needed to render the Groups column and link through
// to the group page.
type UserGroupMembership struct {
	GroupID    string `json:"group_id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	OrgID      string `json:"org_id"`
	IsOrgAdmin bool   `json:"is_org_admin"`
}

// ContractGrantSummary contains the count of grants and the groups assigned to a contract.
type ContractGrantSummary struct {
	Count  int            `json:"count"`
	Groups []GroupSummary `json:"groups"`
}

// HasMethod checks if the effective permissions allow a specific method.
// "*" in AllowedMethods means all methods are permitted (used by admin auto-grant).
//
// Glob entries of shape "prefix*" are honored only when a global wildcard
// namespace is registered with the same prefix AND that wildcard would allow
// the method (deny list checked there). This prevents groups from inventing
// prefixes the operator hasn't enabled in EXTRA_RPC_NAMESPACES.
//
// M8 (security audit): a registered global wildcard's Deny list now
// blocks the method regardless of whether the group's AllowedMethods
// has the method enumerated explicitly. Pre-fix, an operator who
// registered Wildcard{Prefix:"linea_", Deny:["linea_sendTransaction"]}
// could be defeated by a tier-1/2 admin listing `linea_sendTransaction`
// explicitly in a group's AllowedMethods — the explicit-match
// short-circuited before the wildcard Deny consultation. Only
// GlobalBlockedMethods was a hard floor. Now Wildcards[].Deny is
// also a hard floor (consulted before the explicit-allow short-circuit).
func (e *EffectivePermissions) HasMethod(method string) bool {
	// Hard-floor check: if any registered global wildcard covers this
	// method's prefix and the wildcard's Deny list rejects the method,
	// it is denied — even if the group explicitly enumerates it.
	if IsDeniedByWildcard(method) {
		return false
	}

	if slices.Contains(e.AllowedMethods, "*") || slices.Contains(e.AllowedMethods, method) {
		return true
	}
	for _, entry := range e.AllowedMethods {
		if entry == "*" || !strings.HasSuffix(entry, "*") {
			continue
		}
		groupPrefix := strings.TrimSuffix(entry, "*")
		if groupPrefix == "" {
			continue // bare "*" handled above; an empty prefix would match everything
		}
		if !strings.HasPrefix(method, groupPrefix) {
			continue
		}
		// The group glob is honored only if a registered global wildcard
		// covers this method (so the deny list and operator opt-in apply).
		if !HasWildcardForPrefix(groupPrefix) {
			continue
		}
		if MatchWildcard(method) != nil {
			return true
		}
	}
	return false
}

// GetContractAccess returns the access for a specific contract address.
// For registered contracts, returns the explicit access from ContractAccess.
// For EVM precompiles (0x01-0x09), returns read-only access (precompiles are
// always accessible since they are built into the EVM).
// For all other unregistered addresses, returns nil (deny). All contracts are
// private by default — only explicit grants or org membership grant access.
// The caller (access.go) enforces cross-org isolation: contracts registered
// to a different org are denied regardless of claims.
func (e *EffectivePermissions) GetContractAccess(address string) *ContractAccess {
	addr := strings.ToLower(address)
	if access, ok := e.ContractAccess[addr]; ok {
		return &access
	}
	// Precompiles (0x01-0x09) are always accessible — they are native EVM functions.
	if precompile.IsPrecompileAddress(addr) {
		return &ContractAccess{
			Claims:    nil, // No operational claims needed; access is implied by the entry existing.
			Functions: nil,
		}
	}
	// All other unregistered addresses are private by default — deny.
	return nil
}

// hasClaim checks if a specific claim exists in a claims slice.
func hasClaim(claims []Claim, target Claim) bool {
	return slices.Contains(claims, target)
}

// HasContractClaim checks if the user has a specific claim on a contract.
func (e *EffectivePermissions) HasContractClaim(address string, claim Claim) bool {
	access := e.GetContractAccess(address)
	if access == nil {
		return false
	}
	return slices.Contains(access.Claims, claim)
}

// HasFunctionSelector checks if a function selector is allowed for an address.
// If the contract has no specific function restrictions, all functions are allowed.
func (e *EffectivePermissions) HasFunctionSelector(address, selector string) bool {
	access := e.GetContractAccess(address)
	if access == nil {
		return false
	}

	// nil = unrestricted (all functions allowed)
	if access.Functions == nil {
		return true
	}
	// Non-nil but empty = explicitly no functions allowed (deny all)
	if len(access.Functions) == 0 {
		return false
	}

	// Check if selector is in the allowed list (case-insensitive)
	for _, rule := range access.Functions {
		if strings.EqualFold(rule.Selector, selector) {
			return true
		}
	}

	return false
}

// GetFunctionRule returns the FunctionRule for a specific selector on a contract.
// Returns nil if no specific rule exists (selector is allowed without constraints or not found).
func (e *EffectivePermissions) GetFunctionRule(address, selector string) *FunctionRule {
	access := e.GetContractAccess(address)
	if access == nil {
		return nil
	}
	if access.Functions == nil {
		return nil // nil = unrestricted, no specific rule
	}
	if len(access.Functions) == 0 {
		return nil // empty = deny all, no matching rule (HasFunctionSelector handles denial)
	}
	for i := range access.Functions {
		if strings.EqualFold(access.Functions[i].Selector, selector) {
			return &access.Functions[i]
		}
	}
	return nil
}

// GetEventRules returns the event rules for a specific contract address.
// Returns nil if no event rules are configured (deny all).
func (e *EffectivePermissions) GetEventRules(address string) *EventRulesField {
	access := e.GetContractAccess(address)
	if access == nil {
		return nil
	}
	return access.EventRules
}

// IsContractRegistered checks if a contract is explicitly registered in RBAC.
func (e *EffectivePermissions) IsContractRegistered(address string) bool {
	addr := strings.ToLower(address)
	_, ok := e.ContractAccess[addr]
	return ok
}

// HasAdminOnContract checks if the user has admin claim on a contract (i.e., is owner).
func (e *EffectivePermissions) HasAdminOnContract(address string) bool {
	return e.HasContractClaim(address, ClaimAdmin)
}

// HasContractAccess checks if the user has any access defined for a contract.
func (e *EffectivePermissions) HasContractAccess(address string) bool {
	addr := strings.ToLower(address)
	_, ok := e.ContractAccess[addr]
	return ok
}

// HasDefaultClaim checks if the user has a specific default claim.
func (e *EffectivePermissions) HasDefaultClaim(claim Claim) bool {
	return slices.Contains(e.Claims, claim)
}

// HasClaim checks if a ContractAccess includes a specific claim.
func (ca ContractAccess) HasClaim(claim Claim) bool {
	return slices.Contains(ca.Claims, claim)
}

// PreregisteredAddress represents a pre-registered CREATE3 deployment address.
// These addresses can be whitelisted before the actual contract is deployed,
// enabling upgradeable proxy patterns where implementation addresses need pre-approval.
type PreregisteredAddress struct {
	ID             string     `json:"id"`
	OrgID          string     `json:"org_id"`
	Address        string     `json:"address"` // The pre-computed CREATE3 address (lowercase 0x-prefixed)
	Factory        string     `json:"factory"` // The CREATE3 factory contract address
	Salt           []byte     `json:"salt"`    // The 32-byte salt used for address derivation
	Note           string     `json:"note,omitempty"`
	ConstructorABI string     `json:"constructor_abi,omitempty"` // Contract ABI JSON for constructor arg validation
	CreatedAt      time.Time  `json:"created_at"`
	UsedAt         *time.Time `json:"used_at,omitempty"` // Timestamp when the address was actually deployed to
}
