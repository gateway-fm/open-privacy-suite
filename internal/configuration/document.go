// Package configuration defines the typed source documents and review diffs
// used by revision lifecycle operations. Operational identity state stays out.
package configuration

import (
	"encoding/json"

	"privacy-proxy/internal/rbac"
)

const APIVersion = "ops.configuration/v1"

type Kind string

const (
	Groups           Kind = "groups"
	ContractRegistry Kind = "contract-registry"
	Compliance       Kind = "compliance"
	Approvers        Kind = "approvers"
	ExecutionRules   Kind = "execution-rules"
	Platform         Kind = "platform"
)

// OrganizationKinds lists the streams an organization scope owns, in the order
// clients present them. Platform is a separate scope with its own routes.
func OrganizationKinds() []Kind {
	return []Kind{Groups, ContractRegistry, Compliance, Approvers, ExecutionRules}
}

// HumanAuthorKinds lists the streams that only a human principal may draft and
// approve: they configure who may approve and the platform trust root, so a
// service principal must never be able to widen its own authority there.
func HumanAuthorKinds() []Kind { return []Kind{Approvers, Platform} }

// RequiresHumanAuthor reports whether kind is one of HumanAuthorKinds.
func RequiresHumanAuthor(kind Kind) bool {
	return kind == Approvers || kind == Platform
}

// Approval modes a deployment can offer for activating a revision.
const (
	// ApprovalModeHuman is the default: a human with current full authority who
	// is not the revision's author activates it.
	ApprovalModeHuman = "human"
	// ApprovalModeTrustedCI activates through configured external approval
	// evidence (a signed ops.configuration-approval/v1 manifest); see CIApproval.
	ApprovalModeTrustedCI = "trusted-ci"
)

// ApprovalModes lists the modes in the order clients present them.
func ApprovalModes() []string { return []string{ApprovalModeHuman, ApprovalModeTrustedCI} }

type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty" optional:"true"`
}

type Deletion struct {
	ID              string `json:"id"`
	LiveMemberships *int64 `json:"liveMemberships,omitempty" optional:"true"`
}

type Spec interface{ configurationKind() Kind }

type Document struct {
	APIVersion   string          `json:"apiVersion"`
	Kind         Kind            `json:"kind"`
	Scope        Scope           `json:"scope"`
	BaseRevision int64           `json:"baseRevision"`
	Dependencies map[Kind]string `json:"dependencies"`
	Deletions    []Deletion      `json:"deletions"`
	Spec         Spec            `json:"spec"`
}

type Group struct {
	ID                 string   `json:"id"`
	Slug               string   `json:"slug"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	IsOrgAdmin         bool     `json:"isOrgAdmin"`
	IsOrgReadonlyAdmin bool     `json:"isOrgReadonlyAdmin"`
	AllowedMethods     []string `json:"allowedMethods"`
	Claims             []string `json:"claims"`
	VerboseErrors      bool     `json:"verboseErrors"`
}

type GroupsSpec struct {
	Groups []Group `json:"groups"`
}

func (GroupsSpec) configurationKind() Kind { return Groups }

type EventRules struct {
	Mode  string      `json:"mode"`
	Rules []EventRule `json:"rules"`
}
type EventRule struct {
	Topic0     string           `json:"topic0"`
	Name       string           `json:"name"`
	ParamRules []rbac.ParamRule `json:"paramRules"`
}
type ReadGrant struct {
	ID           string     `json:"id"`
	GroupID      string     `json:"groupId"`
	LegacyClaims []string   `json:"legacyClaims"`
	EventRules   EventRules `json:"eventRules"`
}
type Contract struct {
	ID                        string          `json:"id"`
	Address                   string          `json:"address"`
	Name                      string          `json:"name"`
	ABI                       json.RawMessage `json:"abi"`
	AllowVisibleToUnlock      bool            `json:"allowVisibleToUnlock"`
	EventsAllowDynamicPayload bool            `json:"eventsAllowDynamicPayload"`
	ReadGrants                []ReadGrant     `json:"readGrants"`
}
type RegistrySpec struct {
	Contracts []Contract `json:"contracts"`
}

func (RegistrySpec) configurationKind() Kind { return ContractRegistry }

type ContractState struct {
	Contract        Contract `json:"contract"`
	Managed         bool     `json:"managed"`
	ManagedGrantIDs []string `json:"managedGrantIds"`
}
type RegistrySnapshot struct {
	Scope          Scope           `json:"scope"`
	ActiveRevision int64           `json:"activeRevision"`
	Contracts      []ContractState `json:"contracts"`
}
type RegistryChange struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	ID       string `json:"id"`
}
type RegistryDiff struct {
	Changes        []RegistryChange `json:"changes"`
	PreservedDrift []string         `json:"preservedDrift"`
	Projection     []Contract       `json:"projection"`
}

// GroupState includes server-owned provenance and current operation counts;
// neither may be asserted by a source document.
type GroupState struct {
	Group           Group `json:"group"`
	Managed         bool  `json:"managed"`
	Protected       bool  `json:"protected"`
	LiveMemberships int64 `json:"liveMemberships"`
	ActiveMembers   int64 `json:"activeMembers"`
	// LegacyHierarchy is retained database metadata, not authorable source.
	LegacyHierarchy *LegacyGroupHierarchy `json:"legacyHierarchy,omitempty"`
}
type LegacyGroupHierarchy struct {
	ParentID *string `json:"parentId"`
	Depth    int     `json:"depth"`
	Path     string  `json:"path"`
}
type GroupSnapshot struct {
	Scope          Scope        `json:"scope"`
	ActiveRevision int64        `json:"activeRevision"`
	Groups         []GroupState `json:"groups"`
}
type GroupChange struct {
	Action           string `json:"action"`
	ID               string `json:"id"`
	Before           *Group `json:"before"`
	After            *Group `json:"after"`
	LiveMemberships  int64  `json:"liveMemberships"`
	RequiresPlatform bool   `json:"requiresPlatform"`
}
type GroupDiff struct {
	Changes        []GroupChange `json:"changes"`
	PreservedDrift []string      `json:"preservedDrift"`
	Projection     []Group       `json:"projection"`
}

// GrantRow retains claims even though the legacy public rbac.ContractGrant
// model omits that database column.
type GrantRow struct {
	Grant  *rbac.ContractGrant
	Claims []string
}
type RegistryRow struct {
	Contract *rbac.Contract
	Grants   []GrantRow
}
type LegacyExecutionGrant struct {
	Address string `json:"address"`
	GroupID string `json:"groupId"`
	// null grants all functions; [] grants none. This import-only representation
	// must never be silently normalized or projected by the registry stream.
	Functions []rbac.FunctionRule `json:"functions"`
}
