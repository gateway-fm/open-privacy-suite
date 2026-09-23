package apimodels

import (
	"encoding/json"
	"time"

	"privacy-proxy/internal/configuration"
)

// ConfigurationRevision retains the exact submitted source and review identity.
type ConfigurationRevision struct {
	ID                   string                        `json:"id"`
	Scope                configuration.Scope           `json:"scope"`
	Kind                 configuration.Kind            `json:"kind"`
	Revision             int64                         `json:"revision"`
	BaseRevision         int64                         `json:"baseRevision"`
	Source               string                        `json:"source"`
	Digest               string                        `json:"digest"`
	Dependencies         map[configuration.Kind]string `json:"dependencies"`
	Status               string                        `json:"status"`
	CreatedBy            string                        `json:"createdBy"`
	CreatedAt            time.Time                     `json:"createdAt"`
	ActivatedBy          *string                       `json:"activatedBy"`
	ActivatedAt          *time.Time                    `json:"activatedAt"`
	Artifact             json.RawMessage               `json:"artifact,omitempty" swaggertype:"object"`
	CreatedPrincipalKind string                        `json:"createdPrincipalKind"`
}

type ConfigurationContext struct {
	Capabilities       ConfigurationCapabilities               `json:"capabilities"`
	Viewer             ConfigurationViewer                     `json:"viewer"`
	Active             *ConfigurationRevision                  `json:"active"`
	Source             json.RawMessage                         `json:"source" swaggertype:"object"`
	Groups             *configuration.GroupSnapshot            `json:"groups,omitempty"`
	Registry           *configuration.RegistrySnapshot         `json:"registry,omitempty"`
	Compliance         *configuration.ComplianceSnapshot       `json:"compliance,omitempty"`
	Approvers          *configuration.ApproversSpec            `json:"approvers,omitempty"`
	LegacyExecution    []configuration.LegacyExecutionGrant    `json:"legacyExecution"`
	Platform           *configuration.PlatformSnapshot         `json:"platform,omitempty"`
	Execution          *configuration.ExecutionSpec            `json:"execution,omitempty"`
	ExecutionMigration *configuration.ExecutionMigrationReview `json:"executionMigration,omitempty"`
}

// ConfigurationCapabilities lets a headless client discover the configuration
// API before drafting, without probing endpoints: which streams exist, which
// may only be authored and approved by a human, how a revision can be approved,
// the document size limit, and whether this deployment can compile
// execution-rules artifacts right now. It describes the API, not the caller's
// authority; see ConfigurationViewer for that.
type ConfigurationCapabilities struct {
	APIVersion       string                 `json:"apiVersion"`
	Kinds            []string               `json:"kinds"`
	HumanOnlyKinds   []string               `json:"humanOnlyKinds"`
	ApprovalModes    []string               `json:"approvalModes"`
	MaxDocumentBytes int                    `json:"maxDocumentBytes"`
	Compiler         ConfigurationCompiler  `json:"compiler"`
	PriceFeed        ConfigurationPriceFeed `json:"priceFeed"`
}

// ConfigurationPriceFeed reports whether a price feed declared in the platform
// document is polled by this deployment. Available=false means the pricing
// service is not running here because the environment turned it off; a
// declared feed is still accepted and stored, but has no effect until the
// setting named in Reason changes.
type ConfigurationPriceFeed struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// ConfigurationCompiler reports the pinned Solidity version execution-rules
// artifacts are built with and whether that exact compiler is usable now.
// Available=false means an execution-rules submission will be refused until
// the operator installs the pinned compiler; other streams are unaffected.
type ConfigurationCompiler struct {
	Version   string `json:"version"`
	Available bool   `json:"available"`
}

// Presentation hint only. Activation rechecks authority and author separation
// under the configuration transaction's locks.
type ConfigurationViewer struct {
	PrincipalID   string `json:"principalId"`
	PrincipalKind string `json:"principalKind"`
	CanActivate   bool   `json:"canActivate"`
}

type ConfigurationRevisionList struct {
	Revisions []ConfigurationRevision `json:"revisions"`
}

// Coactivate contains sibling draft IDs; the revision in the URL is implicit.
type ConfigurationCoactivateRequest struct {
	Coactivate []string `json:"coactivate"`
}

type ConfigurationReview struct {
	Revisions       []ConfigurationRevision              `json:"revisions"`
	Groups          configuration.GroupSnapshot          `json:"groups"`
	Registry        configuration.RegistrySnapshot       `json:"registry"`
	GroupDiff       *configuration.GroupDiff             `json:"groupDiff"`
	RegistryDiff    *configuration.RegistryDiff          `json:"registryDiff"`
	Compliance      configuration.ComplianceSnapshot     `json:"compliance"`
	ComplianceDiff  *configuration.ComplianceDiff        `json:"complianceDiff"`
	Approvers       *configuration.ApproversSpec         `json:"approvers"`
	ApproversDiff   *configuration.ApproversSpec         `json:"approversDiff"`
	LegacyExecution []configuration.LegacyExecutionGrant `json:"legacyExecution"`
	Platform        configuration.PlatformSnapshot       `json:"platform"`
	PlatformDiff    *configuration.PlatformDiff          `json:"platformDiff"`
	ExecutionDiff   *configuration.ExecutionDiff         `json:"executionDiff"`
}

// ConfigurationManaged answers the one question an admin screen asks before
// it offers an edit control: is this stream owned by an active reviewed
// document right now? While Managed is true the legacy write endpoints for
// the stream answer 409 and the database refuses direct writes; the screen
// should switch to read-only and point at the configuration screen.
type ConfigurationManaged struct {
	Kind    string `json:"kind"`
	Managed bool   `json:"managed"`
}
