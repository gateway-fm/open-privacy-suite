package configuration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"privacy-proxy/internal/policydsl"
)

// ExecutionSpec delegates policy syntax to the compiler's versioned schema.
// Artifact bytes are server-generated revision evidence, never source input.
type ExecutionSpec struct {
	Policy                  json.RawMessage             `json:"policy"`
	LegacyRestrictionDigest string                      `json:"legacyRestrictionDigest,omitempty" optional:"true"`
	ProxyPairs              []policydsl.LegacyProxyPair `json:"proxyPairs,omitempty" optional:"true"`
}

// ExecutionMigrationReview is read-only evidence. It is never accepted inside
// an authored source document; the author acknowledges only the old digest.
type ExecutionMigrationReview struct {
	LegacyRestriction *LegacyRestrictionEvidence    `json:"legacyRestriction,omitempty"`
	Diagnostics       []policydsl.LegacyImportIssue `json:"diagnostics"`
}
type LegacyRestrictionEvidence struct {
	RevisionID   string             `json:"revisionId"`
	Revision     int64              `json:"revision"`
	PolicyDigest string             `json:"policyDigest"`
	Source       string             `json:"source"`
	Artifact     policydsl.Artifact `json:"artifact"`
}

func (ExecutionSpec) configurationKind() Kind { return ExecutionRules }

func normalizeExecution(spec *ExecutionSpec) error {
	if spec.LegacyRestrictionDigest != "" {
		decoded, err := hex.DecodeString(spec.LegacyRestrictionDigest)
		if err != nil || len(decoded) != 32 || strings.ToLower(spec.LegacyRestrictionDigest) != spec.LegacyRestrictionDigest {
			return fmt.Errorf("legacyRestrictionDigest must be the exact lowercase policy sha256 digest")
		}
	}
	pairs, err := policydsl.NormalizeProxyPairs(spec.ProxyPairs)
	if err != nil {
		return err
	}
	spec.ProxyPairs = pairs
	p, err := policydsl.Parse(spec.Policy)
	if err != nil {
		return fmt.Errorf("execution policy: %w", err)
	}
	if p.APIVersion != policydsl.APIVersion || p.Kind != policydsl.Kind || p.Org == "" || p.NestedCalls != policydsl.NestedCallsRequireOwnRule {
		return fmt.Errorf("execution policy has unsupported version, kind, organization or nested-call semantics")
	}
	spec.Policy, err = json.Marshal(p)
	if err != nil {
		return fmt.Errorf("execution policy cannot be serialized")
	}
	return nil
}

type ExecutionDiff struct {
	Before                     *policydsl.Policy         `json:"before"`
	After                      *policydsl.Policy         `json:"after"`
	Changes                    []ExecutionChange         `json:"changes"`
	PreviousProjectionID       string                    `json:"previousProjectionId"`
	PreviousProjectionRevision int64                     `json:"previousProjectionRevision"`
	ProjectionRevision         int64                     `json:"projectionRevision"`
	PolicyDigest               string                    `json:"policyDigest"`
	RuntimeDigest              string                    `json:"runtimeDigest"`
	SourceDigest               string                    `json:"sourceDigest"`
	Migration                  *ExecutionMigrationReview `json:"migration,omitempty"`
}

// ExecutionChange shows a binding's complete before/after rules so review never
// substitutes a digest or a claimed widening/narrowing label for actual scope.
type ExecutionChange struct {
	Action  string                `json:"action"`
	GroupID string                `json:"groupId"`
	Before  []policydsl.FrameRule `json:"before"`
	After   []policydsl.FrameRule `json:"after"`
}

func ExecutionChanges(before, after *policydsl.Policy) []ExecutionChange {
	a, b := map[string][]policydsl.FrameRule{}, map[string][]policydsl.FrameRule{}
	if before != nil {
		for _, binding := range before.Bindings {
			a[binding.Group] = binding.Allow
		}
	}
	if after != nil {
		for _, binding := range after.Bindings {
			b[binding.Group] = binding.Allow
		}
	}
	groups := map[string]bool{}
	for id := range a {
		groups[id] = true
	}
	for id := range b {
		groups[id] = true
	}
	changes := []ExecutionChange{}
	for id := range groups {
		old, oldOK := a[id]
		next, nextOK := b[id]
		if oldOK && nextOK && reflect.DeepEqual(old, next) {
			continue
		}
		action := "replace"
		if !oldOK {
			action = "add"
		}
		if !nextOK {
			action = "remove"
		}
		changes = append(changes, ExecutionChange{Action: action, GroupID: id, Before: old, After: next})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].GroupID < changes[j].GroupID })
	return changes
}
