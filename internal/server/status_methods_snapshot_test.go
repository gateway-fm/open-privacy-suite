package server

import (
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
)

// RD-1262 — the /status methods block must not alias the live rbac method
// registries. Pre-fix, StatusResponse carried rbac.ExtraNamespaces (the
// package-global map) by reference and ExtraWildcardInfo.Deny aliased the
// registry's deny slice, so a consumer mutating the response (or the JSON
// encoder iterating concurrently with a hypothetical writer) touched global
// RBAC state.

func TestBuildExtraWildcardsResponse_DoesNotAliasDenyList(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()

	rbac.Wildcards = []*rbac.WildcardNamespace{{
		Namespace: "Linea",
		Prefix:    "linea_",
		Deny:      []string{"linea_sendTransaction"},
	}}

	out := buildExtraWildcardsResponse()
	if assert.Contains(t, out, "Linea") {
		info := out["Linea"]
		if assert.Len(t, info.Deny, 1) {
			info.Deny[0] = "mutated_by_consumer"
		}
	}

	assert.Equal(t, "linea_sendTransaction", rbac.Wildcards[0].Deny[0],
		"mutating the status response must not touch the rbac.Wildcards registry")
}

func TestSnapshotExtraNamespaces_DoesNotAliasRegistry(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()

	rbac.ExtraNamespaces = map[string][]string{
		"Linea": {"linea_estimateGas"},
	}

	out := snapshotExtraNamespaces()
	if assert.Contains(t, out, "Linea") {
		out["Linea"][0] = "mutated_by_consumer"
		out["NewNS"] = []string{"injected"}
	}

	assert.Equal(t, "linea_estimateGas", rbac.ExtraNamespaces["Linea"][0],
		"mutating the status response must not touch rbac.ExtraNamespaces")
	assert.NotContains(t, rbac.ExtraNamespaces, "NewNS",
		"adding to the status response must not touch rbac.ExtraNamespaces")
}

func TestSnapshotExtraNamespaces_EmptyStaysOmitted(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()

	rbac.ExtraNamespaces = nil
	assert.Nil(t, snapshotExtraNamespaces(),
		"nil registry must stay nil so the JSON field keeps its omitempty behavior")
}
