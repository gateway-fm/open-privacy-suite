package server

import (
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
)

// RD-1262 — the /status methods block must not alias the live rbac method
// registries. Pre-fix, apimodels.StatusResponse carried rbac.ExtraNamespaces (the
// package-global map) by reference, so a consumer mutating the response (or the
// JSON encoder iterating concurrently with a hypothetical writer) touched global
// RBAC state.

func TestBuildExtraPassthroughResponse_SortedAndDoesNotAliasRegistry(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()

	rbac.PassthroughMethods = map[string]bool{"trace_block": true, "linea_getTransactionExclusionStatusV1": true}

	out := buildExtraPassthroughResponse()
	assert.Equal(t, []string{"linea_getTransactionExclusionStatusV1", "trace_block"}, out, "sorted for a stable UI")
	out[0] = "mutated_by_consumer"
	assert.True(t, rbac.PassthroughMethods["linea_getTransactionExclusionStatusV1"],
		"mutating the status response must not touch rbac.PassthroughMethods")
	assert.False(t, rbac.PassthroughMethods["mutated_by_consumer"])

	rbac.PassthroughMethods = map[string]bool{}
	assert.Nil(t, buildExtraPassthroughResponse(), "no passthrough methods → field omitted")
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
