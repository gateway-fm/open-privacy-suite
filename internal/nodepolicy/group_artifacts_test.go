package nodepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func groupArtifact(group string) PolicyArtifact {
	code := []byte{0x60, 0, 0x60, 0, 0xf3}
	h := sha256.Sum256(code)
	digest := hex.EncodeToString(h[:])
	return PolicyArtifact{OrgID: "org-a", GroupID: group, Revision: 1, PolicyDigest: digest, RuntimeDigest: digest, Bytecode: code}
}

func TestGroupArtifactDeltaRemovesReplacedGroupsAtomically(t *testing.T) {
	base := snapshotFixture()
	base.Policies = []PolicyArtifact{groupArtifact("payments"), groupArtifact("readers")}
	feed := new(Feed)
	require.NoError(t, applySigned(t, feed, testVerifier(), "snapshot", base))
	before, err := feed.Pin(time.Unix(1020, 0))
	require.NoError(t, err)
	next := cloneSnapshot(base)
	next.Version++
	next.Policies = next.Policies[:1]
	next.Policies[0].Revision++
	delta, err := BuildDelta(base, before.Digest(), next)
	require.NoError(t, err)
	require.Equal(t, []string{"org-a\x00readers"}, delta.Deletes.Policies)
	require.NoError(t, applySigned(t, feed, testVerifier(), "delta", delta))
	after, err := feed.Pin(time.Unix(1020, 0))
	require.NoError(t, err)
	require.Len(t, before.Snapshot().Policies, 2)
	require.Equal(t, next.Policies, after.Snapshot().Policies)
}

func TestGroupArtifactSetRejectsMixedRevisionsAndLegacyRows(t *testing.T) {
	for _, mutation := range []string{"revision", "document", "duplicate", "legacy"} {
		t.Run(mutation, func(t *testing.T) {
			s := snapshotFixture()
			s.Policies = []PolicyArtifact{groupArtifact("payments"), groupArtifact("readers")}
			switch mutation {
			case "revision":
				s.Policies[1].Revision++
			case "document":
				s.Policies[1].PolicyDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "duplicate":
				s.Policies[1].GroupID = "payments"
			case "legacy":
				s.Policies[1].GroupID = ""
			}
			_, err := Pin(s)
			require.Error(t, err)
		})
	}
	// Colons are legal identifiers: concatenating with ':' would collide here.
	require.NotEqual(t, policyKey(PolicyArtifact{OrgID: "a:b", GroupID: "c"}), policyKey(PolicyArtifact{OrgID: "a", GroupID: "b:c"}))
}

func TestGroupCandidateSimulationBindsTheCompleteReplacement(t *testing.T) {
	candidates := []PolicyArtifact{groupArtifact("payments"), groupArtifact("readers")}
	request := SimulationRequest{Method: "eth_call", Params: json.RawMessage(`[{"from":"0x1111111111111111111111111111111111111111"},"latest"]`), CandidatePolicies: &candidates}
	wire, err := EncodeSimulation(request)
	require.NoError(t, err)
	parsed, err := ParseSimulation(wire, SimulationHash(wire))
	require.NoError(t, err)
	require.Equal(t, candidates, *parsed.CandidatePolicies)
	candidates = candidates[:1]
	changed, err := EncodeSimulation(request)
	require.NoError(t, err)
	_, err = ParseSimulation(changed, SimulationHash(wire))
	require.Error(t, err, "removing a candidate artifact must invalidate the signed request binding")
	for _, mutation := range []string{"duplicate", "org", "revision", "legacy", "bytes"} {
		t.Run(mutation, func(t *testing.T) {
			candidates = []PolicyArtifact{groupArtifact("payments"), groupArtifact("readers")}
			switch mutation {
			case "duplicate":
				candidates[1].GroupID = candidates[0].GroupID
			case "org":
				candidates[1].OrgID = "other"
			case "revision":
				candidates[1].Revision++
			case "legacy":
				candidates[1].GroupID = ""
			case "bytes":
				candidates[1].Bytecode[0] ^= 1
			}
			_, err := EncodeSimulation(request)
			require.Error(t, err)
		})
	}
	candidates = []PolicyArtifact{}
	empty, err := EncodeSimulation(request)
	require.NoError(t, err)
	parsed, err = ParseSimulation(empty, SimulationHash(empty))
	require.NoError(t, err)
	require.NotNil(t, parsed.CandidatePolicies, "an empty replacement is distinct from no candidate")
}
