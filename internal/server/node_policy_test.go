package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/nodepolicy"
	"strings"
	"testing"
	"time"
)

type nodeVersionFixture struct {
	version uint64
	err     error
}

func (f nodeVersionFixture) NodePolicyVersion(context.Context) (uint64, error) {
	return f.version, f.err
}

type nodeClientFixture struct {
	status nodepolicy.NodeStatus
	err    error
}

func (f nodeClientFixture) PolicyStatus(context.Context) (nodepolicy.NodeStatus, error) {
	return f.status, f.err
}
func (f nodeClientFixture) SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error) {
	return nodepolicy.Submission{}, f.err
}
func (f nodeClientFixture) Simulate(context.Context, []byte, []byte) (json.RawMessage, error) {
	return nil, f.err
}

func TestNodeIdentityBridgeRequiresCurrentFactsAndExactNetwork(t *testing.T) {
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "bridge-test"}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	status := nodepolicy.NodeStatus{ProtocolVersion: 1, Network: network, Capabilities: nodepolicy.RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1060, Ready: true}
	request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: "user-a", OrgID: "org-a", Signer: "0x" + strings.Repeat("11", 20), BindingHash: "0x" + strings.Repeat("22", 32)}
	clock := func() time.Time { return time.Unix(1020, 0) }
	bridge, err := newNodeExecutionBridge(nodeVersionFixture{version: 7}, nodeClientFixture{status: status}, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: key}, network, time.Minute, clock)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := bridge.PrepareIdentity(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	v := nodepolicy.Verifier{Network: network, Keys: map[string]ed25519.PublicKey{"ops-a": key.Public().(ed25519.PublicKey)}, Now: clock}
	i, err := v.OpenIdentity(wire)
	if err != nil {
		t.Fatal(err)
	}
	if i.PrincipalID != request.PrincipalID || i.OrgID != request.OrgID || i.BindingHash != request.BindingHash || i.MinSnapshotVersion != 7 || i.ContextID == "" || i.ExpiresAt != 1080 {
		t.Fatalf("identity was not exact: %+v", i)
	}
	for _, what := range []string{"lag", "ahead", "stale", "not_ready", "network", "capability", "protocol", "database", "transport"} {
		t.Run(what, func(t *testing.T) {
			versions := nodeVersionFixture{version: 7}
			node := nodeClientFixture{status: status}
			switch what {
			case "lag":
				versions.version++
			case "ahead":
				node.status.Version++
			case "stale":
				node.status.ExpiresAt = 1020
			case "not_ready":
				node.status.Ready = false
			case "network":
				node.status.Network.DeploymentID = "elsewhere"
			case "capability":
				node.status.Capabilities = []string{"signed_identity_v1"}
			case "protocol":
				node.status.ProtocolVersion++
			case "database":
				versions.err = errors.New("database unavailable")
			case "transport":
				node.err = nodepolicy.ErrNodeUnavailable
			}
			b, err := newNodeExecutionBridge(versions, node, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: key}, network, time.Minute, clock)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.PrepareIdentity(context.Background(), request); err == nil {
				t.Fatal("identity minted without ready authoritative facts")
			}
		})
	}
}

func TestNodeReadinessNeverReportsUnavailableFactsAsReady(t *testing.T) {
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "ready-test"}
	status := nodepolicy.NodeStatus{ProtocolVersion: 1, Network: network, Capabilities: nodepolicy.RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1060, Ready: true}
	for _, test := range []string{"legacy", "ready", "lag", "expired", "unavailable", "unwired"} {
		t.Run(test, func(t *testing.T) {
			s := &Server{config: &config.Config{NodePolicy: config.NodePolicyConfig{Mode: "reth"}}}
			node := nodeClientFixture{status: status}
			switch test {
			case "legacy":
				s.config.NodePolicy.Mode = "legacy"
			case "lag":
				node.status.Version--
			case "expired":
				node.status.ExpiresAt = 1020
			case "unavailable":
				node.err = errors.New("secret private URL and credentials")
			}
			if test != "unwired" {
				s.nodeExecution = &nodeExecutionBridge{source: nodeVersionFixture{version: 7}, node: node, network: network, now: func() time.Time { return time.Unix(1020, 0) }}
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/ready", nil)
			s.handleReady(c)
			want := http.StatusServiceUnavailable
			if test == "legacy" || test == "ready" {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "version") {
				t.Fatal("public readiness disclosed private state")
			}
		})
	}
}
