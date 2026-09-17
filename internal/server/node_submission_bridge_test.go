package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

type nodeSubmitSource struct {
	saved           *db.NodeSubmission
	saveErr, ackErr error
	accepted        bool
}

func (s *nodeSubmitSource) NodePolicyVersion(context.Context) (uint64, error) { return 7, nil }
func (s *nodeSubmitSource) SaveNodeSubmission(_ context.Context, in db.NodeSubmission) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = &in
	return nil
}
func (s *nodeSubmitSource) MarkNodeSubmissionAccepted(context.Context, nodepolicy.Network, string) error {
	s.accepted = true
	return s.ackErr
}

type nodeSubmitClient struct {
	nodeClientFixture
	source    *nodeSubmitSource
	calls     int
	submitErr error
}

func (n *nodeSubmitClient) SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error) {
	n.calls++
	if n.source.saved == nil {
		return nodepolicy.Submission{}, errors.New("node called before durable intent")
	}
	if n.submitErr != nil {
		return nodepolicy.Submission{}, n.submitErr
	}
	return nodepolicy.Submission{TransactionHash: n.source.saved.TransactionHash, ContextID: n.source.saved.ContextID, Status: "accepted"}, nil
}
func TestNodeSubmissionBridgePersistsBeforeTransportAndPreservesAmbiguousAcknowledgement(t *testing.T) {
	for _, test := range []string{"success", "save_failure", "lost_ack", "ack_write_failure"} {
		t.Run(test, func(t *testing.T) {
			source := &nodeSubmitSource{}
			network := nodepolicy.Network{ChainID: 31337, DeploymentID: "bridge-test"}
			node := &nodeSubmitClient{source: source, nodeClientFixture: nodeClientFixture{status: nodepolicy.NodeStatus{ProtocolVersion: 1, Network: network, Capabilities: nodepolicy.RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1060, Ready: true}}}
			switch test {
			case "save_failure":
				source.saveErr = errors.New("db unavailable")
			case "lost_ack":
				node.submitErr = nodepolicy.ErrNodeUnavailable
			case "ack_write_failure":
				source.ackErr = errors.New("db unavailable")
			}
			bridge, err := newNodeExecutionBridge(source, node, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, func() time.Time { return time.Unix(1020, 0) })
			if err != nil {
				t.Fatal(err)
			}
			request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: uuid.NewString(), OrgID: uuid.NewString(), Signer: "0x" + strings.Repeat("11", 20), BindingHash: "0x" + strings.Repeat("22", 32)}
			wire, err := bridge.PrepareIdentity(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = bridge.SubmitTransaction(context.Background(), wire, "0x01", NodeSubmissionMetadata{SenderDID: "did:test:author", VisibleTo: []string{"did:test:recipient"}})
			if test == "save_failure" {
				if err == nil || node.calls != 0 {
					t.Fatal("submission escaped without durable intent")
				}
				return
			}
			if source.saved == nil || source.saved.PrincipalID != request.PrincipalID || len(source.saved.VisibleTo) != 1 || node.calls != 1 {
				t.Fatal("durable recovery metadata lost")
			}
			if test == "lost_ack" {
				if err == nil || source.accepted {
					t.Fatal("ambiguous transport was claimed accepted")
				}
				return
			}
			if err != nil || !source.accepted {
				t.Fatalf("accepted transaction incorrectly reported failed: %v", err)
			}
		})
	}
}
