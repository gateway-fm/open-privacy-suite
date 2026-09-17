package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log/slog"
	"net/http"
	"os"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type nodeFactVersion interface {
	NodePolicyVersion(context.Context) (uint64, error)
}
type executionNodeClient interface {
	PolicyStatus(context.Context) (nodepolicy.NodeStatus, error)
	SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error)
	Simulate(context.Context, []byte, []byte) (json.RawMessage, error)
}
type nodeSubmissionStore interface {
	SaveNodeSubmission(context.Context, db.NodeSubmission) error
	MarkNodeSubmissionAccepted(context.Context, nodepolicy.Network, string) error
}
type nodeExecutionBridge struct {
	source   nodeFactVersion
	node     executionNodeClient
	signer   nodepolicy.Signer
	network  nodepolicy.Network
	lifetime time.Duration
	now      func() time.Time
}

func newNodeExecutionBridge(source nodeFactVersion, node executionNodeClient, signer nodepolicy.Signer, network nodepolicy.Network, lifetime time.Duration, now func() time.Time) (*nodeExecutionBridge, error) {
	if source == nil || node == nil || len(signer.PrivateKey) != ed25519.PrivateKeySize || signer.KeyID == "" || lifetime < time.Second || lifetime > nodepolicy.MaxMessageLifetime {
		return nil, nodepolicy.ErrIdentity
	}
	if now == nil {
		now = time.Now
	}
	return &nodeExecutionBridge{source: source, node: node, signer: signer, network: network, lifetime: lifetime, now: now}, nil
}
func (b *nodeExecutionBridge) readiness(ctx context.Context) (uint64, error) {
	version, _, err := b.executionStatus(ctx)
	return version, err
}
func (b *nodeExecutionBridge) executionStatus(ctx context.Context) (uint64, nodepolicy.NodeStatus, error) {
	version, err := b.source.NodePolicyVersion(ctx)
	if err != nil {
		return 0, nodepolicy.NodeStatus{}, nodepolicy.ErrNodeUnavailable
	}
	status, err := b.node.PolicyStatus(ctx)
	if err != nil {
		return version, status, err
	}
	if version == 0 || status.Network != b.network || status.ProtocolVersion != nodepolicy.ProtocolVersion {
		return version, status, nodepolicy.ErrNodeResponse
	}
	if status.Version > version {
		return version, status, nodepolicy.ErrFeedConflict
	}
	if err := status.RequireReady(b.now(), version); err != nil {
		return version, status, err
	}
	return version, status, nil
}

// handleReady reports whether execution can use current authoritative facts.
// @Summary Execution readiness
// @Description Returns 503 until the configured execution node has fresh policy facts matching the database. No private policy or identity data is returned.
// @Tags Health
// @Produce json
// @Success 200 {object} apimodels.ReadinessResponse
// @Failure 503 {object} apimodels.ReadinessResponse
// @Router /ready [get]
// @Router /ready [head]
func (s *Server) handleReady(c *gin.Context) {
	status := s.executionStatus(c.Request.Context())
	code, text := http.StatusOK, "ready"
	if !status.Ready {
		code, text = http.StatusServiceUnavailable, "not_ready"
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(code, apimodels.ReadinessResponse{Status: text})
}

func (s *Server) executionStatus(ctx context.Context) apimodels.ExecutionStatus {
	result := apimodels.ExecutionStatus{Mode: "legacy", Ready: true}
	if s.config == nil || !s.config.NodePolicy.Enabled() {
		return result
	}
	result.Mode, result.Ready, result.Reason = "reth", false, "execution_unavailable"
	if s.nodeExecution == nil {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	desired, node, err := s.nodeExecution.executionStatus(ctx)
	result.DesiredVersion, result.AppliedVersion, result.ExpiresAt = desired, node.Version, node.ExpiresAt
	if err == nil {
		result.Ready = true
		result.Reason = ""
	} else if desired > 0 && node.Version < desired {
		result.Reason = "publication_pending"
	} else if node.Version > desired && desired > 0 {
		result.Reason = "version_conflict"
	} else if node.ExpiresAt > 0 && node.ExpiresAt <= s.nodeExecution.now().Unix() {
		result.Reason = "facts_expired"
	}
	return result
}
func (b *nodeExecutionBridge) PrepareIdentity(ctx context.Context, request NodeExecutionIdentityRequest) ([]byte, error) {
	version, err := b.readiness(ctx)
	if err != nil {
		return nil, err
	}
	at := b.now()
	identity := nodepolicy.Identity{Header: nodepolicy.Header{Network: b.network, IssuedAt: at.Unix(), ExpiresAt: at.Add(b.lifetime).Unix()}, Scope: request.Scope, ContextID: uuid.NewString(), PrincipalID: request.PrincipalID, OrgID: request.OrgID, Signer: request.Signer, BindingHash: request.BindingHash, MinSnapshotVersion: version}
	wire, err := b.signer.Seal("identity", identity)
	if err != nil {
		return nil, err
	}
	// Validate internal caller input with the shared strict wire contract before
	// emitting an envelope. This does not make a permission decision.
	verifier := nodepolicy.Verifier{Network: b.network, Keys: map[string]ed25519.PublicKey{b.signer.KeyID: b.signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: b.now}
	if _, err := verifier.OpenIdentity(wire); err != nil {
		return nil, err
	}
	return wire, nil
}
func (b *nodeExecutionBridge) SubmitTransaction(ctx context.Context, identity []byte, raw string, metadata NodeSubmissionMetadata) (nodepolicy.Submission, error) {
	store, ok := b.source.(nodeSubmissionStore)
	if !ok {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	verifier := nodepolicy.Verifier{Network: b.network, Keys: map[string]ed25519.PublicKey{b.signer.KeyID: b.signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: b.now}
	i, err := verifier.OpenIdentity(identity)
	if err != nil || i.Scope != "transaction" {
		return nodepolicy.Submission{}, nodepolicy.ErrIdentity
	}
	intent := db.NodeSubmission{Network: b.network, TransactionHash: i.BindingHash, PrincipalID: i.PrincipalID, OrgID: i.OrgID, Signer: i.Signer, ContextID: i.ContextID, RawTransaction: raw, IdentityEnvelope: identity, SenderDID: metadata.SenderDID, VisibleTo: metadata.VisibleTo}
	if err := store.SaveNodeSubmission(ctx, intent); err != nil {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	submitted, err := b.node.SubmitTransaction(ctx, identity, raw)
	if err != nil {
		return nodepolicy.Submission{}, err
	}
	// The durable queued intent already guarantees recovery if this update
	// fails after the node accepted. Do not claim submission failed in that case.
	if err := store.MarkNodeSubmissionAccepted(ctx, b.network, i.BindingHash); err != nil {
		slog.Warn("node submission acknowledgement pending", "tx", i.BindingHash, "error", err)
	}
	return submitted, nil
}
func (b *nodeExecutionBridge) Simulate(ctx context.Context, identity, request []byte) (json.RawMessage, error) {
	return b.node.Simulate(ctx, identity, request)
}

func loadNodePolicySigner(c config.NodePolicyConfig) (nodepolicy.Signer, error) {
	file, err := os.Open(c.PrivateKeyFile)
	if err != nil {
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key file is unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key file is invalid")
	}
	encoded := strings.TrimSpace(string(raw))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(key) != encoded {
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key must be canonical base64")
	}
	switch len(key) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(key)
	case ed25519.PrivateKeySize:
		if !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
			return nodepolicy.Signer{}, fmt.Errorf("node policy signing key public half does not match its seed")
		}
	default:
		return nodepolicy.Signer{}, fmt.Errorf("node policy signing key must contain a 32-byte seed or 64-byte private key")
	}
	return nodepolicy.Signer{KeyID: c.KeyID, PrivateKey: ed25519.PrivateKey(key)}, nil
}
func (s *Server) initNodePolicy() error {
	c := s.config.NodePolicy
	if err := c.Validate(); err != nil {
		return err
	}
	if !c.Enabled() {
		return nil
	}
	signer, err := loadNodePolicySigner(c)
	if err != nil {
		return err
	}
	network := nodepolicy.Network{ChainID: c.ChainID, DeploymentID: c.DeploymentID}
	client, err := nodepolicy.NewClient(c.URL, c.Token, network, nil)
	if err != nil {
		return err
	}
	bridge, err := newNodeExecutionBridge(s.db, client, signer, network, c.IdentityTTL, nil)
	if err != nil {
		return err
	}
	publisher, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: c.ConsumerID, Signer: signer, Source: s.db, Node: client, Lifetime: c.FactTTL})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.nodeExecution = bridge
	s.nodePolicyCancel = cancel
	s.nodePolicyDone = make(chan struct{})
	go func() {
		defer close(s.nodePolicyDone)
		reconcilerDone := make(chan struct{})
		go func() { defer close(reconcilerDone); runNodeReconciler(ctx, s.db, client, network) }()
		_ = publisher.Run(ctx, c.PublishInterval, func(err error) {
			if ctx.Err() == nil {
				slog.Warn("node policy publication pending", "error", err)
			}
		})
		<-reconcilerDone
	}()
	return nil
}
