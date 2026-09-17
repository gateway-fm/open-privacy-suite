package nodepolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"time"
)

type FactSource interface {
	NodePolicyVersion(context.Context) (uint64, error)
	ExportNodePolicySnapshot(context.Context, Network, time.Time, time.Duration) (Snapshot, error)
	AcknowledgeNodePolicy(context.Context, string, AppliedState) error
}
type FactNode interface {
	PolicyStatus(context.Context) (NodeStatus, error)
	ApplyPolicy(context.Context, []byte) (AppliedState, error)
}
type PublisherConfig struct {
	Network    Network
	ConsumerID string
	Signer     Signer
	Source     FactSource
	Node       FactNode
	Lifetime   time.Duration
	Now        func() time.Time
}
type Publisher struct {
	mu         sync.Mutex
	config     PublisherConfig
	last       *Snapshot
	lastDigest string
	deltaCount int
	deltaBytes int
}

// Keep replay checkpoints comfortably below the node's signed-history bounds.
const maxCheckpointDeltas = 128
const maxCheckpointDeltaBytes = 128 << 20

func NewPublisher(config PublisherConfig) (*Publisher, error) {
	if config.Source == nil || config.Node == nil || config.Network.ChainID == 0 || !identifier(config.Network.DeploymentID) || !identifier(config.ConsumerID) || !identifier(config.Signer.KeyID) || len(config.Signer.PrivateKey) != ed25519.PrivateKeySize || config.Lifetime < time.Second || config.Lifetime > MaxMessageLifetime {
		return nil, ErrEnvelope
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Publisher{config: config}, nil
}

// Tick publishes at most one coherent generation, then persists only its exact
// node acknowledgement. A failed/ambiguous send is recovered by the next status
// read; it is never recorded as applied based on a returned transaction hash.
func (p *Publisher) Tick(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.config
	version, err := c.Source.NodePolicyVersion(ctx)
	if err != nil {
		return err
	}
	if version == 0 {
		return ErrSnapshot
	}
	status, err := c.Node.PolicyStatus(ctx)
	if err != nil {
		return err
	}
	if status.ProtocolVersion != ProtocolVersion || status.Network != c.Network || !slices.Contains(status.Capabilities, "fact_stream_v1") {
		return ErrNodeResponse
	}
	if status.Version > version {
		return ErrFeedConflict
	}
	at := c.Now()
	header := Header{Network: c.Network, IssuedAt: at.Unix(), ExpiresAt: at.Add(c.Lifetime).Unix()}
	var kind string
	var payload any
	var snapshot *Snapshot
	var expected AppliedState
	if status.Version == version {
		if !hexDigest(status.Digest) {
			return ErrNodeResponse
		}
		kind = "heartbeat"
		payload = Heartbeat{Header: header, Version: version, Digest: status.Digest}
		expected = AppliedState{Version: version, Digest: status.Digest, ExpiresAt: header.ExpiresAt}
	} else {
		exported, err := c.Source.ExportNodePolicySnapshot(ctx, c.Network, at, c.Lifetime)
		if err != nil {
			return err
		}
		if exported.Version < version || exported.Version <= status.Version || exported.Header != header {
			return ErrSnapshot
		}
		if _, err := Pin(exported); err != nil {
			return err
		}
		snapshot = &exported
		kind, payload = "snapshot", exported
		if p.last != nil && p.last.Version == status.Version && p.lastDigest == status.Digest && p.deltaCount < maxCheckpointDeltas && p.deltaBytes < maxCheckpointDeltaBytes {
			delta, err := BuildDelta(*p.last, p.lastDigest, exported)
			if err != nil {
				return err
			}
			kind, payload = "delta", delta
		}
		expected = AppliedState{Version: exported.Version, ExpiresAt: header.ExpiresAt}
	}
	wire, err := c.Signer.Seal(kind, payload)
	if err != nil {
		return err
	}
	if kind == "delta" && p.deltaBytes+len(wire) > maxCheckpointDeltaBytes {
		kind = "snapshot"
		wire, err = c.Signer.Seal(kind, *snapshot)
		if err != nil {
			return err
		}
	}
	if kind != "heartbeat" {
		var envelope Envelope
		if err := decodeStrict(wire, &envelope); err != nil {
			return err
		}
		expected.Digest = PayloadDigest(envelope.Payload)
	}
	ack, err := c.Node.ApplyPolicy(ctx, wire)
	if errors.Is(err, ErrNodeResync) && kind == "delta" {
		// The rejected delta never advanced the node. Replace it with this
		// same coherent, strictly newer database generation.
		kind = "snapshot"
		wire, err = c.Signer.Seal(kind, *snapshot)
		if err != nil {
			return err
		}
		var envelope Envelope
		if err := decodeStrict(wire, &envelope); err != nil {
			return err
		}
		expected.Digest = PayloadDigest(envelope.Payload)
		ack, err = c.Node.ApplyPolicy(ctx, wire)
	}
	if err != nil {
		return err
	}
	if ack.Version != expected.Version || ack.Digest != expected.Digest || ack.ExpiresAt < expected.ExpiresAt {
		return ErrNodeResponse
	}
	if err := c.Source.AcknowledgeNodePolicy(ctx, c.ConsumerID, ack); err != nil {
		return err
	}
	if snapshot != nil {
		p.last = snapshot
		p.lastDigest = ack.Digest
		if kind == "snapshot" {
			p.deltaCount, p.deltaBytes = 0, 0
		} else {
			p.deltaCount++
			p.deltaBytes += len(wire)
		}
	}
	return nil
}

// Run keeps retrying through transient outages. The node's lease enforces the
// staleness bound while unavailable; errors are reported without hiding them.
func (p *Publisher) Run(ctx context.Context, interval time.Duration, report func(error)) error {
	if interval <= 0 || interval > p.config.Lifetime/3 {
		return errors.New("fact publish interval exceeds freshness budget")
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		err := p.Tick(ctx)
		if err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
