package nodepolicy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const MaxNodeResponseBytes = 16 << 20

var (
	ErrNodeUnavailable = errors.New("private execution node is unavailable")
	ErrNodeResponse    = errors.New("invalid private execution node response")
	ErrNodeRejected    = errors.New("private execution node rejected request")
	ErrNodeResync      = errors.New("private execution node requires a full fact snapshot")
)

type AppliedState struct {
	Version   uint64 `json:"version"`
	Digest    string `json:"digest"`
	ExpiresAt int64  `json:"expires_at"`
}
type NodeStatus struct {
	ProtocolVersion int      `json:"protocol_version"`
	Network         Network  `json:"network"`
	Capabilities    []string `json:"capabilities"`
	Version         uint64   `json:"version"`
	Digest          string   `json:"digest"`
	ExpiresAt       int64    `json:"expires_at"`
	Ready           bool     `json:"ready"`
	Reason          string   `json:"reason"`
}
type Submission struct {
	TransactionHash string `json:"transaction_hash"`
	ContextID       string `json:"context_id"`
	Status          string `json:"status"`
}

func RequiredCapabilities() []string {
	return []string{"per_frame_a5", "signed_identity_v1", "fact_stream_v1", "simulation_v1", "archive_v1", "candidate_simulation_v1", "scoped_diagnostics_v1", "finalized_status_v1"}
}
func (s NodeStatus) RequireReady(at time.Time, version uint64) error {
	if !s.Ready || s.Version < version || s.ExpiresAt <= at.Unix() {
		return ErrSnapshotLag
	}
	for _, capability := range RequiredCapabilities() {
		if !slices.Contains(s.Capabilities, capability) {
			return ErrNodeResponse
		}
	}
	return nil
}

// Client talks exclusively to the configured private listener. It never follows
// redirects, so a misrouted response cannot forward the service credential.
type Client struct {
	endpoint string
	token    string
	network  Network
	http     *http.Client
	sequence atomic.Uint64
}

func NewClient(endpoint, token string, network Network, client *http.Client) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") || network.ChainID == 0 || !identifier(network.DeploymentID) {
		return nil, ErrEnvelope
	}
	copyClient := http.Client{Timeout: 15 * time.Second}
	if client != nil {
		copyClient = *client
		if copyClient.Timeout <= 0 {
			copyClient.Timeout = 15 * time.Second
		}
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: endpoint, token: token, network: network, http: &copyClient}, nil
}

func (c *Client) PolicyStatus(ctx context.Context) (NodeStatus, error) {
	var out NodeStatus
	raw, err := c.call(ctx, "ops_policyStatus", []any{})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return NodeStatus{}, ErrNodeResponse
	}
	if out.ProtocolVersion != ProtocolVersion || out.Network != c.network || (out.Version == 0 && (out.Digest != "" || out.ExpiresAt != 0 || out.Ready)) || (out.Version > 0 && (!hexDigest(out.Digest) || out.ExpiresAt <= 0)) {
		return NodeStatus{}, ErrNodeResponse
	}
	return out, nil
}
func (c *Client) ApplyPolicy(ctx context.Context, wire []byte) (AppliedState, error) {
	var out AppliedState
	if len(wire) == 0 || len(wire) > MaxEnvelopeBytes || !json.Valid(wire) {
		return out, ErrEnvelope
	}
	raw, err := c.call(ctx, "ops_policyApply", []any{json.RawMessage(wire)})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil || out.Version == 0 || !hexDigest(out.Digest) || out.ExpiresAt <= 0 {
		return AppliedState{}, ErrNodeResponse
	}
	return out, nil
}
func (c *Client) SubmitTransaction(ctx context.Context, identity []byte, rawTx string) (Submission, error) {
	var out Submission
	if len(identity) == 0 || len(identity) > MaxIdentityBytes || !json.Valid(identity) || len(rawTx) < 4 || !strings.HasPrefix(rawTx, "0x") {
		return out, ErrIdentity
	}
	txBytes, err := hex.DecodeString(rawTx[2:])
	if err != nil {
		return out, ErrIdentity
	}
	var envelope Envelope
	var submitted Identity
	if decodeStrict(identity, &envelope) != nil || envelope.Kind != "identity" || decodeStrict(envelope.Payload, &submitted) != nil || submitted.Scope != "transaction" || submitted.Network != c.network {
		return out, ErrIdentity
	}
	var transaction types.Transaction
	if transaction.UnmarshalBinary(txBytes) != nil {
		return out, ErrIdentity
	}
	// A pooled blob sidecar wraps the signed consensus envelope; its bytes
	// are deliberately excluded from the Ethereum transaction hash.
	expectedHash := transaction.Hash().Hex()
	if submitted.BindingHash != expectedHash {
		return out, ErrIdentity
	}
	raw, err := c.call(ctx, "ops_submitTransaction", []any{json.RawMessage(identity), rawTx})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil || out.TransactionHash != expectedHash || out.ContextID != submitted.ContextID || !identifier(out.ContextID) || out.Status != "accepted" {
		return Submission{}, ErrNodeResponse
	}
	return out, nil
}
func (c *Client) Simulate(ctx context.Context, identity, request []byte) (json.RawMessage, error) {
	if len(identity) == 0 || len(identity) > MaxIdentityBytes || !json.Valid(identity) {
		return nil, ErrIdentity
	}
	var envelope Envelope
	var submitted Identity
	if decodeStrict(identity, &envelope) != nil || envelope.Kind != "identity" || decodeStrict(envelope.Payload, &submitted) != nil || submitted.Scope != "simulation" || submitted.Network != c.network || submitted.BindingHash != SimulationHash(request) {
		return nil, ErrIdentity
	}
	parsed, err := ParseSimulation(request, submitted.BindingHash)
	if err != nil {
		return nil, err
	}
	if parsed.CandidatePolicies != nil {
		for _, candidate := range *parsed.CandidatePolicies {
			if candidate.OrgID != submitted.OrgID {
				return nil, ErrIdentity
			}
		}
	}
	if parsed.CandidatePolicy != nil && parsed.CandidatePolicy.OrgID != submitted.OrgID {
		return nil, ErrIdentity
	}
	var params map[string]json.RawMessage
	// Only the first parameter is an object; the block selector/tracer options
	// are checked by ParseSimulation and the node's method-specific parser.
	var values []json.RawMessage
	if json.Unmarshal(parsed.Params, &values) != nil || len(values) == 0 || json.Unmarshal(values[0], &params) != nil {
		return nil, ErrIdentity
	}
	var from string
	if json.Unmarshal(params["from"], &from) != nil || from != submitted.Signer {
		return nil, ErrIdentity
	}
	return c.call(ctx, "ops_simulate", []any{json.RawMessage(identity), base64.StdEncoding.EncodeToString(request)})
}
func (c *Client) call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	id := "ops-" + strconv.FormatUint(c.sequence.Add(1), 10)
	body, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"2.0", id, method, params})
	if err != nil || len(body) > MaxEnvelopeBytes+4096 {
		return nil, ErrEnvelope
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrNodeUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrNodeUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrNodeUnavailable
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, MaxNodeResponseBytes+1))
	if err != nil || len(response) > MaxNodeResponseBytes {
		return nil, ErrNodeResponse
	}
	d := json.NewDecoder(bytes.NewReader(response))
	d.UseNumber()
	if err := uniqueValue(d, 0); err != nil {
		return nil, ErrNodeResponse
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrNodeResponse
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response, &fields); err != nil {
		return nil, ErrNodeResponse
	}
	for key := range fields {
		if key != "jsonrpc" && key != "id" && key != "result" && key != "error" {
			return nil, ErrNodeResponse
		}
	}
	var version, responseID string
	if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" || json.Unmarshal(fields["id"], &responseID) != nil || responseID != id {
		return nil, ErrNodeResponse
	}
	result, hasResult := fields["result"]
	rpcError, hasError := fields["error"]
	if hasResult == hasError {
		return nil, ErrNodeResponse
	}
	if hasError {
		var value struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(rpcError, &value); err != nil {
			return nil, ErrNodeResponse
		}
		// Node diagnostics belong to its private operator logs, never responses
		// proxied to ordinary users or error messages containing request data.
		if value.Code == -32011 {
			return nil, ErrNodeResync
		}
		return nil, fmt.Errorf("%w (code %d)", ErrNodeRejected, value.Code)
	}
	return result, nil
}
