package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/policydsl"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
)

type previewNode struct {
	source  nodeFactVersion
	network nodepolicy.Network
	calls   int
	request nodepolicy.SimulationRequest
	result  json.RawMessage
}

func (n *previewNode) PolicyStatus(ctx context.Context) (nodepolicy.NodeStatus, error) {
	v, err := n.source.NodePolicyVersion(ctx)
	return nodepolicy.NodeStatus{ProtocolVersion: 1, Network: n.network, Version: v, Digest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Minute).Unix(), Ready: true, Capabilities: nodepolicy.RequiredCapabilities()}, err
}
func (n *previewNode) SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error) {
	panic("preview must never submit")
}
func (n *previewNode) Simulate(_ context.Context, _ []byte, b []byte) (json.RawMessage, error) {
	n.calls++
	if err := json.Unmarshal(b, &n.request); err != nil {
		return nil, err
	}
	if n.result != nil {
		return n.result, nil
	}
	return json.RawMessage(`{"result":"0x","policy":{"would_allow":false,"decisions":[]}}`), nil
}

func TestNodeSimulationDiagnosticRequiresNamedHumanAndSelectedOrg(t *testing.T) {
	for _, actor := range []string{"human", "legacy", "service", "readonly", "bootstrap", "foreign_target", "strict", "strict_legacy", "strict_trace", "strict_legacy_send"} {
		t.Run(actor, func(t *testing.T) {
			f := configurationAPI(t)
			s := f.server
			s.config.ReadProfile = rbac.ReadProfileStandard
			if strings.HasPrefix(actor, "strict") {
				s.config.ReadProfile = rbac.ReadProfileStrict
			}
			network := nodepolicy.Network{ChainID: 31337, DeploymentID: "preview-test"}
			s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: network.ChainID, DeploymentID: network.DeploymentID}
			s.rateLimiter = middleware.NewRateLimiter(middleware.RateLimiterCleanupInterval)
			t.Cleanup(s.rateLimiter.Stop)
			s.rbacAccessCtrl = rbac.NewAccessController(s.db, time.Second)
			t.Cleanup(s.rbacAccessCtrl.Stop)
			n := &previewNode{source: s.db, network: network}
			var err error
			s.nodeExecution, err = newNodeExecutionBridge(s.db, n, nodepolicy.Signer{KeyID: "test", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, nil)
			require.NoError(t, err)
			target, err := s.db.GetUser(t.Context(), f.readonlyUserID)
			require.NoError(t, err)
			address := "0x" + strings.Repeat("11", 20)
			require.NoError(t, s.db.SystemLinkEthAddress(t.Context(), target.ExternalID, address))
			_, err = s.db.Conn().ExecContext(t.Context(), `UPDATE users SET banned=true WHERE id=$1`, target.ID)
			require.NoError(t, err)
			token := f.admin
			want := http.StatusOK
			switch actor {
			case "service":
				token = f.service
				want = http.StatusForbidden
			case "readonly":
				token = f.readonly
				want = http.StatusForbidden
			case "bootstrap":
				token = ""
				want = http.StatusUnauthorized
			case "foreign_target":
				target.ID = "00000000-0000-0000-0000-000000000001"
				want = http.StatusNotFound
			case "strict", "strict_legacy":
				want = http.StatusForbidden
			}
			path := "/api/v1/admin/orgs/" + f.orgID + "/execution/simulate"
			body := map[string]any{"principalId": target.ID, "method": "eth_call", "params": []any{map[string]any{"from": address, "to": address}, "latest"}, "dryRun": true}
			if actor == "strict_trace" {
				body["method"] = "debug_traceCall"
			}
			if actor == "legacy" || actor == "strict_legacy" || actor == "strict_legacy_send" {
				path = "/api/v1/admin/orgs/" + f.orgID + "/dry-run"
				method, params := "eth_call", body["params"]
				if actor == "strict_legacy_send" {
					method, params = "eth_sendTransaction", []any{map[string]any{"from": address, "to": address}}
				}
				body = map[string]any{"user_did": target.ExternalID, "rpc": map[string]any{"method": method, "params": params}}
			}
			response := f.request(t, token, http.MethodPost, path, body)
			require.Equal(t, want, response.Code, response.Body.String())
			if want == http.StatusOK {
				if actor == "strict_trace" {
					require.JSONEq(t, `{"result":null,"policy":{"would_allow":false}}`, response.Body.String())
				}
				if actor == "strict_legacy_send" {
					require.JSONEq(t, `{"decision":"deny"}`, response.Body.String())
				}
				require.Equal(t, 1, n.calls)
				require.True(t, n.request.DryRun)
				var count int
				require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT count(*) FROM rbac_audit_log WHERE action='execution.simulate' AND org_id=$1`, f.orgID).Scan(&count))
				require.Equal(t, 1, count)
			} else {
				require.Zero(t, n.calls)
			}
		})
	}
}

func TestRethModeClosesLegacyExecutionWritersAndReferenceSimulation(t *testing.T) {
	f := configurationAPI(t)
	f.server.config.NodePolicy = config.NodePolicyConfig{Mode: "reth"}
	base := "/api/v1/admin/orgs/" + f.orgID + "/execution-policy/revisions"
	for _, suffix := range []string{"", "/00000000-0000-0000-0000-000000000001/activate", "/00000000-0000-0000-0000-000000000001/simulate"} {
		response := f.request(t, f.admin, http.MethodPost, base+suffix, map[string]any{})
		require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
		require.Contains(t, response.Body.String(), "configuration")
	}

	// Withdrawing a leftover legacy draft is not closed by the mode switch. It
	// only abandons a draft that enforces nothing and can never be published
	// (the node-policy feed marks active rows only), so drafts left behind can
	// still be cleaned up while the organisation's execution-rules stream is
	// unmanaged. Reads stay open for the same reason.
	artifact := &policydsl.Artifact{PolicyDigest: "policy", Source: "contract Policy {}", SourceDigest: "source", RuntimeBytecode: []byte{0}, RuntimeDigest: "runtime"}
	leftover, err := f.server.db.CreateExecutionPolicyRevision(t.Context(), f.orgID, 0, "{}", artifact, &f.readonlyUserID)
	require.NoError(t, err)
	abandoned, err := f.server.db.CreateExecutionPolicyRevision(t.Context(), f.orgID, 0, "{}", artifact, &f.readonlyUserID)
	require.NoError(t, err)
	response := f.request(t, f.admin, http.MethodPost, base+"/"+abandoned.ID+"/activate", map[string]any{})
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	response = f.request(t, f.admin, http.MethodGet, base+"/"+abandoned.ID, nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	response = f.request(t, f.admin, http.MethodPost, base+"/"+abandoned.ID+"/withdraw", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"status":"withdrawn"`)
	response = f.request(t, f.admin, http.MethodPost, base+"/"+abandoned.ID+"/withdraw", nil)
	require.Equal(t, http.StatusNotFound, response.Code, "a withdrawn draft is no longer a draft: %s", response.Body.String())

	// Once the organisation's execution rules are a managed stream, the same
	// guard that closes every legacy writer closes withdraw too: the draft
	// left behind stays readable but can no longer be touched here.
	rules := "/api/v1/admin/orgs/" + f.orgID + "/configuration/execution-rules"
	response = f.request(t, f.readonly, http.MethodGet, rules+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var rulesContext apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &rulesContext))
	response = f.request(t, f.readonly, http.MethodPost, rules+"/revisions", rulesContext.Source)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var rulesDraft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &rulesDraft))
	response = f.request(t, f.reviewer, http.MethodPost, rules+"/revisions/"+rulesDraft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	response = f.request(t, f.admin, http.MethodPost, base+"/"+leftover.ID+"/withdraw", nil)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "managed stream")
	response = f.request(t, f.admin, http.MethodGet, base+"/"+leftover.ID, nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}

func TestNodeCandidatePreviewAllowsReadonlySelfAndNeverImpersonation(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "candidate-test"}
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: network.ChainID, DeploymentID: network.DeploymentID}
	s.rateLimiter = middleware.NewRateLimiter(middleware.RateLimiterCleanupInterval)
	t.Cleanup(s.rateLimiter.Stop)
	s.rbacAccessCtrl = rbac.NewAccessController(s.db, time.Second)
	t.Cleanup(s.rbacAccessCtrl.Stop)
	n := &previewNode{source: s.db, network: network}
	var err error
	s.nodeExecution, err = newNodeExecutionBridge(s.db, n, nodepolicy.Signer{KeyID: "test", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, nil)
	require.NoError(t, err)
	user, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	_, err = s.db.Conn().ExecContext(t.Context(), `UPDATE users SET kyc=true WHERE id=$1`, user.ID)
	require.NoError(t, err)
	address := "0x" + strings.Repeat("11", 20)
	require.NoError(t, s.db.SystemLinkEthAddress(t.Context(), user.ExternalID, address))
	base := "/api/v1/admin/orgs/" + f.orgID + "/configuration/execution-rules"
	contextResponse := f.request(t, f.readonly, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, contextResponse.Code, contextResponse.Body.String())
	var contextView apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(contextResponse.Body.Bytes(), &contextView))
	response := f.request(t, f.readonly, http.MethodPost, base+"/revisions", contextView.Source)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	path := "/api/v1/admin/orgs/" + f.orgID + "/execution/simulate"
	request := map[string]any{"candidateRevisionId": draft.ID, "method": "eth_call", "params": []any{map[string]any{"from": address}, "latest"}, "dryRun": false, "principalId": "00000000-0000-0000-0000-000000000001"}
	response = f.request(t, f.readonly, http.MethodPost, path, request)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	require.Zero(t, n.calls)
	delete(request, "principalId")
	response = f.request(t, f.readonly, http.MethodPost, path, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, 1, n.calls)
	require.False(t, n.request.DryRun)
	require.Nil(t, n.request.CandidatePolicy)
	require.NotNil(t, n.request.CandidatePolicies)
	for _, candidate := range *n.request.CandidatePolicies {
		require.Equal(t, f.orgID, candidate.OrgID)
		require.NotEmpty(t, candidate.GroupID)
	}
	request["dryRun"] = true
	response = f.request(t, f.readonly, http.MethodPost, path, request)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	require.Equal(t, 1, n.calls)

	// Previewing one's own trace, including a stored candidate, keeps the
	// same nested-value privacy as the public RPC. A permitted execution is
	// not permission to read the callee's private storage.
	s.rateLimiter = &noopRateLimiter{} // These requests test visibility, not throttling.
	_, err = s.db.Conn().ExecContext(t.Context(), `UPDATE group_access SET allowed_methods=ARRAY['eth_call','debug_traceCall'] WHERE group_id IN (SELECT group_id FROM user_memberships WHERE user_id=$1)`, user.ID)
	require.NoError(t, err)
	require.NoError(t, s.rbacAccessCtrl.InvalidateUser(t.Context(), user.ID))
	trace := json.RawMessage(`{"type":"CALL","from":"` + address + `","to":"` + address + `","input":"0x1234","calls":[{"type":"CALL","from":"` + address + `","to":"0x2222222222222222222222222222222222222222","input":"0xdeadbeef","output":"0xabcdef"}]}`)
	request["dryRun"], request["method"] = false, "debug_traceCall"
	for _, candidate := range []bool{true, false} {
		if candidate {
			n.result, err = json.Marshal(map[string]any{"result": trace, "policy": map[string]any{"would_allow": true}})
			require.NoError(t, err)
		} else {
			delete(request, "candidateRevisionId")
			n.result = trace
		}
		response = f.request(t, f.readonly, http.MethodPost, path, request)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		require.Contains(t, response.Body.String(), "0x1234")
		require.NotContains(t, response.Body.String(), "0xdeadbeef")
		require.NotContains(t, response.Body.String(), "0xabcdef")
	}
}

func TestNodeDryRunSendAppliesCompliancePreview(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	s.config.ReadProfile = rbac.ReadProfileStandard
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "preview-test"}
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: network.ChainID, DeploymentID: network.DeploymentID}
	s.rateLimiter = middleware.NewRateLimiter(middleware.RateLimiterCleanupInterval)
	t.Cleanup(s.rateLimiter.Stop)
	s.rbacAccessCtrl = rbac.NewAccessController(s.db, time.Second)
	t.Cleanup(s.rbacAccessCtrl.Stop)
	n := &previewNode{source: s.db, network: network, result: json.RawMessage(`{"result":{"type":"CALL"},"policy":{"would_allow":true,"decisions":[]}}`)}
	var err error
	s.nodeExecution, err = newNodeExecutionBridge(s.db, n, nodepolicy.Signer{KeyID: "test", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, nil)
	require.NoError(t, err)
	target, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	from := "0x" + strings.Repeat("11", 20)
	sanctioned := "0x" + strings.Repeat("22", 20)
	require.NoError(t, s.db.SystemLinkEthAddress(t.Context(), target.ExternalID, from))
	require.NoError(t, s.db.UpsertComplianceConfig(t.Context(), &compliance.ComplianceConfig{ID: uuid.New().String(), OrgID: f.orgID, Enabled: true}))
	require.NoError(t, s.db.AddSanctionedAddress(t.Context(), &compliance.SanctionedAddress{ID: uuid.New().String(), OrgID: &f.orgID, Address: sanctioned, Reason: "test"}))
	s.complianceChecker = compliance.NewChecker(s.db, time.Hour, time.Hour)

	body := map[string]any{"user_did": target.ExternalID, "rpc": map[string]any{"method": "eth_sendTransaction", "params": []any{map[string]any{"from": from, "to": sanctioned, "value": "0x1"}}}}
	response := f.request(t, f.admin, http.MethodPost, "/api/v1/admin/orgs/"+f.orgID+"/dry-run", body)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.JSONEq(t, `{"decision":"deny","reason":"compliance"}`, response.Body.String())
	require.Zero(t, n.calls, "a compliance denial must not reach the node")
	var decision, reason string
	require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT decision, reason FROM impersonation_log WHERE org_id=$1 ORDER BY created_at DESC LIMIT 1`, f.orgID).Scan(&decision, &reason))
	require.Equal(t, "deny", decision)
	require.Equal(t, ReasonComplianceBlocked, reason)
}
