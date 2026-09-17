package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
)

func TestConfigurationCIAPIRequiresSignedExternalReview(t *testing.T) {
	f := configurationAPI(t)
	reviewer, err := f.server.jwtService.ValidateAccessToken(f.reviewer)
	require.NoError(t, err)
	service, err := f.server.jwtService.ValidateAccessToken(f.service)
	require.NoError(t, err)
	var eligible string
	require.NoError(t, f.server.db.Conn().QueryRowContext(t.Context(), `SELECT g.id FROM groups g JOIN user_memberships m ON m.group_id=g.id JOIN users u ON u.id=m.user_id WHERE u.external_id=$1 AND g.org_id=$2`, reviewer.Subject, f.orgID).Scan(&eligible))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	trust := configuration.TrustedCI{ID: uuid.NewString(), Issuer: "review-ci", Audience: "ops", Subject: service.Subject, Repository: "customer/ops", Ref: "refs/heads/main", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	scope := configuration.Scope{Kind: "organization", ID: f.orgID}
	policy := &configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Approvers, Scope: scope, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.ApproversSpec{GroupIDs: []string{eligible}, TrustedCI: []configuration.TrustedCI{trust}}}
	base := strings.TrimSuffix(f.base(), "groups") + "approvers"
	serviceDraft := f.request(t, f.service, http.MethodPost, base+"/revisions", policy)
	require.Equal(t, http.StatusForbidden, serviceDraft.Code, serviceDraft.Body.String())
	response := f.request(t, f.admin, http.MethodPost, base+"/revisions", policy)
	require.Equal(t, 201, response.Code, response.Body.String())
	var approvalDraft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &approvalDraft))
	response = f.request(t, f.reviewer, http.MethodPost, base+"/revisions/"+approvalDraft.ID+"/activate", nil)
	require.Equal(t, 200, response.Code, response.Body.String())
	doc := f.document(t)
	response = f.request(t, f.service, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, 201, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	path := f.base() + "/revisions/" + draft.ID + "/activate-ci"
	response = f.request(t, f.service, http.MethodPost, path, map[string]any{})
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	now := time.Now()
	proof := configuration.CIApproval{Version: "ops.configuration-approval/v1", TrustID: trust.ID, Issuer: trust.Issuer, Audience: trust.Audience, Subject: trust.Subject, Repository: trust.Repository, Ref: trust.Ref, Commit: strings.Repeat("a", 40), Scope: scope, CandidateDigests: map[configuration.Kind]string{configuration.Groups: draft.Digest}, ReviewerSubjects: []string{reviewer.Subject}, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Nonce: uuid.NewString()}
	signing, err := proof.SigningBytes()
	require.NoError(t, err)
	proof.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, signing))
	response = f.request(t, f.admin, http.MethodPost, path, map[string]any{"coactivate": []string{}, "approval": proof})
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	response = f.request(t, f.service, http.MethodPost, path, map[string]any{"coactivate": []string{}, "approval": proof})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}
