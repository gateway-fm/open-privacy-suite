package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCIApprovalBindsExactReviewedSourceAndIndependentReviewer(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustedCI{ID: "22222222-2222-2222-2222-222222222222", Issuer: "ops-review", Audience: "privacy-proxy", Subject: "azure-ad-sp:worker", Repository: "customer/ops", Ref: "refs/heads/main", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	now := time.Unix(1700000000, 0)
	scope := Scope{Kind: "organization", ID: "11111111-1111-1111-1111-111111111111"}
	candidates := map[Kind]string{Groups: "sha256:" + strings.Repeat("a", 64)}
	raw := map[string]any{"version": "ops.configuration-approval/v1", "trustId": trust.ID, "issuer": trust.Issuer, "audience": trust.Audience, "subject": trust.Subject, "repository": trust.Repository, "ref": trust.Ref, "commit": strings.Repeat("a", 40), "scope": map[string]string{"kind": scope.Kind, "id": scope.ID}, "candidateDigests": candidates, "reviewerSubjects": []string{"did:human:reviewer"}, "issuedAt": now.Unix(), "expiresAt": now.Add(5 * time.Minute).Unix(), "nonce": "33333333-3333-3333-3333-333333333333"}
	unsigned, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, unsigned))
	encoded, _ := json.Marshal(raw)
	// Verify parses exact keys and signs the canonical JSON object, independent
	// of insignificant whitespace in the transported manifest.
	approval, err := ParseCIApproval(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCIApproval(approval, ApproversSpec{TrustedCI: []TrustedCI{trust}}, scope, trust.Subject, candidates, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCIApproval(approval, ApproversSpec{TrustedCI: []TrustedCI{trust}}, scope, "other-worker", candidates, now); err == nil {
		t.Fatal("wrong service accepted")
	}
	if err := VerifyCIApproval(approval, ApproversSpec{TrustedCI: []TrustedCI{trust}}, scope, trust.Subject, map[Kind]string{Groups: "sha256:" + strings.Repeat("b", 64)}, now); err == nil {
		t.Fatal("different document accepted")
	}
	if err := VerifyCIApproval(approval, ApproversSpec{TrustedCI: []TrustedCI{trust}}, scope, trust.Subject, candidates, now.Add(6*time.Minute)); err == nil {
		t.Fatal("expired approval accepted")
	}
	raw["reviewerSubjects"] = []string{trust.Subject}
	delete(raw, "signature")
	unsigned, _ = json.Marshal(raw)
	raw["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, unsigned))
	encoded, _ = json.Marshal(raw)
	approval, err = ParseCIApproval(encoded)
	if err == nil && VerifyCIApproval(approval, ApproversSpec{TrustedCI: []TrustedCI{trust}}, scope, trust.Subject, candidates, now) == nil {
		t.Fatal("self-review accepted")
	}
}
