package configuration

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

// CIApproval is an assertion signed by the independently operated, configured
// approval system. It attests that named humans reviewed a merged commit and
// these exact documents. It is not an assertion inferred from an agent's text.
type CIApproval struct {
	Version          string          `json:"version"`
	TrustID          string          `json:"trustId"`
	Issuer           string          `json:"issuer"`
	Audience         string          `json:"audience"`
	Subject          string          `json:"subject"`
	Repository       string          `json:"repository"`
	Ref              string          `json:"ref"`
	Commit           string          `json:"commit"`
	Scope            Scope           `json:"scope"`
	CandidateDigests map[Kind]string `json:"candidateDigests"`
	ReviewerSubjects []string        `json:"reviewerSubjects"`
	IssuedAt         int64           `json:"issuedAt"`
	ExpiresAt        int64           `json:"expiresAt"`
	Nonce            string          `json:"nonce"`
	Signature        string          `json:"signature"`
}

type CIActivationRequest struct {
	Coactivate []string    `json:"coactivate"`
	Approval   *CIApproval `json:"approval"`
}

// A non-nil error is a *SourceError.
func ParseCIActivationRequest(raw []byte) (CIActivationRequest, error) {
	v0, err := parseCIActivationRequest(raw)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// parseCIActivationRequest is ParseCIActivationRequest before its error is typed.
func parseCIActivationRequest(raw []byte) (CIActivationRequest, error) {
	var request CIActivationRequest
	if len(raw) == 0 || len(raw) > 65536 {
		return request, fmt.Errorf("CI activation request size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return request, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return request, fmt.Errorf("CI activation has trailing JSON")
	}
	if err := exactDecode(value, &request); err != nil {
		return request, err
	}
	if len(request.Coactivate) > 4 {
		return request, fmt.Errorf("too many coactivated revisions")
	}
	for _, id := range request.Coactivate {
		if !canonicalUUID(id) {
			return request, fmt.Errorf("invalid coactivated revision id")
		}
	}
	return request, nil
}

// A non-nil error is a *SourceError.
func ParseCIApproval(raw []byte) (*CIApproval, error) {
	v0, err := parseCIApproval(raw)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// parseCIApproval is ParseCIApproval before its error is typed.
func parseCIApproval(raw []byte) (*CIApproval, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, fmt.Errorf("approval manifest size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("approval has trailing JSON")
	}
	var approval CIApproval
	if err := exactDecode(value, &approval); err != nil {
		return nil, err
	}
	return &approval, nil
}

// SigningBytes is canonical JSON: object keys sorted recursively by Go's JSON
// encoder, integer timestamps, no insignificant whitespace, signature omitted.
func (a CIApproval) SigningBytes() ([]byte, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	delete(value, "signature")
	return json.Marshal(value)
}

// A non-nil error is a *SourceError.
func VerifyCIApproval(a *CIApproval, policy ApproversSpec, scope Scope, subject string, candidates map[Kind]string, now time.Time) error {
	return sourceError(verifyCIApproval(a, policy, scope, subject, candidates, now))
}

// verifyCIApproval is VerifyCIApproval before its error is typed.
func verifyCIApproval(a *CIApproval, policy ApproversSpec, scope Scope, subject string, candidates map[Kind]string, now time.Time) error {
	if a == nil || a.Version != "ops.configuration-approval/v1" || a.Scope != scope || scope.Kind != "organization" || a.Subject != subject || subject == "" || !canonicalUUID(a.TrustID) || !canonicalUUID(a.Nonce) {
		return fmt.Errorf("approval identity or scope is invalid")
	}
	if a.IssuedAt <= 0 || a.ExpiresAt <= a.IssuedAt || a.ExpiresAt-a.IssuedAt > 900 || a.IssuedAt > now.Unix()+30 || a.ExpiresAt <= now.Unix() {
		return fmt.Errorf("approval is expired or outside its bounded validity window")
	}
	if len(a.Commit) != 40 && len(a.Commit) != 64 {
		return fmt.Errorf("approval requires the reviewed commit digest")
	}
	if _, err := hex.DecodeString(a.Commit); err != nil || strings.ToLower(a.Commit) != a.Commit {
		return fmt.Errorf("approval commit is invalid")
	}
	if len(candidates) == 0 || len(candidates) > 5 || !reflect.DeepEqual(a.CandidateDigests, candidates) {
		return fmt.Errorf("approval does not bind the exact candidate document digests")
	}
	for kind, digest := range a.CandidateDigests {
		if !isOrgKind(kind) || kind == Approvers || !validDigest(digest) {
			return fmt.Errorf("CI cannot change its own approval trust policy")
		}
	}
	if len(a.ReviewerSubjects) == 0 || len(a.ReviewerSubjects) > 20 {
		return fmt.Errorf("approval requires an independent human reviewer")
	}
	seen := map[string]bool{}
	for _, reviewer := range a.ReviewerSubjects {
		if reviewer == "" || reviewer == subject || strings.TrimSpace(reviewer) != reviewer || len(reviewer) > 1024 || seen[reviewer] {
			return fmt.Errorf("approval reviewers must be distinct and independent of the service principal")
		}
		seen[reviewer] = true
	}
	var trust *TrustedCI
	for i := range policy.TrustedCI {
		if policy.TrustedCI[i].ID == a.TrustID {
			trust = &policy.TrustedCI[i]
			break
		}
	}
	if trust == nil || trust.Issuer != a.Issuer || trust.Audience != a.Audience || trust.Subject != a.Subject || trust.Repository != a.Repository || trust.Ref != a.Ref {
		return fmt.Errorf("approval issuer or repository binding is not trusted")
	}
	key, err := base64.StdEncoding.DecodeString(trust.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("approval verification key is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != a.Signature {
		return fmt.Errorf("approval signature is invalid")
	}
	message, err := a.SigningBytes()
	if err != nil {
		return fmt.Errorf("approval manifest cannot be canonicalized")
	}
	if !ed25519.Verify(key, message, signature) {
		return fmt.Errorf("approval signature is invalid")
	}
	return nil
}
