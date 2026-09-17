package configuration

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// TrustedCI identifies an external approval signer, independent of the service
// principal that submits revisions. Its assertion is trusted change-management
// evidence; the application does not claim to independently query a Git host.
type TrustedCI struct {
	ID         string `json:"id"`
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	Subject    string `json:"subject"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	PublicKey  string `json:"publicKey"`
}
type ApproversSpec struct {
	GroupIDs  []string    `json:"groupIds"`
	TrustedCI []TrustedCI `json:"trustedCI"`
}

func (ApproversSpec) configurationKind() Kind { return Approvers }

func normalizeApprovers(s *ApproversSpec) error {
	if len(s.GroupIDs) == 0 {
		return fmt.Errorf("approvers must name at least one current full-admin group")
	}
	ids := map[string]bool{}
	for _, id := range s.GroupIDs {
		if !canonicalUUID(id) || ids[id] {
			return fmt.Errorf("invalid or duplicate approver group")
		}
		ids[id] = true
	}
	ids = map[string]bool{}
	bindings := map[string]bool{}
	for _, ci := range s.TrustedCI {
		if !canonicalUUID(ci.ID) || ids[ci.ID] {
			return fmt.Errorf("invalid or duplicate trusted CI id")
		}
		ids[ci.ID] = true
		for _, field := range []string{ci.Issuer, ci.Audience, ci.Subject, ci.Repository, ci.Ref} {
			if field == "" || strings.TrimSpace(field) != field || strings.ContainsAny(field, "\x00\r\n") || len(field) > 1024 {
				return fmt.Errorf("trusted CI requires exact issuer, audience, subject, repository and ref")
			}
		}
		key, err := base64.StdEncoding.DecodeString(ci.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != ci.PublicKey {
			return fmt.Errorf("trusted CI requires a canonical base64 Ed25519 public key")
		}
		binding := strings.Join([]string{ci.Issuer, ci.Audience, ci.Subject, ci.Repository, ci.Ref}, "\x00")
		if bindings[binding] {
			return fmt.Errorf("duplicate trusted CI binding")
		}
		bindings[binding] = true
	}
	sort.Strings(s.GroupIDs)
	sort.Slice(s.TrustedCI, func(i, j int) bool { return s.TrustedCI[i].ID < s.TrustedCI[j].ID })
	return nil
}

// ValidateApprovers uses projected group metadata but never creates authority.
// Activation eligibility is resolved against the previously active policy.
// A non-nil error is a *SourceError.
func ValidateApprovers(spec ApproversSpec, groups []Group) error {
	return sourceError(validateApprovers(spec, groups))
}

// validateApprovers is ValidateApprovers before its error is typed.
func validateApprovers(spec ApproversSpec, groups []Group) error {
	available := map[string]bool{}
	for _, g := range groups {
		available[g.ID] = g.IsOrgAdmin
	}
	for _, id := range spec.GroupIDs {
		if !available[id] {
			return fmt.Errorf("approver group %s must be an existing full-admin group in this scope", id)
		}
	}
	return nil
}

// A non-nil error is a *SourceError.
func DiffApprovers(doc *Document, previous *ApproversSpec) (ApproversSpec, error) {
	v0, err := diffApprovers(doc, previous)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// diffApprovers is DiffApprovers before its error is typed.
func diffApprovers(doc *Document, previous *ApproversSpec) (ApproversSpec, error) {
	spec, ok := doc.Spec.(ApproversSpec)
	if !ok {
		return spec, fmt.Errorf("invalid approvers source")
	}
	current := []TrustedCI{}
	managed := []string{}
	if previous != nil {
		current = previous.TrustedCI
		for _, ci := range current {
			managed = append(managed, ci.ID)
		}
	}
	used := map[string]bool{}
	_, _, _, err := diffResources("trustedCI", current, spec.TrustedCI, managed, doc.Deletions, used, func(v TrustedCI) string { return v.ID })
	if err != nil {
		return spec, err
	}
	for _, del := range doc.Deletions {
		if !used[del.ID] {
			return spec, fmt.Errorf("deletion names unknown CI trust resource %s", del.ID)
		}
	}
	return spec, nil
}
