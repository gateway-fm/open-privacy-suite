package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// ZKRoleExtractor extracts role claims from Privado ID proofs.
type ZKRoleExtractor struct {
	store rbac.Store
}

// NewZKRoleExtractor creates a new ZK role extractor.
func NewZKRoleExtractor(store rbac.Store) *ZKRoleExtractor {
	return &ZKRoleExtractor{store: store}
}

// ExtractRoleClaims extracts claims from a Privado ID proof response.
// This is called after a successful ZK proof verification.
// The proofData contains the verified credential data from Privado.
func (e *ZKRoleExtractor) ExtractRoleClaims(proofData map[string]any) (*ZKRoleClaims, error) {
	claims := &ZKRoleClaims{
		Groups:         []string{},
		Claims:         []string{},
		CredentialRefs: []string{},
		ProofTimestamp: time.Now().Unix(),
	}

	// Extract credential data from the proof data
	// The exact structure depends on the Privado credential schema
	// Expected format in credential:
	// {
	//   "credentialSubject": {
	//     "rbac_groups": ["org:group1", "org:group2"],
	//     "rbac_claims": ["deploy", "upgrade"],
	//     "id": "did:polygonid:..."
	//   }
	// }

	if credSubject, ok := proofData["credentialSubject"].(map[string]any); ok {
		// Extract groups
		if groups, ok := credSubject["rbac_groups"].([]any); ok {
			for _, g := range groups {
				if gs, ok := g.(string); ok {
					claims.Groups = append(claims.Groups, gs)
				}
			}
		}

		// Extract claims (read, write, admin, upgrade)
		if claimsArr, ok := credSubject["rbac_claims"].([]any); ok {
			for _, c := range claimsArr {
				if cs, ok := c.(string); ok {
					claims.Claims = append(claims.Claims, cs)
				}
			}
		}
	}

	// Extract credential reference for audit
	if credID, ok := proofData["id"].(string); ok {
		claims.CredentialRefs = append(claims.CredentialRefs, credID)
	}

	return claims, nil
}

// ProcessZKMemberships creates or updates user memberships based on ZK-attested claims.
// This synchronizes the RBAC database with the ZK credentials.
// Note: In the simplified RBAC model, ZK credentials grant group membership only.
// Contract-level claims come from ContractGrants, not from user memberships.
func (e *ZKRoleExtractor) ProcessZKMemberships(ctx context.Context, userID string, zkClaims *ZKRoleClaims) error {
	if zkClaims == nil {
		return nil
	}

	for _, groupPath := range zkClaims.Groups {
		// Parse group path (format: "org:group" or "org:parent:child")
		org, group, err := e.parseGroupPath(groupPath)
		if err != nil {
			continue // Skip invalid paths
		}

		// Get organization
		orgEntity, err := e.store.GetOrganizationBySlug(ctx, org)
		if err != nil || orgEntity == nil {
			continue // Skip if org doesn't exist
		}

		// Get group by slug
		groupEntity, err := e.store.GetGroupBySlug(ctx, orgEntity.ID, group)
		if err != nil || groupEntity == nil {
			continue // Skip if group doesn't exist
		}

		// Check if membership already exists
		existing, err := e.store.GetMembershipByUserAndGroup(ctx, userID, groupEntity.ID)
		if err != nil {
			return fmt.Errorf("failed to check existing membership: %w", err)
		}

		if existing != nil {
			// Update existing membership
			existing.Source = rbac.MembershipSourceZKAttested
			existing.ZKCredentialRef = strings.Join(zkClaims.CredentialRefs, ",")
			if err := e.store.UpdateMembership(ctx, existing); err != nil {
				return fmt.Errorf("failed to update membership: %w", err)
			}
		} else {
			// Create new membership
			membership := &rbac.UserMembership{
				ID:              uuid.New().String(),
				UserID:          userID,
				GroupID:         groupEntity.ID,
				Source:          rbac.MembershipSourceZKAttested,
				ZKCredentialRef: strings.Join(zkClaims.CredentialRefs, ","),
			}
			if err := e.store.CreateMembership(ctx, membership); err != nil {
				return fmt.Errorf("failed to create membership: %w", err)
			}
		}
	}

	return nil
}

// parseGroupPath parses a group path like "org:group" or "org:parent:child".
// Returns the organization slug and the leaf group slug.
func (e *ZKRoleExtractor) parseGroupPath(path string) (org string, group string, err error) {
	parts := strings.Split(path, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid group path: %s", path)
	}

	org = parts[0]
	group = parts[len(parts)-1] // Use the leaf group

	return org, group, nil
}

// ValidateZKClaims validates that ZK claims are well-formed and not expired.
func ValidateZKClaims(claims *ZKRoleClaims, maxAge time.Duration) error {
	if claims == nil {
		return nil // No claims is valid (optional)
	}

	// Check proof age
	if claims.ProofTimestamp > 0 {
		proofTime := time.Unix(claims.ProofTimestamp, 0)
		if time.Since(proofTime) > maxAge {
			return fmt.Errorf("ZK proof expired: generated %v ago", time.Since(proofTime))
		}
	}

	return nil
}
