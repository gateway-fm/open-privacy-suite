//go:build mockauth

package server

import (
	"net/http"
	"privacy-proxy/internal/apimodels"
	"strings"

	"github.com/gin-gonic/gin"
)

// TestIdentity represents a pre-configured test user for the dev identity picker.
type TestIdentity struct {
	DID       string   `json:"did"`
	Name      string   `json:"name"`
	Note      string   `json:"note,omitempty"`
	Addresses []string `json:"addresses"`
	Orgs      []string `json:"orgs"`
}

// handleGetTestIdentities returns test identities (users with did:test: prefix) for the dev identity picker.
// Only available in mockauth builds when AllowMockLogin is enabled.
//
// @Summary      List dev test identities
// @Description  Available only in non-production builds with mock login enabled. Returns the pre-configured test users (DIDs with the did:test: prefix), with their linked ETH addresses and org names, to populate the dev identity picker.
// @Tags         Auth
// @Produce      json
// @Success      200 {object} apimodels.TestIdentitiesResponse
// @Failure      403 {object} apimodels.APIError "not available"
// @Failure      500 {object} apimodels.APIError "failed to list users"
// @Router       /api/v1/dev/test-identities [get]
func (s *Server) handleGetTestIdentities(c *gin.Context) {
	if s.config.IsProduction() || !s.config.AllowMockLogin {
		c.JSON(http.StatusForbidden, gin.H{"error": "not available"})
		return
	}

	ctx := c.Request.Context()

	// List users (up to 200 to cover test accounts)
	users, _, err := s.db.ListUsersPaginated(ctx, 200, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
		return
	}

	var identities []TestIdentity
	for _, u := range users {
		if !strings.HasPrefix(u.ExternalID, "did:test:") {
			continue
		}

		// Extract display name from DID: did:test:alice -> Alice
		name := strings.TrimPrefix(u.ExternalID, "did:test:")
		if len(name) > 0 {
			name = strings.ToUpper(name[:1]) + name[1:]
		}

		// Use note as name if set
		if u.Note != "" {
			name = u.Note
		}

		identity := TestIdentity{
			DID:  u.ExternalID,
			Name: name,
		}

		// Get linked ETH addresses
		links, err := s.db.GetEthAddressesByDID(ctx, u.ExternalID)
		if err == nil {
			for _, link := range links {
				identity.Addresses = append(identity.Addresses, link.EthAddress)
			}
		}

		// Get org memberships via group details
		memberships, err := s.db.ListUserMembershipsWithDetails(ctx, u.ID)
		if err == nil {
			seen := map[string]bool{}
			for _, m := range memberships {
				if m.Group != nil && m.Group.OrgID != "" {
					org, orgErr := s.db.GetOrganization(ctx, m.Group.OrgID)
					if orgErr == nil && org != nil && !seen[org.Name] {
						identity.Orgs = append(identity.Orgs, org.Name)
						seen[org.Name] = true
					}
				}
			}
		}

		identities = append(identities, identity)
	}

	c.JSON(http.StatusOK, gin.H{"identities": identities})
}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
