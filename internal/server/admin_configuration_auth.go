package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/auth"
)

// Only a verified human login can use the interactive approval path. Legacy
// JWTs must log in again; service tokens require the separately verified CI path.
func requireHumanConfigurationActor(c *gin.Context) bool {
	kind, _ := c.Get("admin_principal_kind")
	if kind != auth.PrincipalHuman {
		c.JSON(http.StatusForbidden, gin.H{"error": "activation requires a verified human login; sign in again or use a trusted CI approval"})
		return false
	}
	return true
}

func (s *Server) configurationPlatformSubject(subject string) bool {
	if subject == "" || s.config == nil {
		return false
	}
	for _, allowed := range s.config.PlatformAdminSubjects {
		if allowed == subject {
			return true
		}
	}
	return false
}

func isPlatformConfigurationRoute(c *gin.Context) bool {
	for _, mount := range []string{"/api/v1/admin", "/api/admin"} {
		for _, base := range []string{mount + "/configuration/platform"} {
			switch c.FullPath() {
			case base + "/context", base + "/managed", base + "/revisions", base + "/revisions/:revision_id", base + "/revisions/:revision_id/simulate", base + "/revisions/:revision_id/activate", base + "/revisions/:revision_id/withdraw":
				return true
			}
		}
	}
	return false
}
func isConfigurationPreparation(c *gin.Context) bool {
	if c.Request.Method != http.MethodPost {
		return false
	}
	for _, mount := range []string{"/api/v1/admin", "/api/admin"} {
		if c.FullPath() == mount+"/orgs/:org_id/execution/simulate" {
			return true
		}
		for _, base := range []string{mount + "/orgs/:org_id/configuration/:kind", mount + "/configuration/platform"} {
			if c.FullPath() == base+"/revisions" || c.FullPath() == base+"/revisions/:revision_id/simulate" {
				return true
			}
		}
	}
	return false
}
