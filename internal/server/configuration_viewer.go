package server

import (
	"github.com/gin-gonic/gin"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db"
)

func (s *Server) configurationViewer(c *gin.Context, scope configuration.Scope) (apimodels.ConfigurationViewer, error) {
	kind, _ := c.Get("admin_principal_kind")
	principalKind, _ := kind.(auth.PrincipalKind)
	viewer := apimodels.ConfigurationViewer{PrincipalID: c.GetString("admin_user_id"), PrincipalKind: string(principalKind)}
	if principalKind != auth.PrincipalHuman {
		return viewer, nil
	}
	err := s.db.WithTx(c.Request.Context(), func(tx *db.Tx) error {
		full, err := tx.ConfigurationActorCanApprove(c.Request.Context(), viewer.PrincipalID, scope)
		if err != nil {
			return err
		}
		viewer.CanActivate = full || (scope.Kind == "platform" && s.configurationPlatformSubject(c.GetString("admin_subject")))
		return nil
	})
	return viewer, err
}
