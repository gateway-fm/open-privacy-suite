package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/server/apispec"
)

// Spec-serving endpoint and annotation carriers (RD-1166). The document is
// generated from the swaggo annotations across this package by
// `make api-spec` (swag v2, pinned in go.mod tools) into
// internal/server/apispec/, embedded there, and served at GET /openapi.json.
// The general API info lives in openapi_general_info.go (which must stay
// free of operation annotations).

// handleOpenAPISpec serves the embedded generated OpenAPI document (RD-1166).
// Public by design: it is the published API reference of an open-source
// project, and the response is static embedded bytes — no DB or upstream work.
//
// @Summary      OpenAPI specification
// @Description  The full generated OpenAPI document for this API — the same file the docs site renders. Regenerated from handler annotations on every merge.
// @Tags         System
// @Produce      json
// @Success      200 {object} map[string]interface{} "OpenAPI 3.1 document"
// @Router       /openapi.json [get]
func (s *Server) handleOpenAPISpec(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", apispec.JSON)
}

// specMetricsEndpoint is an annotation carrier for GET /metrics, which is
// served by the Prometheus client handler via gin.WrapH and therefore has no
// annotatable Go handler of its own. Never called.
//
// @Summary      Prometheus metrics
// @Description  Prometheus text exposition of the proxy's metrics. Private-network only.
// @Tags         System
// @Produce      plain
// @Success      200 {string} string "Prometheus text exposition format"
// @Failure      403 {object} apimodels.APIError "source address not on the private network"
// @Router       /metrics [get]
func specMetricsEndpoint() {}

// Reference the annotation carriers so linters don't flag them as unused.
var _ = []any{generalAPIInfo, specMetricsEndpoint}

// swaggo resolves an annotation's apimodels.Type through this file's import
// list, but a reference from a comment is not Go usage — so without this the
// import would be stripped and `make api-spec` would fail. See RD-1265.
var _ = apimodels.APIError{}
