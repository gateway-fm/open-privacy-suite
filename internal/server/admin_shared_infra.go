package server

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/apimodels"
)

// shared_infrastructure admin API (KD-1, follow-up to M5 / RD-915).
//
// shared_infrastructure is a small whitelist of contracts the runtime
// trace validator skips when validating cross-org calls — Uniswap V3
// Router, Multicall3, ENS resolver, CREATE3 factory etc. The trust
// promise is "this address is public infrastructure callable by every
// org". M5 added the optional `codehash` column so the validator can
// reject the skip if the bytecode at the address drifts from what the
// operator attested.
//
// The table has no `org_id` column — entries are global. Mutating it
// changes policy for every tenant in the cluster. The admin surface
// is therefore **super-admin only** (X-Admin-Token); JWT org admins,
// even tier-2 with full admin rights in their org, cannot touch it.
// Same scoping rationale as Azure tenant CRUD (audit C4) and the
// base-currency switch (audit C5).
//
// Endpoints:
//
//   GET    /api/v1/admin/shared-infrastructure
//   POST   /api/v1/admin/shared-infrastructure
//   GET    /api/v1/admin/shared-infrastructure/:address
//   PUT    /api/v1/admin/shared-infrastructure/:address
//   DELETE /api/v1/admin/shared-infrastructure/:address
//   POST   /api/v1/admin/shared-infrastructure/:address/refresh-codehash
//
// Refresh-codehash is the operationally common case: a tracked
// upstream contract (e.g. Uniswap V3 Router) was upgraded, its
// bytecode rotated, the trace validator now denies every call to it.
// Operator hits refresh-codehash → handler fetches eth_getCode at
// "latest", computes keccak256, stores in the row's codehash column.
// Subsequent traces match and the skip resumes.
//
// Every mutation records an audit-log entry via
// recordAuditAction(ResourceTypeSharedInfra, ...) — operators can
// trace who added / rotated / removed which entry via the standard
// /admin/audit-logs endpoint.

// registerSharedInfraRoutes mounts the shared_infrastructure admin
// routes under the given admin router group. Called from
// registerRBACRoutes.
func (s *Server) registerSharedInfraRoutes(api *gin.RouterGroup) {
	api.GET("/shared-infrastructure", s.listSharedInfrastructure)
	api.POST("/shared-infrastructure", s.createSharedInfrastructure)
	api.GET("/shared-infrastructure/:address", s.getSharedInfrastructure)
	api.PUT("/shared-infrastructure/:address", s.updateSharedInfrastructure)
	api.DELETE("/shared-infrastructure/:address", s.deleteSharedInfrastructure)
	api.POST("/shared-infrastructure/:address/refresh-codehash", s.refreshSharedInfraCodehash)
}

// validateSharedInfraInput checks the input shape before any DB
// write. Returns the normalized lowercase address + normalized
// codehash (or empty for no-pin) on success.
//
// Defense-in-depth: lowercase + format validation before write
// matches the read path's case-insensitive lookup; an operator
// passing a checksummed address gets the lowercase row.
func validateSharedInfraInput(addr, codehash string) (string, string, error) {
	addr = strings.TrimSpace(addr)
	if !auth.IsValidAddress(addr) {
		return "", "", errors.New("address must be a valid 0x-prefixed 20-byte hex address")
	}
	addr = strings.ToLower(addr)

	codehash = strings.TrimSpace(codehash)
	if codehash != "" {
		if !isValidHash32(codehash) {
			return "", "", errors.New("codehash must be a 0x-prefixed 32-byte hex string (or omitted)")
		}
		codehash = strings.ToLower(codehash)
	}
	return addr, codehash, nil
}

// isValidHash32 checks for a 0x-prefixed 32-byte (64 hex char) hash.
// Mirrors auth.IsValidAddress but at the keccak256 length. Used by
// the shared_infrastructure admin API for the codehash field.
func isValidHash32(h string) bool {
	if !strings.HasPrefix(h, "0x") && !strings.HasPrefix(h, "0X") {
		return false
	}
	hex := h[2:]
	if len(hex) != 64 {
		return false
	}
	for _, c := range hex {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// listSharedInfrastructure lists the fleet-wide shared-infrastructure allowlist.
//
// @Summary      List shared infrastructure
// @Description  Lists the global shared-infrastructure contracts the cross-org trace validator skips (public routers, factories, resolvers). Super-admin token only — the list reveals the operator's trust topology, so org admins cannot read it.
// @Tags         Admin: shared infrastructure
// @Produce      json
// @Success      200 {object} apimodels.SharedInfraListResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "super-admin token required"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/shared-infrastructure [get]
func (s *Server) listSharedInfrastructure(c *gin.Context) {
	// Read is super-admin only too — the list itself reveals the
	// operator's trust topology (which DEXes, factories, etc. are
	// whitelisted), and JWT org admins have no legitimate need for
	// it. Same shape as listAzureTenants post-C4 fix.
	if !requireSuperAdmin(c) {
		return
	}
	rows, err := s.db.ListSharedInfrastructure(c.Request.Context())
	if err != nil {
		slog.Error("list shared_infrastructure: db read failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list shared_infrastructure"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// getSharedInfrastructure returns one shared-infrastructure entry by address.
//
// @Summary      Get a shared-infrastructure entry
// @Description  Returns one global shared-infrastructure entry by address. Super-admin token only.
// @Tags         Admin: shared infrastructure
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} rbac.SharedInfrastructure
// @Failure      400 {object} apimodels.APIError "invalid address"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "super-admin token required"
// @Failure      404 {object} apimodels.APIError "not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/shared-infrastructure/{address} [get]
func (s *Server) getSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}
	row, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("get shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read"})
		return
	}
	if row == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, row)
}

// createSharedInfrastructure adds a contract to the shared-infrastructure allowlist.
//
// @Summary      Add a shared-infrastructure entry
// @Description  Registers a global shared-infrastructure contract (address from the body). The optional codehash pin, if supplied, must be a 0x-prefixed 32-byte hex string; omit it and use refresh-codehash to compute it server-side. Super-admin token only; the mutation is audit-logged.
// @Tags         Admin: shared infrastructure
// @Accept       json
// @Produce      json
// @Param        request body apimodels.SharedInfraInput true "shared-infrastructure entry to create"
// @Success      201 {object} rbac.SharedInfrastructure
// @Failure      400 {object} apimodels.APIError "invalid body, invalid address, invalid codehash, or missing name"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "super-admin token required"
// @Failure      409 {object} apimodels.APIError "address already registered; use PUT to update"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/shared-infrastructure [post]
func (s *Server) createSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	var input apimodels.SharedInfraInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	addr, codehash, vErr := validateSharedInfraInput(input.Address, input.Codehash)
	if vErr != nil {
		// Opaque client message; the specific validation detail goes to slog.
		// (RD-1178 / RD-934: never echo an error value to the client.)
		slog.Warn("admin_shared_infra: invalid input", "err", vErr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address or codehash"})
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	// Reject duplicate up front (the table has no unique constraint
	// on address today, but inserting two rows for the same address
	// is meaningless — they'd both be checked, and the first one
	// found wins — silently shadowing the second).
	existing, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("create shared_infrastructure: dedup read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "address already registered as shared_infrastructure; use PUT to update"})
		return
	}

	row := &rbac.SharedInfrastructure{
		Address:     addr,
		Name:        strings.TrimSpace(input.Name),
		Description: strings.TrimSpace(input.Description),
	}
	if codehash != "" {
		ch := codehash
		row.Codehash = &ch
	}
	if err := s.db.CreateSharedInfrastructure(c.Request.Context(), row); err != nil {
		// Race window between the dedup-check above and this INSERT
		// is closed by the UNIQUE constraint on
		// shared_infrastructure.address (migration 054). Postgres
		// raises a unique-violation error here — translate to 409.
		// The plain-text marker is robust across pgx and lib/pq.
		if strings.Contains(strings.ToLower(err.Error()), "unique") ||
			strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			c.JSON(http.StatusConflict, gin.H{"error": "address already registered as shared_infrastructure; use PUT to update"})
			return
		}
		slog.Error("create shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create"})
		return
	}

	// Audit-log the mutation. ResourceID = address (canonical key for
	// this table); resource name = the human-readable Name field so
	// listAuditLogs renders something useful.
	s.recordAuditAction(c, rbac.AuditActionCreate, rbac.ResourceTypeSharedInfra, row.Address, row.Name,
		nil,
		map[string]any{
			"address":     row.Address,
			"name":        row.Name,
			"description": row.Description,
			"codehash":    codehashForLog(row.Codehash),
		})

	c.JSON(http.StatusCreated, row)
}

// updateSharedInfrastructure updates the name, description, and codehash pin of an entry.
//
// @Summary      Update a shared-infrastructure entry
// @Description  Updates the name, description, and codehash pin of a shared-infrastructure entry. The address comes from the path (the body address field is ignored); an empty codehash clears the pin. Super-admin token only; the change is audit-logged.
// @Tags         Admin: shared infrastructure
// @Accept       json
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Param        request body apimodels.SharedInfraInput true "updated fields (address field ignored)"
// @Success      200 {object} rbac.SharedInfrastructure
// @Failure      400 {object} apimodels.APIError "invalid address, invalid body, invalid codehash, or missing name"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "super-admin token required"
// @Failure      404 {object} apimodels.APIError "not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/shared-infrastructure/{address} [put]
func (s *Server) updateSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}

	var input apimodels.SharedInfraInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	// Codehash field, if present, must be a valid 32-byte hash.
	// Empty/omitted is allowed (clears the pin).
	_, codehash, vErr := validateSharedInfraInput(addr, input.Codehash)
	if vErr != nil {
		// Opaque client message; the specific validation detail goes to slog.
		// (RD-1178 / RD-934: never echo an error value to the client.)
		slog.Warn("admin_shared_infra: invalid input", "err", vErr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address or codehash"})
		return
	}

	// Load current state for the audit log before-image and to
	// confirm the row exists (404 if not).
	before, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("update shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	row := &rbac.SharedInfrastructure{
		Address:     addr,
		Name:        strings.TrimSpace(input.Name),
		Description: strings.TrimSpace(input.Description),
	}
	if codehash != "" {
		ch := codehash
		row.Codehash = &ch
	}
	if err := s.db.UpdateSharedInfrastructure(c.Request.Context(), row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		slog.Error("update shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeSharedInfra, row.Address, row.Name,
		map[string]any{
			"name":        before.Name,
			"description": before.Description,
			"codehash":    codehashForLog(before.Codehash),
		},
		map[string]any{
			"name":        row.Name,
			"description": row.Description,
			"codehash":    codehashForLog(row.Codehash),
		})

	c.JSON(http.StatusOK, row)
}

// deleteSharedInfrastructure removes an entry from the shared-infrastructure allowlist.
//
// @Summary      Delete a shared-infrastructure entry
// @Description  Removes a contract from the global shared-infrastructure allowlist; the trace validator will resume enforcing cross-org checks on it. Super-admin token only; the deletion is audit-logged.
// @Tags         Admin: shared infrastructure
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} apimodels.APIMessage "shared_infrastructure entry deleted"
// @Failure      400 {object} apimodels.APIError "invalid address"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "super-admin token required"
// @Failure      404 {object} apimodels.APIError "not found"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/shared-infrastructure/{address} [delete]
func (s *Server) deleteSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}

	before, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("delete shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	if err := s.db.DeleteSharedInfrastructure(c.Request.Context(), addr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		slog.Error("delete shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete"})
		return
	}

	s.recordAuditAction(c, rbac.AuditActionDelete, rbac.ResourceTypeSharedInfra, before.Address, before.Name,
		map[string]any{
			"name":        before.Name,
			"description": before.Description,
			"codehash":    codehashForLog(before.Codehash),
		},
		nil)

	c.JSON(http.StatusOK, gin.H{"message": "shared_infrastructure entry deleted"})
}

// refreshSharedInfraCodehash fetches eth_getCode at the address and
// writes its keccak256 into the row's codehash column. The common
// operational case: a tracked upstream contract was legitimately
// upgraded, its bytecode rotated, and the trace validator now denies
// every call to it. After the operator verifies (out of band) that
// the new bytecode is what they expect, this endpoint re-attests so
// the validator skip resumes.
//
// Race window: between the eth_getCode here and a subsequent trace
// validation read, a malicious actor could theoretically rotate the
// implementation slot back and forth. Mitigation: the operator's
// out-of-band verification + the fact that this is super-admin only.
// For high-assurance attestation flows the operator should compute
// the hash locally and PUT it explicitly rather than trust this
// endpoint.
//
// @Summary      Refresh a shared-infrastructure codehash
// @Description  Fetches the current bytecode at the entry's address via eth_getCode, computes its keccak256, and stores it as the codehash pin — used after a tracked upstream contract is legitimately upgraded. Verify the new bytecode out of band first. Super-admin token only; the change is audit-logged.
// @Tags         Admin: shared infrastructure
// @Produce      json
// @Param        address path string true "Contract address (0x-prefixed hex)"
// @Success      200 {object} rbac.SharedInfrastructure
// @Failure      400 {object} apimodels.APIError "invalid address"
// @Failure      401 {object} apimodels.APIError "missing or invalid admin token"
// @Failure      403 {object} apimodels.APIError "super-admin token required"
// @Failure      404 {object} apimodels.APIError "not found"
// @Failure      502 {object} apimodels.APIError "upstream node failed or returned an invalid bytecode hash"
// @Failure      503 {object} apimodels.APIError "runtime tracer not configured"
// @Failure      500 {object} apimodels.APIError
// @Security     AdminToken
// @Router       /api/v1/admin/shared-infrastructure/{address}/refresh-codehash [post]
func (s *Server) refreshSharedInfraCodehash(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	if s.runtimeTracer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "runtime tracer not configured; refresh-codehash unavailable"})
		return
	}

	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}

	before, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("refresh shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	newHash, err := s.runtimeTracer.GetCodeHash(c.Request.Context(), addr)
	if err != nil {
		slog.Error("refresh shared_infrastructure: code-hash fetch failed", "addr", addr, "err", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch current bytecode hash from upstream node"})
		return
	}
	newHash = strings.ToLower(newHash)
	if !isValidHash32(newHash) {
		slog.Error("refresh shared_infrastructure: upstream returned invalid hash", "addr", addr, "hash", newHash)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream returned invalid bytecode hash"})
		return
	}

	row := &rbac.SharedInfrastructure{
		Address:     before.Address,
		Name:        before.Name,
		Description: before.Description,
		Codehash:    &newHash,
	}
	if err := s.db.UpdateSharedInfrastructure(c.Request.Context(), row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		slog.Error("refresh shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh"})
		return
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeSharedInfra, row.Address, row.Name,
		map[string]any{
			"codehash":     codehashForLog(before.Codehash),
			"refresh_kind": "refresh-codehash",
		},
		map[string]any{
			"codehash":     newHash,
			"refresh_kind": "refresh-codehash",
		})

	c.JSON(http.StatusOK, row)
}

// codehashForLog renders a *string codehash field for inclusion in
// the audit log payload. Empty pointer → empty string.
func codehashForLog(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
