package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/types"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Common error messages for eth_link handlers (for consistency)
const (
	errMissingIdentity = "missing identity in context"
	errInvalidIdentity = "invalid identity in context"
)

// LinkChallenge is an alias for the shared type.
type LinkChallenge = types.LinkChallenge

// ChallengeStore stores pending link challenges with TTL
type ChallengeStore struct {
	challenges map[string]*LinkChallenge // key: nonce
	mu         sync.RWMutex
	ttl        time.Duration
	stopCh     chan struct{}
}

// NewChallengeStore creates a new challenge store with cleanup
func NewChallengeStore(ttl time.Duration, cleanupInterval time.Duration) *ChallengeStore {
	cs := &ChallengeStore{
		challenges: make(map[string]*LinkChallenge),
		ttl:        ttl,
		stopCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cs.cleanup()
			case <-cs.stopCh:
				return
			}
		}
	}()

	return cs
}

// Stop stops the cleanup goroutine
func (cs *ChallengeStore) Stop() {
	close(cs.stopCh)
}

// CreateChallenge creates a new link challenge
func (cs *ChallengeStore) CreateChallenge(did string) (*LinkChallenge, error) {
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, err
	}

	message := auth.GenerateLinkMessage(did, nonce)

	challenge := &LinkChallenge{
		DID:       did,
		Nonce:     nonce,
		Message:   message,
		CreatedAt: time.Now(),
	}

	cs.mu.Lock()
	cs.challenges[nonce] = challenge
	cs.mu.Unlock()

	return challenge, nil
}

// GetChallenge retrieves and removes a challenge by nonce
func (cs *ChallengeStore) GetChallenge(nonce string) *LinkChallenge {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	challenge, exists := cs.challenges[nonce]
	if !exists {
		return nil
	}

	// Check TTL
	if time.Since(challenge.CreatedAt) > cs.ttl {
		delete(cs.challenges, nonce)
		return nil
	}

	// Remove after retrieval (one-time use)
	delete(cs.challenges, nonce)
	return challenge
}

// cleanup removes expired challenges
func (cs *ChallengeStore) cleanup() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()
	for nonce, challenge := range cs.challenges {
		if now.Sub(challenge.CreatedAt) > cs.ttl {
			delete(cs.challenges, nonce)
		}
	}
}

// ChallengeRequest is the request body for creating a challenge
type ChallengeRequest struct {
	Address string `json:"address,omitempty"` // Optional: pre-specify the address to link
}

// handleEthLinkChallenge handles POST /eth/link/challenge - create a challenge to sign
//
// @Summary      Create an ETH address link challenge
// @Description  Issues a one-time challenge message for the caller to sign with their Ethereum key, proving key ownership before the address is linked to the authenticated DID. The nonce is single-use and expires after a short TTL.
// @Tags         ETH linking
// @Produce      json
// @Success      200 {object} apimodels.ChallengeResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid token"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/eth/link/challenge [post]
func (s *Server) handleEthLinkChallenge(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		respondUnauthorized(c, errMissingIdentity)
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		respondUnauthorized(c, errInvalidIdentity)
		return
	}

	// Create challenge
	challenge, err := s.challengeStore.CreateChallenge(userDID)
	if err != nil {
		respondInternalError(c, "failed to create challenge")
		return
	}

	respondOK(c, apimodels.ChallengeResponse{
		Nonce:   challenge.Nonce,
		Message: challenge.Message,
	})
}

// handleEthLinkVerify handles POST /eth/link/verify - verify signature and link address
//
// @Summary      Verify a signed challenge and link the address
// @Description  Verifies the signature over the challenge message and links the address to the caller's DID. Fail-closed: an invalid or expired nonce, a challenge issued to a different DID, a malformed address, or a bad signature all reject the link.
// @Tags         ETH linking
// @Accept       json
// @Produce      json
// @Param        request body apimodels.VerifyLinkRequest true "signed challenge"
// @Success      200 {object} apimodels.EthLinkVerifyResponse
// @Failure      400 {object} apimodels.APIError "invalid body, nonce, address format, or signature"
// @Failure      401 {object} apimodels.APIError "missing or invalid token"
// @Failure      403 {object} apimodels.APIError "challenge belongs to another user, or the link was revoked by an administrator"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/eth/link/verify [post]
func (s *Server) handleEthLinkVerify(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		respondUnauthorized(c, errMissingIdentity)
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		respondUnauthorized(c, errInvalidIdentity)
		return
	}

	var req apimodels.VerifyLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequest(c, "invalid request body")
		return
	}

	// Get the challenge
	challenge := s.challengeStore.GetChallenge(req.Nonce)
	if challenge == nil {
		respondBadRequest(c, "invalid or expired nonce")
		return
	}

	// Verify the challenge belongs to this user
	if challenge.DID != userDID {
		respondForbidden(c, "challenge does not belong to this user")
		return
	}

	// Validate address format
	if !auth.IsValidAddress(req.Address) {
		respondBadRequest(c, "invalid ethereum address format")
		return
	}

	// Normalize the address
	normalizedAddr := auth.NormalizeAddress(req.Address)

	// Verify the signature (unless mock mode is enabled for demos)
	if s.config.MockSignatures {
		slog.Warn("mock signature mode enabled, skipping signature verification", "address", normalizedAddr)
	} else {
		if err := auth.VerifyAddressOwnership(normalizedAddr, challenge.Message, req.Signature); err != nil {
			respondBadRequest(c, "signature verification failed")
			return
		}
	}

	// Get the message hash for storage
	messageHash := auth.MessageHashHex(challenge.Message)

	// Check for existing links to other DIDs before linking (for SIEM severity).
	existingDIDs, lookupErr := s.db.GetDIDsByEthAddress(c.Request.Context(), normalizedAddr)
	if lookupErr != nil {
		slog.Warn("failed to check for address collisions before linking", "address", normalizedAddr, "error", lookupErr)
	}
	otherDIDs := make([]string, 0)
	for _, d := range existingDIDs {
		if d != userDID {
			otherDIDs = append(otherDIDs, d)
		}
	}

	// Store the link in the database
	if err := s.db.LinkEthAddress(c.Request.Context(), userDID, normalizedAddr, req.Signature, messageHash); err != nil {
		if errors.Is(err, db.ErrAddressLinkRevoked) {
			respondForbidden(c, "ETH address link has been revoked — contact an administrator")
			return
		}
		slog.Error("failed to link address", "address", normalizedAddr, "user", userDID, "error", err)
		respondInternalError(c, "failed to link address")
		return
	}

	// Invalidate the RBAC permission cache for this user. Address ownership feeds
	// into contract-auto-claim and deploy-grant decisions, so a freshly linked
	// address may unlock (or lock) contract access on the next request.
	s.invalidateUserCacheByDID(c.Request.Context(), userDID)

	// Emit SIEM audit event. Escalate severity when the address was already
	// claimed by another DID — this may indicate key sharing or key compromise.
	if s.siemForwarder != nil {
		eventType := "eth_address_linked"
		details := fmt.Sprintf("address=%s link_type=user", normalizedAddr)
		if len(otherDIDs) > 0 {
			eventType = "eth_address_linked_collision"
			// Log count only in the SIEM event — full DID list is PII and must not
			// leave the system in forwarded events. Full list is in the internal log below.
			details = fmt.Sprintf("address=%s link_type=user existing_dids_count=%d",
				normalizedAddr, len(otherDIDs))
			slog.Warn("ETH address linked to multiple DIDs — possible key sharing or compromise",
				"address", normalizedAddr, "new_did", userDID, "existing_dids", otherDIDs)
		}
		s.siemForwarder.Send(audit.SIEMEvent{
			Timestamp: time.Now(),
			EventType: eventType,
			ActorID:   userDID,
			Action:    "eth_address_link",
			Outcome:   "success",
			Details:   details,
			SourceIP:  c.ClientIP(),
		})
	}

	// Resolve ENS name in background (non-blocking)
	if s.ensResolver != nil {
		go s.resolveAndStoreENS(normalizedAddr)
	}

	respondOK(c, gin.H{
		"message": "address linked successfully",
		"address": normalizedAddr,
	})
}

// handleGetEthAddresses handles GET /eth/addresses - list linked addresses for current user
//
// @Summary      List linked ETH addresses
// @Description  Lists the Ethereum addresses linked to the caller's DID, with verification time and any resolved ENS name.
// @Tags         ETH linking
// @Produce      json
// @Success      200 {object} apimodels.EthAddressListResponse
// @Failure      401 {object} apimodels.APIError "missing or invalid token"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/eth/addresses [get]
func (s *Server) handleGetEthAddresses(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		respondUnauthorized(c, errMissingIdentity)
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		respondUnauthorized(c, errInvalidIdentity)
		return
	}

	// Get linked addresses
	links, err := s.db.GetEthAddressesByDID(c.Request.Context(), userDID)
	if err != nil {
		slog.Error("failed to get addresses for user", "user", userDID, "error", err)
		respondInternalError(c, "failed to get addresses")
		return
	}

	// Convert to response format
	addresses := make([]apimodels.EthAddressResponse, 0, len(links))
	for _, link := range links {
		addresses = append(addresses, apimodels.EthAddressResponse{
			Address:       link.EthAddress,
			VerifiedAt:    link.VerifiedAt,
			ENSName:       link.ENSName,
			ENSResolvedAt: link.ENSResolvedAt,
		})
	}

	respondOK(c, gin.H{"addresses": addresses})
}

// handleDeleteEthAddress handles DELETE /eth/addresses/:address - unlink an address
//
// @Summary      Unlink an ETH address
// @Description  Revokes the link between the address and the caller's DID. A revoked link cannot be re-created without administrator intervention.
// @Tags         ETH linking
// @Produce      json
// @Param        address path string true "ETH address (0x-prefixed hex)"
// @Success      200 {object} apimodels.APIMessage
// @Failure      400 {object} apimodels.APIError "address parameter required"
// @Failure      401 {object} apimodels.APIError "missing or invalid token"
// @Failure      404 {object} apimodels.APIError "address not linked to your account"
// @Failure      500 {object} apimodels.APIError
// @Security     BearerAuth
// @Router       /api/v1/eth/addresses/{address} [delete]
func (s *Server) handleDeleteEthAddress(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		respondUnauthorized(c, errMissingIdentity)
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		respondUnauthorized(c, errInvalidIdentity)
		return
	}

	// Get and normalize the address
	address := c.Param("address")
	if address == "" {
		respondBadRequest(c, "address parameter required")
		return
	}
	normalizedAddr := strings.ToLower(address)

	// Revoke the link
	if err := s.db.RevokeEthAddressLink(c.Request.Context(), userDID, normalizedAddr); err != nil {
		if strings.Contains(err.Error(), "no matching link") {
			respondNotFound(c, "address not found or not linked to your account")
			return
		}
		respondInternalError(c, "failed to unlink address")
		return
	}

	// Revoking an address may change what contracts the user is permitted to
	// interact with (deploy-attribution, auto-grant). Drop the cached permissions
	// so the next request re-resolves them from the DB.
	s.invalidateUserCacheByDID(c.Request.Context(), userDID)

	respondMessage(c, "address unlinked successfully")
}

// handleRefreshENS handles POST /eth/addresses/:address/refresh-ens - refresh ENS name for an address
//
// @Summary      Refresh the ENS name of a linked address
// @Description  Re-resolves the ENS name for one of the caller's linked addresses and stores the result (which may be empty).
// @Tags         ETH linking
// @Produce      json
// @Param        address path string true "ETH address (0x-prefixed hex)"
// @Success      200 {object} apimodels.EthLinkENSResponse
// @Failure      400 {object} apimodels.APIError "address parameter required"
// @Failure      401 {object} apimodels.APIError "missing or invalid token"
// @Failure      404 {object} apimodels.APIError "address not linked to your account"
// @Failure      500 {object} apimodels.APIError
// @Failure      503 {object} apimodels.APIError "ENS resolver not configured"
// @Security     BearerAuth
// @Router       /api/v1/eth/addresses/{address}/refresh-ens [post]
func (s *Server) handleRefreshENS(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		respondUnauthorized(c, errMissingIdentity)
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		respondUnauthorized(c, errInvalidIdentity)
		return
	}

	// Get and normalize the address
	address := c.Param("address")
	if address == "" {
		respondBadRequest(c, "address parameter required")
		return
	}
	normalizedAddr := strings.ToLower(address)

	// Check ENS resolver is available
	if s.ensResolver == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ENS resolver not available"})
		return
	}

	// Verify the address is linked to this user (scope by DID to handle shared-address cases
	// where multiple DIDs are linked to the same address).
	link, err := s.db.GetEthAddressLinkForDID(c.Request.Context(), userDID, normalizedAddr)
	if err != nil {
		respondInternalError(c, "failed to get address")
		return
	}
	if link == nil {
		respondNotFound(c, "address not found or not linked to your account")
		return
	}

	// Resolve ENS name
	ensName, err := s.ensResolver.ResolveAddress(c.Request.Context(), normalizedAddr)
	if err != nil {
		respondInternalError(c, "failed to resolve ENS name")
		return
	}

	// Store the result (even if empty - it means no ENS name)
	var ensNamePtr *string
	if ensName != "" {
		ensNamePtr = &ensName
	}
	if err := s.db.UpdateENSName(c.Request.Context(), normalizedAddr, ensNamePtr); err != nil {
		respondInternalError(c, "failed to update ENS name")
		return
	}

	respondOK(c, gin.H{
		"address":  normalizedAddr,
		"ens_name": ensNamePtr,
	})
}

// invalidateUserCacheByDID looks up the RBAC user for a DID and drops their
// cached effective permissions (both layers). Silent no-op if the DID has no
// RBAC user record yet — nothing is cached for a user that doesn't exist.
func (s *Server) invalidateUserCacheByDID(ctx context.Context, did string) {
	user, err := s.db.GetUserByExternalID(ctx, did)
	if err != nil {
		slog.Warn("failed to look up user for cache invalidation", "did", did, "error", err)
		return
	}
	if user == nil {
		return
	}
	if err := s.rbacAccessCtrl.InvalidateUser(ctx, user.ID); err != nil {
		slog.Warn("failed to invalidate rbac cache", "user_id", user.ID, "error", err)
	}
}

// resolveAndStoreENS resolves the ENS name for an address and stores it in the database
// This is called in a goroutine after linking an address
func (s *Server) resolveAndStoreENS(address string) {
	if s.ensResolver == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ensName, err := s.ensResolver.ResolveAddress(ctx, address)
	if err != nil {
		// Log but don't fail - ENS resolution is optional
		return
	}

	var ensNamePtr *string
	if ensName != "" {
		ensNamePtr = &ensName
	}

	if err := s.db.UpdateENSName(ctx, address, ensNamePtr); err != nil {
		slog.Warn("failed to update ENS name", "address", address, "error", err)
	}
}
