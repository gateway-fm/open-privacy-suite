package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
)

// grantRequesterEligible applies the same requester and organization boundary
// to every disclosure read, including the legacy token routes. Grant lifetime
// and scope are checked by callers before returning data.
func (s *Server) grantRequesterEligible(ctx context.Context, gw *disclosure.GrantWithRequest, viewerDID string) bool {
	if gw == nil || gw.Grant == nil || gw.Request == nil || viewerDID == "" ||
		gw.Request.RequesterDID != viewerDID || gw.Request.Status != disclosure.StatusApproved ||
		disclosure.ViewerGrantsSuppressed(ctx) {
		return false
	}
	if org, pinned := viewerOrgScope(ctx); pinned && (org == "" || org != gw.Request.OrgID) {
		return false
	}
	member, err := s.db.IsUserInOrg(ctx, viewerDID, gw.Request.OrgID)
	if err != nil {
		slog.Error("disclosure: requester membership lookup failed", "grant_id", gw.Grant.ID, "err", err)
		return false
	}
	return member
}

// explorerGrant authenticates before looking up a grant, so its existence and
// state are never exposed to a non-holder. The activity endpoint historically
// returns 404 for inactive grants; other grant routes return 403 to the holder.
func (s *Server) explorerGrant(c *gin.Context, inactiveNotFound bool) (*disclosure.GrantWithRequest, bool) {
	if !disclosureGrantsApply(c) {
		respondNotFound(c, "grant not found")
		return nil, false
	}
	viewer := s.getViewerDIDFromRequest(c)
	if viewer == "" {
		respondUnauthorized(c, "authentication required")
		return nil, false
	}
	gw, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), c.Param("grant_id"))
	if err != nil || !s.grantRequesterEligible(c.Request.Context(), gw, viewer) {
		respondNotFound(c, "grant not found")
		return nil, false
	}
	if !gw.Grant.IsActive() {
		if inactiveNotFound {
			respondNotFound(c, "grant not found")
		} else {
			respondForbidden(c, "grant has been revoked or has expired")
		}
		return nil, false
	}
	scope, err := gw.Grant.Scope.ForRead()
	if err != nil {
		respondNotFound(c, "grant not found")
		return nil, false
	}
	gw.Grant.Scope = scope
	return gw, true
}

func (s *Server) grantAddressID(address, grantID string) string {
	var key []byte
	if s.config != nil {
		key = s.config.ExplorerPseudonymKey
	}
	return explorer.GenerateAddressIDKeyed(address, grantID, key)
}

func (s *Server) externalPseudonym(address, grantID string) string {
	return "External-" + strings.ToUpper(s.grantAddressID(address, grantID)[:4])
}

// grantSubjectAddress resolves only a current linked address of this grant's
// subject. Opaque IDs from another grant never resolve here.
func (s *Server) grantSubjectAddress(ctx context.Context, gw *disclosure.GrantWithRequest, addressID string) (string, error) {
	user, err := s.db.GetUser(ctx, gw.Request.TargetUserID)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", nil
	}
	links, err := s.db.GetEthAddressesByDID(ctx, user.ExternalID)
	if err != nil {
		return "", err
	}
	for _, link := range links {
		if s.grantAddressID(link.EthAddress, gw.Grant.ID) == addressID {
			return link.EthAddress, nil
		}
	}
	return "", nil
}

// recordGrantListRead retains one event per disclosed grant, while resolving
// the viewer once and normally writing the list in one database statement.
// Recovery for a concurrently deleted grant shares the same five-second budget.
func (s *Server) recordGrantListRead(c *gin.Context, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Second)
	defer cancel()
	viewer, err := s.db.GetUserByExternalID(ctx, s.getViewerDIDFromRequest(c))
	if err != nil || viewer == nil {
		slog.Error("disclosure: audit viewer lookup failed", "err", err)
		return
	}
	now, ip := time.Now(), c.ClientIP()
	events := make([]disclosure.Event, 0, len(counts))
	for grantID, count := range counts {
		events = append(events, disclosure.Event{
			GrantID: grantID, ViewerUserID: &viewer.ID,
			Action: disclosure.ActionListAddresses, ResourceType: disclosure.ResourceAddresses,
			DataSummary: &disclosure.DataSummary{RecordCount: count},
			ViewerIP:    ip, AccessedAt: now,
		})
	}
	if err := s.db.CreateDisclosureEvents(ctx, events); err != nil {
		slog.Error("disclosure: access audit write incomplete", "grants", len(events), "err", err)
	}
}

// recordGrantRead records data access against the grant UUID. The event carries
// counts, never transaction hashes or hidden addresses. Audit failures are
// logged; request cancellation cannot silently discard the evidence.
func (s *Server) recordGrantRead(c *gin.Context, grantID string, action disclosure.EventAction, resource disclosure.ResourceType, count int) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Second)
	defer cancel()
	viewer, err := s.db.GetUserByExternalID(ctx, s.getViewerDIDFromRequest(c))
	if err != nil || viewer == nil {
		slog.Error("disclosure: audit viewer lookup failed", "grant_id", grantID, "err", err)
		return
	}
	event := &disclosure.Event{
		GrantID: grantID, ViewerUserID: &viewer.ID, Action: action,
		ResourceType: resource, DataSummary: &disclosure.DataSummary{RecordCount: count},
		ViewerIP: c.ClientIP(), AccessedAt: time.Now(),
	}
	if err := s.db.CreateDisclosureEvent(ctx, event); err != nil {
		slog.Error("disclosure: access audit write failed", "grant_id", grantID, "action", action, "err", err)
	}
}

func grantTxDirection(tx explorer.Transaction, subject string) string {
	from := strings.EqualFold(tx.From, subject)
	to := tx.HasRecipient() && strings.EqualFold(*tx.To, subject)
	if from && to {
		return "self"
	}
	if from {
		return "out"
	}
	return "in"
}

// grantTxTimestamp supplies the block's chain time when an individual backend
// transaction lookup does not populate it. Local insertion time is never used.
func (s *Server) grantTxTimestamp(ctx context.Context, tx *explorer.Transaction) error {
	if tx.BlockTimestamp != 0 {
		return nil
	}
	block, err := s.explorerStore.GetBlock(ctx, tx.BlockNumber)
	if err != nil {
		return err
	}
	if block == nil {
		return fmt.Errorf("transaction block unavailable")
	}
	tx.BlockTimestamp = block.Timestamp
	return nil
}
