package explorer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// VisibilityLevel represents how much of an address's data is visible
type VisibilityLevel string

const (
	VisibilityFull         VisibilityLevel = "full"
	VisibilityPseudonymous VisibilityLevel = "pseudonymous"
	VisibilityRedacted     VisibilityLevel = "redacted"
	VisibilityHidden       VisibilityLevel = "hidden"
)

// VisibilityReason explains why an address has certain visibility
type VisibilityReason string

const (
	ReasonOwnAddress          VisibilityReason = "own_address"
	ReasonDisclosureGrant     VisibilityReason = "disclosure_grant"
	ReasonPublicAddress       VisibilityReason = "public_address"
	ReasonNoAccess            VisibilityReason = "no_access"
	ReasonRBACGroupMember     VisibilityReason = "rbac_group_member"
	ReasonParticipantOverride VisibilityReason = "participant_override"
	ReasonVisibleToGrant      VisibilityReason = "visible_to_grant"
)

// AddressVisibility represents the visibility status of a single address
type AddressVisibility struct {
	Address   string           `json:"address"`
	Visible   bool             `json:"visible"`
	Level     VisibilityLevel  `json:"level"`
	Reason    VisibilityReason `json:"reason"`
	Pseudonym *string          `json:"pseudonym,omitempty"`
	GrantID   *string          `json:"grant_id,omitempty"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
}

// GeneratePseudonym creates a stable, non-reversible pseudonym for an address.
//
// RD-1164 #8: the 4-letter identifier is derived from HMAC-SHA256(key, address),
// NOT from the address's own hex nibbles. The previous scheme mapped the first
// 4 real nibbles to letters, which leaked the first 2 address bytes and was
// trivially invertible. HMAC output leaks nothing about the address and cannot
// be inverted, while staying deterministic per address so the explorer keeps a
// stable "Address-XXXX" alias (consistency the UI and grant views rely on).
//
// When key is empty the HMAC is still non-reversible, but a candidate address
// can be recomputed and matched; set EXPLORER_PSEUDONYM_KEY in production to
// make the pseudonym non-enumerable as well.
func GeneratePseudonym(address string, key []byte) string {
	addr := strings.ToLower(strings.TrimPrefix(strings.ToLower(address), "0x"))
	if len(addr) < 4 {
		return "Address-Unknown"
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(addr))
	sum := mac.Sum(nil)
	letters := make([]byte, 4)
	for i := 0; i < 4; i++ {
		letters[i] = 'A' + (sum[i] & 0x0f) // low nibble of each HMAC byte → 'A'..'P'
	}
	return "Address-" + string(letters)
}

// StrictAllowlist returns the explorer list allowlist of the strict read
// profile (RD-1299) from a viewer's detailed visibility: the viewer's own
// linked addresses and addresses under an approved disclosure grant, lowercased
// and sorted. Visibility through a contract grant, an admin role or a visibleTo
// share adds nothing. An empty map (for example after a failed lookup) yields
// an empty allowlist, which hides every row.
func StrictAllowlist(detailed map[string]AddressVisibility) []string {
	out := make([]string, 0, len(detailed))
	for addr, meta := range detailed {
		if meta.Reason == ReasonOwnAddress || meta.Reason == ReasonDisclosureGrant {
			out = append(out, strings.ToLower(addr))
		}
	}
	sort.Strings(out)
	return out
}

// GenerateAddressID creates an opaque identifier for an address that can be used for routing.
// The ID is derived from the address and grant ID to be unique per grant.
// SECURITY: This allows routing without revealing the real address.
func GenerateAddressID(address string, grantID string) string {
	data := strings.ToLower(address) + ":" + grantID
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // 16 hex chars
}
