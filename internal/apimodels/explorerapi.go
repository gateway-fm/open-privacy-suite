package apimodels

import (
	"time"

	"privacy-proxy/internal/explorer"
)

// Transport models relocated from explorer_api.go, explorer_grants.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// OwnAddress represents an address owned by the viewer
type OwnAddress struct {
	Address string  `json:"address"`
	ENSName *string `json:"ens_name,omitempty"`
}

// DisclosedAddress represents an address disclosed to the viewer via a grant
// SECURITY: For non-full disclosures, Address contains the pseudonym or placeholder, NOT the real address
type DisclosedAddress struct {
	Address         string     `json:"address"`    // Pseudonym for pseudonymous, "[PRIVATE]" for redacted, real for full
	AddressID       string     `json:"address_id"` // Opaque identifier for routing (hash of real address)
	OwnerDID        string     `json:"owner_did"`
	DisclosureLevel string     `json:"disclosure_level"`
	GrantID         string     `json:"grant_id"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ENSName         *string    `json:"ens_name,omitempty"` // Only included for full disclosure
}

// ViewableAddressesResponse is the response for GET /api/v1/explorer/viewable-addresses
type ViewableAddressesResponse struct {
	ViewerWallet       string             `json:"viewer_wallet"`
	ViewerDID          string             `json:"viewer_did,omitempty"`
	OwnAddresses       []OwnAddress       `json:"own_addresses"`
	DisclosedAddresses []DisclosedAddress `json:"disclosed_addresses"`
}

// ResolveAddressResponse is returned when resolving an address_id.
// SECURITY: RealAddress is only populated for "full" disclosure level.
type ResolveAddressResponse struct {
	RealAddress     *string  `json:"real_address,omitempty"`
	DisclosureLevel string   `json:"disclosure_level"`
	GrantID         string   `json:"grant_id"`
	Pseudonym       string   `json:"pseudonym,omitempty"`     // For pseudonymous, the display name to use
	ScopeMethods    []string `json:"scope_methods,omitempty"` // Methods from grant scope (e.g. "transaction_history", "activity_logs")
}

// GrantTransactionsResponse is the response for GET /api/v1/explorer/grant/:grant_id/:address_id/transactions
type GrantTransactionsResponse struct {
	Transactions    []GrantTransaction `json:"transactions"`
	DisclosureLevel string             `json:"disclosure_level"`
	AddressLabels   map[string]string  `json:"address_labels"`
	// NextCursor is the opaque continuation to pass back as ?cursor= (RD-1149).
	// Its presence is the sole "more pages" signal: a client keeps paging while
	// next_cursor is present and stops when it is omitted (feed exhausted). It is
	// deliberately the only pagination field — there is no has_more, which would
	// only ever be `next_cursor != ""` and could drift from it.
	NextCursor string `json:"next_cursor,omitempty"`
}

// AddressTransactionsResponse wraps a page of an address's transactions with the
// opaque pagination cursor (RD-1149). NextCursor follows the same token-only
// contract as GrantTransactionsResponse: present ⇒ more pages, omitted ⇒ done.
type AddressTransactionsResponse struct {
	Transactions []explorer.Transaction `json:"transactions"`
	NextCursor   string                 `json:"next_cursor,omitempty"`
}

// AddressTransfersResponse wraps a page of an address's token transfers with the
// opaque pagination cursor (RD-1149). Same token-only contract as above.
type AddressTransfersResponse struct {
	Transfers  []explorer.TokenTransfer `json:"transfers"`
	NextCursor string                   `json:"next_cursor,omitempty"`
}

// GrantTransaction represents a transaction in the context of a disclosure grant.
// For pseudonymous grants, addresses are replaced with pseudonyms and financial data is hidden.
type GrantTransaction struct {
	TxHash         *string `json:"tx_hash,omitempty"` // only for full disclosure
	BlockNumber    uint64  `json:"block_number"`
	BlockTimestamp uint64  `json:"block_timestamp,omitempty"`
	Direction      string  `json:"direction"` // "in", "out", "self"
	From           string  `json:"from"`
	To             string  `json:"to,omitempty"`
	Value          string  `json:"value"`
	GasUsed        uint64  `json:"gas_used"`
	Status         int     `json:"status"`
}

// GrantActivityLogsResponse is the response for GET /api/v1/explorer/grant/:grant_id/activity
type GrantActivityLogsResponse struct {
	Logs   []GrantActivityLogEntry `json:"logs"`
	Total  int                     `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

// GrantActivityLogEntry is a stripped-down log entry safe for grant holders.
// SECURITY: Does NOT include request_params, ip_address, correlation_id, or entry_hash.
type GrantActivityLogEntry struct {
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"` // RFC 3339
}
