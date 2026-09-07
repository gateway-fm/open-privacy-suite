package apimodels

// Transport models relocated from server.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// StatusResponse represents the system status
type StatusResponse struct {
	Proxy    ProxyStatus    `json:"proxy"`
	Node     NodeStatus     `json:"node"`
	Security SecurityStatus `json:"security"`
	Methods  MethodsStatus  `json:"methods"`
}

// MethodsStatus exposes available RPC methods to the admin frontend.
type MethodsStatus struct {
	ExtraNamespaces map[string][]string          `json:"extra_namespaces,omitempty"`
	ExtraWildcards  map[string]ExtraWildcardInfo `json:"extra_wildcards,omitempty"`
}

// ExtraWildcardInfo describes a chain namespace running in prefix-wildcard mode.
// The frontend uses this to render a single togglable picker entry per
// wildcard-enabled namespace, plus a read-only view of the deny list.
type ExtraWildcardInfo struct {
	Prefix string   `json:"prefix"`
	Deny   []string `json:"deny,omitempty"`
}

// ProxyStatus represents the proxy status
type ProxyStatus struct {
	Status string `json:"status"`
	Port   string `json:"port"`
}

// SecurityStatus represents the security configuration status
type SecurityStatus struct {
	TravelRuleEnabled bool `json:"travel_rule_enabled"`
	// ComplianceDefaultMode is the cluster-wide default compliance enforcement
	// mode ("enforce" | "monitor"). Per-org config may override it. (RD-1044)
	ComplianceDefaultMode string `json:"compliance_default_mode"`
}

// NodeStatus represents the node status
type NodeStatus struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// TestRequestInput represents the input for test request
type TestRequestInput struct {
	Method   string        `json:"method"`
	Params   []interface{} `json:"params"`
	JWTToken string        `json:"jwt_token,omitempty"`
	OrgID    string        `json:"org_id,omitempty"`
}

// TestRequestResponse represents the response for test request
type TestRequestResponse struct {
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	LatencyMs int64       `json:"latency_ms,omitempty"`
	Identity  string      `json:"identity,omitempty"` // The identity used for access control
}

// UserOrgResponse represents an organization the user belongs to.
type UserOrgResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}
