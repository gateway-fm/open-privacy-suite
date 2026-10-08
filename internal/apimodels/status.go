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
	// ExtraNamespaces maps each operator-configured namespace label to its
	// method names (aliased and passthrough entries).
	ExtraNamespaces map[string][]string `json:"extra_namespaces,omitempty"`
	// ExtraPassthrough lists the operator methods forwarded unfiltered (no
	// per-address access check, no response filtering, no tracing). A group
	// reaches them only by listing them by name.
	ExtraPassthrough []string `json:"extra_passthrough,omitempty"`
	// SupportedMethods lists every method a group's allowed_methods may hold
	// (built-in methods plus the operator methods above), sorted. Any other
	// stored entry is refused at request time and rejected on save.
	SupportedMethods []string `json:"supported_methods"`
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
