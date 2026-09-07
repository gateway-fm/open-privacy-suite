package apimodels

// Transport models relocated from dev_deploy_demo.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// DeployDemoERC20Request is the request body for deploying a DemoERC20 token.
type DeployDemoERC20Request struct {
	OrgID string `json:"org_id"` // optional - auto-register to this org
	Name  string `json:"name"`   // optional - contract name, defaults to "DemoERC20"
}

// DeployDemoERC20Response is the response from deploying a DemoERC20 token.
type DeployDemoERC20Response struct {
	Address    string `json:"address"`
	TxHash     string `json:"tx_hash"`
	Registered bool   `json:"registered"`
	Name       string `json:"name"`
}
