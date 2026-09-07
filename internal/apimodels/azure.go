package apimodels

// Transport models relocated from auth_azure.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// AzureURLResponse is the response from GET /api/v1/auth/azure/url.
type AzureURLResponse struct {
	URL   string `json:"url"`
	State string `json:"state"`
}

// AzureCallbackRequest is the body for POST /api/v1/auth/azure/callback.
type AzureCallbackRequest struct {
	Code        string `json:"code" binding:"required"`
	State       string `json:"state" binding:"required"`
	RedirectURI string `json:"redirect_uri" binding:"required"`
}

// ProvidersResponse is the response from GET /api/v1/auth/providers.
type ProvidersResponse struct {
	Providers []string `json:"providers"`
	// Networks lists the iden3 "blockchain:network" identifiers this deployment
	// has a state resolver for (e.g. ["billions:main","privado:main"]). The
	// login UI uses it to avoid advertising a wallet network that cannot be
	// verified here (RD-1241). Always present, possibly empty.
	Networks []string `json:"networks"`
}

// AzureServicePrincipalRequest is the body for
// POST /api/v1/auth/azure/service-principal. The client obtains the Azure AD
// access token out-of-band via the OAuth2 client-credentials grant
// (`scope=<resource>/.default`) against its own tenant, then exchanges it here
// for our local tokens.
type AzureServicePrincipalRequest struct {
	AccessToken string `json:"access_token" binding:"required"`
}
