package apimodels

// Transport models relocated from oauth.go (RD-1265).
// These describe the wire contract; the schema names in the published
// OpenAPI document derive from this package, not from handler layout.

// OAuthTokenRequest represents the request body for /oauth/token
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" binding:"required"`
	Code         string `json:"code" form:"code" binding:"required"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" binding:"required"`
	ClientID     string `json:"client_id" form:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" form:"client_secret"` // RD-1006 client_secret_post; client_secret_basic also accepted via HTTP Basic
}

// OAuthTokenResponse represents the response from /oauth/token
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// OAuthErrorResponse represents an OAuth error response
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthSessionStatusResponse represents the response for OAuth session status polling
type OAuthSessionStatusResponse struct {
	Completed   bool   `json:"completed"`
	RedirectURL string `json:"redirect_url,omitempty"`
}
