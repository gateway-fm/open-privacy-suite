package apimodels

// Spec-only response models for the auth / OAuth-SSO / dev handlers (RD-1166).
//
// These mirror the wire shapes of handlers that respond with `gin.H` or other
// anonymous JSON objects and therefore have no runtime Go type for swaggo to
// reference. They are never constructed at runtime — annotation targets only.
//
// Kept import-free (compiles standalone): the Privado authorization-request
// message that some responses embed is typed as a free-form object
// (`map[string]interface{}`) rather than importing the iden3 protocol package.
// Its concrete shape is the wallet-facing iden3comm AuthorizationRequestMessage.

// OAuthMockCompleteResponse is the success body of
// POST /oauth/session/{id}/mock-complete (dev builds only).
type OAuthMockCompleteResponse struct {
	OK  bool   `json:"ok" example:"true"`
	DID string `json:"did" example:"did:privado:mock_1717000000000000000"`
}

// OAuthSessionInfoResponse is the success body of GET /oauth/session/{id}/info.
// auth_request carries the Privado authorization request the login page renders
// as a QR code; allow_mock reports whether the dev mock-complete path is offered.
type OAuthSessionInfoResponse struct {
	AuthRequest map[string]interface{} `json:"auth_request"`
	AllowMock   bool                   `json:"allow_mock" example:"false"`
}

// OAuthAuthorizeJSONResponse is the JSON success body of GET /oauth/authorize
// for non-browser clients (browser clients receive a 302 redirect instead).
// The client polls /oauth/session/{id}/status and renders auth_request as a QR
// code.
type OAuthAuthorizeJSONResponse struct {
	OAuthSessionID string                 `json:"oauth_session_id" example:"3b1e...c7"`
	AuthSessionID  string                 `json:"auth_session_id" example:"9f2a...41"`
	AuthRequest    map[string]interface{} `json:"auth_request"`
}

// OAuthCallbackResponse is the success body of POST /oauth/callback. redirect_url
// is the client's redirect_uri with the authorization code and state appended.
type OAuthCallbackResponse struct {
	Status      string `json:"status" example:"success"`
	RedirectURL string `json:"redirect_url" example:"https://client.example.com/callback?code=<code>&state=<state>"`
}

// TestIdentity mirrors the TestIdentity wire shape (dev builds only). The real
// TestIdentity lives in the mockauth-tagged dev_test_identities.go, so it is
// absent from default (non-mockauth) builds; this untagged spec-only copy keeps
// the response model resolvable in every build and by the spec generator.
type TestIdentity struct {
	DID       string   `json:"did" example:"did:test:alice"`
	Name      string   `json:"name" example:"Alice"`
	Note      string   `json:"note,omitempty" example:"treasury signer"`
	Addresses []string `json:"addresses"`
	Orgs      []string `json:"orgs"`
}

// TestIdentitiesResponse is the success body of GET /api/v1/dev/test-identities
// (dev builds only).
type TestIdentitiesResponse struct {
	Identities []TestIdentity `json:"identities"`
}
