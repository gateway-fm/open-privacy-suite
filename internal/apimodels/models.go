package apimodels

// Spec-only response models (RD-1166). Handlers that respond through the
// gin.H-based helpers in http_responses.go have no Go type to reference from
// swaggo annotations; these mirror those wire shapes exactly. They are never
// constructed at runtime — annotation references only.

// HealthResponse is the GET /health body.
type HealthResponse struct {
	Status string `json:"status" example:"ok"`
}

// APIError is the uniform error envelope produced by the respond* helpers.
// Messages are intentionally opaque (RD-934): internal error details never
// reach the client.
type APIError struct {
	Error string `json:"error" example:"invalid request"`
}

// APIMessage is the uniform success envelope of respondMessage/respondDeleted.
type APIMessage struct {
	Message string `json:"message" example:"operation completed"`
}

// EthLinkVerifyResponse is the success body of POST /api/v1/eth/link/verify.
type EthLinkVerifyResponse struct {
	Message string `json:"message" example:"address linked successfully"`
	Address string `json:"address" example:"0x70997970c51812dc3a010c7d01b50e0d17dc79c8"`
}

// EthAddressListResponse is the success body of GET /api/v1/eth/addresses.
type EthAddressListResponse struct {
	Addresses []EthAddressResponse `json:"addresses"`
}

// EthLinkENSResponse is the success body of POST /api/v1/eth/addresses/{address}/refresh-ens.
type EthLinkENSResponse struct {
	Address string  `json:"address" example:"0x70997970c51812dc3a010c7d01b50e0d17dc79c8"`
	ENSName *string `json:"ens_name" example:"alice.eth"`
}
