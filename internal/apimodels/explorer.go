package apimodels

// Spec-only response models for the explorer API (RD-1166).
//
// The explorer handlers in explorer_api.go mostly marshal real Go structs
// (explorer.Transaction, explorer.Block, ...) which are referenced directly
// from the @Success annotations. The handlers that respond through gin.H (map)
// literals have no Go type to reference; the structs below mirror those wire
// shapes exactly (same JSON keys and value types) so swaggo can emit a schema.
//
// These types are never constructed at runtime — they exist purely as
// annotation targets. This file must compile standalone: plain structs only,
// no imports. For the "data + total" list wrappers, the `data` field is a
// placeholder ([]interface{}); each @Success line overrides it with the real
// element type via swag's composition syntax, e.g.
// `ExplorerListResponse{data=[]explorer.Transaction}`.

// ExplorerChainIDResponse is the GET /api/v1/explorer/chain-id body.
type ExplorerChainIDResponse struct {
	ChainID int `json:"chain_id" example:"1"`
}

// ExplorerBlockNumberResponse is the GET /api/v1/explorer/blocks/latest/number body.
type ExplorerBlockNumberResponse struct {
	Number uint64 `json:"number" example:"1234567"`
}

// ExplorerIsContractResponse is the GET /api/v1/explorer/addresses/{address}/is-contract body.
type ExplorerIsContractResponse struct {
	IsContract bool `json:"is_contract" example:"true"`
}

// ExplorerABIUpdateResponse is the POST /api/v1/explorer/addresses/{address}/abi success body.
type ExplorerABIUpdateResponse struct {
	Success bool   `json:"success" example:"true"`
	Address string `json:"address" example:"0x0000000000000000000000000000000000000001"`
}

// ExplorerListResponse is the generic "data + total" envelope returned by the
// list endpoints that never expose a raw DB total (transactions/paginated,
// address internal/logs, tokens, token holders/transfers, all transfers,
// accounts). `total` is the count of rows in `data` after visibility filtering,
// NOT the raw table total. `data` is a placeholder — each @Success overrides it
// with the concrete element type.
type ExplorerListResponse struct {
	Data  []interface{} `json:"data"`
	Total int64         `json:"total" example:"25"`
}

// ExplorerCatchupProgressResponse is the GET /api/v1/explorer/sync/catchup body.
// The proxy has no indexer of its own, so this is a static "not running" shape.
type ExplorerCatchupProgressResponse struct {
	Processed       int  `json:"processed" example:"0"`
	Total           int  `json:"total" example:"0"`
	PercentComplete int  `json:"percentComplete" example:"0"`
	IsRunning       bool `json:"isRunning" example:"false"`
}
