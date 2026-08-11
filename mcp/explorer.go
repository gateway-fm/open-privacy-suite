package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerExplorerTools(s *mcp.Server, client *httpClient) {
	registerExplorerSyncStatus(s, client)
	registerExplorerBlocks(s, client)
	registerExplorerBlock(s, client)
	registerExplorerTransactions(s, client)
	registerExplorerTransaction(s, client)
	registerExplorerAddress(s, client)
	registerExplorerAddressTxs(s, client)
	registerExplorerAddressBalance(s, client)
	registerExplorerTokens(s, client)
	registerViewableAddresses(s, client)
}

func registerExplorerSyncStatus(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_sync_status",
		Description: "Get block explorer indexer sync status and progress.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/explorer/sync/status")
		if err != nil {
			return errorResult("getting sync status: %v", err)
		}
		return textResult(section("Explorer Sync Status"), prettyJSON(json.RawMessage(raw)))
	})
}

// Explorer responses are privacy-filtered per viewer, and the viewer identity
// is resolved ONLY from a validated user JWT (RD-1164 #7) — never from the
// admin token or a wallet param. Without viewer_jwt every explorer tool
// renders the anonymous view (mostly empty / redacted), which is correct but
// rarely what you want: pass a user's JWT to see the chain as that user.
type explorerListArgs struct {
	Limit     int    `json:"limit,omitempty" jsonschema:"max entries (default 20)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	ViewerJWT string `json:"viewer_jwt,omitempty" jsonschema:"user JWT to view as (explorer data is privacy-filtered per viewer; omit for the anonymous view)"`
}

func registerExplorerBlocks(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_blocks",
		Description: "List recent blocks from the explorer.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args explorerListArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.getAs("/api/v1/explorer/blocks", args.ViewerJWT, pageQuery(limit, args.Offset))
		if err != nil {
			return errorResult("listing blocks: %v", err)
		}
		var blocks []any
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Blocks") + "\n"
		for _, b := range blocks {
			block, ok := b.(map[string]any)
			if !ok {
				continue
			}
			lines += fmt.Sprintf("Block %-8.0f | ts %.0f | %.0f txs\n",
				getFloat(block, "number"),
				getFloat(block, "timestamp"),
				getFloat(block, "transactionCount"),
			)
		}

		return textResult(lines)
	})
}

type blockArgs struct {
	Number    string `json:"number" jsonschema:"block number or 'latest' (required)"`
	ViewerJWT string `json:"viewer_jwt,omitempty" jsonschema:"user JWT to view as (explorer data is privacy-filtered per viewer; omit for the anonymous view)"`
}

func registerExplorerBlock(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_block",
		Description: "Get details of a specific block by number.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args blockArgs) (*mcp.CallToolResult, any, error) {
		if args.Number == "" {
			return errorResult("number is required")
		}
		raw, err := client.getAs(pathf("/api/v1/explorer/blocks/%s", args.Number), args.ViewerJWT)
		if err != nil {
			return errorResult("getting block: %v", err)
		}
		return textResult(section("Block "+args.Number), prettyJSON(json.RawMessage(raw)))
	})
}

func registerExplorerTransactions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_transactions",
		Description: "List recent transactions from the explorer.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args explorerListArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.getAs("/api/v1/explorer/transactions", args.ViewerJWT, pageQuery(limit, args.Offset))
		if err != nil {
			return errorResult("listing transactions: %v", err)
		}
		var txs []any
		if err := json.Unmarshal(raw, &txs); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Transactions") + "\n"
		for i, t := range txs {
			if i >= 20 {
				lines += fmt.Sprintf("\n... and %d more", len(txs)-20)
				break
			}
			tx, ok := t.(map[string]any)
			if !ok {
				continue
			}
			lines += fmt.Sprintf("%s → %s (%.0f)\n",
				getString(tx, "from"),
				getString(tx, "to"),
				getFloat(tx, "value"),
			)
		}

		return textResult(lines)
	})
}

type txHashArgs struct {
	Hash      string `json:"hash" jsonschema:"transaction hash (0x-prefixed, required)"`
	ViewerJWT string `json:"viewer_jwt,omitempty" jsonschema:"user JWT to view as (explorer data is privacy-filtered per viewer; omit for the anonymous view)"`
}

func registerExplorerTransaction(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_transaction",
		Description: "Get details of a specific transaction by hash.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args txHashArgs) (*mcp.CallToolResult, any, error) {
		if args.Hash == "" {
			return errorResult("hash is required")
		}
		raw, err := client.getAs(pathf("/api/v1/explorer/transactions/%s", args.Hash), args.ViewerJWT)
		if err != nil {
			return errorResult("getting transaction: %v", err)
		}
		return textResult(section("Transaction"), prettyJSON(json.RawMessage(raw)))
	})
}

type addressArgs struct {
	Address   string `json:"address" jsonschema:"ETH address (0x-prefixed, required)"`
	ViewerJWT string `json:"viewer_jwt,omitempty" jsonschema:"user JWT to view as (explorer data is privacy-filtered per viewer; omit for the anonymous view)"`
}

func registerExplorerAddress(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_address",
		Description: "Get address statistics: transaction count, balance, contract info.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addressArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		raw, err := client.getAs(pathf("/api/v1/explorer/addresses/%s/stats", args.Address), args.ViewerJWT)
		if err != nil {
			return errorResult("getting address stats: %v", err)
		}
		return textResult(section("Address: "+args.Address), prettyJSON(json.RawMessage(raw)))
	})
}

type addressTxsArgs struct {
	Address   string `json:"address" jsonschema:"ETH address (0x-prefixed, required)"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max entries (default 20)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	ViewerJWT string `json:"viewer_jwt,omitempty" jsonschema:"user JWT to view as (explorer data is privacy-filtered per viewer; omit for the anonymous view)"`
}

func registerExplorerAddressTxs(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_address_transactions",
		Description: "Get transactions for a specific address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addressTxsArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.getAs(pathf("/api/v1/explorer/addresses/%s/transactions", args.Address), args.ViewerJWT, pageQuery(limit, args.Offset))
		if err != nil {
			return errorResult("getting address transactions: %v", err)
		}
		return textResult(section("Transactions for "+args.Address), prettyJSON(json.RawMessage(raw)))
	})
}

func registerExplorerAddressBalance(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_address_balance",
		Description: "Get ETH balance for an address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addressArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		raw, err := client.getAs(pathf("/api/v1/explorer/addresses/%s/balance", args.Address), args.ViewerJWT)
		if err != nil {
			return errorResult("getting balance: %v", err)
		}
		return textResult(section("Balance: "+args.Address), prettyJSON(json.RawMessage(raw)))
	})
}

func registerExplorerTokens(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_tokens",
		Description: "List tokens indexed by the explorer.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args explorerListArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.getAs("/api/v1/explorer/tokens", args.ViewerJWT, pageQuery(limit, args.Offset))
		if err != nil {
			return errorResult("listing tokens: %v", err)
		}
		return textResult(section("Tokens"), prettyJSON(json.RawMessage(raw)))
	})
}

type viewableAddressesArgs struct {
	ViewerJWT string `json:"viewer_jwt" jsonschema:"JWT of the user whose visibility set to list (required — the viewer is resolved from the validated JWT only, never from a wallet address)"`
	Wallet    string `json:"wallet,omitempty" jsonschema:"wallet address, echoed back for display only"`
}

func registerViewableAddresses(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "viewable_addresses",
		Description: "List the addresses a user can see: their own linked wallets plus addresses disclosed to them via active disclosure grants. Requires the user's JWT (viewer_jwt) — the server resolves the viewer only from a validated JWT, so a wallet address alone always yields the empty anonymous view.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args viewableAddressesArgs) (*mcp.CallToolResult, any, error) {
		if args.ViewerJWT == "" {
			return errorResult("viewer_jwt is required (the viewer is resolved from the validated JWT; without it the response is always empty)")
		}

		q := url.Values{}
		if args.Wallet != "" {
			q.Set("wallet", args.Wallet)
		}
		raw, err := client.getAs("/api/v1/explorer/viewable-addresses", args.ViewerJWT, q)
		if err != nil {
			return errorResult("getting viewable addresses: %v", err)
		}

		return textResult(section("Viewable Addresses"), prettyJSON(json.RawMessage(raw)))
	})
}
