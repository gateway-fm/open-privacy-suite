package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerComplianceTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerComplianceConfig(s, client)
	registerUpdateComplianceConfig(s, client)
	registerListTokenPrices(s, client)
	registerSetTokenPrice(s, client)
	registerDeleteTokenPrice(s, client, confirms)
	registerSystemTokenPrices(s, client)
	registerListSanctions(s, client)
	registerAddSanction(s, client)
	registerDeleteSanction(s, client, confirms)
	registerListAddressThresholds(s, client)
	registerSetAddressThreshold(s, client)
	registerDeleteAddressThreshold(s, client, confirms)
	registerComplianceLogs(s, client)
	registerComplianceCurrency(s, client)
	registerSetComplianceCurrency(s, client)
	registerListTravelRuleRecords(s, client)
	registerCreateTravelRuleRecord(s, client)
	registerDeleteTravelRuleRecord(s, client, confirms)
}

type orgIDArgs struct {
	OrgID string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
}

func registerComplianceConfig(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "compliance_config",
		Description: "Get compliance configuration for an organization (enabled, threshold).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args orgIDArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/config", args.OrgID))
		if err != nil {
			return errorResult("getting compliance config: %v", err)
		}
		return textResult(section("Compliance Config"), prettyJSON(json.RawMessage(raw)))
	})
}

type updateComplianceConfigArgs struct {
	OrgID         string   `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Enabled       *bool    `json:"enabled,omitempty" jsonschema:"enable/disable compliance"`
	ThresholdFiat *float64 `json:"threshold_fiat,omitempty" jsonschema:"fiat threshold for travel rule"`
}

func registerUpdateComplianceConfig(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_compliance_config",
		Description: "Update compliance configuration for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updateComplianceConfigArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		body := map[string]any{}
		if args.Enabled != nil {
			body["enabled"] = *args.Enabled
		}
		if args.ThresholdFiat != nil {
			body["threshold_fiat"] = *args.ThresholdFiat
		}
		raw, err := client.put(pathf("/api/v1/admin/orgs/%s/compliance/config", args.OrgID), body)
		if err != nil {
			return errorResult("updating compliance config: %v", err)
		}
		return textResult(section("Compliance Config Updated"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerListTokenPrices(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_token_prices",
		Description: "List token prices configured for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args orgIDArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/tokens", args.OrgID))
		if err != nil {
			return errorResult("listing token prices: %v", err)
		}
		return textResult(section("Token Prices"), prettyJSON(json.RawMessage(raw)))
	})
}

type setTokenPriceArgs struct {
	OrgID       string             `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address     string             `json:"address" jsonschema:"token contract address (0x-prefixed, required)"`
	Symbol      string             `json:"symbol" jsonschema:"token symbol e.g. ETH, USDT (required)"`
	Decimals    *int               `json:"decimals,omitempty" jsonschema:"token decimals (default 18)"`
	Prices      map[string]float64 `json:"prices" jsonschema:"price map by currency e.g. {usd: 3500, eur: 3200} (required unless coingecko_id set)"`
	CoingeckoID string             `json:"coingecko_id,omitempty" jsonschema:"CoinGecko ID for auto-pricing: ethereum, tether, or usd-coin"`
}

func registerSetTokenPrice(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_token_price",
		Description: "Set or update a token's price for compliance. Provide prices map for manual pricing, or coingecko_id for auto-pricing. Valid currencies: usd, eur, chf, gbp, aed.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setTokenPriceArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" || args.Symbol == "" {
			return errorResult("org_id, address, and symbol are required")
		}
		if len(args.Prices) == 0 && args.CoingeckoID == "" {
			return errorResult("either prices or coingecko_id is required")
		}
		decimals := 18
		if args.Decimals != nil {
			decimals = *args.Decimals
		}
		body := map[string]any{
			"symbol":   args.Symbol,
			"decimals": decimals,
		}
		if args.Prices != nil {
			body["prices"] = args.Prices
		}
		if args.CoingeckoID != "" {
			body["coingecko_id"] = args.CoingeckoID
		}
		raw, err := client.put(pathf("/api/v1/admin/orgs/%s/compliance/tokens/%s", args.OrgID, args.Address), body)
		if err != nil {
			return errorResult("setting token price: %v", err)
		}
		return textResult(section("Token Price Set"), prettyJSON(json.RawMessage(raw)))
	})
}

type deleteTokenPriceArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address      string `json:"address" jsonschema:"token contract address (required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token"`
}

func registerDeleteTokenPrice(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_token_price",
		Description: "Remove a token price. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteTokenPriceArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_token_price", map[string]any{"org_id": args.OrgID, "address": args.Address})
			return textResult(section("Confirm Delete Token Price"), kvf("Token", args.Address), "", kvf("Confirmation Token", token))
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_token_price")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/orgs/%s/compliance/tokens/%s", confirmParam(params, "org_id"), confirmParam(params, "address")))
		if err != nil {
			return errorResult("deleting token price: %v", err)
		}
		return textResult(section("Token Price Removed"))
	})
}

func registerSystemTokenPrices(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "system_token_prices",
		Description: "Get system-wide token prices (fetched from CoinGecko).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/compliance/system-token-prices")
		if err != nil {
			return errorResult("getting system token prices: %v", err)
		}
		return textResult(section("System Token Prices"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerListSanctions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_sanctions",
		Description: "List sanctioned addresses.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/compliance/sanctions")
		if err != nil {
			return errorResult("listing sanctions: %v", err)
		}
		return textResult(section("Sanctioned Addresses"), prettyJSON(json.RawMessage(raw)))
	})
}

type addSanctionArgs struct {
	Address string `json:"address" jsonschema:"ETH address to sanction (0x-prefixed, required)"`
	Reason  string `json:"reason,omitempty" jsonschema:"reason for sanctioning"`
	Source  string `json:"source,omitempty" jsonschema:"source of sanction (e.g. OFAC)"`
}

func registerAddSanction(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "add_sanction",
		Description: "Add an address to the sanctions list.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addSanctionArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		body := map[string]any{"address": args.Address}
		if args.Reason != "" {
			body["reason"] = args.Reason
		}
		if args.Source != "" {
			body["source"] = args.Source
		}
		raw, err := client.post("/api/v1/admin/compliance/sanctions", body)
		if err != nil {
			return errorResult("adding sanction: %v", err)
		}
		return textResult(section("Sanction Added"), prettyJSON(json.RawMessage(raw)))
	})
}

type deleteSanctionArgs struct {
	ID           string `json:"id" jsonschema:"sanction record ID (required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token"`
}

func registerDeleteSanction(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_sanction",
		Description: "Remove an address from the sanctions list. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteSanctionArgs) (*mcp.CallToolResult, any, error) {
		if args.ID == "" {
			return errorResult("id is required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_sanction", map[string]any{"id": args.ID})
			return textResult(section("Confirm Delete Sanction"), kvf("ID", args.ID), "", kvf("Confirmation Token", token))
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_sanction")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/compliance/sanctions/%s", confirmParam(params, "id")))
		if err != nil {
			return errorResult("deleting sanction: %v", err)
		}
		return textResult(section("Sanction Removed"))
	})
}

type orgAddressArgs struct {
	OrgID   string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address string `json:"address" jsonschema:"ETH address (0x-prefixed)"`
}

func registerListAddressThresholds(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_address_thresholds",
		Description: "List risk-based address threshold overrides for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args orgIDArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/address-thresholds", args.OrgID))
		if err != nil {
			return errorResult("listing address thresholds: %v", err)
		}
		return textResult(section("Address Thresholds"), prettyJSON(json.RawMessage(raw)))
	})
}

type setAddressThresholdArgs struct {
	OrgID         string  `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address       string  `json:"address" jsonschema:"ETH address (0x-prefixed, required)"`
	ThresholdFiat float64 `json:"threshold_fiat" jsonschema:"fiat threshold override"`
}

func registerSetAddressThreshold(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_address_threshold",
		Description: "Set a risk-based threshold override for a specific address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setAddressThresholdArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		raw, err := client.put(pathf("/api/v1/admin/orgs/%s/compliance/address-thresholds/%s", args.OrgID, args.Address), map[string]any{
			"threshold_fiat": args.ThresholdFiat,
		})
		if err != nil {
			return errorResult("setting address threshold: %v", err)
		}
		return textResult(section("Address Threshold Set"), prettyJSON(json.RawMessage(raw)))
	})
}

type deleteAddressThresholdArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Address      string `json:"address" jsonschema:"ETH address (required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token"`
}

func registerDeleteAddressThreshold(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_address_threshold",
		Description: "Remove an address threshold override. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteAddressThresholdArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Address == "" {
			return errorResult("org_id and address are required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_address_threshold", map[string]any{"org_id": args.OrgID, "address": args.Address})
			return textResult(section("Confirm Delete Threshold"), kvf("Address", args.Address), "", kvf("Confirmation Token", token))
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_address_threshold")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/orgs/%s/compliance/address-thresholds/%s", confirmParam(params, "org_id"), confirmParam(params, "address")))
		if err != nil {
			return errorResult("deleting address threshold: %v", err)
		}
		return textResult(section("Address Threshold Removed"))
	})
}

type complianceLogsArgs struct {
	OrgID  string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries (default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

func registerComplianceLogs(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "compliance_logs",
		Description: "Query compliance decision logs for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args complianceLogsArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		limit := args.Limit
		if limit == 0 {
			limit = 50
		}
		raw, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/logs", args.OrgID), pageQuery(limit, args.Offset))
		if err != nil {
			return errorResult("getting compliance logs: %v", err)
		}
		return textResult(section("Compliance Logs"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerComplianceCurrency(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "compliance_currency",
		Description: "Get the base currency for compliance calculations.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/compliance/currency")
		if err != nil {
			return errorResult("getting currency: %v", err)
		}
		return textResult(section("Compliance Currency"), prettyJSON(json.RawMessage(raw)))
	})
}

type setCurrencyArgs struct {
	Currency string `json:"currency" jsonschema:"base currency code (e.g. USD, EUR, required)"`
}

func registerSetComplianceCurrency(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "set_compliance_currency",
		Description: "Set the base currency for compliance calculations. Valid: usd, eur, chf, gbp, aed.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setCurrencyArgs) (*mcp.CallToolResult, any, error) {
		if args.Currency == "" {
			return errorResult("currency is required")
		}
		raw, err := client.put("/api/v1/admin/compliance/currency", map[string]any{"currency": strings.ToLower(args.Currency)})
		if err != nil {
			return errorResult("setting currency: %v", err)
		}
		return textResult(section("Currency Updated"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerListTravelRuleRecords(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_travel_rule_records",
		Description: "List IVMS101 travel rule records for an organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args orgIDArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/orgs/%s/compliance/travel-rule-records", args.OrgID))
		if err != nil {
			return errorResult("listing travel rule records: %v", err)
		}
		return textResult(section("Travel Rule Records"), prettyJSON(json.RawMessage(raw)))
	})
}

type createTravelRuleArgs struct {
	OrgID string         `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Data  map[string]any `json:"data" jsonschema:"IVMS101 record data (required)"`
}

func registerCreateTravelRuleRecord(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_travel_rule_record",
		Description: "Create an IVMS101 travel rule record.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createTravelRuleArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.Data == nil {
			return errorResult("org_id and data are required")
		}
		raw, err := client.post(pathf("/api/v1/admin/orgs/%s/compliance/travel-rule-records", args.OrgID), args.Data)
		if err != nil {
			return errorResult("creating travel rule record: %v", err)
		}
		return textResult(section("Travel Rule Record Created"), prettyJSON(json.RawMessage(raw)))
	})
}

type deleteTravelRuleArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	ID           string `json:"id" jsonschema:"record ID (required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token"`
}

func registerDeleteTravelRuleRecord(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_travel_rule_record",
		Description: "Delete a travel rule record. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteTravelRuleArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" || args.ID == "" {
			return errorResult("org_id and id are required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_travel_rule_record", map[string]any{"org_id": args.OrgID, "id": args.ID})
			return textResult(section("Confirm Delete Travel Rule Record"), kvf("ID", args.ID), "", kvf("Confirmation Token", token))
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_travel_rule_record")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/orgs/%s/compliance/travel-rule-records/%s", confirmParam(params, "org_id"), confirmParam(params, "id")))
		if err != nil {
			return errorResult("deleting travel rule record: %v", err)
		}
		return textResult(section("Travel Rule Record Deleted"))
	})
}
