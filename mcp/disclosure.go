package main

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerDisclosureTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerCreateDisclosureRequest(s, client)
	registerListDisclosureRequests(s, client)
	registerGetDisclosureRequest(s, client)
	registerDeleteDisclosureRequest(s, client, confirms)
	registerListDisclosureGrants(s, client)
	registerRevokeDisclosureGrant(s, client, confirms)
	registerDisclosureCheckAccess(s, client)
	registerDisclosureGrantLogs(s, client)
	registerDisclosureGrantReport(s, client)
	registerDisclosureGrantSummary(s, client)
	registerDisclosureGrantEvents(s, client)
}

type createDisclosureReqArgs struct {
	RequesterDID    string   `json:"requester_did" jsonschema:"DID of the entity requesting disclosure (required)"`
	RequesterUserID string   `json:"requester_user_id,omitempty" jsonschema:"internal user ID of requester"`
	TargetUserID    string   `json:"target_user_id" jsonschema:"user ID whose data is being requested (UUID, required)"`
	OrgID           string   `json:"org_id,omitempty" jsonschema:"organization ID (defaults to default org)"`
	DisclosureLevel string   `json:"disclosure_level" jsonschema:"how much to reveal: full, pseudonymous, or redacted (required)"`
	Methods         []string `json:"methods,omitempty" jsonschema:"specific RPC methods to disclose"`
	Addresses       []string `json:"addresses,omitempty" jsonschema:"specific contract addresses to disclose"`
	Reason          string   `json:"reason" jsonschema:"reason for the disclosure request (required)"`
	LegalBasis      string   `json:"legal_basis,omitempty" jsonschema:"legal basis for disclosure"`
	ExpiresInHours  int      `json:"expires_in_hours,omitempty" jsonschema:"hours until expiry (0 = no expiration)"`
}

func registerCreateDisclosureRequest(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_disclosure_request",
		Description: "Create a disclosure request for access to a user's data (admin). Scope controls what is disclosed: disclosure_level (full/pseudonymous/redacted), optional methods and addresses filters.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createDisclosureReqArgs) (*mcp.CallToolResult, any, error) {
		if args.RequesterDID == "" || args.TargetUserID == "" || args.DisclosureLevel == "" || args.Reason == "" {
			return errorResult("requester_did, target_user_id, disclosure_level, and reason are required")
		}
		scope := map[string]any{
			"disclosure_level": args.DisclosureLevel,
		}
		if len(args.Methods) > 0 {
			scope["methods"] = args.Methods
		}
		if len(args.Addresses) > 0 {
			scope["addresses"] = args.Addresses
		}
		body := map[string]any{
			"requester_did":  args.RequesterDID,
			"target_user_id": args.TargetUserID,
			"scope":          scope,
			"reason":         args.Reason,
		}
		if args.RequesterUserID != "" {
			body["requester_user_id"] = args.RequesterUserID
		}
		if args.OrgID != "" {
			body["org_id"] = args.OrgID
		}
		if args.LegalBasis != "" {
			body["legal_basis"] = args.LegalBasis
		}
		if args.ExpiresInHours > 0 {
			body["expires_in_hours"] = args.ExpiresInHours
		}
		raw, err := client.post("/api/v1/admin/disclosure/requests", body)
		if err != nil {
			return errorResult("creating disclosure request: %v", err)
		}
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Disclosure Request Created"),
			kvf("ID", getString(r, "id")),
			kvf("Status", getString(r, "status")),
			kvf("Scope", prettyJSON(r["scope"])),
		)
	})
}

type listDisclosureReqArgs struct {
	Status string `json:"status,omitempty" jsonschema:"filter by status (pending, approved, rejected, expired, revoked)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries (default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

func registerListDisclosureRequests(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_disclosure_requests",
		Description: "List disclosure requests with optional status filter.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listDisclosureReqArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 50
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(limit))
		q.Set("offset", strconv.Itoa(args.Offset))
		if args.Status != "" {
			q.Set("status", args.Status)
		}

		raw, err := client.get("/api/v1/admin/disclosure/requests", q)
		if err != nil {
			return errorResult("listing disclosure requests: %v", err)
		}
		return textResult(section("Disclosure Requests"), prettyJSON(json.RawMessage(raw)))
	})
}

type getDisclosureReqArgs struct {
	RequestID string `json:"request_id" jsonschema:"disclosure request ID (UUID, required)"`
}

func registerGetDisclosureRequest(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_disclosure_request",
		Description: "Get details of a specific disclosure request.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getDisclosureReqArgs) (*mcp.CallToolResult, any, error) {
		if args.RequestID == "" {
			return errorResult("request_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/disclosure/requests/%s", args.RequestID))
		if err != nil {
			return errorResult("getting disclosure request: %v", err)
		}
		return textResult(section("Disclosure Request"), prettyJSON(json.RawMessage(raw)))
	})
}

type deleteDisclosureReqArgs struct {
	RequestID    string `json:"request_id" jsonschema:"disclosure request ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteDisclosureRequest(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_disclosure_request",
		Description: "Delete a disclosure request. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteDisclosureReqArgs) (*mcp.CallToolResult, any, error) {
		if args.RequestID == "" {
			return errorResult("request_id is required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_disclosure_request", map[string]any{"request_id": args.RequestID})
			return textResult(
				section("Confirm Delete Disclosure Request"),
				kvf("Request ID", args.RequestID),
				"",
				kvf("Confirmation Token", token),
				"Call delete_disclosure_request again with this confirm_token to execute.",
			)
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_disclosure_request")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/disclosure/requests/%s", confirmParam(params, "request_id")))
		if err != nil {
			return errorResult("deleting disclosure request: %v", err)
		}
		return textResult(section("Disclosure Request Deleted"))
	})
}

func registerListDisclosureGrants(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_disclosure_grants",
		Description: "List all active disclosure grants.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/disclosure/grants")
		if err != nil {
			return errorResult("listing disclosure grants: %v", err)
		}
		return textResult(section("Disclosure Grants"), prettyJSON(json.RawMessage(raw)))
	})
}

type revokeGrantArgs struct {
	GrantID      string `json:"grant_id" jsonschema:"disclosure grant ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerRevokeDisclosureGrant(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "revoke_disclosure_grant",
		Description: "Revoke a disclosure grant. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args revokeGrantArgs) (*mcp.CallToolResult, any, error) {
		if args.GrantID == "" {
			return errorResult("grant_id is required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("revoke_disclosure_grant", map[string]any{"grant_id": args.GrantID})
			return textResult(
				section("Confirm Revoke Disclosure Grant"),
				kvf("Grant ID", args.GrantID),
				"",
				kvf("Confirmation Token", token),
				"Call revoke_disclosure_grant again with this confirm_token to execute.",
			)
		}
		params, err := confirms.Validate(args.ConfirmToken, "revoke_disclosure_grant")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.post(pathf("/api/v1/admin/disclosure/grants/%s/revoke", confirmParam(params, "grant_id")), nil)
		if err != nil {
			return errorResult("revoking disclosure grant: %v", err)
		}
		return textResult(section("Disclosure Grant Revoked"))
	})
}

type disclosureCheckAccessArgs struct {
	DID    string `json:"did" jsonschema:"DID to check access for (required)"`
	UserID string `json:"user_id" jsonschema:"target user ID (required)"`
}

func registerDisclosureCheckAccess(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "disclosure_check_access",
		Description: "Check if a DID has disclosure access to a user's data.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args disclosureCheckAccessArgs) (*mcp.CallToolResult, any, error) {
		if args.DID == "" || args.UserID == "" {
			return errorResult("did and user_id are required")
		}
		raw, err := client.get("/api/v1/admin/disclosure/check-access", url.Values{"did": {args.DID}, "user_id": {args.UserID}})
		if err != nil {
			return errorResult("checking disclosure access: %v", err)
		}
		return textResult(section("Disclosure Access Check"), prettyJSON(json.RawMessage(raw)))
	})
}

type grantLogsArgs struct {
	GrantID string `json:"grant_id" jsonschema:"disclosure grant ID (UUID, required)"`
}

func registerDisclosureGrantLogs(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "disclosure_grant_logs",
		Description: "Get access logs for a specific disclosure grant.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args grantLogsArgs) (*mcp.CallToolResult, any, error) {
		if args.GrantID == "" {
			return errorResult("grant_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/disclosure/grants/%s/logs", args.GrantID))
		if err != nil {
			return errorResult("getting grant logs: %v", err)
		}
		return textResult(section("Disclosure Grant Logs"), prettyJSON(json.RawMessage(raw)))
	})
}

type grantReportArgs struct {
	GrantID    string `json:"grant_id" jsonschema:"disclosure grant ID (UUID, required)"`
	ReportType string `json:"report_type" jsonschema:"report type: summary, detailed, compliance (required)"`
}

func registerDisclosureGrantReport(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "disclosure_grant_report",
		Description: "Export a compliance report for a disclosure grant.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args grantReportArgs) (*mcp.CallToolResult, any, error) {
		if args.GrantID == "" || args.ReportType == "" {
			return errorResult("grant_id and report_type are required")
		}
		raw, err := client.get(pathf("/api/v1/admin/disclosure/grants/%s/report/%s", args.GrantID, args.ReportType))
		if err != nil {
			return errorResult("getting report: %v", err)
		}
		return textResult(section("Disclosure Report ("+args.ReportType+")"), prettyJSON(json.RawMessage(raw)))
	})
}

type disclosureGrantSummaryArgs struct {
	GrantID string `json:"grant_id" jsonschema:"disclosure grant ID (UUID, required)"`
}

func registerDisclosureGrantSummary(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "disclosure_grant_summary",
		Description: "Get a summary of a disclosure grant including scope and usage.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args disclosureGrantSummaryArgs) (*mcp.CallToolResult, any, error) {
		if args.GrantID == "" {
			return errorResult("grant_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/disclosure/grants/%s/summary", args.GrantID))
		if err != nil {
			return errorResult("getting grant summary: %v", err)
		}
		return textResult(section("Disclosure Grant Summary"), prettyJSON(json.RawMessage(raw)))
	})
}

type disclosureGrantEventsArgs struct {
	GrantID string `json:"grant_id" jsonschema:"disclosure grant ID (UUID, required)"`
}

func registerDisclosureGrantEvents(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "disclosure_grant_events",
		Description: "Get events for a disclosure grant (approvals, revocations, access).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args disclosureGrantEventsArgs) (*mcp.CallToolResult, any, error) {
		if args.GrantID == "" {
			return errorResult("grant_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/disclosure/grants/%s/events", args.GrantID))
		if err != nil {
			return errorResult("getting grant events: %v", err)
		}
		return textResult(section("Disclosure Grant Events"), prettyJSON(json.RawMessage(raw)))
	})
}
