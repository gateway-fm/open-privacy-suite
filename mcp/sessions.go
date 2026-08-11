package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerSessionTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerListSessions(s, client)
	registerDeleteSession(s, client, confirms)
	registerListProviders(s, client)
	registerListAzureTenants(s, client)
	registerGetAzureTenant(s, client)
	registerCreateAzureTenant(s, client)
	registerUpdateAzureTenant(s, client)
	registerDeleteAzureTenant(s, client, confirms)
}

func registerListSessions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_sessions",
		Description: "List active auth sessions.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/sessions")
		if err != nil {
			return errorResult("listing sessions: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		sessions := getSlice(resp, "sessions")
		lines := section("Sessions") + "\n"
		lines += kvf("Total", getFloat(resp, "total")) + "\n"

		for _, s := range sessions {
			sess, ok := s.(map[string]any)
			if !ok {
				continue
			}
			lines += joinLines(
				"",
				kvf("ID", getString(sess, "id")),
				kvf("Created", getString(sess, "created_at")),
				kvf("Expires", getString(sess, "expires_at")),
				kvf("Completed", boolYesNo(getBool(sess, "completed"))),
			) + "\n"
		}
		return textResult(lines)
	})
}

type deleteSessionArgs struct {
	SessionID    string `json:"session_id" jsonschema:"session ID (required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteSession(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_session",
		Description: "Revoke an auth session. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteSessionArgs) (*mcp.CallToolResult, any, error) {
		if args.SessionID == "" {
			return errorResult("session_id is required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_session", map[string]any{"session_id": args.SessionID})
			return textResult(
				section("Confirm Revoke Session"),
				kvf("Session ID", args.SessionID),
				"",
				kvf("Confirmation Token", token),
				"Call delete_session again with this confirm_token to execute.",
			)
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_session")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/sessions/%s", confirmParam(params, "session_id")))
		if err != nil {
			return errorResult("revoking session: %v", err)
		}
		return textResult(section("Session Revoked"))
	})
}

func registerListProviders(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_providers",
		Description: "List enabled authentication providers (Privado ID, Azure AD, etc.).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/auth/providers")
		if err != nil {
			return errorResult("listing providers: %v", err)
		}
		return textResult(section("Auth Providers"), prettyJSON(json.RawMessage(raw)))
	})
}

func registerListAzureTenants(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_azure_tenants",
		Description: "List allowed Azure AD tenants.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/azure-tenants")
		if err != nil {
			return errorResult("listing azure tenants: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		tenants := getSlice(resp, "data")
		lines := section("Azure AD Tenants") + "\n"

		for _, t := range tenants {
			tenant, ok := t.(map[string]any)
			if !ok {
				continue
			}
			lines += joinLines(
				"",
				kvf("ID", getString(tenant, "id")),
				kvf("Tenant ID", getString(tenant, "tenant_id")),
				kvf("Label", getString(tenant, "label")),
				kvf("Auto Provision", boolYesNo(getBool(tenant, "auto_provision"))),
				kvf("Default Org", getString(tenant, "default_org_id")),
			) + "\n"
		}
		return textResult(lines)
	})
}

type getAzureTenantArgs struct {
	ID string `json:"id" jsonschema:"tenant record ID (UUID, required)"`
}

func registerGetAzureTenant(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_azure_tenant",
		Description: "Get details of a specific Azure AD tenant.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getAzureTenantArgs) (*mcp.CallToolResult, any, error) {
		if args.ID == "" {
			return errorResult("id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/azure-tenants/%s", args.ID))
		if err != nil {
			return errorResult("getting azure tenant: %v", err)
		}
		var tenant map[string]any
		if err := json.Unmarshal(raw, &tenant); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(
			section("Azure Tenant"),
			kvf("ID", getString(tenant, "id")),
			kvf("Tenant ID", getString(tenant, "tenant_id")),
			kvf("Label", getString(tenant, "label")),
			kvf("Auto Provision", boolYesNo(getBool(tenant, "auto_provision"))),
			kvf("Default Org", getString(tenant, "default_org_id")),
			kvf("Default Group", getString(tenant, "default_group_id")),
		)
	})
}

type updateAzureTenantArgs struct {
	ID             string `json:"id" jsonschema:"tenant record ID (UUID, required)"`
	Label          string `json:"label,omitempty" jsonschema:"display label"`
	DefaultOrgID   string `json:"default_org_id,omitempty" jsonschema:"default org for new users"`
	DefaultGroupID string `json:"default_group_id,omitempty" jsonschema:"default group for new users"`
	AutoProvision  *bool  `json:"auto_provision,omitempty" jsonschema:"auto-create users on first login"`
}

func registerUpdateAzureTenant(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_azure_tenant",
		Description: "Update an Azure AD tenant's settings.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updateAzureTenantArgs) (*mcp.CallToolResult, any, error) {
		if args.ID == "" {
			return errorResult("id is required")
		}
		body := map[string]any{}
		if args.Label != "" {
			body["label"] = args.Label
		}
		if args.DefaultOrgID != "" {
			body["default_org_id"] = args.DefaultOrgID
		}
		if args.DefaultGroupID != "" {
			body["default_group_id"] = args.DefaultGroupID
		}
		if args.AutoProvision != nil {
			body["auto_provision"] = *args.AutoProvision
		}
		raw, err := client.put(pathf("/api/v1/admin/azure-tenants/%s", args.ID), body)
		if err != nil {
			return errorResult("updating azure tenant: %v", err)
		}
		var tenant map[string]any
		if err := json.Unmarshal(raw, &tenant); err != nil {
			return errorResult("parsing response: %v", err)
		}
		return textResult(
			section("Azure Tenant Updated"),
			kvf("ID", getString(tenant, "id")),
			kvf("Label", getString(tenant, "label")),
		)
	})
}

type createAzureTenantArgs struct {
	TenantID       string `json:"tenant_id" jsonschema:"Azure AD tenant ID (UUID, required)"`
	Label          string `json:"label,omitempty" jsonschema:"display label"`
	DefaultOrgID   string `json:"default_org_id,omitempty" jsonschema:"default org for new users from this tenant"`
	DefaultGroupID string `json:"default_group_id,omitempty" jsonschema:"default group for new users"`
	AutoProvision  *bool  `json:"auto_provision,omitempty" jsonschema:"auto-create users on first login (default true)"`
}

func registerCreateAzureTenant(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_azure_tenant",
		Description: "Add an Azure AD tenant to the allowlist.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createAzureTenantArgs) (*mcp.CallToolResult, any, error) {
		if args.TenantID == "" {
			return errorResult("tenant_id is required")
		}
		body := map[string]any{"tenant_id": args.TenantID}
		if args.Label != "" {
			body["label"] = args.Label
		}
		if args.DefaultOrgID != "" {
			body["default_org_id"] = args.DefaultOrgID
		}
		if args.DefaultGroupID != "" {
			body["default_group_id"] = args.DefaultGroupID
		}
		if args.AutoProvision != nil {
			body["auto_provision"] = *args.AutoProvision
		}

		raw, err := client.post("/api/v1/admin/azure-tenants", body)
		if err != nil {
			return errorResult("creating azure tenant: %v", err)
		}
		var tenant map[string]any
		if err := json.Unmarshal(raw, &tenant); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Azure Tenant Added"),
			kvf("ID", getString(tenant, "id")),
			kvf("Tenant ID", getString(tenant, "tenant_id")),
			kvf("Label", getString(tenant, "label")),
		)
	})
}

type deleteAzureTenantArgs struct {
	ID           string `json:"id" jsonschema:"tenant record ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteAzureTenant(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_azure_tenant",
		Description: "Remove an Azure AD tenant from the allowlist. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteAzureTenantArgs) (*mcp.CallToolResult, any, error) {
		if args.ID == "" {
			return errorResult("id is required")
		}
		if args.ConfirmToken == "" {
			token := confirms.Request("delete_azure_tenant", map[string]any{"id": args.ID})
			return textResult(
				section("Confirm Delete Azure Tenant"),
				kvf("ID", args.ID),
				"",
				kvf("Confirmation Token", token),
				"Call delete_azure_tenant again with this confirm_token to execute.",
			)
		}
		params, err := confirms.Validate(args.ConfirmToken, "delete_azure_tenant")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		_, err = client.del(pathf("/api/v1/admin/azure-tenants/%s", confirmParam(params, "id")))
		if err != nil {
			return errorResult("deleting azure tenant: %v", err)
		}
		return textResult(section("Azure Tenant Removed"))
	})
}

func registerAccessLogs(s *mcp.Server, client *httpClient) {
	type args struct {
		Limit int `json:"limit,omitempty" jsonschema:"max entries (default 50)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "access_logs",
		Description: "Get recent access logs from the Open Privacy Suite.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		limit := a.Limit
		if limit == 0 {
			limit = 50
		}
		raw, err := client.get("/api/v1/admin/logs", pageQuery(limit, 0))
		if err != nil {
			return errorResult("getting logs: %v", err)
		}
		var envelope struct {
			Data  []map[string]any `json:"data"`
			Total int              `json:"total"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Access Logs") + "\n"
		lines += kvf("Total", envelope.Total) + "\n"

		for i, entry := range envelope.Data {
			if i >= 20 {
				lines += fmt.Sprintf("\n... and %d more entries", len(envelope.Data)-20)
				break
			}
			lines += fmt.Sprintf("\n%s %s %s → %.0f",
				getString(entry, "created_at"),
				getString(entry, "external_id"),
				getString(entry, "method"),
				getFloat(entry, "status_code"),
			)
		}
		return textResult(lines)
	})
}

func registerAuditLogs(s *mcp.Server, client *httpClient) {
	type args struct {
		ResourceType string `json:"resource_type,omitempty" jsonschema:"filter by resource type — common values (not exhaustive): organization, group, user, membership, contract, grant, disclosure_request, disclosure_grant, system_setting"`
		ActorID      string `json:"actor_id,omitempty" jsonschema:"filter by actor ID"`
		Limit        int    `json:"limit,omitempty" jsonschema:"max entries (default 100)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "audit_logs",
		Description: "Query RBAC audit logs. At least one filter (resource_type or actor_id) is required.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		if a.ResourceType == "" && a.ActorID == "" {
			return errorResult("at least one of resource_type or actor_id is required")
		}
		limit := a.Limit
		if limit == 0 {
			limit = 100
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(limit))
		if a.ResourceType != "" {
			q.Set("resource_type", a.ResourceType)
		}
		if a.ActorID != "" {
			q.Set("actor_id", a.ActorID)
		}

		raw, err := client.get("/api/v1/admin/audit-logs", q)
		if err != nil {
			return errorResult("getting audit logs: %v", err)
		}
		var logs []any
		if err := json.Unmarshal(raw, &logs); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Audit Logs") + "\n"
		lines += kvf("Count", len(logs)) + "\n"

		for i, l := range logs {
			if i >= 20 {
				lines += fmt.Sprintf("\n... and %d more entries", len(logs)-20)
				break
			}
			entry, ok := l.(map[string]any)
			if !ok {
				continue
			}
			lines += joinLines(
				"",
				fmt.Sprintf("**%s** %s on %s (%s)",
					getString(entry, "action"),
					getString(entry, "actor_external_id"),
					getString(entry, "resource_type"),
					getString(entry, "resource_name"),
				),
				kvf("  Time", getString(entry, "created_at")),
			)
		}
		return textResult(lines)
	})
}

func registerCacheStats(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "cache_stats",
		Description: "Get RBAC cache statistics for debugging.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/admin/cache/stats")
		if err != nil {
			return errorResult("getting cache stats: %v", err)
		}
		return textResult(section("Cache Stats"), prettyJSON(json.RawMessage(raw)))
	})
}
