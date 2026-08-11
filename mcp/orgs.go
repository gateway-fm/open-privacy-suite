package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerOrgTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerListOrgs(s, client)
	registerGetOrg(s, client)
	registerCreateOrg(s, client)
	registerUpdateOrg(s, client)
	registerDeleteOrg(s, client, confirms)
}

type listOrgsArgs struct {
	Limit  int `json:"limit,omitempty" jsonschema:"max entries to return (default 50)"`
	Offset int `json:"offset,omitempty" jsonschema:"pagination offset (default 0)"`
}

func registerListOrgs(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_orgs",
		Description: "List all organizations configured in the Open Privacy Suite.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listOrgsArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 50
		}
		raw, err := client.get("/api/v1/admin/orgs", pageQuery(limit, args.Offset))
		if err != nil {
			return errorResult("listing orgs: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		orgs := getSlice(resp, "data")
		lines := section("Organizations") + "\n"
		lines += kvf("Total", getFloat(resp, "total")) + "\n"

		if len(orgs) == 0 {
			lines += "\nNo organizations configured."
			return textResult(lines)
		}

		for _, o := range orgs {
			org, ok := o.(map[string]any)
			if !ok {
				continue
			}
			lines += fmt.Sprintf("\n### %s\n", getString(org, "name"))
			lines += joinLines(
				kvf("ID", getString(org, "id")),
				kvf("Slug", getString(org, "slug")),
			) + "\n"
		}
		return textResult(lines)
	})
}

type getOrgArgs struct {
	OrgID string `json:"org_id" jsonschema:"organization ID (UUID)"`
}

func registerGetOrg(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_org",
		Description: "Get details of a specific organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getOrgArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/orgs/%s", args.OrgID))
		if err != nil {
			return errorResult("getting org: %v", err)
		}
		var org map[string]any
		if err := json.Unmarshal(raw, &org); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Organization: "+getString(org, "name")),
			kvf("ID", getString(org, "id")),
			kvf("Slug", getString(org, "slug")),
			kvf("Name", getString(org, "name")),
			kvf("Created", getString(org, "created_at")),
			kvf("Updated", getString(org, "updated_at")),
			kvf("Settings", prettyJSON(getMap(org, "settings"))),
		)
	})
}

type createOrgArgs struct {
	Slug     string         `json:"slug" jsonschema:"URL-friendly identifier (required, alphanumeric/hyphen/underscore)"`
	Name     string         `json:"name" jsonschema:"display name (required)"`
	Settings map[string]any `json:"settings,omitempty" jsonschema:"optional settings map"`
}

func registerCreateOrg(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_org",
		Description: "Create a new organization.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createOrgArgs) (*mcp.CallToolResult, any, error) {
		if args.Slug == "" || args.Name == "" {
			return errorResult("slug and name are required")
		}
		raw, err := client.post("/api/v1/admin/orgs", args)
		if err != nil {
			return errorResult("creating org: %v", err)
		}
		var org map[string]any
		if err := json.Unmarshal(raw, &org); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Organization Created"),
			kvf("ID", getString(org, "id")),
			kvf("Slug", getString(org, "slug")),
			kvf("Name", getString(org, "name")),
		)
	})
}

type updateOrgArgs struct {
	OrgID    string         `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	Slug     string         `json:"slug,omitempty" jsonschema:"new slug"`
	Name     string         `json:"name,omitempty" jsonschema:"new name"`
	Settings map[string]any `json:"settings,omitempty" jsonschema:"new settings"`
}

func registerUpdateOrg(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_org",
		Description: "Update an organization's name, slug, or settings.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updateOrgArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}
		body := map[string]any{}
		if args.Slug != "" {
			body["slug"] = args.Slug
		}
		if args.Name != "" {
			body["name"] = args.Name
		}
		if args.Settings != nil {
			body["settings"] = args.Settings
		}
		raw, err := client.put(pathf("/api/v1/admin/orgs/%s", args.OrgID), body)
		if err != nil {
			return errorResult("updating org: %v", err)
		}
		var org map[string]any
		if err := json.Unmarshal(raw, &org); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Organization Updated"),
			kvf("ID", getString(org, "id")),
			kvf("Slug", getString(org, "slug")),
			kvf("Name", getString(org, "name")),
		)
	})
}

type deleteOrgArgs struct {
	OrgID        string `json:"org_id" jsonschema:"organization ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run (required to execute)"`
}

func registerDeleteOrg(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_org",
		Description: "Delete an organization. First call without confirm_token for preview, then call with the returned token to execute.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteOrgArgs) (*mcp.CallToolResult, any, error) {
		if args.OrgID == "" {
			return errorResult("org_id is required")
		}

		if args.ConfirmToken == "" {
			token := confirms.Request("delete_org", map[string]any{"org_id": args.OrgID})
			return textResult(
				section("Confirm Delete Organization"),
				kvf("Org ID", args.OrgID),
				"",
				"This will permanently delete the organization and all its groups, contracts, and grants.",
				"",
				kvf("Confirmation Token", token),
				"",
				"Call delete_org again with this confirm_token to execute.",
			)
		}

		params, err := confirms.Validate(args.ConfirmToken, "delete_org")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}
		orgID := confirmParam(params, "org_id")

		_, err = client.del(pathf("/api/v1/admin/orgs/%s", orgID))
		if err != nil {
			return errorResult("deleting org: %v", err)
		}
		return textResult(section("Organization Deleted"), kvf("Org ID", orgID))
	})
}
