package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerUserTools(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	registerListUsers(s, client)
	registerGetUser(s, client)
	registerResolveUser(s, client)
	registerUpdateUser(s, client)
	registerDeleteUser(s, client, confirms)
	registerUserAddresses(s, client)
	registerUserMemberships(s, client)
	registerAddMembership(s, client)
	registerRemoveMembership(s, client, confirms)
	registerEffectivePermissions(s, client)
	registerCheckAccess(s, client)
}

type listUsersArgs struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"max entries (default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	OrgID  string `json:"org_id,omitempty" jsonschema:"filter by organization ID"`
	Search string `json:"search,omitempty" jsonschema:"search by DID or linked ETH address"`
}

func registerListUsers(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_users",
		Description: "List users. Can filter by organization and search by DID or ETH address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listUsersArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 50
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(limit))
		q.Set("offset", strconv.Itoa(args.Offset))
		if args.OrgID != "" {
			q.Set("org_id", args.OrgID)
		}
		if args.Search != "" {
			q.Set("search", args.Search)
		}

		raw, err := client.get("/api/v1/admin/users", q)
		if err != nil {
			return errorResult("listing users: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		users := getSlice(resp, "data")
		lines := section("Users") + "\n"
		lines += kvf("Total", getFloat(resp, "total")) + "\n"

		for _, u := range users {
			user, ok := u.(map[string]any)
			if !ok {
				continue
			}
			lines += fmt.Sprintf("\n### User %s\n", getString(user, "id"))
			lines += joinLines(
				kvf("DID", getString(user, "external_id")),
				kvf("KYC", boolYesNo(getBool(user, "kyc"))),
				kvf("Banned", boolYesNo(getBool(user, "banned"))),
				kvf("Created", getString(user, "created_at")),
			) + "\n"
		}
		return textResult(lines)
	})
}

type getUserArgs struct {
	UserID string `json:"user_id" jsonschema:"user ID (UUID, required)"`
}

func registerGetUser(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_user",
		Description: "Get details of a specific user.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getUserArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/users/%s", args.UserID))
		if err != nil {
			return errorResult("getting user: %v", err)
		}
		var user map[string]any
		if err := json.Unmarshal(raw, &user); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("User"),
			kvf("ID", getString(user, "id")),
			kvf("DID", getString(user, "external_id")),
			kvf("KYC", boolYesNo(getBool(user, "kyc"))),
			kvf("Banned", boolYesNo(getBool(user, "banned"))),
			kvf("Note", getString(user, "note")),
			kvf("Created", getString(user, "created_at")),
			kvf("Updated", getString(user, "updated_at")),
		)
	})
}

type resolveUserArgs struct {
	Query string `json:"query" jsonschema:"search term — DID, ETH address, or partial match (required)"`
}

func registerResolveUser(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "resolve_user",
		Description: "Find a user by DID or ETH address. Returns matching users for the search term.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args resolveUserArgs) (*mcp.CallToolResult, any, error) {
		if args.Query == "" {
			return errorResult("query is required")
		}
		q := url.Values{}
		q.Set("search", args.Query)
		q.Set("limit", "10")
		raw, err := client.get("/api/v1/admin/users", q)
		if err != nil {
			return errorResult("searching users: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		users := getSlice(resp, "data")
		total := getFloat(resp, "total")

		if len(users) == 0 {
			return textResult("No users found matching: " + args.Query)
		}

		lines := fmt.Sprintf("## Found %.0f user(s) matching \"%s\"\n", total, args.Query)
		for _, u := range users {
			user, ok := u.(map[string]any)
			if !ok {
				continue
			}
			lines += joinLines(
				"",
				kvf("ID", getString(user, "id")),
				kvf("DID", getString(user, "external_id")),
				kvf("Banned", boolYesNo(getBool(user, "banned"))),
			) + "\n"
		}
		return textResult(lines)
	})
}

type updateUserArgs struct {
	UserID string `json:"user_id" jsonschema:"user ID (UUID, required)"`
	KYC    *bool  `json:"kyc,omitempty" jsonschema:"set KYC status"`
	Banned *bool  `json:"banned,omitempty" jsonschema:"ban or unban user (banning revokes all sessions)"`
	Note   string `json:"note,omitempty" jsonschema:"admin note"`
}

func registerUpdateUser(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_user",
		Description: "Update user properties: KYC status, ban status, or admin note. Banning revokes all active sessions.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args updateUserArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}
		body := map[string]any{}
		if args.KYC != nil {
			body["kyc"] = *args.KYC
		}
		if args.Banned != nil {
			body["banned"] = *args.Banned
		}
		if args.Note != "" {
			body["note"] = args.Note
		}

		raw, err := client.put(pathf("/api/v1/admin/users/%s", args.UserID), body)
		if err != nil {
			return errorResult("updating user: %v", err)
		}
		var user map[string]any
		if err := json.Unmarshal(raw, &user); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("User Updated"),
			kvf("ID", getString(user, "id")),
			kvf("Banned", boolYesNo(getBool(user, "banned"))),
			kvf("KYC", boolYesNo(getBool(user, "kyc"))),
		)
	})
}

type deleteUserArgs struct {
	UserID       string `json:"user_id" jsonschema:"user ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerDeleteUser(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_user",
		Description: "Delete a user and all their memberships. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteUserArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}

		if args.ConfirmToken == "" {
			token := confirms.Request("delete_user", map[string]any{"user_id": args.UserID})
			return textResult(
				section("Confirm Delete User"),
				kvf("User ID", args.UserID),
				"",
				"This will permanently delete the user and all their memberships.",
				"",
				kvf("Confirmation Token", token),
				"Call delete_user again with this confirm_token to execute.",
			)
		}

		params, err := confirms.Validate(args.ConfirmToken, "delete_user")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}

		_, err = client.del(pathf("/api/v1/admin/users/%s", confirmParam(params, "user_id")))
		if err != nil {
			return errorResult("deleting user: %v", err)
		}
		return textResult(section("User Deleted"))
	})
}

func registerUserAddresses(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "user_addresses",
		Description: "Get a user's linked Ethereum addresses.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getUserArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/users/%s/linked-addresses", args.UserID))
		if err != nil {
			return errorResult("getting addresses: %v", err)
		}
		var resp map[string]any
		if err := json.Unmarshal(raw, &resp); err != nil {
			return errorResult("parsing response: %v", err)
		}

		addrs := getSlice(resp, "addresses")
		lines := section("Linked Addresses") + "\n"

		if len(addrs) == 0 {
			lines += "No linked addresses."
			return textResult(lines)
		}

		for _, a := range addrs {
			addr, ok := a.(map[string]any)
			if !ok {
				continue
			}
			ens := getString(addr, "ens_name")
			if ens == "" {
				ens = "(none)"
			}
			lines += joinLines(
				kvf("Address", getString(addr, "address")),
				kvf("ENS", ens),
				kvf("Verified At", getString(addr, "verified_at")),
			) + "\n"
		}
		return textResult(lines)
	})
}

func registerUserMemberships(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "user_memberships",
		Description: "List a user's group memberships with group details.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getUserArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}
		raw, err := client.get(pathf("/api/v1/admin/users/%s/memberships", args.UserID))
		if err != nil {
			return errorResult("getting memberships: %v", err)
		}
		var items []any
		if err := json.Unmarshal(raw, &items); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Memberships") + "\n"

		if len(items) == 0 {
			lines += "No group memberships."
			return textResult(lines)
		}

		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			membership := getMap(entry, "membership")
			group := getMap(entry, "group")
			if group == nil || membership == nil {
				continue
			}
			lines += joinLines(
				fmt.Sprintf("\n### %s", getString(group, "name")),
				kvf("Membership ID", getString(membership, "id")),
				kvf("Group ID", getString(group, "id")),
				kvf("Group Path", getString(group, "path")),
				kvf("Source", getString(membership, "source")),
				kvf("Org Admin", boolYesNo(getBool(group, "is_org_admin"))),
			) + "\n"
		}
		return textResult(lines)
	})
}

type addMembershipArgs struct {
	UserID  string `json:"user_id" jsonschema:"user ID (UUID, required)"`
	GroupID string `json:"group_id" jsonschema:"group ID to add user to (UUID, required)"`
}

func registerAddMembership(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "add_membership",
		Description: "Add a user to a group.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addMembershipArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" || args.GroupID == "" {
			return errorResult("user_id and group_id are required")
		}
		raw, err := client.post(pathf("/api/v1/admin/users/%s/memberships", args.UserID), map[string]any{
			"group_id": args.GroupID,
		})
		if err != nil {
			return errorResult("adding membership: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return errorResult("parsing response: %v", err)
		}

		return textResult(
			section("Membership Created"),
			kvf("Membership ID", getString(m, "id")),
			kvf("User ID", getString(m, "user_id")),
			kvf("Group ID", getString(m, "group_id")),
			kvf("Source", getString(m, "source")),
		)
	})
}

type removeMembershipArgs struct {
	UserID       string `json:"user_id" jsonschema:"user ID (UUID, required)"`
	MembershipID string `json:"membership_id" jsonschema:"membership ID (UUID, required)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"confirmation token from dry-run"`
}

func registerRemoveMembership(s *mcp.Server, client *httpClient, confirms *ConfirmationEngine) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "remove_membership",
		Description: "Remove a user from a group. Requires two-step confirmation.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args removeMembershipArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" || args.MembershipID == "" {
			return errorResult("user_id and membership_id are required")
		}

		if args.ConfirmToken == "" {
			token := confirms.Request("remove_membership", map[string]any{
				"user_id":       args.UserID,
				"membership_id": args.MembershipID,
			})
			return textResult(
				section("Confirm Remove Membership"),
				kvf("User ID", args.UserID),
				kvf("Membership ID", args.MembershipID),
				"",
				kvf("Confirmation Token", token),
				"Call remove_membership again with this confirm_token to execute.",
			)
		}

		params, err := confirms.Validate(args.ConfirmToken, "remove_membership")
		if err != nil {
			return errorResult("confirmation failed: %v", err)
		}

		_, err = client.del(pathf("/api/v1/admin/users/%s/memberships/%s", confirmParam(params, "user_id"), confirmParam(params, "membership_id")))
		if err != nil {
			return errorResult("removing membership: %v", err)
		}
		return textResult(section("Membership Removed"))
	})
}

type effectivePermsArgs struct {
	UserID string `json:"user_id" jsonschema:"user ID (UUID, required)"`
	Org    string `json:"org,omitempty" jsonschema:"organization slug (default: 'default')"`
}

func registerEffectivePermissions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "effective_permissions",
		Description: "Get a user's computed effective permissions: claims, allowed methods, contract access, and rate limits.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args effectivePermsArgs) (*mcp.CallToolResult, any, error) {
		if args.UserID == "" {
			return errorResult("user_id is required")
		}
		q := url.Values{}
		if args.Org != "" {
			q.Set("org", args.Org)
		}

		raw, err := client.get(pathf("/api/v1/admin/users/%s/effective-permissions", args.UserID), q)
		if err != nil {
			return errorResult("getting permissions: %v", err)
		}
		var perms map[string]any
		if err := json.Unmarshal(raw, &perms); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Effective Permissions") + "\n"
		lines += joinLines(
			kvf("User ID", getString(perms, "user_id")),
			kvf("Org ID", getString(perms, "org_id")),
			kvf("Claims", fmt.Sprintf("%v", getSlice(perms, "claims"))),
			kvf("Allowed Methods", fmt.Sprintf("%v", getSlice(perms, "allowed_methods"))),
		) + "\n"

		if contracts := getMap(perms, "contract_access"); contracts != nil && len(contracts) > 0 {
			lines += "\n### Contract Access\n"
			for addr, v := range contracts {
				ca, ok := v.(map[string]any)
				if !ok {
					continue
				}
				lines += joinLines(
					kvf("Contract", addr),
					kvf("  Claims", fmt.Sprintf("%v", getSlice(ca, "claims"))),
				) + "\n"
			}
		}

		return textResult(lines)
	})
}

type checkAccessArgs struct {
	UserExternalID   string   `json:"user_external_id" jsonschema:"user DID (required)"`
	OrgID            string   `json:"org_id,omitempty" jsonschema:"organization ID"`
	Method           string   `json:"method" jsonschema:"RPC method to check (e.g. eth_call, required)"`
	TargetAddress    string   `json:"target_address,omitempty" jsonschema:"contract address (0x-prefixed)"`
	FunctionSelector string   `json:"function_selector,omitempty" jsonschema:"4-byte function selector (0x-prefixed)"`
	RequiredClaims   []string `json:"required_claims,omitempty" jsonschema:"claims to check (read, write, deploy, etc.)"`
}

func registerCheckAccess(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "check_access",
		Description: "Check whether a user is allowed to perform a specific RPC call, optionally against a specific contract and function.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args checkAccessArgs) (*mcp.CallToolResult, any, error) {
		if args.UserExternalID == "" || args.Method == "" {
			return errorResult("user_external_id and method are required")
		}
		body := map[string]any{
			"user_external_id": args.UserExternalID,
			"method":           args.Method,
		}
		if args.OrgID != "" {
			body["org_id"] = args.OrgID
		}
		if args.TargetAddress != "" {
			body["target_address"] = args.TargetAddress
		}
		if args.FunctionSelector != "" {
			body["function_selector"] = args.FunctionSelector
		}
		if len(args.RequiredClaims) > 0 {
			body["required_claims"] = args.RequiredClaims
		}

		raw, err := client.post("/api/v1/admin/access/check", body)
		if err != nil {
			return errorResult("checking access: %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			return errorResult("parsing response: %v", err)
		}

		allowed := getBool(result, "allowed")
		status := "DENIED"
		if allowed {
			status = "ALLOWED"
		}

		lines := section("Access Check: "+status) + "\n"
		lines += joinLines(
			kvf("Allowed", boolYesNo(allowed)),
			kvf("Reason", getString(result, "reason")),
			kvf("Claims", fmt.Sprintf("%v", getSlice(result, "claims"))),
		)

		return textResult(lines)
	})
}
