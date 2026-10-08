package server

// This file must contain ONLY swag's general API info (RD-1166): swag parses
// every comment group of the `-g` file for top-level attributes, so any
// operation annotation placed here would bleed into (and overwrite) the
// document's info block. Operation annotations live on the handlers;
// spec-serving endpoints are in openapi_info.go.

// generalAPIInfo exists only to carry the general annotations below.
//
// @title        Open Privacy Suite REST API
// @version      1.0
// @description  REST control-plane and data API of the Open Privacy Suite: authentication (Privado ID wallet flow, Azure AD), ETH address linking, user profile and disclosure, RBAC / compliance / system administration, the block-explorer data API, and the proxied Ethereum JSON-RPC endpoint.
// @description
// @description  **Authentication.** User endpoints take a Bearer JWT issued by the auth endpoints (`Authorization: Bearer <token>`). `/api/v1/admin/*` requires the `X-Admin-Token` header and is additionally reachable only from private-network addresses. `/api/v1/explorer/*` serves the explorer backend and is private-network only.
// @description
// @description  **Aliases.** Every `/api/v1/eth/*` endpoint is also mounted at `/eth/*`; the auth endpoints are also mounted at the root (`/auth/...`, `/refresh`, `/revoke`, `/introspect`). Legacy unversioned `/api/*` mounts are deprecated and respond with an `X-Deprecated` header. Aliases are intentionally not listed as separate operations. `POST /` is the same operation as `POST /rpc`.
// @description
// @description  **Dev-only.** A small number of operations exist only in non-production builds and say so in their descriptions.
// @contact.name Gateway.fm
// @contact.url  https://gateway.fm
//
// @tag.name Auth
// @tag.description Session authentication: Privado ID wallet flow, Azure AD (interactive and service principal), token refresh/revoke/introspection.
// @tag.name OAuth SSO
// @tag.description OAuth 2.0 endpoints the proxy exposes as an identity provider (used by the block explorer for SSO).
// @tag.name JSON-RPC
// @tag.description The proxied Ethereum JSON-RPC endpoint: method allowlist, RBAC, response redaction. Also mounted at POST /.
// @tag.name ETH linking
// @tag.description Linking Ethereum addresses to the authenticated DID by signature challenge.
// @tag.name Profile
// @tag.description The authenticated user's own profile.
// @tag.name Disclosure (user)
// @tag.description Disclosure requests and grants, from the data owner's side.
// @tag.name Explorer
// @tag.description Privacy-filtered chain data for the block explorer backend (private network only).
// @tag.name Admin: RBAC
// @tag.description Organizations, groups, users, memberships, contracts, and grants.
// @tag.name Admin: disclosure
// @tag.description Administering disclosure requests.
// @tag.name Admin: compliance
// @tag.description Travel-rule compliance configuration, sanctions lists, and token prices.
// @tag.name Admin: impersonation
// @tag.description Read-only "view as user" mirror: the explorer and JSON-RPC surfaces re-mounted under /api/v1/admin/impersonate/{target_did}/in/{org_id}/..., GET-only, tier-2 admin gated, per-request audited. The mirrored operations are documented once, under their canonical /api/v1/explorer and /rpc paths. The JSON-RPC mirror serves only the dry-run read methods and the org-free metadata methods (any other method in the body returns 400), and answers them as the dry-run does.
// @tag.name Admin: shared infrastructure
// @tag.description Fleet-level shared contract infrastructure and Azure tenant administration.
// @tag.name Admin: system
// @tag.description Fleet-level system toggles and build identity.
// @tag.name Admin: ops
// @tag.description Operational admin endpoints: access logs, status, and test requests.
// @tag.name System
// @tag.description Health, metrics, and this specification.
func generalAPIInfo() {}

// Each security scheme must live in its OWN comment group: swag v2 keys a
// scheme by the first @securitydefinitions line of the group it is parsed
// from, so two schemes in one group would collide under one key.

// @securitydefinitions.bearerauth BearerAuth
// @description  JWT issued by the auth endpoints, sent as `Authorization: Bearer <token>`.
// @bearerFormat JWT

// @securitydefinitions.apikey AdminToken
// @in   header
// @name X-Admin-Token
// @description Admin API token (full admin, or the restricted operator token). Admin endpoints additionally require a private-network source address.
