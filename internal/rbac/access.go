package rbac

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"privacy-proxy/internal/evm/precompile"

	"github.com/google/uuid"
)

// ErrContractAccessDenied is the generic error message for all contract access
// denials. Using a single message prevents attackers from enumerating deployed
// contracts by observing different error strings (contract existence oracle).
const ErrContractAccessDenied = "contract access denied"

// GlobalBlockedMethods contains methods that are NEVER allowed regardless of RBAC permissions.
// These methods pose security risks and should never be exposed through the proxy.
// Using map for O(1) lookup instead of slice.
// All keys MUST be lowercase for case-insensitive matching in IsMethodBlocked.
var GlobalBlockedMethods = map[string]bool{
	// Debug namespace - information disclosure, DoS risk
	"debug_accountrange":                true,
	"debug_backtraceat":                 true,
	"debug_blockprofile":                true,
	"debug_chaindbcompact":              true,
	"debug_chaindbproperty":             true,
	"debug_cpuprofile":                  true,
	"debug_dbancient":                   true,
	"debug_dbancients":                  true,
	"debug_dbget":                       true,
	"debug_dumpblock":                   true,
	"debug_freeosmemory":                true,
	"debug_freezeclient":                true,
	"debug_gcstats":                     true,
	"debug_getbadblocks":                true,
	"debug_getheaderrlp":                true,
	"debug_getmodifiedaccountsbyhash":   true,
	"debug_getmodifiedaccountsbynumber": true,
	"debug_gotrace":                     true,
	"debug_intermediateroots":           true,
	"debug_memstats":                    true,
	"debug_mutexprofile":                true,
	"debug_preimage":                    true,
	"debug_printblock":                  true,
	"debug_seedhash":                    true,
	"debug_setblockprofilerate":         true,
	"debug_setgcpercent":                true,
	"debug_sethead":                     true,
	"debug_setmutexprofilefraction":     true,
	"debug_stacks":                      true,
	"debug_standardtracebadblocktofile": true,
	"debug_standardtraceblocktofile":    true,
	"debug_startcpuprofile":             true,
	"debug_startgotrace":                true,
	"debug_stopcpuprofile":              true,
	"debug_stopgotrace":                 true,
	"debug_storagerangeat":              true,
	"debug_subscribe":                   true,
	"debug_tracebadblock":               true,
	"debug_traceblock":                  true,
	"debug_traceblockbyhash":            true,
	"debug_traceblockbynumber":          true,
	"debug_traceblockfromfile":          true,
	"debug_tracechain":                  true,
	"debug_unsubscribe":                 true,
	"debug_verbosity":                   true,
	"debug_vmodule":                     true,
	"debug_writeblockprofile":           true,
	"debug_writememprofile":             true,
	"debug_writemutexprofile":           true,

	// Admin namespace - node administration
	"admin_addpeer":           true,
	"admin_addtrustedpeer":    true,
	"admin_clearhistory":      true,
	"admin_datadir":           true,
	"admin_exportchain":       true,
	"admin_importchain":       true,
	"admin_nodeinfo":          true,
	"admin_peers":             true,
	"admin_removepeer":        true,
	"admin_removetrustedpeer": true,
	"admin_sleep":             true,
	"admin_sleepblocks":       true,
	"admin_starthttp":         true,
	"admin_startrpc":          true,
	"admin_startws":           true,
	"admin_stophttp":          true,
	"admin_stoprpc":           true,
	"admin_stopws":            true,

	// Personal namespace - key exposure risk
	"personal_deriveaccount":    true,
	"personal_ecrecover":        true,
	"personal_importrawkey":     true,
	"personal_initializewallet": true,
	"personal_listaccounts":     true,
	"personal_listwallets":      true,
	"personal_lockaccount":      true,
	"personal_newaccount":       true,
	"personal_openwallet":       true,
	"personal_sendtransaction":  true,
	"personal_sign":             true,
	"personal_signtransaction":  true,
	"personal_unlockaccount":    true,
	"personal_unpair":           true,

	// Miner namespace - MEV risk, node control
	"miner_gethashrate":         true,
	"miner_setetherbase":        true,
	"miner_setextra":            true,
	"miner_setgaslimit":         true,
	"miner_setgasprice":         true,
	"miner_setrecommitinterval": true,
	"miner_start":               true,
	"miner_stop":                true,

	// Txpool namespace - MEV risk, information disclosure
	"txpool_content":     true,
	"txpool_contentfrom": true,
	"txpool_inspect":     true,
	"txpool_status":      true,

	// NOTE: eth_getStorageAt is NOT globally blocked — it uses tiered access control
	// in CheckAccess: admin-claim users get all slots, non-admin users get only
	// well-known infrastructure slots (EIP-1967, EIP-2535). See storage_slots.go.

	// Signing methods - key exposure risk
	"eth_sign":            true,
	"eth_signtransaction": true,

	// NOTE: eth_sendRawTransaction is handled specially - it's allowed ONLY when
	// runtime tracing is enabled. The proxy decodes the RLP transaction, extracts
	// from/to/data/value, and runs runtime tracing to validate all call targets.
	// See jsonrpc_processor.go for the implementation.
	// When runtime tracing is disabled, this method is blocked by CheckAccess.

	// Clique namespace - consensus manipulation
	"clique_discard":           true,
	"clique_getsigners":        true,
	"clique_getsignersathash":  true,
	"clique_getsnapshot":       true,
	"clique_getsnapshotathash": true,
	"clique_proposals":         true,
	"clique_propose":           true,
	"clique_status":            true,

	// Les namespace - light client control
	"les_addbalance":         true,
	"les_clientinfo":         true,
	"les_latestcheckpoint":   true,
	"les_priorityclientinfo": true,
	"les_serverinfo":         true,
	"les_setclientparams":    true,
	"les_setdefaultparams":   true,

	// WebSocket subscriptions - not supported, use polling instead
	// eth_subscribe could bypass eth_getLogs filtering for real-time events
	"eth_subscribe":   true,
	"eth_unsubscribe": true,

	// Stateful filter API - same bypass risk as eth_subscribe.
	// These create server-side filter state that can't be per-user scoped.
	// Use eth_getLogs (which is properly filtered) instead.
	strings.ToLower(MethodNewFilter):                   true,
	strings.ToLower(MethodNewBlockFilter):              true,
	strings.ToLower(MethodNewPendingTransactionFilter): true,
	strings.ToLower(MethodGetFilterLogs):               true,
	strings.ToLower(MethodGetFilterChanges):            true,
	strings.ToLower(MethodUninstallFilter):             true,
}

// orgFreeMetadataMethods are chain-level metadata methods that carry no user or org state.
// Authenticated users may call these on /rpc without an org_id in the path — the same set
// the anonymous group allows. Banning remains a blanket gate above this check; KYC is
// exempt for exactly this set (RD-1197) — anonymous callers get these methods with no
// account at all, so a KYC deny would make signing in stricter than staying anonymous.
var orgFreeMetadataMethods = map[string]bool{
	"eth_blocknumber":    true,
	"eth_chainid":        true,
	"eth_gasprice":       true,
	"net_version":        true,
	"net_listening":      true,
	"web3_clientversion": true,
}

// blockedMethodPrefixes is used for future-proofing (checked after exact match fails)
var blockedMethodPrefixes = []string{
	"debug_",
	"admin_",
	"personal_",
	"miner_",
	"txpool_",
	"clique_",
	"les_",
}

// prefixBlockExemptions are methods that match a blocked prefix but are explicitly
// allowed through to the RBAC layer (e.g., debug trace methods gated by deploy claim).
var prefixBlockExemptions = map[string]bool{
	"debug_tracetransaction": true,
	"debug_tracecall":        true,
}

// IsMethodBlocked checks if a method is globally blocked.
// Case-insensitive matching is used for security.
func IsMethodBlocked(method string) bool {
	method = strings.ToLower(strings.TrimSpace(method))

	// Check exact match in map (O(1) lookup)
	if GlobalBlockedMethods[method] {
		return true
	}

	// Check exemptions before prefix blocking
	if prefixBlockExemptions[method] {
		return false
	}

	// Check prefix matches for future-proofing
	for _, prefix := range blockedMethodPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}

	return false
}

// Multicall contract addresses (Multicall3 is deployed at same address on most chains)
var MulticallAddresses = map[string]bool{
	"0xca11bde05977b3631167028862be2a173976ca11": true, // Multicall3
	"0x5ba1e12693dc8f9c48aad8770482f4739beed696": true, // Multicall2 (Ethereum mainnet)
	"0xeefba1e63905ef1d7acba5a8513c70307c1ce441": true, // Multicall (original)
}

// Multicall function selectors (first 4 bytes of keccak256 hash)
var MulticallSelectors = map[string]string{
	"0x252dba42": "aggregate",            // aggregate((address,bytes)[])
	"0x82ad56cb": "aggregate3",           // aggregate3((address,bool,bytes)[])
	"0x174dea71": "aggregate3Value",      // aggregate3Value((address,bool,uint256,bytes)[])
	"0xc3077fa9": "blockAndAggregate",    // blockAndAggregate((address,bytes)[])
	"0xbce38bd7": "tryAggregate",         // tryAggregate(bool,(address,bytes)[])
	"0x399542e9": "tryBlockAndAggregate", // tryBlockAndAggregate(bool,(address,bytes)[])
}

// IsMulticallTarget checks if the target address is a known Multicall contract.
func IsMulticallTarget(address string) bool {
	return MulticallAddresses[strings.ToLower(address)]
}

// IsMulticallData checks if the call data appears to be a Multicall function call.
// Returns true if the data starts with a known Multicall function selector.
func IsMulticallData(data string) bool {
	if len(data) < 10 { // "0x" + 8 hex chars for selector
		return false
	}
	selector := strings.ToLower(data[:10])
	_, isMulticall := MulticallSelectors[selector]
	return isMulticall
}

// DetectMulticall checks if a request is a Multicall that could bypass contract ACLs.
// Returns (isMulticall, reason) where reason explains why Multicall was detected.
// Blocks eth_call, eth_estimateGas, AND eth_sendTransaction to Multicall contracts
// because inner calls cannot be validated against per-contract ACLs.
func DetectMulticall(method string, params []any) (bool, string) {
	// Check all methods that can interact with Multicall contracts
	// - eth_call: read batching (information disclosure risk)
	// - eth_estimateGas: gas estimation for batched operations
	// - eth_sendTransaction: write batching (state manipulation risk - most severe)
	if method != "eth_call" && method != "eth_estimateGas" && method != "eth_sendTransaction" {
		return false, ""
	}

	if len(params) == 0 {
		return false, ""
	}

	callObj, ok := params[0].(map[string]any)
	if !ok {
		return false, ""
	}

	to, ok := callObj["to"].(string)
	if !ok || to == "" {
		return false, ""
	}

	// Check if targeting a Multicall contract
	if !IsMulticallTarget(to) {
		return false, ""
	}

	// Check if the data is a Multicall function
	data, ok := callObj["data"].(string)
	if !ok || data == "" {
		return false, ""
	}

	if IsMulticallData(data) {
		return true, fmt.Sprintf("multicall to %s detected - inner calls cannot be validated", to)
	}

	return false, ""
}

// AccessController handles access control decisions for RBAC.
type AccessController struct {
	store            Store
	resolver         *Resolver
	cache            PermissionCache
	upgradeValidator *UpgradeValidator
	pendingTracker   *PendingDeploymentTracker

	// L9 (security audit): anonymous group_access is read on every
	// anonymous request — at the documented 10 RPS rate limit per IP
	// that's many DB hits per second per IP. Cache the row for a few
	// seconds; invalidated whenever any group_access is edited via
	// InvalidateOrg / InvalidateGroup. anonAccessCacheTTL is short
	// (5s) so policy changes propagate quickly.
	anonAccess         *GroupAccess
	anonAccessExpires  time.Time
	anonAccessCacheTTL time.Duration
}

// Store returns the underlying RBAC store for the access controller.
// This is used for cross-org isolation checks that require direct database access.
func (c *AccessController) Store() Store {
	return c.store
}

// getAnonymousAccessCached returns the anonymous group's access row
// with a short-TTL in-memory cache to avoid a DB hit on every
// anonymous request (security audit L9).
//
// The cache is intentionally a single-row scalar (no map / no mutex
// beyond a simple lock) — the anonymous group is one row and the
// read path is the only consumer. TTL is 5 seconds so policy
// changes propagate quickly without explicit invalidation, but
// InvalidateAnonymousAccess can be called for instant refresh.
func (c *AccessController) getAnonymousAccessCached(ctx context.Context) (*GroupAccess, error) {
	if c.anonAccess != nil && time.Now().Before(c.anonAccessExpires) {
		return c.anonAccess, nil
	}
	access, err := c.store.GetGroupAccess(ctx, AnonymousGroupID)
	if err != nil {
		return nil, err
	}
	c.anonAccess = access
	c.anonAccessExpires = time.Now().Add(c.anonAccessCacheTTL)
	return access, nil
}

// InvalidateAnonymousAccess drops the cached anonymous group_access.
// Called by admin handlers that mutate group_access on the anonymous
// system group so the change takes effect immediately. Safe to call
// from any goroutine — the cache reads in CheckAccess are best-effort
// and a stale read at worst defers policy change by anonAccessCacheTTL.
func (c *AccessController) InvalidateAnonymousAccess() {
	c.anonAccess = nil
	c.anonAccessExpires = time.Time{}
}

// SetEncryptionKey configures the AES-256 key used by the resolver to decrypt
// RPC API keys stored in the database.
func (c *AccessController) SetEncryptionKey(key []byte) {
	c.resolver.SetEncryptionKey(key)
}

// NewAccessController creates a new access controller.
func NewAccessController(store Store, cacheTTL time.Duration) *AccessController {
	return &AccessController{
		store:              store,
		resolver:           NewResolver(store, cacheTTL),
		cache:              NewCache(CacheConfig{TTL: cacheTTL}),
		upgradeValidator:   NewUpgradeValidator(store),
		pendingTracker:     NewPendingDeploymentTracker(1 * time.Hour),
		anonAccessCacheTTL: 5 * time.Second,
	}
}

// NewAccessControllerWithCache creates a new access controller with a custom cache implementation.
// This allows injecting alternative cache backends (e.g., Redis) for horizontal scaling.
func NewAccessControllerWithCache(store Store, cacheTTL time.Duration, cache PermissionCache) *AccessController {
	return &AccessController{
		store:              store,
		resolver:           NewResolver(store, cacheTTL),
		cache:              cache,
		upgradeValidator:   NewUpgradeValidator(store),
		pendingTracker:     NewPendingDeploymentTracker(1 * time.Hour),
		anonAccessCacheTTL: 5 * time.Second,
	}
}

// CheckAccess validates if a request should be allowed based on RBAC.
//
// The check proceeds in sequential phases, each factored into a private helper
// on *AccessController. A helper that returns (result *AccessCheckResult,
// handled bool, err error) short-circuits the whole check when handled is true:
// CheckAccess returns (result, err) immediately. When handled is false the
// helper's result is ignored and evaluation falls through to the next phase.
// The decomposition is a pure structural refactor of the original monolithic
// method — the order of checks, every condition, reason string, error, and
// AccessCheckResult field are preserved exactly.
func (c *AccessController) CheckAccess(ctx context.Context, req *AccessCheckRequest) (*AccessCheckResult, error) {
	// Global blocklist + Multicall bypass detection — before any RBAC evaluation.
	if res, handled := c.checkGlobalBlocks(req); handled {
		return res, nil
	}

	// Handle anonymous access (no JWT provided).
	if req.UserExternalID == "" {
		return c.checkAnonymousAccess(ctx, req)
	}

	// Get user by external ID and enforce user-level gates (existence, ban, KYC).
	user, res, handled, err := c.resolveAndValidateUser(ctx, req)
	if handled {
		return res, err
	}

	// Authenticated historical-state query guard (M9 security audit).
	if res, handled, err := c.checkHistoricalStateQuery(ctx, req, user); handled {
		return res, err
	}

	// Org-free metadata methods (same set as anonymous allowlist) require no org context.
	// Any valid authenticated user may call these on /rpc without an explicit org_id.
	if orgFreeMetadataMethods[strings.ToLower(strings.TrimSpace(req.Method))] {
		return &AccessCheckResult{Allowed: true, UserID: user.ID}, nil
	}

	// Resolve the org context and the org to evaluate permissions against.
	org, orgCtx, res, handled, err := c.resolveOrgContextForRequest(ctx, req, user)
	if handled {
		return res, err
	}

	// From here on the org is resolved, so every outcome — allow or deny — is
	// attributed to it at this single choke point. The deny sites in the
	// phases below used to return without OrgID/UserID, which logged
	// access_logs rows with a NULL org_id and made an org's own RBAC denials
	// (method_not_allowed, eth_getLogs address denials, claim and
	// contract-access denials) invisible in the tier-2 per-org audit view —
	// only the fleet-wide super-admin scope matched NULL (RD-1199).
	result, err := c.checkWithResolvedOrg(ctx, req, user, org, orgCtx)
	if result != nil {
		if result.OrgID == "" {
			result.OrgID = org.ID
		}
		if result.UserID == "" {
			result.UserID = user.ID
		}
	}
	return result, err
}

// checkWithResolvedOrg runs the post-org-resolution phases of CheckAccess:
// permission resolution, method allowlist, eth_getLogs multi-address
// validation, carve-outs, contract-access/claim checks, and the final allow.
// Pure structural extraction from CheckAccess (RD-1199) — order of checks,
// conditions, reason strings, errors, and result fields are unchanged; the
// caller stamps OrgID/UserID onto every result.
func (c *AccessController) checkWithResolvedOrg(ctx context.Context, req *AccessCheckRequest, user *User, org *Organization, orgCtx *OrgContext) (*AccessCheckResult, error) {
	// Resolve effective permissions (in-memory cache, DB cache, or compute).
	perms, err := c.resolvePermissionsForRequest(ctx, req, user, org)
	if err != nil {
		return nil, err
	}

	// Check method permission.
	if res, handled := c.checkMethodAllowed(req, perms); handled {
		return res, nil
	}

	// Handle eth_getLogs specially - needs multi-address validation.
	if res, handled := c.checkEthGetLogsAccess(ctx, req, user, org, orgCtx, perms); handled {
		return res, nil
	}

	// Determine required claim based on the operation
	requiredClaim := ClassifyOperation(req.EffectiveMethod(), req.Params)

	// Simple value transfers (no calldata) to unregistered addresses carve-out.
	if res, handled, err := c.classifyValueTransferCarveout(ctx, req, user, org, orgCtx, perms, requiredClaim); handled {
		return res, err
	}

	// Basic state queries (balance, nonce) on unregistered addresses carve-out.
	if res, handled, err := c.classifyBasicAddressQueryCarveout(ctx, req, user, org, orgCtx, perms); handled {
		return res, err
	}

	// Check contract access if target address is specified.
	if req.TargetAddress != "" {
		if res, handled, err := c.validateContractAccess(ctx, req, user, org, orgCtx, perms, requiredClaim); handled {
			return res, err
		}
	} else if requiredClaim == ClaimDeploy {
		if res, handled, err := c.validateDeploymentWithoutTarget(req, user, org, perms, requiredClaim); handled {
			return res, err
		}
	}

	// Check additional required claims from the request.
	if res, handled := c.checkAdditionalRequiredClaims(req, perms); handled {
		return res, nil
	}

	// Collect all claims the user has (from all contracts + defaults)
	allClaims := collectAllClaims(perms)

	return &AccessCheckResult{
		Allowed:   true,
		OrgID:     org.ID,
		UserID:    user.ID,
		RPCAPIKey: perms.RPCAPIKey,
		Claims:    allClaims,
	}, nil
}

// checkGlobalBlocks enforces the global method blocklist and the Multicall
// bypass detector. These run before any RBAC evaluation. Returns handled=true
// with a deny result when either check fires.
func (c *AccessController) checkGlobalBlocks(req *AccessCheckRequest) (*AccessCheckResult, bool) {
	// Check global blocklist FIRST - before any RBAC evaluation
	if IsMethodBlocked(req.Method) {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("method %s is globally blocked for security reasons", req.Method),
		}, true
	}

	// Check for Multicall bypass attempts
	if isMulticall, reason := DetectMulticall(req.Method, req.Params); isMulticall {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  reason,
		}, true
	}

	return nil, false
}

// checkAnonymousAccess evaluates access for requests with no authenticated
// principal (req.UserExternalID == ""). This phase always terminates the
// check — the caller returns its result directly.
//
// Anonymous permissions live in the `anonymous` group's group_access row
// (seeded by migration 044, RD-870). Edits restricted to super admin
// (X-Admin-Token) so the auditable rules are explicit and configurable
// rather than hardcoded here.
func (c *AccessController) checkAnonymousAccess(ctx context.Context, req *AccessCheckRequest) (*AccessCheckResult, error) {
	// Block historical state queries up-front. These reveal point-in-time
	// state and aren't safe to expose anonymously even if the method name
	// is on the allowlist. Authenticated users skip this check because
	// per-address visibility filters take over.
	if isHistorical, reason := IsHistoricalStateQuery(req.Method, req.Params); isHistorical {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  reason,
		}, nil
	}

	anonAccess, err := c.getAnonymousAccessCached(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load anonymous group access: %w", err)
	}
	if anonAccess == nil {
		// Migration not run, row deleted, or DB inconsistency. Fail closed.
		return &AccessCheckResult{
			Allowed:      false,
			AuthRequired: true,
			Reason:       "anonymous access not configured",
		}, nil
	}

	methodLower := strings.ToLower(strings.TrimSpace(req.Method))
	methodAllowed := false
	for _, allowed := range anonAccess.AllowedMethods {
		if strings.ToLower(allowed) == methodLower {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		return &AccessCheckResult{
			Allowed:      false,
			AuthRequired: true,
			Reason:       "authentication required for this operation",
		}, nil
	}

	// Defense in depth: deployment payloads always require an authenticated
	// principal with the deploy claim. The anonymous group has empty Claims
	// by default; even if a super admin allowlists eth_sendTransaction, a
	// CREATE-shaped payload still requires auth.
	if IsContractDeployment(req.Method, req.Params) {
		return &AccessCheckResult{
			Allowed:      false,
			AuthRequired: true,
			Reason:       "deployment requires authentication",
		}, nil
	}

	return &AccessCheckResult{Allowed: true}, nil
}

// resolveAndValidateUser loads the authenticated user and enforces the
// user-level gates (existence, ban, KYC). Returns the user for downstream
// phases. handled=true means the check terminated (either a deny result or a
// lookup error); the user return is only valid when handled=false.
func (c *AccessController) resolveAndValidateUser(ctx context.Context, req *AccessCheckRequest) (*User, *AccessCheckResult, bool, error) {
	// Get user by external ID
	user, err := c.store.GetUserByExternalID(ctx, req.UserExternalID)
	if err != nil {
		return nil, nil, true, fmt.Errorf("failed to get user: %w", err)
	}

	// If user doesn't exist in RBAC, deny access
	if user == nil {
		slog.Debug("access denied: user not found", "external_id", req.UserExternalID)
		return nil, &AccessCheckResult{
			Allowed: false,
			Reason:  "access denied",
		}, true, nil
	}

	// Check if user is banned
	if user.Banned {
		return nil, &AccessCheckResult{
			Allowed: false,
			Reason:  "user is banned",
		}, true, nil
	}

	// Check KYC requirement. Org-free metadata methods are exempt: the
	// anonymous allowlist serves the same methods with no user at all, so a
	// blanket deny here would make signing in strictly more restrictive than
	// staying anonymous (RD-1197). The ban check above stays a blanket deny
	// on purpose — it is an explicit administrative action.
	if !user.KYC && !orgFreeMetadataMethods[strings.ToLower(strings.TrimSpace(req.Method))] {
		return nil, &AccessCheckResult{
			Allowed: false,
			Reason:  "KYC verification required",
		}, true, nil
	}

	return user, nil, false, nil
}

// checkHistoricalStateQuery is the authenticated historical-state guard.
//
// M9 (security audit): historical-state queries can probe a
// contract's state at a past block when ownership may have been
// different. The pre-fix IsHistoricalStateQuery guard only ran for
// anonymous viewers. Authenticated non-admin viewers are now also
// denied historical queries — the per-address visibility resolver
// uses CURRENT ownership, so a contract that was owned by another
// org at block N could leak past state to today's owner.
//
// Admin viewers (is_org_admin or admin claim on a specific
// contract) are exempted by checking the user's group memberships
// via the optional OrgAdminChecker extension on the store
// interface. When the extension is not implemented (test fixtures
// using a minimal mock store) we err on the side of allowing
// historical queries — those fixtures don't model multi-tenant
// ownership changes, so the leak isn't reproducible there.
// The production store (*db.DB) is guaranteed to implement
// OrgAdminChecker at compile time (see the `var _ rbac.OrgAdminChecker`
// assertion in internal/db, RD-1164 #14), so this fail-open branch is
// unreachable in production and cannot be silently disabled by a
// dropped method.
func (c *AccessController) checkHistoricalStateQuery(ctx context.Context, req *AccessCheckRequest, user *User) (*AccessCheckResult, bool, error) {
	if isHistorical, reason := IsHistoricalStateQuery(req.Method, req.Params); isHistorical {
		allow := true
		if adminChk, ok := c.store.(OrgAdminChecker); ok {
			isAdmin, _, adminErr := adminChk.IsOrgAdmin(ctx, user.ID)
			if adminErr != nil {
				return nil, true, fmt.Errorf("failed to check admin status for historical query: %w", adminErr)
			}
			allow = isAdmin
		}
		if !allow {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  reason,
			}, true, nil
		}
	}
	return nil, false, nil
}

// resolveOrgContextForRequest builds the OrgContext (which performs cross-org
// isolation from the start) and determines which org to evaluate permissions
// against. handled=true means the check terminated with the returned result/err.
// When handled=false, both org and orgCtx are valid for downstream phases.
// callerOrgForDenial best-effort resolves the org to attribute a denial to
// when the check fails before an org has been selected (RD-1199): the
// explicitly requested org if the caller is a member of it, else the caller's
// only org — including when the caller supplied a foreign org id, since their
// own org's auditor should still see their member's denied probe. Ambiguous
// (multi-org, no usable explicit org) or lookup failure returns "" — the row
// stays NULL / super-admin-only, matching pre-org denials. It never returns
// an org the caller is not a member of.
func (c *AccessController) callerOrgForDenial(ctx context.Context, req *AccessCheckRequest, user *User) string {
	memberships, err := c.store.ListUserMembershipsWithDetails(ctx, user.ID)
	if err != nil || len(memberships) == 0 {
		return ""
	}
	orgIDs := make(map[string]bool, len(memberships))
	for _, m := range memberships {
		if m.Group != nil && m.Group.OrgID != "" {
			orgIDs[m.Group.OrgID] = true
		}
	}
	if req.OrgID != "" && orgIDs[req.OrgID] {
		return req.OrgID
	}
	if len(orgIDs) == 1 {
		for id := range orgIDs {
			return id
		}
	}
	return ""
}

func (c *AccessController) resolveOrgContextForRequest(ctx context.Context, req *AccessCheckRequest, user *User) (*Organization, *OrgContext, *AccessCheckResult, bool, error) {
	// Create OrgContext - handles cross-org isolation from the start
	// This replaces the scattered getUserOrganizationIDs + getOrgContextForTarget calls
	targetAddr := strings.ToLower(strings.TrimSpace(req.TargetAddress))
	orgCtx, err := NewOrgContext(ctx, c.store, user, targetAddr)
	if err != nil {
		// Cross-org violation detected (e.g., contract belongs to org user is not member of).
		// Attribute the denial to the caller's own org when unambiguous
		// (RD-1199) so the tier-2 per-org audit view shows the org its own
		// members' contract-access denials. Never attributed to the probed
		// contract's org — a foreign user's probe must not surface in another
		// tenant's audit view.
		return nil, nil, &AccessCheckResult{
			Allowed: false,
			Reason:  ErrContractAccessDenied,
			OrgID:   c.callerOrgForDenial(ctx, req, user),
			UserID:  user.ID,
		}, true, nil
	}

	// Ensure user has org membership
	if len(orgCtx.UserOrgIDs()) == 0 {
		return nil, nil, &AccessCheckResult{
			Allowed: false,
			Reason:  "user has no organization membership",
		}, true, nil
	}

	// Determine which org to use for permissions.
	// Priority: 1) explicit OrgID, 2) explicit OrgSlug, 3) target-based org context.
	// No implicit fallback: if none of the above resolves, the request is denied.
	// Clients must use /rpc/:org_id or target a registered contract.
	var org *Organization
	if req.OrgID != "" {
		// Explicit org ID requested - look it up and verify membership
		org, err = c.store.GetOrganization(ctx, req.OrgID)
		if err != nil {
			return nil, nil, nil, true, fmt.Errorf("failed to get organization by ID: %w", err)
		}
		if org == nil {
			slog.Debug("access denied: organization not found", "org_id", req.OrgID, "user", req.UserExternalID)
			return nil, nil, &AccessCheckResult{
				Allowed: false,
				Reason:  "access denied",
			}, true, nil
		}
		// Verify user is a member of this org
		if !orgCtx.UserOrgIDs()[org.ID] {
			slog.Debug("access denied: user not member of org", "org_id", req.OrgID, "user", req.UserExternalID)
			return nil, nil, &AccessCheckResult{
				Allowed: false,
				Reason:  "access denied",
			}, true, nil
		}
	} else if req.OrgSlug != "" && req.OrgSlug != "default" {
		// Explicit org slug requested - look it up and verify membership
		org, err = c.store.GetOrganizationBySlug(ctx, req.OrgSlug)
		if err != nil {
			return nil, nil, nil, true, fmt.Errorf("failed to get organization by slug: %w", err)
		}
		if org == nil {
			slog.Debug("access denied: organization not found", "org_slug", req.OrgSlug, "user", req.UserExternalID)
			return nil, nil, &AccessCheckResult{
				Allowed: false,
				Reason:  "access denied",
			}, true, nil
		}
		// Verify user is a member of this org
		if !orgCtx.UserOrgIDs()[org.ID] {
			slog.Debug("access denied: user not member of org", "org_slug", req.OrgSlug, "user", req.UserExternalID)
			return nil, nil, &AccessCheckResult{
				Allowed: false,
				Reason:  "access denied",
			}, true, nil
		}
	} else {
		// No explicit org - derive from target address ownership first,
		// then fall back to implicit single-org resolution.
		org = orgCtx.Org()
		if org == nil {
			userOrgs := orgCtx.UserOrgIDs()
			if len(userOrgs) == 1 {
				// Exactly one org: unambiguous — use it without requiring org_id in the path.
				// Wallets and tools that use a plain /rpc URL work out of the box for
				// single-org users. Multi-org users must specify /rpc/:org_id.
				var singleOrgID string
				for id := range userOrgs {
					singleOrgID = id
				}
				org, err = c.store.GetOrganization(ctx, singleOrgID)
				if err != nil {
					return nil, nil, nil, true, fmt.Errorf("failed to get organization: %w", err)
				}
				if org == nil {
					return nil, nil, &AccessCheckResult{
						Allowed: false,
						Reason:  "access denied",
					}, true, nil
				}
			} else {
				// 0 orgs: already caught above; 2+ orgs: caller must specify.
				return nil, nil, &AccessCheckResult{
					Allowed: false,
					Reason:  "multiple organizations: use /rpc/:org_id to specify which org",
				}, true, nil
			}
		}
	}

	return org, orgCtx, nil, false, nil
}

// resolvePermissionsForRequest returns the user's effective permissions in the
// given org.
//
// Check in-memory cache first, unless the caller asked for a fresh
// resolution. BypassCache is set by the RD-928 impersonation surface
// so a tier-2 admin running "View as user X" sees X's current perms,
// not a snapshot the cache picked up before X's last group/grant
// mutation. We also skip the post-resolve Set so the bypassed call
// doesn't pollute the cache for non-impersonated callers.
func (c *AccessController) resolvePermissionsForRequest(ctx context.Context, req *AccessCheckRequest, user *User, org *Organization) (*EffectivePermissions, error) {
	var perms *EffectivePermissions
	if !req.BypassCache {
		if cachedPerms := c.cache.Get(user.ID, org.ID); cachedPerms != nil {
			perms = cachedPerms
		}
	}
	if perms == nil {
		// Resolve permissions (checks DB cache, then computes).
		//
		// cacheable is the RD-1267 verdict: false when an invalidation
		// committed while the compute was in flight. The request still gets
		// the permissions, but caching them here would keep a just-revoked
		// grant usable for the whole TTL — the shared SQL cache already
		// refused the same entry, and this cache must agree with it.
		resolved, cacheable, err := c.resolver.ResolvePermissionsCacheable(ctx, user.ID, org.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve permissions: %w", err)
		}
		perms = resolved

		if !req.BypassCache && cacheable {
			// Store in in-memory cache for the normal hot path.
			c.cache.Set(perms)
		}
	}
	return perms, nil
}

// checkMethodAllowed enforces the group method allowlist. Returns handled=true
// with a deny result when the method is not permitted.
func (c *AccessController) checkMethodAllowed(req *AccessCheckRequest, perms *EffectivePermissions) (*AccessCheckResult, bool) {
	// Check method permission
	if !perms.HasMethod(req.Method) {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  fmt.Sprintf("method %s not allowed", req.Method),
		}, true
	}
	return nil, false
}

// checkEthGetLogsAccess handles eth_getLogs specially - needs multi-address
// validation. eth_getLogs can have multiple addresses in the filter, unlike
// other methods that target a single contract. We validate ALL addresses in
// the filter. handled=true when the effective method is eth_getLogs (this phase
// always terminates the check for that method).
func (c *AccessController) checkEthGetLogsAccess(ctx context.Context, req *AccessCheckRequest, user *User, org *Organization, orgCtx *OrgContext, perms *EffectivePermissions) (*AccessCheckResult, bool) {
	if req.EffectiveMethod() == "eth_getLogs" {
		if err := c.validateGetLogsWithOrgContext(ctx, perms, orgCtx, req.Params); err != nil {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  err.Error(),
			}, true
		}
		// eth_getLogs passed validation - return allowed
		allClaims := collectAllClaims(perms)
		return &AccessCheckResult{
			Allowed:   true,
			OrgID:     org.ID,
			UserID:    user.ID,
			RPCAPIKey: perms.RPCAPIKey,
			Claims:    allClaims,
		}, true
	}
	return nil, false
}

// classifyValueTransferCarveout handles simple value transfers.
//
// Simple value transfers (no calldata) to unregistered addresses are treated
// as EOA transfers. No contract-level access check is needed since EOAs
// don't have code to execute; method allowlist already verified the method
// is permitted.
//
// Covers both eth_sendTransaction (actually sending) and eth_estimateGas
// (the pre-flight call standard tooling makes before signing — cast send,
// hardhat, ethers, viem all hit estimateGas first). Without the
// estimateGas carve-out, every mainstream client breaks at the pre-flight
// step even though sendTransaction would have been allowed. RD-969.
func (c *AccessController) classifyValueTransferCarveout(ctx context.Context, req *AccessCheckRequest, user *User, org *Organization, orgCtx *OrgContext, perms *EffectivePermissions, requiredClaim Claim) (*AccessCheckResult, bool, error) {
	if (req.EffectiveMethod() == "eth_sendTransaction" || req.EffectiveMethod() == "eth_estimateGas") &&
		req.TargetAddress != "" && isValueTransferParams(req.Params) {
		addr := strings.ToLower(req.TargetAddress)
		// Check if this address is registered as a contract or preregistered address
		if !perms.IsContractRegistered(addr) {
			ownerOrgID, err := orgCtx.OwnerOrgID(ctx, addr)
			if err != nil {
				return nil, true, fmt.Errorf("failed to check address ownership: %w", err)
			}
			if ownerOrgID == "" {
				// Address is not a known contract — treat as EOA value transfer.
				if requiredClaim != "" && !hasClaim(perms.Claims, requiredClaim) {
					slog.Debug("access denied: missing claim for value transfer", "claim", requiredClaim, "target", req.TargetAddress, "user", req.UserExternalID)
					return &AccessCheckResult{
						Allowed: false,
						Reason:  "access denied",
					}, true, nil
				}
				allClaims := collectAllClaims(perms)
				return &AccessCheckResult{
					Allowed:   true,
					OrgID:     org.ID,
					UserID:    user.ID,
					RPCAPIKey: perms.RPCAPIKey,
					Claims:    allClaims,
				}, true, nil
			}
		}
	}
	return nil, false, nil
}

// classifyBasicAddressQueryCarveout handles basic state queries.
//
// Basic state queries (balance, nonce) on addresses not registered to any org
// are allowed if the method is in the user's allowlist. These are needed for:
//   - eth_getTransactionCount: nonce lookups for tx building (cast send, wallets)
//   - eth_getBalance: wallet balance display
//
// eth_getStorageAt has tiered access (admin=all slots, non-admin=well-known only)
// enforced below. eth_getProof needs strict contract-level gating since
// both methods access contract-internal state that could leak sensitive data.
func (c *AccessController) classifyBasicAddressQueryCarveout(ctx context.Context, req *AccessCheckRequest, user *User, org *Organization, orgCtx *OrgContext, perms *EffectivePermissions) (*AccessCheckResult, bool, error) {
	if req.TargetAddress != "" && isBasicAddressQuery(req.EffectiveMethod()) {
		addr := strings.ToLower(req.TargetAddress)
		if !perms.IsContractRegistered(addr) {
			ownerOrgID, err := orgCtx.OwnerOrgID(ctx, addr)
			if err != nil {
				return nil, true, fmt.Errorf("failed to check address ownership: %w", err)
			}
			if ownerOrgID == "" {
				// Not owned by any org — allow (method allowlist already verified).
				allClaims := collectAllClaims(perms)
				return &AccessCheckResult{
					Allowed:   true,
					OrgID:     org.ID,
					UserID:    user.ID,
					RPCAPIKey: perms.RPCAPIKey,
					Claims:    allClaims,
				}, true, nil
			}
			// Owned by an org — fall through to contract access check
		}
	}
	return nil, false, nil
}

// validateContractAccess is the dense contract-access gate, run when the
// request targets a specific address. It resolves the effective ContractAccess
// (explicit grant, cross-org-filtered default claims, pre-registration, or
// deployer auto-grant), then enforces the cross-org isolation check, required
// claim, tiered eth_getStorageAt access, function-selector rules, and proxy
// upgrade validation. handled=true means the check terminated with the returned
// result/err; handled=false means all inner gates passed and evaluation falls
// through to the additional-required-claims phase.
func (c *AccessController) validateContractAccess(ctx context.Context, req *AccessCheckRequest, user *User, org *Organization, orgCtx *OrgContext, perms *EffectivePermissions, requiredClaim Claim) (*AccessCheckResult, bool, error) {
	addr := strings.ToLower(req.TargetAddress)

	// Check if user has EXPLICIT access to this contract in their permissions
	hasExplicitAccess := perms.IsContractRegistered(addr)

	// Get contract access for this address (may return default_claims for unregistered contracts)
	access := perms.GetContractAccess(addr)

	// For non-explicit access (default claims), check ownership to enforce cross-org isolation.
	// Unregistered addresses (ownerOrgID == "") are public — keep default claims.
	// Addresses owned by another org are denied — strip access.
	// Cache the owner lookup so the preregistered-address check below can reuse it.
	var (
		ownerOrgID        string
		ownerOrgIDFetched bool
	)
	if access != nil && !hasExplicitAccess {
		var err error
		ownerOrgID, err = orgCtx.OwnerOrgID(ctx, addr)
		if err != nil {
			return nil, true, fmt.Errorf("failed to check address ownership: %w", err)
		}
		ownerOrgIDFetched = true
		if ownerOrgID != "" && !orgCtx.UserOrgIDs()[ownerOrgID] {
			// Registered to a different org — deny via default claims.
			access = nil
		}
		// ownerOrgID == "" means unregistered — keep default claims (public).
		// ownerOrgID in user's orgs — keep default claims (own org).
	}

	// Preregistered addresses: planned CREATE/CREATE2 deployments that are
	// expected to land at a deterministic address. The deployer needs access
	// to the future contract before it's mined. If the address is in
	// preregistered_addresses for one of the user's orgs, grant access and
	// treat as explicit (skips the cross-org / 3-tier grant check below).
	//
	// Registered contracts (contracts table) without an explicit grant do NOT
	// fall through here anymore — RD-849 requires an explicit contract_grant
	// for tier 3 admins to reach a contract, matching the explorer visibility
	// layer. Tier 2 org admins (is_org_admin) already get all org contracts
	// materialized as explicit ContractAccess in computeOrgAdminPermissions.
	if access == nil {
		if !ownerOrgIDFetched {
			var err error
			ownerOrgID, err = orgCtx.OwnerOrgID(ctx, addr)
			if err != nil {
				return nil, true, fmt.Errorf("failed to check address ownership: %w", err)
			}
		}
		if ownerOrgID != "" && orgCtx.UserOrgIDs()[ownerOrgID] {
			preregistered, err := c.store.IsAddressPreregistered(ctx, ownerOrgID, addr)
			if err != nil {
				return nil, true, fmt.Errorf("failed to check preregistered address: %w", err)
			}
			// Preserve the prior gate: pre-reg access requires admin or deploy
			// claim. Pre-registration is a deployment-related operation, so it's
			// scoped to users with operational claims (plus is_org_admin tier 2
			// via the hasExplicitAccess fast path, and the actual deployer via
			// the auto-grant below).
			if preregistered && (hasClaim(perms.Claims, ClaimDeploy) || hasClaim(perms.Claims, ClaimAdmin)) {
				access = &ContractAccess{
					Claims:    []Claim{ClaimDeploy},
					Functions: nil, // All functions allowed
				}
				hasExplicitAccess = true
			}
		}
	}

	// Deployer auto-grant: if the user deployed this contract, they get access automatically.
	// This happens even without explicit grants - the deployer should always be able to interact
	// with their own contracts. Note: this does NOT grant upgrade/admin claims.
	if access == nil || (requiredClaim != "" && !hasClaim(access.Claims, requiredClaim)) {
		deployerID, err := c.store.GetContractDeployerByAddress(ctx, addr)
		if err != nil {
			return nil, true, fmt.Errorf("failed to check contract deployer: %w", err)
		}
		if deployerID != nil && *deployerID == user.ID {
			// User is the deployer - grant access (method allowlist controls read/write).
			deployerClaims := []Claim{}
			if access == nil {
				access = &ContractAccess{
					Claims:    deployerClaims,
					Functions: nil, // All functions allowed
				}
			} else {
				// Merge deployer claims with existing claims (union)
				mergedClaims := make(map[Claim]bool)
				for _, c := range access.Claims {
					mergedClaims[c] = true
				}
				for _, c := range deployerClaims {
					mergedClaims[c] = true
				}
				combined := make([]Claim, 0, len(mergedClaims))
				for c := range mergedClaims {
					combined = append(combined, c)
				}
				access = &ContractAccess{
					Claims:    combined,
					Functions: access.Functions, // Keep existing function restrictions
				}
			}
			hasExplicitAccess = true // Deployer access counts as explicit for cross-org check
		}
	}

	// If still no access, deny
	if access == nil {
		slog.Debug("access denied: no contract access", "contract", req.TargetAddress, "user", req.UserExternalID, "method", req.Method)
		return &AccessCheckResult{
			Allowed: false,
			Reason:  ErrContractAccessDenied,
		}, true, nil
	}

	// CROSS-ORG ISOLATION CHECK (P0 Security Fix) - now encapsulated in OrgContext
	// If user doesn't have explicit access but got access via default_claims,
	// we must verify the contract isn't registered to a DIFFERENT organization.
	if err := orgCtx.CheckDefaultClaimsAllowed(ctx, addr, hasExplicitAccess); err != nil {
		slog.Debug("access denied: cross-org isolation", "contract", req.TargetAddress, "user", req.UserExternalID, "detail", err.Error())
		return &AccessCheckResult{
			Allowed: false,
			Reason:  err.Error(),
		}, true, nil
	}

	// Check if user has the required claim on this contract
	if requiredClaim != "" && !hasClaim(access.Claims, requiredClaim) {
		slog.Debug("access denied: missing claim on contract", "claim", requiredClaim, "contract", req.TargetAddress, "user", req.UserExternalID)
		return &AccessCheckResult{
			Allowed: false,
			Reason:  ErrContractAccessDenied,
		}, true, nil
	}

	// Tiered eth_getStorageAt access: admin-claim users get all slots,
	// non-admin users get only well-known infrastructure slots (EIP-1967, EIP-2535).
	// This runs AFTER the contract access check (so we know the user has access
	// to the contract) but BEFORE function selector checks (which don't apply
	// to storage reads).
	if req.EffectiveMethod() == MethodGetStorageAt {
		if res, handled := c.validateStorageSlotAccess(req, access); handled {
			return res, true, nil
		}
		// Admin users pass through — all slots allowed
	}

	// Check function selector if specified.
	if res, handled, err := c.validateFunctionSelector(ctx, req, org, access); handled {
		return res, true, err
	}

	// Validate proxy upgrades for eth_sendTransaction (not deployments)
	// This must happen AFTER verifying write access
	if req.EffectiveMethod() == "eth_sendTransaction" {
		if res, handled, err := c.validateProxyUpgrade(ctx, req, org, access); handled {
			return res, true, err
		}
	}

	return nil, false, nil
}

// validateStorageSlotAccess enforces tiered eth_getStorageAt access: admin-claim
// users get all slots, non-admin users get only well-known infrastructure slots
// (EIP-1967, EIP-2535). Returns handled=true with a deny result when a non-admin
// requests a non-well-known slot.
func (c *AccessController) validateStorageSlotAccess(req *AccessCheckRequest, access *ContractAccess) (*AccessCheckResult, bool) {
	if !hasClaim(access.Claims, ClaimAdmin) {
		slot := extractStorageSlot(req.Params)
		if !IsWellKnownStorageSlot(slot) {
			slog.Debug("access denied: non-admin user accessing non-well-known storage slot",
				"slot", slot, "contract", req.TargetAddress, "user", req.UserExternalID)
			return &AccessCheckResult{
				Allowed: false,
				Reason:  ErrContractAccessDenied,
			}, true
		}
	}
	return nil, false
}

// validateFunctionSelector checks the function selector against the contract's
// function rules and parameter constraints.
//
// Uses the already-retrieved local `access` variable instead of calling
// perms.HasFunctionSelector/GetFunctionRule, which would call GetContractAccess
// again and could return the deploy default (Functions: nil) instead of the
// actual function restrictions from the grant.
//
// handled=true means the check terminated with the returned result/err.
func (c *AccessController) validateFunctionSelector(ctx context.Context, req *AccessCheckRequest, org *Organization, access *ContractAccess) (*AccessCheckResult, bool, error) {
	if req.FunctionSelector != "" {
		if !accessHasFunctionSelector(access, req.FunctionSelector) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("function %s not allowed on contract %s", req.FunctionSelector, req.TargetAddress),
			}, true, nil
		}

		// Check parameter constraints
		rule := accessGetFunctionRule(access, req.FunctionSelector)
		if rule != nil && len(rule.ParamRules) > 0 {
			// Get calldata - from request field or extract from params
			calldata := req.Calldata
			if calldata == nil {
				calldata = extractCalldata(req.EffectiveMethod(), req.Params)
			}
			if calldata == nil {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  "calldata required for parameter constraint validation",
				}, true, nil
			}

			// Get user's linked ETH addresses
			userAddresses, err := c.store.GetLinkedEthAddresses(ctx, req.UserExternalID)
			if err != nil {
				return nil, true, fmt.Errorf("failed to get linked ETH addresses: %w", err)
			}

			// Get contract ABI
			contract, err := c.store.GetContractByAddress(ctx, org.ID, strings.ToLower(req.TargetAddress))
			if err != nil {
				return nil, true, fmt.Errorf("failed to get contract: %w", err)
			}
			var contractABI string
			if contract != nil {
				contractABI = contract.ABI
			}

			// Validate parameter constraints
			if err := ValidateParamRules(rule, calldata, contractABI, userAddresses); err != nil {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  fmt.Sprintf("parameter constraint violation on %s: %s", req.TargetAddress, err.Error()),
				}, true, nil
			}
		}
	} else {
		// No function selector available.
		// Only eth_call, eth_estimateGas, and eth_sendTransaction use function selectors.
		// For those methods: deny if the contract has function-level restrictions because
		// we cannot verify which function is being called.
		// Other methods (eth_getCode, etc.) never produce a selector — applying this
		// check to them would make access depend on ABI registration rather than the
		// intended AllowedMethods + claim gates.
		methodUsesSelector := req.EffectiveMethod() == "eth_call" || req.EffectiveMethod() == "eth_estimateGas" || req.EffectiveMethod() == "eth_sendTransaction"
		if methodUsesSelector && access.Functions != nil {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("function selector required: contract %s has function-level restrictions", req.TargetAddress),
			}, true, nil
		}
	}
	return nil, false, nil
}

// validateProxyUpgrade validates proxy upgrades for eth_sendTransaction (not
// deployments). This must happen AFTER verifying write access. handled=true
// means the check terminated with the returned result/err.
func (c *AccessController) validateProxyUpgrade(ctx context.Context, req *AccessCheckRequest, org *Organization, access *ContractAccess) (*AccessCheckResult, bool, error) {
	addr := strings.ToLower(req.TargetAddress)
	calldata := extractCalldata(req.EffectiveMethod(), req.Params)
	if len(calldata) > 0 {
		// Check upgrade claim BEFORE proxy validation — if the calldata
		// matches an upgrade selector, the user must have the upgrade claim
		// regardless of proxy management state.
		if len(calldata) >= 4 {
			selector := hex.EncodeToString(calldata[:4])
			if IsUpgradeSelector(selector) && !hasClaim(access.Claims, ClaimUpgrade) {
				return &AccessCheckResult{
					Allowed: false,
					Reason:  ErrContractAccessDenied,
				}, true, nil
			}
		}

		upgradeResult, err := c.upgradeValidator.ValidateUpgrade(ctx, org.ID, addr, calldata)
		if err != nil {
			return nil, true, fmt.Errorf("failed to validate upgrade: %w", err)
		}
		if !upgradeResult.Allowed {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  fmt.Sprintf("proxy upgrade denied: %s", upgradeResult.Reason),
			}, true, nil
		}
	}
	return nil, false, nil
}

// validateDeploymentWithoutTarget handles a request with no target address that
// requires the 'deploy' claim (contract deployment).
//
// No claim check for deploy-less methods without a target address;
// the method allowlist is the only gate for non-deploy operations.
//
// handled=true means the check terminated with the returned result/err;
// handled=false falls through to the additional-required-claims phase (the
// deploy-claim gate passed but the request is not a contract deployment).
func (c *AccessController) validateDeploymentWithoutTarget(req *AccessCheckRequest, user *User, org *Organization, perms *EffectivePermissions, requiredClaim Claim) (*AccessCheckResult, bool, error) {
	// No target address but operation requires 'deploy' claim (contract deployment)
	// Check if user has the deploy claim via default claims
	if !hasClaim(perms.Claims, ClaimDeploy) {
		return &AccessCheckResult{
			Allowed: false,
			Reason:  "access denied",
		}, true, nil
	}

	// For contract deployments, runtime tracing
	// (jsonrpc_processor.validateDeployWithTracing — debug_traceCall
	// against empty `to`) is the authoritative cross-org isolation
	// gate. We just confirm the bytecode is present (404 helps the
	// client distinguish missing-payload from access-denied) and
	// pass — every executed frame is checked at the trace layer
	// against userOrgIDs. The pre-M10 static bytecode analyzer
	// covered only constant CALL targets; the dynamic ones it
	// claimed to delegate to runtime tracing weren't actually
	// wired. M10 wired the trace gate and the static analyzer was
	// removed.
	if requiredClaim == ClaimDeploy && IsContractDeployment(req.EffectiveMethod(), req.Params) {
		bytecodeHex := extractDeploymentBytecode(req.EffectiveMethod(), req.Params)
		if bytecodeHex == "" {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  "contract deployment missing bytecode",
			}, true, nil
		}
		allClaims := collectAllClaims(perms)
		return &AccessCheckResult{
			Allowed:   true,
			OrgID:     org.ID,
			UserID:    user.ID,
			RPCAPIKey: perms.RPCAPIKey,
			Claims:    allClaims,
		}, true, nil
	}
	return nil, false, nil
}

// checkAdditionalRequiredClaims enforces the request's explicit RequiredClaims.
// For each required claim the user must have it on any registered contract or
// via default claims. Returns handled=true with a deny result when any required
// claim is missing.
func (c *AccessController) checkAdditionalRequiredClaims(req *AccessCheckRequest, perms *EffectivePermissions) (*AccessCheckResult, bool) {
	for _, claim := range req.RequiredClaims {
		// For required claims, check if user has it on any registered contract or via default claims
		hasClaimOnAnyContract := false
		for _, access := range perms.ContractAccess {
			if hasClaim(access.Claims, claim) {
				hasClaimOnAnyContract = true
				break
			}
		}
		if !hasClaimOnAnyContract && !hasClaim(perms.Claims, claim) {
			return &AccessCheckResult{
				Allowed: false,
				Reason:  "access denied",
			}, true
		}
	}
	return nil, false
}

// collectAllClaims returns the union of all claims from all contracts and default claims.
func collectAllClaims(perms *EffectivePermissions) []Claim {
	claimSet := make(map[Claim]bool)

	// Add default claims
	for _, c := range perms.Claims {
		claimSet[c] = true
	}

	// Add claims from all contracts
	for _, access := range perms.ContractAccess {
		for _, c := range access.Claims {
			claimSet[c] = true
		}
	}

	result := make([]Claim, 0, len(claimSet))
	for c := range claimSet {
		result = append(result, c)
	}
	return result
}

// WriteOpsMap classifies state-modifying RPC methods. These methods are no
// longer gated by a "write" claim — the method allowlist is the source of
// truth. The map is retained for reference and test completeness checks.
// All keys must be lowercase.
var WriteOpsMap = map[string]bool{
	"eth_sendtransaction":    true,
	"eth_sendrawtransaction": true, // Requires auth; processor enforces runtime-tracing gate
}

// ReadOpsMap classifies read-only RPC methods that access blockchain state.
// These methods are no longer gated by a "read" claim — the method allowlist
// is the source of truth. The map is retained for reference, test completeness
// checks, and documentation of which methods access sensitive data on a
// private network:
//   - Contract state (balance, code, storage, logs) reveals private holdings
//   - Block contents reveal which transactions occurred (sender, receiver, value)
//   - Transaction details reveal identities and amounts
//   - Receipts reveal execution outcomes and logs
//   - Filters are equivalent to eth_getLogs and must require the same auth
//   - State proofs (eth_getProof) expose balance, nonce, and storage
//
// Only pure network/chain metadata that contains no user data is claim-free
// (eth_blockNumber, eth_chainId, eth_gasPrice, net_version, etc.).
//
// All keys must be lowercase.
var ReadOpsMap = map[string]bool{
	// Contract state reads
	"eth_call":                true,
	"eth_estimategas":         true,
	"eth_getcode":             true,
	"eth_getbalance":          true,
	"eth_getstorageat":        true,
	"eth_gettransactioncount": true,
	"eth_getlogs":             true,
	// State proofs — expose balance, nonce, storage hash (equivalent to eth_getBalance+eth_getStorageAt)
	"eth_getproof": true,
	// Access list simulation — reveals storage and address access patterns
	"eth_createaccesslist": true,
	// Node keystore accounts — may expose signer addresses on private PoA networks
	"eth_accounts": true,
	// Log filters — functionally equivalent to eth_getLogs, same auth requirement
	"eth_newfilter":                    true,
	"eth_newblockfilter":               true,
	"eth_newpendingtransactionfilter":  true,
	"eth_getfilterchanges":             true,
	"eth_getfilterlogs":                true,
	"eth_uninstallfilter":              true,
	// Block contents (include transaction lists with from/to/value)
	"eth_getblockbyhash":                   true,
	"eth_getblockbynumber":                 true,
	"eth_getblocktransactioncountbyhash":   true,
	"eth_getblocktransactioncountbynumber": true,
	"eth_getunclebyblockhashandindex":      true,
	"eth_getunclebyblocknumberandindex":    true,
	"eth_getunclecountbyblockhash":         true,
	"eth_getunclecountbyblocknumber":       true,
	// Transaction details (sender, receiver, value, input data)
	"eth_gettransactionbyhash":                 true,
	"eth_gettransactionbyblockhashandindex":    true,
	"eth_gettransactionbyblocknumberandindex":  true,
	// Receipts (logs, status, contract address)
	"eth_gettransactionreceipt": true,
	"eth_getblockreceipts":      true, // Block receipts (same privacy requirements as eth_getLogs)
}

// ClassifyOperation determines the required claim for a JSON-RPC method.
// Returns the claim needed to execute this operation, or "" if the method
// is gated only by the method allowlist (no additional claim required).
//
// Only deployment requires a claim gate (ClaimDeploy). Read/write methods
// are controlled entirely by the method allowlist on the group — if a method
// is in allowed_methods, it's permitted; claims are not consulted.
func ClassifyOperation(method string, params []any) Claim {
	// Normalize to lowercase for case-insensitive matching.
	method = strings.ToLower(strings.TrimSpace(method))

	// Contract deployment requires deploy claim
	if IsContractDeployment(method, params) {
		return ClaimDeploy
	}

	// All other methods are gated by AllowedMethods, not claims
	return ""
}

// IsContractDeployment checks if the method+params represent a contract deployment.
// Contract deployments are eth_sendTransaction calls with no 'to' address.
// Also detects eth_estimateGas for deployment (estimating gas for contract creation).
// NOTE: eth_sendRawTransaction is globally blocked because it cannot be validated
// without RLP decoding, which would bypass all RBAC security controls.
func IsContractDeployment(method string, params []any) bool {
	// Normalize to lowercase so both direct callers and ClassifyOperation work correctly.
	method = strings.ToLower(strings.TrimSpace(method))
	// Only eth_sendtransaction and eth_estimategas can be validated for deployment.
	if method != "eth_sendtransaction" && method != "eth_estimategas" {
		return false
	}

	if len(params) == 0 {
		// No params means we can't determine if it's a deployment.
		// Return false and let the method-level permissions handle access.
		// The caller can still require specific claims via required_claims.
		return false
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		// Malformed params, treat as deployment to be safe
		return true
	}

	// Check if 'to' field exists and is non-empty
	to, exists := txObj["to"]
	if !exists {
		// No 'to' field = contract deployment
		return true
	}

	// Handle various forms of empty 'to':
	// - nil/null
	// - empty string ""
	// - "0x" (some clients send this for deployment)
	if to == nil {
		return true
	}

	toStr, ok := to.(string)
	if !ok {
		// 'to' is not a string (e.g., number or object), treat as deployment to be safe
		return true
	}

	// Empty string or just "0x" means deployment
	if toStr == "" || toStr == "0x" {
		return true
	}

	// Has a valid 'to' address, not a deployment
	return false
}

// extractDeploymentBytecode extracts the bytecode from contract deployment params.
// For eth_sendTransaction and eth_estimateGas, the bytecode is in the "data" or "input" field.
// Returns empty string if bytecode cannot be extracted.
func extractDeploymentBytecode(method string, params []any) string {
	if method != "eth_sendTransaction" && method != "eth_estimateGas" {
		return ""
	}

	if len(params) == 0 {
		return ""
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return ""
	}

	// Try "data" field first (standard), then "input" field (some clients use this)
	if data, ok := txObj["data"].(string); ok && data != "" && data != "0x" {
		return data
	}
	if input, ok := txObj["input"].(string); ok && input != "" && input != "0x" {
		return input
	}

	return ""
}

// extractCalldata extracts the calldata from transaction params as raw bytes.
// For eth_sendTransaction, the calldata is in the "data" or "input" field.
// Returns nil if calldata cannot be extracted or is empty.
func extractCalldata(method string, params []any) []byte {
	if method != "eth_sendTransaction" && method != "eth_call" && method != "eth_estimateGas" {
		return nil
	}

	if len(params) == 0 {
		return nil
	}

	txObj, ok := params[0].(map[string]any)
	if !ok {
		return nil
	}

	// Try "data" field first (standard), then "input" field (some clients use this)
	var hexData string
	if data, ok := txObj["data"].(string); ok && data != "" && data != "0x" {
		hexData = data
	} else if input, ok := txObj["input"].(string); ok && input != "" && input != "0x" {
		hexData = input
	}

	if hexData == "" {
		return nil
	}

	// Remove 0x prefix if present
	hexData = strings.TrimPrefix(hexData, "0x")

	// Decode hex to bytes
	calldata, err := hex.DecodeString(hexData)
	if err != nil {
		return nil
	}

	return calldata
}

// accessHasFunctionSelector checks if a function selector is allowed in the given ContractAccess.
// Unlike EffectivePermissions.HasFunctionSelector, this operates on an already-retrieved
// *ContractAccess to avoid re-fetching via GetContractAccess (which could return the deploy
// default with Functions: nil, bypassing function restrictions).
func accessHasFunctionSelector(access *ContractAccess, selector string) bool {
	if access == nil {
		return false
	}
	if access.Functions == nil {
		return true // nil = unrestricted (all functions allowed)
	}
	if len(access.Functions) == 0 {
		return false // non-nil empty = explicitly deny all
	}
	for _, rule := range access.Functions {
		if strings.EqualFold(rule.Selector, selector) {
			return true
		}
	}
	return false
}

// accessGetFunctionRule returns the FunctionRule for a specific selector from the given ContractAccess.
// Unlike EffectivePermissions.GetFunctionRule, this operates on an already-retrieved
// *ContractAccess to avoid re-fetching via GetContractAccess.
func accessGetFunctionRule(access *ContractAccess, selector string) *FunctionRule {
	if access == nil || access.Functions == nil || len(access.Functions) == 0 {
		return nil
	}
	for i := range access.Functions {
		if strings.EqualFold(access.Functions[i].Selector, selector) {
			return &access.Functions[i]
		}
	}
	return nil
}

// getUserOrganizationIDs returns the set of organization IDs the user is a member of.
func (c *AccessController) getUserOrganizationIDs(ctx context.Context, userID string) (map[string]bool, error) {
	memberships, err := c.store.ListUserMembershipsWithDetails(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}

	orgIDs := make(map[string]bool)
	for _, m := range memberships {
		if m.Group != nil {
			orgIDs[m.Group.OrgID] = true
		}
	}

	return orgIDs, nil
}

// userHasDeployClaimInAnyOrg checks if the user has deploy or admin claims
// in any of their group memberships across all organizations.
// This is used for unregistered contract access where permissions are resolved
// for one org but deploy claims may exist in another.
func (c *AccessController) userHasDeployClaimInAnyOrg(ctx context.Context, userID string) (bool, error) {
	memberships, err := c.store.ListUserMembershipsWithDetails(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, m := range memberships {
		if m.Membership == nil {
			continue
		}
		access, err := c.store.GetGroupAccess(ctx, m.Membership.GroupID)
		if err != nil || access == nil {
			continue
		}
		for _, claim := range access.Claims {
			if claim == ClaimDeploy || claim == ClaimAdmin {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetUserOrgIDs returns all org IDs the user belongs to.
// Used by response filters to resolve permissions across all orgs.
func (c *AccessController) GetUserOrgIDs(ctx context.Context, userID string) ([]string, error) {
	memberships, err := c.store.ListUserMembershipsWithDetails(ctx, userID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var orgIDs []string
	for _, m := range memberships {
		if m.Group != nil && !seen[m.Group.OrgID] {
			seen[m.Group.OrgID] = true
			orgIDs = append(orgIDs, m.Group.OrgID)
		}
	}
	return orgIDs, nil
}

// getOrgContextForTarget determines the organization context based on the target address.
// For multi-org users, this enables accessing contracts from any org they belong to.
// Returns:
// - The org that owns the target contract (if user is a member)
// - An error if the contract is owned by an org the user is NOT a member of
// - nil org if the contract is public (not owned by any org)
func (c *AccessController) getOrgContextForTarget(ctx context.Context, userOrgIDs map[string]bool, targetAddress string) (*Organization, error) {
	if targetAddress == "" {
		return nil, nil
	}

	// Look up which org owns this contract
	ownerOrgID, err := c.store.GetContractOwnerOrgID(ctx, targetAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get contract owner: %w", err)
	}

	if ownerOrgID == "" {
		// Contract is not owned by any org (public contract)
		return nil, nil
	}

	// Contract is owned by an org - check if user is a member
	if !userOrgIDs[ownerOrgID] {
		return nil, fmt.Errorf(ErrContractAccessDenied)
	}

	// User is a member of the org that owns this contract
	org, err := c.store.GetOrganization(ctx, ownerOrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return org, nil
}

// isBasicAddressQuery returns true for state queries that target an address but
// only return public non-sensitive data. These are safe to allow on unregistered
// EOAs without contract-level grants:
//   - eth_getBalance: always returns a value (0 for non-existent) — no existence leak
//   - eth_getTransactionCount: always returns a value (0 for non-existent) — needed for tx nonce
//
// NOT included:
//   - eth_getCode: reveals whether an address has deployed code (contract existence oracle)
//   - eth_getStorageAt: tiered access enforced in CheckAccess (admin=all, read=well-known only)
//   - eth_getProof: returns balance + storage hash
func isBasicAddressQuery(method string) bool {
	switch method {
	case "eth_getBalance", "eth_getTransactionCount":
		return true
	}
	return false
}

// isValueTransferParams checks if eth_sendTransaction params represent a simple
// value transfer (no calldata). Returns true if the tx object has no "data"/"input"
// field or if it's empty/0x.
func isValueTransferParams(params []any) bool {
	if len(params) == 0 {
		return false
	}
	txObj, ok := params[0].(map[string]any)
	if !ok {
		return false
	}
	// Check "data" field
	if data, ok := txObj["data"].(string); ok {
		d := strings.TrimSpace(data)
		if d != "" && d != "0x" && d != "0X" {
			return false // has calldata
		}
	}
	// Check "input" field (some clients use this instead of "data")
	if input, ok := txObj["input"].(string); ok {
		d := strings.TrimSpace(input)
		if d != "" && d != "0x" && d != "0X" {
			return false // has calldata
		}
	}
	return true
}

// GetTargetAddress extracts the target address from JSON-RPC params.
func GetTargetAddress(method string, params []any) string {
	if len(params) == 0 {
		return ""
	}

	switch method {
	case "eth_call", "eth_estimateGas", "eth_createAccessList":
		// Call-like methods: target is "to" inside the transaction object.
		// eth_createAccessList reveals storage and address access patterns —
		// must be gated per-address like eth_call.
		if callObj, ok := params[0].(map[string]any); ok {
			if to, ok := callObj["to"].(string); ok {
				return strings.ToLower(to)
			}
		}
	case "eth_sendTransaction":
		if txObj, ok := params[0].(map[string]any); ok {
			if to, ok := txObj["to"].(string); ok {
				addr := strings.ToLower(strings.TrimSpace(to))
				// "0x" or "" means no target (contract deployment), not address zero
				if addr == "0x" || addr == "" {
					return ""
				}
				return addr
			}
		}
	case "eth_getCode", "eth_getStorageAt", "eth_getBalance", "eth_getTransactionCount", "eth_getProof":
		// All address-targeted state queries need per-address access checks.
		// On a private network, balances, nonces, bytecode, and storage proofs
		// are sensitive — cross-org queries leak financial and activity data.
		// eth_getProof returns balance + nonce + storage hash for an address,
		// equivalent to eth_getBalance + eth_getStorageAt combined.
		if addr, ok := params[0].(string); ok {
			return strings.ToLower(addr)
		}
	case "eth_getLogs":
		// eth_getLogs filter can have "address" as a string or array of strings.
		// Extract the first address for org resolution. The full multi-address
		// validation happens later in validateGetLogsWithOrgContext.
		if len(params) > 0 {
			if filter, ok := params[0].(map[string]any); ok {
				switch addr := filter["address"].(type) {
				case string:
					return strings.ToLower(addr)
				case []any:
					if len(addr) > 0 {
						if s, ok := addr[0].(string); ok {
							return strings.ToLower(s)
						}
					}
				}
			}
		}
	}

	return ""
}

// extractBlockParam extracts the block parameter from JSON-RPC params.
// For eth_call: params are [txObject, blockParam] - block is 2nd param
// For eth_getStorageAt: params are [address, slot, blockParam] - block is 3rd param
// Returns the block parameter as string, or "latest" if not specified.
func extractBlockParam(method string, params []any) string {
	if len(params) == 0 {
		return "latest"
	}

	var blockParamIndex int
	switch strings.ToLower(method) {
	case "eth_call", "eth_getbalance", "eth_getcode", "eth_gettransactioncount":
		blockParamIndex = 1
	case "eth_getstorageat", "eth_getproof":
		// eth_getStorageAt: [address, slot, block]
		// eth_getProof: [address, storageKeys[], block]
		blockParamIndex = 2
	default:
		return "latest"
	}

	if len(params) <= blockParamIndex {
		return "latest"
	}

	blockParam := params[blockParamIndex]
	if blockParam == nil {
		return "latest"
	}

	blockStr, ok := blockParam.(string)
	if !ok {
		// Non-string block param (e.g., number or block object) - treat as historical for safety
		return "historical"
	}

	if blockStr == "" {
		return "latest"
	}

	return blockStr
}

// isHistoricalBlock checks if a block parameter represents a historical state query.
// Returns true for block numbers (hex like "0x1234") and block hashes.
// Returns false for "latest", "pending", "safe", "finalized", "earliest", or empty string.
func isHistoricalBlock(blockParam string) bool {
	// Empty defaults to "latest" (not historical)
	if blockParam == "" {
		return false
	}

	// Named block tags are NOT historical
	switch strings.ToLower(blockParam) {
	case "latest", "pending", "safe", "finalized", "earliest":
		return false
	}

	// Anything else is considered historical:
	// - Hex block numbers like "0x1234"
	// - Block hashes (66 character hex strings)
	// - Block objects (if someone passes one)
	return true
}

// IsHistoricalStateQuery checks if a request is attempting to query historical blockchain state.
// Returns (isHistorical, reason) where reason explains why it was flagged as historical.
// This is a privacy protection measure to prevent queries at specific past blocks.
func IsHistoricalStateQuery(method string, params []any) (bool, string) {
	method = strings.ToLower(strings.TrimSpace(method))

	// Only check methods that accept block parameters for state queries.
	// We include ALL standard methods that accept a block parameter to prevent
	// leakage of historical state.
	historicalCheckMethods := map[string]bool{
		"eth_call":                true,
		"eth_getstorageat":        true,
		"eth_getbalance":          true,
		"eth_getcode":             true,
		"eth_gettransactioncount": true,
		"eth_getproof":            true,
	}

	if !historicalCheckMethods[method] {
		return false, ""
	}

	blockParam := extractBlockParam(method, params)
	if isHistoricalBlock(blockParam) {
		return true, "historical state queries not permitted"
	}

	return false, ""
}

// GetFunctionSelector extracts the function selector (first 4 bytes) from calldata.
// Returns empty string if no valid selector found.
// Expects selector format "0xXXXXXXXX" (10 characters including 0x prefix).
// Checks both "data" and "input" fields (some clients use "input" instead of "data").
func GetFunctionSelector(method string, params []any) string {
	if len(params) == 0 {
		return ""
	}

	// Only extract selectors for contract call methods
	switch method {
	case "eth_call", "eth_estimateGas", "eth_sendTransaction":
		if callObj, ok := params[0].(map[string]any); ok {
			// Check "data" first, then "input" (some clients use "input")
			if data, ok := callObj["data"].(string); ok && len(data) >= 10 {
				return strings.ToLower(data[:10])
			}
			if input, ok := callObj["input"].(string); ok && len(input) >= 10 {
				return strings.ToLower(input[:10])
			}
		}
	}

	return ""
}

// extractGetLogsAddresses extracts contract addresses from eth_getLogs filter.
// The address field can be:
// - A single address string: "0x..."
// - An array of address strings: ["0x...", "0x..."]
// - null/missing (returns empty slice)
func extractGetLogsAddresses(filter map[string]any) []string {
	var addresses []string

	addrField := filter["address"]
	if addrField == nil {
		return nil
	}

	// Can be a single address string
	if addr, ok := addrField.(string); ok {
		if addr != "" {
			addresses = append(addresses, strings.ToLower(addr))
		}
		return addresses
	}

	// Or an array of addresses
	if addrArray, ok := addrField.([]any); ok {
		for _, a := range addrArray {
			if addr, ok := a.(string); ok && addr != "" {
				addresses = append(addresses, strings.ToLower(addr))
			}
		}
	}

	return addresses
}

// validateGetLogsWithOrgContext validates eth_getLogs access using OrgContext for cross-org checks.
// This is the preferred method that uses the encapsulated OrgContext for cleaner cross-org validation.
func (c *AccessController) validateGetLogsWithOrgContext(ctx context.Context, perms *EffectivePermissions, orgCtx *OrgContext, params []any) error {
	if len(params) == 0 {
		return fmt.Errorf("eth_getLogs: missing filter parameter")
	}

	filterObj, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("eth_getLogs: invalid filter parameter type")
	}

	// Extract addresses from filter
	addresses := extractGetLogsAddresses(filterObj)

	// SECURITY: Require address filter to prevent broad queries
	if len(addresses) == 0 {
		return fmt.Errorf("eth_getLogs: address filter required for security")
	}

	// Check all addresses are in scope using OrgContext (cross-org isolation)
	if err := orgCtx.CheckMultiAddressesInScope(ctx, addresses); err != nil {
		return fmt.Errorf("eth_getLogs: %w", err)
	}

	// Verify user has access to each address (method allowlist already checked eth_getLogs).
	for _, addr := range addresses {
		hasExplicitAccess := perms.IsContractRegistered(addr)
		if !hasExplicitAccess {
			ownerOrgID, err := c.store.GetContractOwnerOrgID(ctx, addr)
			if err != nil {
				return fmt.Errorf("eth_getLogs: failed to check contract owner: %w", err)
			}
			if ownerOrgID == "" {
				// Not owned by any org — deny unless precompile.
				// All unregistered addresses are private by default.
				if !precompile.IsPrecompileAddress(addr) {
					return fmt.Errorf("eth_getLogs: %s", ErrContractAccessDenied)
				}
				// Precompile — always accessible.
				continue
			}
		}

		// For contracts in user's orgs or public contracts, check cross-org isolation
		if err := orgCtx.CheckDefaultClaimsAllowed(ctx, addr, hasExplicitAccess); err != nil {
			// Contract is in another org - should have been caught by CheckMultiAddressesInScope,
			// but double-check here for defense in depth
			return fmt.Errorf("eth_getLogs: %s", ErrContractAccessDenied)
		}

		// Verify contract access exists
		access := perms.GetContractAccess(addr)
		if access == nil {
			return fmt.Errorf("eth_getLogs: %s", ErrContractAccessDenied)
		}
	}

	return nil
}

// EnsureUserExists creates a user if they don't exist, or returns the existing user.
// This is used during authentication to ensure users are in the RBAC system.
// The kyc parameter is only used for NEW users; existing users retain their KYC status
// (KYC status should be managed via admin API, not overwritten during auth).
// If skipDefaultGroup is true, the user is NOT added to the default group on creation
// (used when a specific group will be assigned by the caller, e.g. Azure AD tenant config).
func (c *AccessController) EnsureUserExists(ctx context.Context, externalID string, kyc bool, skipDefaultGroup bool) (*User, error) {
	user, err := c.store.GetUserByExternalID(ctx, externalID)
	if err != nil {
		return nil, err
	}

	if user != nil {
		// Return existing user without modifying their KYC status
		// KYC is admin-managed and should not be changed during authentication
		return user, nil
	}

	// Create new user
	user = &User{
		ID:         uuid.New().String(),
		ExternalID: externalID,
		KYC:        kyc,
		Banned:     false,
		Metadata:   make(map[string]any),
	}

	if err := c.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Add user to default group unless caller will assign a specific group
	if !skipDefaultGroup {
		membership := &UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: DefaultGroupID,
			Source:  MembershipSourceAdmin,
		}

		if err := c.store.CreateMembership(ctx, membership); err != nil {
			// Log but don't fail - user is created
			slog.Warn("failed to add user to default group", "user_id", user.ID, "error", err)
		}
	}

	// Audit log
	c.store.CreateAuditLog(ctx, &AuditLogEntry{
		Action:       AuditActionCreate,
		ResourceType: ResourceTypeUser,
		ResourceID:   &user.ID,
		ResourceName: externalID,
		NewValue: map[string]any{
			"external_id": externalID,
			"kyc":         kyc,
		},
	})

	return user, nil
}

// InvalidateUser invalidates cached permissions for a user.
func (c *AccessController) InvalidateUser(ctx context.Context, userID string) error {
	c.cache.InvalidateUser(userID)
	return c.resolver.InvalidateUserPermissions(ctx, userID)
}

// InvalidateOrg invalidates cached permissions for all users in an organization.
func (c *AccessController) InvalidateOrg(ctx context.Context, orgID string) error {
	c.cache.InvalidateOrg(orgID)
	return c.resolver.InvalidateOrgPermissions(ctx, orgID)
}

// InvalidateOrgLocalCache drops this process's in-memory permissions for an
// org WITHOUT touching the shared SQL cache or its generation counter.
//
// It exists for the revoke handlers that invalidate the shared cache inside
// the same transaction as their mutation (RD-1267): that transaction has
// already bumped the generation and deleted the cache rows, so calling the
// full InvalidateOrg afterwards would bump a second time and needlessly
// invalidate concurrent computes. The in-memory cache is process-local and
// cannot participate in that transaction, so it is cleared here instead —
// after the mutation has committed, so nothing repopulates it from
// pre-mutation state.
func (c *AccessController) InvalidateOrgLocalCache(orgID string) {
	c.cache.InvalidateOrg(orgID)
}

// InvalidateGroup invalidates cached permissions for all users in a group.
func (c *AccessController) InvalidateGroup(ctx context.Context, groupID string) error {
	// Get the group to find its org_id for cache invalidation
	group, err := c.store.GetGroup(ctx, groupID)
	if err == nil && group != nil {
		// Invalidate the in-memory cache for the entire org (safest approach)
		c.cache.InvalidateOrg(group.OrgID)
	}
	return c.resolver.InvalidateGroupPermissions(ctx, groupID)
}

// GetEffectivePermissionsByIDs returns the effective permissions for a user by
// internal user ID and org ID. Used by response filters that already have the
// resolved IDs from the access check.
func (c *AccessController) GetEffectivePermissionsByIDs(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	return c.resolver.ResolvePermissions(ctx, userID, orgID)
}

// GetEffectivePermissions returns the effective permissions for a user in an organization.
func (c *AccessController) GetEffectivePermissions(ctx context.Context, userExternalID, orgSlug string) (*EffectivePermissions, error) {
	user, err := c.store.GetUserByExternalID(ctx, userExternalID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found: %s", userExternalID)
	}

	if orgSlug == "" {
		orgSlug = "default"
	}

	org, err := c.store.GetOrganizationBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, fmt.Errorf("organization not found: %s", orgSlug)
	}

	return c.resolver.ResolvePermissions(ctx, user.ID, org.ID)
}

// CacheStats returns statistics about the in-memory cache.
func (c *AccessController) CacheStats() CacheStats {
	return c.cache.Stats()
}

// Stop stops the access controller's background goroutines.
func (c *AccessController) Stop() {
	c.cache.Stop()
}

// TrackPlainCreateDeployment tracks a plain CREATE deployment for post-mining finalization.
// The pre-registration (in preregistered_addresses) is cleaned up or finalized when the tx mines.
func (c *AccessController) TrackPlainCreateDeployment(
	txHash, orgID, deployerUserID, preRegisteredAddr string,
) {
	if txHash == "" || orgID == "" || preRegisteredAddr == "" {
		return
	}
	deployment := &PendingDeployment{
		TxHash:            txHash,
		OrgID:             orgID,
		IsPlainCreate:     true,
		PreRegisteredAddr: preRegisteredAddr,
		DeployerUserID:    deployerUserID,
		SubmittedAt:       time.Now(),
	}
	c.pendingTracker.Track(txHash, deployment)
}

// NotifyDeploymentMined finalizes (or cleans up) a tracked plain CREATE
// deployment now that its receipt has arrived. The pre-registration row
// inserted before the tx was forwarded is converted to a full contract
// record on success, or deleted on revert. Untracked tx hashes are a
// silent no-op — the caller doesn't need to know which deploys we
// tracked.
//
// Parameters:
//   - ctx: Context for database operations
//   - txHash: The transaction hash of the mined deployment
//   - contractAddress: The address of the deployed contract from the receipt
//     (empty when the tx reverted)
func (c *AccessController) NotifyDeploymentMined(
	ctx context.Context,
	txHash string,
	contractAddress string,
) error {
	// Get the pending deployment (removes it from tracker)
	deployment := c.pendingTracker.Get(txHash)
	if deployment == nil {
		// Not a tracked deployment - this is fine
		return nil
	}
	if !deployment.IsPlainCreate || deployment.PreRegisteredAddr == "" {
		return nil
	}

	if contractAddress == "" {
		// Transaction reverted or receipt had no contract address — clean up.
		if err := c.store.DeletePreregisteredAddressByAddress(ctx, deployment.PreRegisteredAddr); err != nil {
			slog.Warn("failed to clean up plain CREATE pre-registration", "address", deployment.PreRegisteredAddr, "error", err)
		}
		return fmt.Errorf("plain CREATE deployment reverted or produced no contract address")
	}
	// Transaction succeeded — create a full contract record and remove the pre-registration.
	now := time.Now()
	contract := &Contract{
		ID:      uuid.New().String(),
		OrgID:   deployment.OrgID,
		Address: strings.ToLower(contractAddress),
		Name:    fmt.Sprintf("Contract %s", contractAddress[:10]),
		Metadata: map[string]any{
			"auto_registered": true,
			"via":             "plain_create",
		},
	}
	if deployment.DeployerUserID != "" {
		contract.DeployedByUserID = &deployment.DeployerUserID
	}
	contract.DeployedAt = &now
	if err := c.store.CreateContract(ctx, contract); err != nil {
		slog.Warn("failed to create contract record for plain CREATE", "address", contractAddress, "error", err)
		// Still clean up pre-registration even if contract creation failed.
	} else if deployment.DeployerUserID != "" {
		// Grant contract to deployer's existing deploy group (non-fatal if it fails)
		if err := c.store.GrantContractToDeployerGroup(ctx, deployment.OrgID, contract.ID, deployment.DeployerUserID); err != nil {
			slog.Warn("failed to grant contract to deployer group", "address", contractAddress, "error", err)
		} else {
			// Drop the deployer's cached permissions so the next call to the
			// freshly-deployed contract re-resolves and sees the new grant
			// instead of waiting for cache TTL expiry.
			if invErr := c.InvalidateUser(ctx, deployment.DeployerUserID); invErr != nil {
				slog.Warn("failed to invalidate deployer cache after plain CREATE grant", "user_id", deployment.DeployerUserID, "error", invErr)
			}
		}
	}
	if err := c.store.DeletePreregisteredAddressByAddress(ctx, deployment.PreRegisteredAddr); err != nil {
		slog.Warn("failed to delete pre-registration after finalization", "address", deployment.PreRegisteredAddr, "error", err)
	}
	return nil
}

// GetPendingDeployment retrieves a pending deployment without removing it.
// This is useful for checking if a transaction is being tracked.
func (c *AccessController) GetPendingDeployment(txHash string) *PendingDeployment {
	return c.pendingTracker.Peek(txHash)
}

// PendingDeploymentCount returns the number of pending deployments being tracked.
func (c *AccessController) PendingDeploymentCount() int {
	return c.pendingTracker.Size()
}

// CleanupPendingDeployments removes expired pending deployments.
// Returns the number of entries removed.
func (c *AccessController) CleanupPendingDeployments() int {
	return c.pendingTracker.Cleanup()
}
