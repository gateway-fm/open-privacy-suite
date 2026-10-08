package server

import (
	"context"
	"encoding/json"
	"strings"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/viewscope"

	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// withViewerOrgScope anchors an impersonated read to orgID (RD-1308). The only
// callers are the two tier-2 impersonation surfaces: the admin dry-run
// (filterDryRunReadResponse / dryRunTraceLogsVisibleToUser) and the View-as
// RPC mirror (handleJSONRPC under impersonationGateMiddleware). A user's own
// RPC call never carries a scope.
//
// Under the scope every authorization input of the RPC read path resolves in
// orgID only:
//
//   - effective permissions (resolvePermsForFilter): the org's grants only;
//   - the admin exemption (viewerAdminContracts): contracts owned by orgID only;
//   - visibleTo unlock eligibility (buildVisibleToUnlockableMap): contracts
//     owned by orgID only;
//   - visibleTo shares (txVisibilityForViewer): shares whose send was
//     authorised under orgID only;
//   - the RD-915 nested-call gate (validateEthCallWithTracing): orgID only;
//   - embedded-address field redaction: the visibility resolver
//     (db.GetBatchVisibility*) grants Full through orgID's groups only;
//   - the transaction envelope (applyViewerOrgScopeEnvelope): a transaction
//     or receipt addressed to another org's contract is null, even when the
//     user took part in it.
//
// The user's own linked addresses stay theirs: a transaction between the user
// and an address no org owns is part of "what would this user see?".
func withViewerOrgScope(ctx context.Context, orgID string) context.Context {
	return viewscope.WithOrg(ctx, orgID)
}

// viewerOrgScope reports the org an impersonated read is anchored to. present
// is true whenever a scope was set, even an empty one: an empty scope org then
// matches no org, so every scoped lookup fails closed rather than widening.
func viewerOrgScope(ctx context.Context) (orgID string, present bool) {
	return viewscope.Org(ctx)
}

// restrictToViewerOrgScope narrows the viewer's org memberships to the scope
// org. Without a scope the list is returned unchanged; with one, the result is
// the scope org when the viewer is a member of it and empty otherwise.
func restrictToViewerOrgScope(ctx context.Context, orgIDs []string) []string {
	scope, scoped := viewerOrgScope(ctx)
	if !scoped {
		return orgIDs
	}
	for _, id := range orgIDs {
		if scope != "" && id == scope {
			return []string{scope}
		}
	}
	return nil
}

// orgScopedTxVisibilityProvider is the visibleTo share lookup restricted to
// shares whose send was authorised under one org. Implemented by *db.DB.
type orgScopedTxVisibilityProvider interface {
	GetBatchTxVisibilityInOrg(ctx context.Context, txHashes []string, orgID string) (map[string][]string, error)
}

var _ orgScopedTxVisibilityProvider = (*db.DB)(nil)

// txVisibilityForViewer returns the visibleTo recipients of txHashes. Under an
// impersonation scope only shares whose send was authorised under the scope
// org count; a store that cannot answer that question contributes no shares
// (fail closed).
func (p *JSONRPCProcessor) txVisibilityForViewer(ctx context.Context, txHashes []string) (map[string][]string, error) {
	scope, scoped := viewerOrgScope(ctx)
	if !scoped {
		return p.txVisibilityStore.GetBatchTxVisibility(ctx, txHashes)
	}
	store, ok := p.txVisibilityStore.(orgScopedTxVisibilityProvider)
	if !ok || scope == "" {
		return nil, nil
	}
	return store.GetBatchTxVisibilityInOrg(ctx, txHashes, scope)
}

// applyViewerOrgScopeEnvelope nulls, under an impersonation scope, a
// transaction or receipt whose recipient (or deployed contract) is owned by
// another org. Deployment transactions are evaluated using the created
// address derived from the sender and nonce. Runs after the response filter;
// a lookup or parse error returns null. No-op without a scope.
func (p *JSONRPCProcessor) applyViewerOrgScopeEnvelope(ctx context.Context, method string, body []byte) []byte {
	scope, scoped := viewerOrgScope(ctx)
	if !scoped {
		return body
	}
	switch rbac.ResolveMethodAlias(method) {
	case rbac.MethodGetTransactionByHash, rbac.MethodGetTransactionReceipt,
		rbac.MethodGetTransactionByBlockHashAndIndex, rbac.MethodGetTransactionByBlockNumberAndIndex:
	default:
		return body
	}
	null := []byte(`{"jsonrpc":"2.0","id":` + rpcResponseID(body) + `,"result":null}`)
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return null
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return body // RPC error or null: nothing to disclose
	}
	var obj struct {
		From            string  `json:"from"`
		To              *string `json:"to"`
		ContractAddress *string `json:"contractAddress"`
		Nonce           *string `json:"nonce"`
	}
	if err := json.Unmarshal(env.Result, &obj); err != nil {
		return null
	}
	targets := []*string{obj.To, obj.ContractAddress}
	isReceipt := rbac.ResolveMethodAlias(method) == rbac.MethodGetTransactionReceipt
	if !isReceipt && (obj.To == nil || *obj.To == "") {
		// A deployment transaction object: the created address is not in the
		// response, derive it the way the EVM does (CREATE from sender + nonce).
		if obj.Nonce == nil {
			return null
		}
		nonce, err := hexutil.DecodeUint64(*obj.Nonce)
		if err != nil || !gethcommon.IsHexAddress(obj.From) {
			return null
		}
		created := strings.ToLower(gethcrypto.CreateAddress(gethcommon.HexToAddress(obj.From), nonce).Hex())
		targets = append(targets, &created)
	}
	for _, addr := range targets {
		if addr == nil || *addr == "" {
			continue
		}
		owner, err := p.rbacAccessCtrl.Store().GetContractOwnerOrgID(ctx, strings.ToLower(*addr))
		if err != nil {
			return null
		}
		if owner != "" && (scope == "" || owner != scope) {
			return null
		}
	}
	return body
}

// impersonationRPCMethods lists the read methods supported by the View-as
// RPC mirror. Keep it explicit so additions receive their own review.
var impersonationRPCMethods = map[string]bool{
	"eth_call":                  true,
	"eth_getLogs":               true,
	"eth_getTransactionReceipt": true,
	"eth_getTransactionByHash":  true,
	"eth_getBalance":            true,
	"eth_getCode":               true,
	"eth_getStorageAt":          true,
	"eth_blockNumber":           true,
	"eth_chainId":               true,
	"eth_gasPrice":              true,
	"net_version":               true,
	"net_listening":             true,
	"web3_clientVersion":        true,
}
