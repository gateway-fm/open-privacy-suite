package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	ExecutionSenderRequired  = "execution requires an explicit linked from address"
	ExecutionSenderNotLinked = "execution sender is not linked to the authenticated principal"
)

// ExecutionAdmission contains authenticated identity and transport permissions,
// never a contract-execution permission verdict. The node resolves live facts
// and invokes the selected compiled policy before every actual execution frame.
type ExecutionAdmission struct {
	AccessCheckResult
	Signer string
}

// CheckExecutionAdmission retains the existing user, organisation, historical
// query and method gates. Contract selectors, operational claims, multicall
// fingerprints and preflight traces are not execution authorities in node mode.
func (c *AccessController) CheckExecutionAdmission(ctx context.Context, req *AccessCheckRequest) (*ExecutionAdmission, error) {
	deny := func(reason string) *ExecutionAdmission {
		return &ExecutionAdmission{AccessCheckResult: AccessCheckResult{Allowed: false, Reason: reason}}
	}
	if req == nil {
		return deny("invalid execution request"), nil
	}
	switch req.EffectiveMethod() {
	case "eth_call", "eth_estimateGas", "debug_traceCall", "eth_sendTransaction", "eth_sendRawTransaction":
	default:
		return deny("method is not an execution request"), nil
	}
	if IsMethodBlocked(req.Method) {
		return deny("method is globally blocked"), nil
	}
	if req.UserExternalID == "" {
		out := deny("execution requires authentication")
		out.AuthRequired = true
		return out, nil
	}
	user, res, handled, err := c.resolveAndValidateUser(ctx, req)
	if handled {
		return admissionFromAccess(res), err
	}
	// All three simulation methods (and their aliases) take their block at
	// params[1]. Apply the existing historical eth_call privacy guard equally
	// before evaluating the original method's independent allowlist.
	historicalRequest := *req
	switch req.EffectiveMethod() {
	case "eth_call", "eth_estimateGas", "debug_traceCall":
		historicalRequest.Method = "eth_call"
	}
	if res, handled, err := c.checkHistoricalStateQuery(ctx, &historicalRequest, user); handled {
		return admissionFromAccess(res), err
	}
	org, _, res, handled, err := c.resolveOrgContextForRequest(ctx, req, user)
	if handled {
		return admissionFromAccess(res), err
	}
	out := &ExecutionAdmission{AccessCheckResult: AccessCheckResult{OrgID: org.ID, UserID: user.ID}}
	perms, err := c.resolvePermissionsForRequest(ctx, req, user, org)
	if err != nil {
		return nil, err
	}
	if res, handled := c.checkMethodAllowed(req, perms); handled {
		out.Reason = res.Reason
		return out, nil
	}
	linked, err := c.store.GetLinkedEthAddresses(ctx, req.UserExternalID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve execution signer: %w", err)
	}
	addresses := map[string]bool{}
	for _, address := range linked {
		if canonicalExecutionAddress(address) {
			addresses[strings.ToLower(address)] = true
		}
	}
	if len(req.Params) == 0 {
		out.Reason = ExecutionSenderRequired
		return out, nil
	}
	call, ok := req.Params[0].(map[string]any)
	if !ok {
		out.Reason = ExecutionSenderRequired
		return out, nil
	}
	signer := ""
	if raw, present := call["from"]; present {
		var valid bool
		signer, valid = raw.(string)
		if !valid || !canonicalExecutionAddress(signer) {
			out.Reason = ExecutionSenderRequired
			return out, nil
		}
		signer = strings.ToLower(signer)
	} else {
		method := req.EffectiveMethod()
		if (method != "eth_call" && method != "eth_estimateGas" && method != "debug_traceCall") || len(addresses) != 1 {
			out.Reason = ExecutionSenderRequired
			return out, nil
		}
		for address := range addresses {
			signer = address
		}
	}
	if !addresses[signer] {
		out.Reason = ExecutionSenderNotLinked
		return out, nil
	}
	out.Allowed = true
	out.Signer = signer
	out.RPCAPIKey = perms.RPCAPIKey
	return out, nil
}

func admissionFromAccess(result *AccessCheckResult) *ExecutionAdmission {
	if result == nil {
		return nil
	}
	return &ExecutionAdmission{AccessCheckResult: *result}
}
func canonicalExecutionAddress(address string) bool {
	return len(address) == 42 && strings.HasPrefix(address, "0x") && common.IsHexAddress(address)
}
