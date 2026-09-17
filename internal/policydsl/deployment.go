package policydsl

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// DeployerException records a reviewed exception to individual-deployer
// fallback, using immutable policy source and current group membership facts.
type DeployerException struct {
	StorageAddress string   `json:"storageAddress"`
	Groups         []string `json:"groups"`
}

func (e *DeployerException) UnmarshalJSON(raw []byte) error {
	if _, err := strictFields(raw, "storageAddress", "groups"); err != nil {
		return err
	}
	type plain DeployerException
	var p plain
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	*e = DeployerException(p)
	return nil
}

func cloneDeployerExceptions(in []DeployerException) []DeployerException {
	if in == nil {
		return nil
	}
	out := make([]DeployerException, len(in))
	for i, e := range in {
		out[i] = DeployerException{StorageAddress: e.StorageAddress, Groups: append([]string(nil), e.Groups...)}
	}
	return out
}

func compileDeployerExceptions(r FrameRule, cat Catalog) ([]DeployerException, error) {
	if len(r.Except) == 0 {
		return nil, nil
	}
	if r.TargetClass != "deployer" || len(r.Except) > 64 {
		return nil, fmt.Errorf("except requires deployer class and at most 64 target exceptions")
	}
	out := cloneDeployerExceptions(r.Except)
	seen := map[string]bool{}
	for i := range out {
		e := &out[i]
		if !common.IsHexAddress(e.StorageAddress) || len(e.Groups) == 0 || len(e.Groups) > 64 {
			return nil, fmt.Errorf("deployer exception requires an exact target and 1..64 groups")
		}
		e.StorageAddress = strings.ToLower(e.StorageAddress)
		if _, ok := cat.Contracts[e.StorageAddress]; !ok || seen[e.StorageAddress] {
			return nil, fmt.Errorf("deployer exception target must be unique and registered to this organization")
		}
		seen[e.StorageAddress] = true
		sort.Strings(e.Groups)
		for j, g := range e.Groups {
			if _, ok := cat.Groups[g]; !ok || (j > 0 && g == e.Groups[j-1]) {
				return nil, fmt.Errorf("deployer exception groups must be unique and in this organization")
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StorageAddress < out[j].StorageAddress })
	return out, nil
}

func (r *compiledRule) deployerExcepted(ctx Context, f Frame) bool {
	for _, e := range r.exceptions {
		if common.HexToAddress(e.StorageAddress) != f.StorageAddress {
			continue
		}
		for _, g := range e.Groups {
			if slices.Contains(ctx.Groups, g) {
				return true
			}
		}
	}
	return false
}
