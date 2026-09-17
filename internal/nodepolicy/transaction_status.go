package nodepolicy

import "context"

type CreatedContract struct {
	Address     string `json:"address"`
	OrgID       string `json:"org_id"`
	PrincipalID string `json:"principal_id"`
}
type ExecutionOutcome struct {
	Status               string            `json:"status"`
	FactsVersion         uint64            `json:"facts_version"`
	BlockHash            *string           `json:"block_hash"`
	BlockNumber          *uint64           `json:"block_number"`
	Finalized            bool              `json:"finalized"`
	FinalizedBlockHash   *string           `json:"finalized_block_hash"`
	FinalizedBlockNumber *uint64           `json:"finalized_block_number"`
	ReasonCode           string            `json:"reason_code"`
	Created              []CreatedContract `json:"created"`
}
type TransactionStatus struct {
	TransactionHash string           `json:"transaction_hash"`
	PrincipalID     string           `json:"principal_id"`
	OrgID           string           `json:"org_id"`
	ContextID       string           `json:"context_id"`
	Execution       ExecutionOutcome `json:"execution"`
}

func (c *Client) TransactionStatus(ctx context.Context, hash string) (TransactionStatus, error) {
	if !hexField(hash, 32) {
		return TransactionStatus{}, ErrIdentity
	}
	raw, err := c.call(ctx, "ops_transactionStatus", []any{hash})
	if err != nil {
		return TransactionStatus{}, err
	}
	var status TransactionStatus
	if err := decodeStrict(raw, &status); err != nil {
		return TransactionStatus{}, ErrNodeResponse
	}
	if status.TransactionHash != hash || !identifier(status.PrincipalID) || !identifier(status.OrgID) || !identifier(status.ContextID) {
		return TransactionStatus{}, ErrNodeResponse
	}
	if err := status.Validate(); err != nil {
		return TransactionStatus{}, err
	}
	return status, nil
}

func (status TransactionStatus) Validate() error {
	if !hexField(status.TransactionHash, 32) || !identifier(status.PrincipalID) || !identifier(status.OrgID) || !identifier(status.ContextID) {
		return ErrNodeResponse
	}
	outcome := status.Execution
	if (outcome.FinalizedBlockHash == nil) != (outcome.FinalizedBlockNumber == nil) || (outcome.FinalizedBlockHash != nil && !hexField(*outcome.FinalizedBlockHash, 32)) {
		return ErrNodeResponse
	}
	if outcome.Created == nil || len(outcome.Created) > 128 || len(outcome.ReasonCode) > 128 {
		return ErrNodeResponse
	}
	switch outcome.Status {
	case "included", "reverted":
		if outcome.BlockHash == nil || !hexField(*outcome.BlockHash, 32) || outcome.BlockNumber == nil || outcome.FactsVersion == 0 {
			return ErrNodeResponse
		}
		if outcome.Status == "reverted" && len(outcome.Created) > 0 {
			return ErrNodeResponse
		}
		if outcome.Finalized && (outcome.FinalizedBlockNumber == nil || *outcome.FinalizedBlockNumber < *outcome.BlockNumber || (*outcome.FinalizedBlockNumber == *outcome.BlockNumber && *outcome.FinalizedBlockHash != *outcome.BlockHash)) {
			return ErrNodeResponse
		}
	case "pending", "denied", "expired":
		if outcome.Finalized || outcome.BlockHash != nil || outcome.BlockNumber != nil || len(outcome.Created) > 0 {
			return ErrNodeResponse
		}
	default:
		return ErrNodeResponse
	}
	seen := map[string]bool{}
	for _, created := range outcome.Created {
		if !hexField(created.Address, 20) || created.OrgID != status.OrgID || created.PrincipalID != status.PrincipalID || seen[created.Address] {
			return ErrNodeResponse
		}
		seen[created.Address] = true
	}
	return nil
}
