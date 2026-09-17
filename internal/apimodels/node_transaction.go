package apimodels

import "privacy-proxy/internal/nodepolicy"

type NodeTransactionProgress struct {
	TransactionHash    string                       `json:"transaction_hash"`
	ContextID          string                       `json:"context_id"`
	Status             string                       `json:"status"`
	Execution          *nodepolicy.ExecutionOutcome `json:"execution,omitempty"`
	Reconciled         bool                         `json:"reconciled"`
	ReconciliationNote string                       `json:"reconciliation_note,omitempty"`
}
