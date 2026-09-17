package apimodels

type NodeSimulationRequest struct {
	PrincipalID         string `json:"principalId,omitempty"`
	CandidateRevisionID string `json:"candidateRevisionId,omitempty"`
	Method              string `json:"method"`
	Params              []any  `json:"params"`
	DryRun              bool   `json:"dryRun"`
}
