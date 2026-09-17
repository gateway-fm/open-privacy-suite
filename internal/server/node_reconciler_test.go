package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

type reconciliationStore struct {
	mu       sync.Mutex
	rows     []db.NodeSubmission
	recorded []nodepolicy.TransactionStatus
	delays   []time.Duration
}

func (s *reconciliationStore) ListPendingNodeSubmissions(context.Context, nodepolicy.Network, int) ([]db.NodeSubmission, error) {
	return s.rows, nil
}
func (s *reconciliationStore) RecordNodeOutcome(_ context.Context, _ nodepolicy.Network, status nodepolicy.TransactionStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded = append(s.recorded, status)
	return nil
}
func (s *reconciliationStore) ScheduleNodeSubmission(_ context.Context, _ nodepolicy.Network, _ string, delay time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delays = append(s.delays, delay)
	return nil
}

type reconciliationNode struct {
	status nodepolicy.TransactionStatus
	err    error
}

func (n reconciliationNode) TransactionStatus(context.Context, string) (nodepolicy.TransactionStatus, error) {
	return n.status, n.err
}
func TestNodeReconcilerNeverFinalizesUnavailableOrMismatchedStatus(t *testing.T) {
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "reconcile-test"}
	hash := "0x" + strings.Repeat("11", 32)
	for _, test := range []string{"pending", "denied", "expired", "node_failure", "wrong_principal"} {
		t.Run(test, func(t *testing.T) {
			store := &reconciliationStore{rows: []db.NodeSubmission{{Network: network, TransactionHash: hash, PrincipalID: "user-a", OrgID: "org-a"}}}
			node := reconciliationNode{status: nodepolicy.TransactionStatus{TransactionHash: hash, PrincipalID: "user-a", OrgID: "org-a", ContextID: "context-a", Execution: nodepolicy.ExecutionOutcome{Status: test, FactsVersion: 7, Created: []nodepolicy.CreatedContract{}}}}
			if test == "node_failure" {
				node.err = errors.New("unavailable")
			}
			if test == "wrong_principal" {
				node.status.PrincipalID = "user-b"
				node.status.Execution.Status = "pending"
			}
			err := reconcileNodeSubmissionBatch(context.Background(), store, node, network)
			if test == "node_failure" || test == "wrong_principal" {
				if err == nil || len(store.recorded) != 0 {
					t.Fatal("unverified status finalized")
				}
			} else if err != nil || len(store.recorded) != 1 {
				t.Fatalf("outcome lost: %v", err)
			}
			if len(store.delays) != 1 {
				t.Fatal("retry scheduling lost")
			}
			if (test == "denied" || test == "expired") && store.delays[0] < 10*time.Second {
				t.Fatal("nonterminal denial polled too aggressively")
			}
		})
	}
}
