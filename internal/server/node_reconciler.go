package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

type nodeOutcomeStore interface {
	ListPendingNodeSubmissions(context.Context, nodepolicy.Network, int) ([]db.NodeSubmission, error)
	RecordNodeOutcome(context.Context, nodepolicy.Network, nodepolicy.TransactionStatus) error
	ScheduleNodeSubmission(context.Context, nodepolicy.Network, string, time.Duration) error
}
type nodeOutcomeClient interface {
	TransactionStatus(context.Context, string) (nodepolicy.TransactionStatus, error)
}

func reconcileNodeSubmissionBatch(ctx context.Context, store nodeOutcomeStore, node nodeOutcomeClient, network nodepolicy.Network) error {
	rows, err := store.ListPendingNodeSubmissions(ctx, network, 100)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	slots := make(chan struct{}, 8)
	for _, row := range rows {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func(in db.NodeSubmission) {
			defer wg.Done()
			defer func() { <-slots }()
			request, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			status, err := node.TransactionStatus(request, in.TransactionHash)
			delay := time.Second
			if err == nil && (status.TransactionHash != in.TransactionHash || status.PrincipalID != in.PrincipalID || status.OrgID != in.OrgID) {
				err = nodepolicy.ErrNodeResponse
			}
			if err == nil {
				err = status.Validate()
			}
			if err == nil {
				err = store.RecordNodeOutcome(request, network, status)
			}
			if err != nil || status.Execution.Status == "denied" || status.Execution.Status == "expired" {
				delay = 15 * time.Second
			}
			// Move failed/denied rows behind other work; an unreachable old intent
			// must not permanently starve newer submissions. Expiry is nonterminal:
			// execution begun under its valid lease may still become canonical.
			scheduleErr := store.ScheduleNodeSubmission(ctx, network, in.TransactionHash, delay)
			if err != nil || scheduleErr != nil {
				mu.Lock()
				failures = append(failures, errors.Join(err, scheduleErr))
				mu.Unlock()
			}
		}(row)
	}
	wg.Wait()
	return errors.Join(failures...)
}
func runNodeReconciler(ctx context.Context, store nodeOutcomeStore, node nodeOutcomeClient, network nodepolicy.Network) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		if err := reconcileNodeSubmissionBatch(ctx, store, node, network); err != nil && ctx.Err() == nil {
			slog.Warn("node transaction reconciliation pending", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
