package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"privacy-proxy/internal/disclosure"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestDisclosureEventsRecovery_PreservesValidEvents(t *testing.T) {
	foreignKey := &pgconn.PgError{Code: "23503"}
	events := []disclosure.Event{{GrantID: "first"}, {GrantID: "deleted"}, {GrantID: "last"}}
	var saved []string
	calls := 0
	err := insertDisclosureEventsWithRecovery(context.Background(), events, func(_ context.Context, batch []disclosure.Event) error {
		calls++
		for _, event := range batch {
			if event.GrantID == "deleted" {
				return fmt.Errorf("rolled back: %w", foreignKey)
			}
		}
		for _, event := range batch {
			saved = append(saved, event.GrantID)
		}
		return nil
	})
	require.ErrorIs(t, err, foreignKey)
	require.Equal(t, []string{"first", "last"}, saved)
	require.Equal(t, 4, calls)
}

func TestDisclosureEventsRecovery_DoesNotRepeatUncertainWrites(t *testing.T) {
	for _, writeErr := range []error{io.EOF, context.DeadlineExceeded, &pgconn.PgError{Code: "08007"}, &pgconn.PgError{Code: "40003"}} {
		t.Run(writeErr.Error(), func(t *testing.T) {
			events := []disclosure.Event{{GrantID: "first"}, {GrantID: "last"}}
			var saved []string
			calls := 0
			err := insertDisclosureEventsWithRecovery(context.Background(), events, func(_ context.Context, batch []disclosure.Event) error {
				calls++
				// Simulate a commit whose acknowledgement never reached us.
				for _, event := range batch {
					saved = append(saved, event.GrantID)
				}
				return writeErr
			})
			require.ErrorIs(t, err, writeErr)
			require.Equal(t, 1, calls)
			require.Equal(t, []string{"first", "last"}, saved)
		})
	}
}

func TestDisclosureEventsRecovery_IndividualUncertainWriteIsNotRetried(t *testing.T) {
	events := []disclosure.Event{{GrantID: "uncertain"}, {GrantID: "last"}}
	var saved []string
	calls := 0
	err := insertDisclosureEventsWithRecovery(context.Background(), events, func(_ context.Context, batch []disclosure.Event) error {
		calls++
		if len(batch) > 1 {
			return &pgconn.PgError{Code: "23503"}
		}
		saved = append(saved, batch[0].GrantID)
		if batch[0].GrantID == "uncertain" {
			return io.EOF
		}
		return nil
	})
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 3, calls)
	require.Equal(t, []string{"uncertain", "last"}, saved)
}

func TestDisclosureEventsRecovery_StopsWithinOriginalContext(t *testing.T) {
	for _, cancelAt := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("cancel_at_%d", cancelAt), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelAt == 0 {
				cancel()
			}
			calls := 0
			err := insertDisclosureEventsWithRecovery(ctx, []disclosure.Event{{GrantID: "a"}, {GrantID: "b"}}, func(gotCtx context.Context, batch []disclosure.Event) error {
				require.Same(t, ctx, gotCtx, "recovery must not replace or extend the caller's budget")
				calls++
				if calls == cancelAt {
					cancel()
				}
				if len(batch) > 1 {
					return &pgconn.PgError{Code: "23503"}
				}
				return nil
			})
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, cancelAt, calls)
		})
	}
}

func TestDisclosureEventsRecovery_EmptySingleAndNormalBatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		err   error
		calls int
	}{
		{"empty", 0, nil, 0},
		{"single success", 1, nil, 1},
		{"batch success", 50, nil, 1},
		{"single missing grant", 1, &pgconn.PgError{Code: "23503"}, 1},
		{"permission error", 2, &pgconn.PgError{Code: "42501"}, 1},
		{"plain error", 2, errors.New("database unavailable"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := insertDisclosureEventsWithRecovery(context.Background(), make([]disclosure.Event, tc.count), func(context.Context, []disclosure.Event) error {
				calls++
				return tc.err
			})
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.calls, calls)
		})
	}
}
