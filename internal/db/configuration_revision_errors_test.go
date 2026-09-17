package db

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
)

// ConfigurationConflict messages are returned to the revision author. An error
// argument contributes its text only when that text was written for the
// caller; a driver or I/O error is replaced, never echoed (RD-934).
func TestConfigurationConflictRendersOnlyClientText(t *testing.T) {
	_, sourceErr := configuration.Parse(nil)
	typed := ConfigurationConflict("execution registry dependency: %s", sourceErr)
	require.ErrorIs(t, typed, ErrConfigurationConflict)
	require.Equal(t, "configuration conflict: execution registry dependency: "+sourceErr.Error(), typed.Error())
	require.ErrorIs(t, typed, sourceErr, "the cause stays in the chain")

	cause := errors.New(`pq: duplicate key value violates unique constraint "contracts_pkey" (password=secret)`)
	hidden := ConfigurationConflict("registry import requires repair before revision activation: %w", cause)
	require.ErrorIs(t, hidden, ErrConfigurationConflict)
	require.ErrorIs(t, hidden, cause)
	require.Equal(t, "configuration conflict: registry import requires repair before revision activation: internal error", hidden.Error())
	require.NotContains(t, hidden.Error(), "secret")

	var client interface{ ClientMessage() string }
	require.ErrorAs(t, hidden, &client)
	require.Equal(t, hidden.Error(), client.ClientMessage())

	plain := ConfigurationConflict("execution catalog has duplicate addresses")
	require.Equal(t, "configuration conflict: execution catalog has duplicate addresses", plain.Error())
}
