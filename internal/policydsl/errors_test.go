package policydsl

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// Parse, Validate and ApplyProxyPairs describe faults in a document the caller
// authored; handlers return that text verbatim (RD-934 carve-out), so the type
// is the contract that nothing else can travel through this path.
func TestDocumentFaultsAreValidationErrors(t *testing.T) {
	_, parseErr := Parse([]byte(`{"apiVersion":1`))
	_, applyErr := ApplyProxyPairs(nil, nil)
	_, validateErr := Validate(nil, Catalog{})
	for name, err := range map[string]error{"parse": parseErr, "apply": applyErr, "validate": validateErr} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, err)
			var typed *ValidationError
			require.ErrorAs(t, err, &typed)
			require.Equal(t, err.Error(), typed.ClientMessage())
			require.NotNil(t, errors.Unwrap(err), "the original cause stays in the chain")
		})
	}
	_, err := Parse([]byte(`{}`))
	require.NoError(t, err, "a valid document returns a nil error, not a typed nil")
	var unsupported *LegacyImportError
	require.Equal(t, (&LegacyImportError{}).Error(), (&LegacyImportError{}).ClientMessage())
	require.False(t, errors.As(err, &unsupported))
}
