package policydsl

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError marks a fault in a policy document the caller authored.
// Parse, Validate and ApplyProxyPairs return nothing else, and their text names
// document fields, selectors and rule positions — never server internals — so
// an HTTP handler may return it verbatim to the document's author (the RD-934
// rule-4 carve-out). Anything that is not a *ValidationError stays opaque.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }

// Unwrap keeps the original cause in the chain for errors.Is / errors.As.
func (e *ValidationError) Unwrap() error { return e.Err }

// ClientMessage is the text a handler may put on the wire.
func (e *ValidationError) ClientMessage() string { return e.Err.Error() }

// ClientMessage lets a legacy import report travel through the same path and
// names the records (the organization's own groups and addresses) so the
// author can act on it; long reports are truncated.
func (e *LegacyImportError) ClientMessage() string {
	const shown = 5
	var b strings.Builder
	b.WriteString(e.Error())
	for i, issue := range e.Issues {
		if i == shown {
			fmt.Fprintf(&b, "; +%d more", len(e.Issues)-shown)
			break
		}
		b.WriteString("; ")
		if issue.Group != "" {
			fmt.Fprintf(&b, "group %s ", issue.Group)
		}
		if issue.Address != "" {
			fmt.Fprintf(&b, "address %s ", issue.Address)
		}
		b.WriteString(issue.Reason)
	}
	return b.String()
}

func validationError(err error) error {
	if err == nil {
		return nil
	}
	var typed *ValidationError
	if errors.As(err, &typed) {
		return err
	}
	return &ValidationError{Err: err}
}
