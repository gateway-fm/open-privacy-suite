package db

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// ErrConfigurationConflict identifies reviewable authored-state diagnostics:
// every ConfigurationConflict error matches it with errors.Is. Infrastructure
// failures retain their original type and are never exposed.
var ErrConfigurationConflict = errors.New("configuration conflict")

// ErrConfigurationUnavailable means the request is well formed and the state is
// fine, but this deployment cannot carry it out because a dependency it needs
// is missing. It is a capability problem with an operator fix, never a fault of
// the document, so it must not read as a conflict with current state.
var ErrConfigurationUnavailable = errors.New("configuration dependency unavailable")

// ConfigurationUnavailableError carries client-safe text for that case.
type ConfigurationUnavailableError struct{ message string }

func (e *ConfigurationUnavailableError) Error() string {
	return ErrConfigurationUnavailable.Error() + ": " + e.message
}
func (e *ConfigurationUnavailableError) ClientMessage() string { return e.Error() }
func (e *ConfigurationUnavailableError) Is(target error) bool {
	return target == ErrConfigurationUnavailable
}

// ConfigurationUnavailable builds a *ConfigurationUnavailableError.
func ConfigurationUnavailable(format string, args ...any) error {
	return &ConfigurationUnavailableError{message: fmt.Sprintf(format, args...)}
}

// ConfigurationConflictError is what ConfigurationConflict returns. Its text is
// written for the revision author and may be returned verbatim by a handler
// (RD-934 rule-4 carve-out): the format string is a constant from this package
// and an error argument contributes its text only when that text was itself
// written for the caller (configuration.SourceError, policydsl.ValidationError,
// another conflict). Any other error argument — a driver, I/O or unexpected
// error — is replaced in the message and kept only in the chain.
type ConfigurationConflictError struct {
	message string
	causes  []error
}

func (e *ConfigurationConflictError) Error() string {
	return ErrConfigurationConflict.Error() + ": " + e.message
}

// ClientMessage is the text a handler may put on the wire.
func (e *ConfigurationConflictError) ClientMessage() string { return e.Error() }

// Is makes errors.Is(err, ErrConfigurationConflict) hold for every conflict.
func (e *ConfigurationConflictError) Is(target error) bool { return target == ErrConfigurationConflict }

// Unwrap keeps the error arguments in the chain for errors.Is / errors.As.
func (e *ConfigurationConflictError) Unwrap() []error { return e.causes }

type clientMessenger interface{ ClientMessage() string }

// ConfigurationConflict builds a *ConfigurationConflictError. %w and %s render
// an error argument identically: by its client text, or as "internal error"
// when it has none (that case is also logged, so the cause is not lost).
func ConfigurationConflict(format string, args ...any) error {
	rendered := make([]any, len(args))
	var causes []error
	for i, arg := range args {
		err, ok := arg.(error)
		if !ok {
			rendered[i] = arg
			continue
		}
		causes = append(causes, err)
		var client clientMessenger
		if errors.As(err, &client) {
			rendered[i] = client.ClientMessage()
			continue
		}
		slog.Warn("configuration conflict built from an error without client text; the message hides it", "format", format, "err", err)
		rendered[i] = "internal error"
	}
	return &ConfigurationConflictError{message: fmt.Sprintf(strings.ReplaceAll(format, "%w", "%s"), rendered...), causes: causes}
}
