package configuration

import "errors"

// SourceError marks a fault in a configuration document, approval manifest or
// CI request the caller authored. Every exported parser, validator and diff in
// this package returns nothing else, and the text refers to that document —
// never to server internals — so an HTTP handler may return it verbatim (the
// RD-934 rule-4 carve-out). ExportRegistry is the one function whose input is
// stored state rather than the caller's text; its messages are constants that
// describe which stored configuration needs repair. Anything that is not a
// *SourceError stays opaque.
type SourceError struct{ Err error }

func (e *SourceError) Error() string { return e.Err.Error() }

// Unwrap keeps the original cause in the chain for errors.Is / errors.As.
func (e *SourceError) Unwrap() error { return e.Err }

// ClientMessage is the text a handler may put on the wire.
func (e *SourceError) ClientMessage() string { return e.Err.Error() }

func sourceError(err error) error {
	if err == nil {
		return nil
	}
	var typed *SourceError
	if errors.As(err, &typed) {
		return err
	}
	return &SourceError{Err: err}
}
