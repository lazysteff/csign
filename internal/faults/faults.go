package faults

import (
	"errors"
	"fmt"
)

type Kind string

const (
	Invalid       Kind = "invalid"
	NotFound      Kind = "not_found"
	Conflict      Kind = "conflict"
	Unsupported   Kind = "unsupported"
	PolicyDenied  Kind = "policy_denied"
	CustodyFailed Kind = "custody_failed"
	Internal      Kind = "internal"
)

type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string {
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	return e.Err
}

func Wrap(kind Kind, err error) error {
	if err == nil {
		return nil
	}
	var existing *Error
	if errors.As(err, &existing) {
		return err
	}
	return &Error{Kind: kind, Err: err}
}

func New(kind Kind, message string) error {
	return &Error{Kind: kind, Err: errors.New(message)}
}

func Newf(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Err: fmt.Errorf(format, args...)}
}

func KindOf(err error) Kind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return Internal
}
