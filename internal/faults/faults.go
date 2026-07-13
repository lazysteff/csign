package faults

import (
	"errors"
	"fmt"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type Kind string
type Code = v1.ErrorCode

const (
	Invalid       Kind = "invalid"
	NotFound      Kind = "not_found"
	Conflict      Kind = "conflict"
	Unsupported   Kind = "unsupported"
	PolicyDenied  Kind = "policy_denied"
	CustodyFailed Kind = "custody_failed"
	Internal      Kind = "internal"
)

const (
	UnsupportedEIP712Schema          = v1.ErrorUnsupportedEIP712Schema
	InvalidEIP712Domain              = v1.ErrorInvalidEIP712Domain
	InvalidEIP712Message             = v1.ErrorInvalidEIP712Message
	UnsupportedERC4337Version        = v1.ErrorUnsupportedERC4337Version
	UnsupportedAccountImplementation = v1.ErrorUnsupportedAccountImplementation
	UnsupportedAccountSigningSchema  = v1.ErrorUnsupportedAccountSigningSchema
	InvalidUserOperation             = v1.ErrorInvalidUserOperation
	UserOperationHashMismatch        = v1.ErrorUserOperationHashMismatch
	InvalidEIP7702Authorization      = v1.ErrorInvalidEIP7702Authorization
	AuthorizationSignerMismatch      = v1.ErrorAuthorizationSignerMismatch
	DelegateNotAllowed               = v1.ErrorDelegateNotAllowed
	EIP7702RevocationNotAllowed      = v1.ErrorEIP7702RevocationNotAllowed
	InvalidAuthorizationList         = v1.ErrorInvalidAuthorizationList
	UnsupportedTransactionType       = v1.ErrorUnsupportedTransactionType
	Type4TransactionNotSupported     = v1.ErrorType4TransactionNotSupported
	SigningOperationNotAllowed       = v1.ErrorSigningOperationNotAllowed
	SignatureVerificationFailed      = v1.ErrorSignatureVerificationFailed
)

type Error struct {
	Kind Kind
	Code Code
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

func NewCode(kind Kind, code Code, message string) error {
	return &Error{Kind: kind, Code: code, Err: errors.New(message)}
}

func NewCodef(kind Kind, code Code, format string, args ...any) error {
	return &Error{Kind: kind, Code: code, Err: fmt.Errorf(format, args...)}
}

func KindOf(err error) Kind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return Internal
}

func CodeOf(err error) Code {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}
