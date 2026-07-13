package client

import (
	"errors"
	"strings"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
)

// APIError preserves the Vault transport error while exposing a stable CSign
// error code for new typed operations.
type APIError struct {
	Code v1.ErrorCode
	Err  error
}

func (e *APIError) Error() string { return e.Err.Error() }
func (e *APIError) Unwrap() error { return e.Err }

// ErrorCode extracts a stable CSign error code, returning an empty string for
// legacy errors that predate the coded error contract.
func ErrorCode(err error) v1.ErrorCode {
	var typed *APIError
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

func wrapAPIError(err error) error {
	if err == nil {
		return nil
	}
	var responseError *api.ResponseError
	if !errors.As(err, &responseError) {
		return err
	}
	for _, message := range responseError.Errors {
		if code := leadingErrorCode(message); code != "" {
			return &APIError{Code: code, Err: err}
		}
	}
	return err
}

func leadingErrorCode(message string) v1.ErrorCode {
	message = strings.TrimSpace(message)
	if len(message) < 3 || message[0] != '[' {
		return ""
	}
	end := strings.IndexByte(message, ']')
	if end <= 1 {
		return ""
	}
	code := message[1:end]
	for index, char := range code {
		if index == 0 {
			if char < 'a' || char > 'z' {
				return ""
			}
			continue
		}
		if (char < 'a' || char > 'z') && char != '_' && (char < '0' || char > '9') {
			return ""
		}
	}
	return v1.ErrorCode(code)
}
