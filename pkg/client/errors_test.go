package client

import (
	"errors"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestWrapAPIErrorExtractsOnlyAnchoredVaultCodes(t *testing.T) {
	responseError := &api.ResponseError{
		HTTPMethod: "POST",
		URL:        "http://[::1]:8200/v1/chain-signer/v1/evm/eip712/sign",
		StatusCode: 400,
		Errors: []string{
			"authorization_list[0]: malformed",
			"[unsupported_eip712_schema] unsupported schema",
		},
	}

	wrapped := wrapAPIError(responseError)
	require.Equal(t, v1.ErrorUnsupportedEIP712Schema, ErrorCode(wrapped))
	var typed *APIError
	require.ErrorAs(t, wrapped, &typed)
	require.ErrorIs(t, wrapped, responseError)
}

func TestWrapAPIErrorDoesNotInventCodes(t *testing.T) {
	for name, err := range map[string]error{
		"ordinary error": errors.New("network \"[fake]\" is not allowed"),
		"unclassified Vault error": &api.ResponseError{
			StatusCode: 400,
			Errors:     []string{"authorization_list[0]: malformed"},
		},
		"numeric bracket": &api.ResponseError{
			StatusCode: 400,
			Errors:     []string{"[0] malformed"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			wrapped := wrapAPIError(err)
			require.Empty(t, ErrorCode(wrapped))
			require.Same(t, err, wrapped)
		})
	}
}
