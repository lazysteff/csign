package vaultbackend

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestInspectionHandlersUseMatchingDecodeCodesWithoutChangingLegacy(t *testing.T) {
	backend := New(nil)
	ctx := context.Background()
	tests := []struct {
		name string
		call func(*logical.Request) (*logical.Response, error)
		code faults.Code
	}{
		{name: "EIP-712", call: func(req *logical.Request) (*logical.Response, error) {
			return backend.handleVerifyEVMEIP712(ctx, req, nil)
		}, code: faults.InvalidEIP712Message},
		{name: "UserOperation", call: func(req *logical.Request) (*logical.Response, error) {
			return backend.handleVerifyEVMUserOperation(ctx, req, nil)
		}, code: faults.InvalidUserOperation},
		{name: "authorization", call: func(req *logical.Request) (*logical.Response, error) {
			return backend.handleVerifyEVMEIP7702Authorization(ctx, req, nil)
		}, code: faults.InvalidEIP7702Authorization},
		{name: "type-4", call: func(req *logical.Request) (*logical.Response, error) {
			return backend.handleRecoverEVMEIP7702Transaction(ctx, req, nil)
		}, code: faults.InvalidAuthorizationList},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.call(&logical.Request{Data: map[string]interface{}{"unknown": true}})
			require.ErrorContains(t, err, "["+string(test.code)+"]")
		})
	}

	_, legacyErr := backend.handleVerify(ctx, &logical.Request{Data: map[string]interface{}{"chain_family": map[string]interface{}{}}}, nil)
	require.Error(t, legacyErr)
	require.NotContains(t, legacyErr.Error(), "[invalid_eip712_message]")
}
