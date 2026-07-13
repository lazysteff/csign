package client

import (
	"context"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestAdvancedEVMClientMethodsUsePinnedRoutes(t *testing.T) {
	logical := &fakeLogical{
		writeSecret: &api.Secret{Data: map[string]interface{}{
			"api_version": v1.APIVersion,
		}},
	}
	client := New(logical, "/chain-signer/")
	ctx := context.Background()

	tests := []struct {
		name string
		path string
		call func() error
	}{
		{
			name: "key policy update",
			path: "chain-signer/v1/key-policy/orgs/advanced%20key",
			call: func() error {
				_, err := client.Keys.SetPolicy(ctx, "orgs/advanced key", v1.StructuredPolicy{})
				return err
			},
		},
		{
			name: "EIP-712 sign",
			path: "chain-signer/v1/evm/eip712/sign",
			call: func() error {
				_, err := client.Signing.SignEVMEIP712(ctx, v1.EVMEIP712SignRequest{})
				return err
			},
		},
		{
			name: "EIP-712 verify",
			path: "chain-signer/v1/evm/eip712/verify",
			call: func() error {
				_, err := client.Payloads.VerifyEVMEIP712(ctx, v1.EVMEIP712VerifyRequest{})
				return err
			},
		},
		{
			name: "ERC-4337 sign",
			path: "chain-signer/v1/evm/erc4337/user-operations/sign",
			call: func() error {
				_, err := client.Signing.SignEVMUserOperation(ctx, v1.EVMUserOperationSignRequest{})
				return err
			},
		},
		{
			name: "ERC-4337 verify",
			path: "chain-signer/v1/evm/erc4337/user-operations/verify",
			call: func() error {
				_, err := client.Payloads.VerifyEVMUserOperation(ctx, v1.EVMUserOperationVerifyRequest{})
				return err
			},
		},
		{
			name: "EIP-7702 authorization sign",
			path: "chain-signer/v1/evm/eip7702/authorizations/sign",
			call: func() error {
				_, err := client.Signing.SignEVMEIP7702Authorization(ctx, v1.EVMEIP7702AuthorizationSignRequest{})
				return err
			},
		},
		{
			name: "EIP-7702 authorization verify",
			path: "chain-signer/v1/evm/eip7702/authorizations/verify",
			call: func() error {
				_, err := client.Payloads.VerifyEVMEIP7702Authorization(ctx, v1.EVMEIP7702AuthorizationVerifyRequest{})
				return err
			},
		},
		{
			name: "EIP-7702 transaction sign",
			path: "chain-signer/v1/evm/eip7702/transactions/sign",
			call: func() error {
				_, err := client.Signing.SignEVMEIP7702Transaction(ctx, v1.EVMEIP7702TransactionSignRequest{})
				return err
			},
		},
		{
			name: "EIP-7702 transaction recover",
			path: "chain-signer/v1/evm/eip7702/transactions/recover",
			call: func() error {
				_, err := client.Payloads.RecoverEVMEIP7702Transaction(ctx, v1.EVMEIP7702TransactionRecoverRequest{})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logical.lastWritePath = ""
			require.NoError(t, test.call())
			require.Equal(t, test.path, logical.lastWritePath)
		})
	}
}

func TestUserOperationClientPreservesStructuredWirePayloadAndResponse(t *testing.T) {
	logical := &fakeLogical{writeSecret: &api.Secret{Data: map[string]interface{}{
		"api_version": "v1", "protocol_version": v1.ERC4337ProtocolV09,
		"user_operation_hash": "0xabc", "signature": "0xdef",
	}}}
	client := New(logical, "chain-signer")
	request := v1.EVMUserOperationSignRequest{
		EVMAdvancedSignRequestBase: v1.EVMAdvancedSignRequestBase{
			EVMKeyRequestContext: v1.EVMKeyRequestContext{
				EVMRequestContext: v1.EVMRequestContext{ChainFamily: v1.ChainFamilyEVM, Network: "network", RequestID: "request"},
				KeyID:             "key",
			},
			EVMSignerExpectation: v1.EVMSignerExpectation{ExpectedSignerAddress: "0x1000000000000000000000000000000000000001", ChainID: "1"},
		},
		ERC4337OperationDescriptor: v1.ERC4337OperationDescriptor{
			EntryPoint: "0x2000000000000000000000000000000000000002", ProtocolVersion: v1.ERC4337ProtocolV09,
			AccountImplementation: v1.ERC4337AccountSimpleAccount, AccountImplementationVersion: v1.ERC4337AccountSimpleAccountVersion,
			AccountSigningSchema: v1.ERC4337SimpleAccountSigningSchema,
		},
		UserOperation: v1.ERC4337UserOperationV09{Sender: "0x3000000000000000000000000000000000000003", Nonce: "7", CallData: "0x", CallGasLimit: "1", VerificationGasLimit: "2", PreVerificationGas: "3", MaxFeePerGas: "4", MaxPriorityFeePerGas: "1"},
	}

	response, err := client.Signing.SignEVMUserOperation(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "0xabc", response.UserOperationHash)
	require.Equal(t, "0xdef", response.Signature)
	require.Equal(t, v1.ERC4337ProtocolV09, logical.lastWriteData["protocol_version"])
	operation, ok := logical.lastWriteData["user_operation"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "7", operation["nonce"])
	require.Equal(t, "1", operation["call_gas_limit"])
	require.NotContains(t, logical.lastWriteData, "metadata")
}
