package conformance_test

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestConformance_ERC4337SimpleAccount(t *testing.T) {
	fixture, _ := newAdvancedEVMFixture(t, "evm-erc4337", true)
	request := v1.EVMUserOperationSignRequest{
		EVMAdvancedSignRequestBase: fixture.base("user-operation-sign"),
		ERC4337OperationDescriptor: v1.ERC4337OperationDescriptor{
			EntryPoint:                   v1.ERC4337EntryPointV09,
			ProtocolVersion:              v1.ERC4337ProtocolV09,
			AccountImplementation:        v1.ERC4337AccountSimpleAccount,
			AccountImplementationVersion: v1.ERC4337AccountSimpleAccountVersion,
			AccountSigningSchema:         v1.ERC4337SimpleAccountSigningSchema,
		},
		UserOperation: v1.ERC4337UserOperationV09{
			Sender:               testEVMRecipient,
			Nonce:                "0",
			CallData:             "0x",
			CallGasLimit:         "100000",
			VerificationGasLimit: "150000",
			PreVerificationGas:   "21000",
			MaxFeePerGas:         "1000",
			MaxPriorityFeePerGas: "100",
		},
	}

	signed := writeAdvanced[v1.EVMUserOperationSignResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMERC4337UserOperationSign, request)
	require.Equal(t, v1.OperationEVMERC4337UserOperation, signed.Operation)
	require.Equal(t, fixture.signer, signed.SignerAddress)
	require.Equal(t, signed.UserOperationHash, signed.AccountSigningDigest)
	require.Equal(t, v1.ERC4337SimpleAccountSignatureEncoding, signed.SignatureEncoding)
	require.Len(t, signed.Signature, 2+65*2)

	verified := writeAdvanced[v1.EVMUserOperationVerifyResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMERC4337UserOperationVerify, v1.EVMUserOperationVerifyRequest{
		EVMRequestContext:          advancedEVMRequestContext("user-operation-verify"),
		EVMSignerExpectation:       v1.EVMSignerExpectation{ExpectedSignerAddress: fixture.signer, ChainID: fixture.chainID},
		ERC4337OperationDescriptor: request.ERC4337OperationDescriptor,
		UserOperation:              request.UserOperation,
		Signature:                  signed.Signature,
	})
	require.True(t, verified.SignatureValid)
	require.Equal(t, fixture.signer, verified.RecoveredSigner)
	require.Equal(t, signed.UserOperationHash, verified.UserOperationHash)
	require.Equal(t, signed.AccountSigningDigest, verified.AccountSigningDigest)
	require.Equal(t, v1.OperationEVMERC4337UserOperation, verified.Operation)
}
