package evm

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestUserOperationWrapperSignsAndRecoversAccountSignature(t *testing.T) {
	request := advancedUserOperationRequest()
	prepared, err := advancedcodec.PrepareUserOperation(
		request.ProtocolVersion,
		request.AccountImplementation,
		request.AccountImplementationVersion,
		request.AccountSigningSchema,
		request.ChainID,
		request.EntryPoint,
		request.ExpectedSignerAddress,
		"",
		request.UserOperation,
	)
	require.NoError(t, err)
	request.ExpectedUserOperationHash = prepared.Hash.Hex()

	response, err := SignUserOperation(context.Background(), mustAdvancedMaterial(t), &request)
	require.NoError(t, err)
	require.Equal(t, v1.APIVersion, response.APIVersion)
	require.Equal(t, request.KeyID, response.KeyID)
	require.Equal(t, request.RequestID, response.RequestID)
	require.Equal(t, v1.OperationEVMERC4337UserOperation, response.Operation)
	require.Equal(t, advancedSigner, response.SignerAddress)
	require.Equal(t, prepared.Hash.Hex(), response.UserOperationHash)
	require.Equal(t, response.UserOperationHash, response.AccountSigningDigest)
	require.Equal(t, v1.ERC4337SimpleAccountSignatureEncoding, response.SignatureEncoding)
	signature, err := enc.DecodeCanonicalHex("signature", response.Signature, 65)
	require.NoError(t, err)
	require.Contains(t, []byte{27, 28}, signature[64])

	verified, err := VerifyUserOperation(v1.EVMUserOperationVerifyRequest{
		EVMRequestContext:          request.EVMRequestContext,
		EVMSignerExpectation:       request.EVMSignerExpectation,
		ERC4337OperationDescriptor: request.ERC4337OperationDescriptor,
		UserOperation:              request.UserOperation,
		Signature:                  response.Signature,
	})
	require.NoError(t, err)
	require.True(t, verified.SignatureValid)
	require.Equal(t, advancedSigner, verified.RecoveredSigner)
	require.Equal(t, response.UserOperationHash, verified.UserOperationHash)

	tamperedOperation := request.UserOperation
	tamperedOperation.Nonce = "8"
	tampered, err := VerifyUserOperation(v1.EVMUserOperationVerifyRequest{
		EVMRequestContext: v1.EVMRequestContext{
			ChainFamily: request.ChainFamily,
			Network:     request.Network,
			RequestID:   "request-tampered",
		},
		EVMSignerExpectation:       request.EVMSignerExpectation,
		ERC4337OperationDescriptor: request.ERC4337OperationDescriptor,
		UserOperation:              tamperedOperation,
		Signature:                  response.Signature,
	})
	require.NoError(t, err)
	require.False(t, tampered.SignatureValid)
	require.NotEqual(t, response.UserOperationHash, tampered.UserOperationHash)
}

func TestUserOperationWrapperRejectsExpectedHashMismatchBeforeSigning(t *testing.T) {
	request := advancedUserOperationRequest()
	request.ExpectedUserOperationHash = common.Hash{}.Hex()

	_, err := SignUserOperation(context.Background(), mustAdvancedMaterial(t), &request)
	require.ErrorContains(t, err, "expected_user_operation_hash does not match reconstructed hash")
}
