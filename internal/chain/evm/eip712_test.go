package evm

import (
	"context"
	"encoding/json"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestEIP712WrapperSignsAndRecoversPermit(t *testing.T) {
	request := advancedPermitRequest()
	response, err := SignEIP712(context.Background(), mustAdvancedMaterial(t), &request)
	require.NoError(t, err)
	require.Equal(t, v1.APIVersion, response.APIVersion)
	require.Equal(t, request.KeyID, response.KeyID)
	require.Equal(t, request.RequestID, response.RequestID)
	require.Equal(t, v1.OperationEVMEIP712Typed, response.Operation)
	require.Equal(t, advancedSigner, response.SignerAddress)
	require.Equal(t, v1.EIP712SchemaEIP2612Permit, response.SchemaID)
	require.Equal(t, v1.EIP712SchemaEIP2612PermitVersion, response.SchemaVersion)
	require.Equal(t, v1.SignatureEncodingRSV27, response.SignatureEncoding)
	require.Contains(t, []uint8{27, 28}, response.V)
	require.Len(t, response.Signature, 132)
	require.Len(t, response.R, 66)
	require.Len(t, response.S, 66)
	require.Len(t, response.DomainSeparator, 66)
	require.Len(t, response.StructHash, 66)
	require.Len(t, response.EIP712Digest, 66)

	verified, err := VerifyEIP712(v1.EVMEIP712VerifyRequest{
		EVMRequestContext:       request.EVMRequestContext,
		EVMSignerExpectation:    request.EVMSignerExpectation,
		EIP712RegisteredPayload: request.EIP712RegisteredPayload,
		Signature:               response.Signature,
	})
	require.NoError(t, err)
	require.True(t, verified.SignatureValid)
	require.Equal(t, advancedSigner, verified.RecoveredSigner)
	require.Equal(t, response.EIP712Digest, verified.Digest)

	var tamperedMessage v1.EIP2612PermitMessage
	require.NoError(t, json.Unmarshal(request.Message, &tamperedMessage))
	tamperedMessage.Value = "11"
	tampered, err := VerifyEIP712(v1.EVMEIP712VerifyRequest{
		EVMRequestContext: v1.EVMRequestContext{
			ChainFamily: request.ChainFamily,
			Network:     request.Network,
			RequestID:   "request-tampered",
		},
		EVMSignerExpectation: request.EVMSignerExpectation,
		EIP712RegisteredPayload: v1.EIP712RegisteredPayload{
			SchemaID:      request.SchemaID,
			SchemaVersion: request.SchemaVersion,
			Domain:        request.Domain,
			Message:       mustEIP712Message(tamperedMessage),
		},
		Signature: response.Signature,
	})
	require.NoError(t, err)
	require.False(t, tampered.SignatureValid)
	require.NotEqual(t, response.EIP712Digest, tampered.Digest)
}
