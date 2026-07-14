package conformance_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestConformance_EIP712Permit(t *testing.T) {
	fixture, _ := newAdvancedEVMFixture(t, "evm-eip712", true)
	request := v1.EVMEIP712SignRequest{
		EVMAdvancedSignRequestBase: fixture.base("permit-sign"),
		EIP712RegisteredPayload:    conformancePermit(fixture.signer, fixture.chainID),
	}

	signed := writeAdvanced[v1.EVMEIP712SignResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP712Sign, request)
	require.Equal(t, v1.OperationEVMEIP712Typed, signed.Operation)
	require.Equal(t, fixture.signer, signed.SignerAddress)
	require.Equal(t, request.RequestID, signed.RequestID)
	require.Equal(t, v1.SignatureEncodingRSV27, signed.SignatureEncoding)
	require.Len(t, signed.Signature, 2+65*2)
	require.Equal(t, signed.Signature[len(signed.Signature)-2:], strings.ToLower(twoDigitHex(signed.V)))

	verified := writeAdvanced[v1.EVMEIP712VerifyResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP712Verify, v1.EVMEIP712VerifyRequest{
		EVMRequestContext:       advancedEVMRequestContext("permit-verify"),
		EVMSignerExpectation:    v1.EVMSignerExpectation{ExpectedSignerAddress: fixture.signer, ChainID: fixture.chainID},
		EIP712RegisteredPayload: request.EIP712RegisteredPayload,
		Signature:               signed.Signature,
	})
	require.True(t, verified.SignatureValid)
	require.Equal(t, fixture.signer, verified.RecoveredSigner)
	require.Equal(t, signed.EIP712Digest, verified.Digest)
	require.Equal(t, v1.OperationEVMEIP712Typed, verified.Operation)
}

func conformancePermit(owner, chainID string) v1.EIP712RegisteredPayload {
	return v1.EIP712RegisteredPayload{
		SchemaID:      v1.EIP712SchemaEIP2612Permit,
		SchemaVersion: v1.EIP712SchemaEIP2612PermitVersion,
		Domain: v1.EIP712Domain{
			Name:              "Conformance Token",
			Version:           "1",
			ChainID:           chainID,
			VerifyingContract: testEVMContract,
		},
		Message: mustConformanceEIP712Message(v1.EIP2612PermitMessage{
			Owner:    owner,
			Spender:  testEVMRecipient,
			Value:    "5",
			Nonce:    "0",
			Deadline: "2000000000",
		}),
	}
}

func mustConformanceEIP712Message(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
