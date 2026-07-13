package conformance_test

import (
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_EIP7702AuthorizationAndTransaction(t *testing.T) {
	fixture, _ := newAdvancedEVMFixture(t, "evm-eip7702", true)

	authorizationRequest := v1.EVMEIP7702AuthorizationSignRequest{
		EIP7702Authorization: v1.EIP7702Authorization{
			ChainID: fixture.chainID,
			Address: testEIP7702Delegate,
			Nonce:   "0",
		},
		EVMKeyRequestContext: fixture.keyContext("authorization-sign"),
		AuthorityAddress:     fixture.signer,
		AuthorizationSchema:  v1.EIP7702AuthorizationSchemaV1,
	}
	authorization := writeAdvanced[v1.EVMEIP7702AuthorizationSignResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP7702AuthorizationSign, authorizationRequest)
	require.Equal(t, v1.OperationEVMEIP7702Authorization, authorization.Operation)
	require.Equal(t, fixture.signer, authorization.SignerAddress)
	require.Equal(t, fixture.signer, authorization.AuthorityAddress)
	require.Equal(t, fixture.chainID, authorization.ChainID)
	require.Equal(t, testEIP7702Delegate, authorization.Address)
	require.Len(t, authorization.R, 66)
	require.Len(t, authorization.S, 66)
	require.NotEmpty(t, authorization.SerializedAuthorization)

	verified := writeAdvanced[v1.EVMEIP7702AuthorizationVerifyResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP7702AuthorizationVerify, v1.EVMEIP7702AuthorizationVerifyRequest{
		EIP7702SignedAuthorization: authorization.EIP7702SignedAuthorization,
		EVMRequestContext:          advancedEVMRequestContext("authorization-verify"),
		ExpectedAuthorityAddress:   fixture.signer,
		AuthorizationSchema:        authorization.AuthorizationSchema,
	})
	require.True(t, verified.AuthorizationValid)
	require.Equal(t, fixture.signer, verified.RecoveredAuthority)
	require.Equal(t, authorization.AuthorizationHash, verified.AuthorizationHash)
	require.Equal(t, v1.OperationEVMEIP7702Authorization, verified.Operation)

	_, err := handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.EVMEIP7702AuthorizationVerify, mustMap(t, v1.EVMEIP7702AuthorizationVerifyRequest{
		EIP7702SignedAuthorization: authorization.EIP7702SignedAuthorization,
		EVMRequestContext:          advancedEVMRequestContext("authorization-unsupported-schema"),
		ExpectedAuthorityAddress:   fixture.signer,
		AuthorizationSchema:        "unknown-schema",
	}))
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported EIP-7702 authorization schema")

	transactionRequest := v1.EVMEIP7702TransactionSignRequest{
		EVMKeyRequestContext: fixture.keyContext("type4-sign"),
		EIP7702TransactionFields: v1.EIP7702TransactionFields{
			ChainID:              fixture.chainID,
			Nonce:                "1",
			To:                   testEVMRecipient,
			Value:                "1",
			GasLimit:             "150000",
			MaxFeePerGas:         "1000",
			MaxPriorityFeePerGas: "100",
			Data:                 "0x",
			AccessList:           []v1.EVMAccessTuple{},
		},
		SourceAddress: fixture.signer,
		AuthorizationList: []v1.EIP7702SignedAuthorization{{
			EIP7702Authorization: authorization.EIP7702Authorization,
			YParity:              authorization.YParity,
			R:                    authorization.R,
			S:                    authorization.S,
		}},
	}
	signed := writeAdvanced[v1.EVMEIP7702TransactionSignResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP7702TransactionSign, transactionRequest)
	require.Equal(t, v1.OperationEVMEIP7702Transaction, signed.Operation)
	require.Equal(t, fixture.signer, signed.SignerAddress)
	require.Equal(t, v1.EIP7702TransactionTypeV1, signed.TransactionType)
	require.True(t, strings.HasPrefix(signed.SignedPayload, "0x04"))
	require.NotEmpty(t, signed.TransactionHash)
	require.NotEmpty(t, signed.TransactionSigningHash)
	require.Equal(t, v1.PayloadEncodingHex, signed.PayloadEncoding)

	recovered := writeAdvanced[v1.EVMEIP7702TransactionRecoverResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP7702TransactionRecover, v1.EVMEIP7702TransactionRecoverRequest{
		EVMRequestContext:     advancedEVMRequestContext("type4-recover"),
		SignedPayload:         signed.SignedPayload,
		ExpectedSignerAddress: fixture.signer,
	})
	require.True(t, recovered.MatchesExpected)
	require.Equal(t, fixture.signer, recovered.RecoveredSigner)
	require.Equal(t, signed.TransactionHash, recovered.TransactionHash)
	require.Equal(t, v1.EIP7702TransactionTypeV1, recovered.TransactionType)
	require.Equal(t, v1.OperationEVMEIP7702Transaction, recovered.Operation)
	require.Equal(t, fixture.chainID, recovered.DecodedTransaction.ChainID)
	require.Equal(t, transactionRequest.Nonce, recovered.DecodedTransaction.Nonce)
	require.Equal(t, transactionRequest.To, recovered.DecodedTransaction.To)
	require.Equal(t, transactionRequest.Value, recovered.DecodedTransaction.Value)
	require.Len(t, recovered.DecodedTransaction.AuthorizationList, 1)
	require.Equal(t, fixture.signer, recovered.DecodedTransaction.AuthorizationList[0].AuthorityAddress)
	require.Equal(t, testEIP7702Delegate, recovered.DecodedTransaction.AuthorizationList[0].Address)

	mismatched := writeAdvanced[v1.EVMEIP7702TransactionRecoverResponse](t, fixture.ctx, fixture.backend, fixture.storage, routes.EVMEIP7702TransactionRecover, v1.EVMEIP7702TransactionRecoverRequest{
		EVMRequestContext:     advancedEVMRequestContext("type4-recover-mismatch"),
		SignedPayload:         signed.SignedPayload,
		ExpectedSignerAddress: testEVMRecipient,
	})
	require.False(t, mismatched.MatchesExpected)
	require.Equal(t, fixture.signer, mismatched.RecoveredSigner)
}
