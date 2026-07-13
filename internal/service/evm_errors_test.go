package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestAdvancedInspectionErrorsExposeStableCodes(t *testing.T) {
	registry := advancedregistry.Default()
	_, schemaErr := registry.EIP712Schema(eip712.SchemaID, "unsupported")
	_, versionErr := registry.AccountAdapter("unsupported", erc4337.SimpleAccountImplementation, erc4337.SimpleAccountImplementationVersion, erc4337.SimpleAccountSigningSchema)
	tests := []struct {
		name string
		err  error
		want faults.Code
	}{
		{name: "EIP-712 schema", err: classifyEIP712InspectionError(schemaErr), want: faults.UnsupportedEIP712Schema},
		{name: "EIP-712 signature", err: classifyEIP712InspectionError(errors.New("signature is malformed")), want: faults.SignatureVerificationFailed},
		{name: "UserOperation version", err: classifyUserOperationInspectionError(versionErr), want: faults.UnsupportedERC4337Version},
		{name: "Paymaster signature field", err: classifyUserOperationInspectionError(errors.New("user_operation.paymaster.signature must be hexadecimal")), want: faults.InvalidUserOperation},
		{name: "authorization signature", err: classifyAuthorizationInspectionError(errors.New("signature s is not canonical low-s")), want: faults.SignatureVerificationFailed},
		{name: "type-4 transaction type", err: classifyType4InspectionError(errors.New("transaction type 2 is not EIP-7702 type 4")), want: faults.UnsupportedTransactionType},
		{name: "embedded authorization signature", err: classifyType4InspectionError(errors.New("authorization_list[0]: signature s is not canonical low-s")), want: faults.InvalidAuthorizationList},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, faults.CodeOf(test.err))
		})
	}
}

func TestAuthorizationInspectionClassifiesGethInvalidSignature(t *testing.T) {
	_, _, rawErr := advancedcodec.PrepareSignedAuthorization(v1.EIP7702AuthorizationSchemaV1, v1.EIP7702SignedAuthorization{
		EIP7702Authorization: v1.EIP7702Authorization{
			ChainID: "1",
			Address: "0x1000000000000000000000000000000000000001",
			Nonce:   "0",
		},
		R: "0x" + strings.Repeat("00", 32),
		S: "0x" + strings.Repeat("00", 32),
	})
	require.Error(t, rawErr)
	err := classifyAuthorizationInspectionError(rawErr)
	require.Equal(t, faults.SignatureVerificationFailed, faults.CodeOf(err))
}

func TestType4DecodeErrorIsSanitized(t *testing.T) {
	err := classifyType4InspectionError(errors.New("decode type-4 transaction: rlp: implementation detail"))
	require.Equal(t, faults.InvalidAuthorizationList, faults.CodeOf(err))
	require.EqualError(t, err, "invalid EIP-7702 type-4 transaction payload")
	require.NotContains(t, err.Error(), "rlp")
}
