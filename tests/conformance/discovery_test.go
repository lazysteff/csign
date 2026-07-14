package conformance_test

import (
	"context"
	"testing"

	registeredeip712 "github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestConformance_AdvancedEVMCapabilityDiscovery(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	version := readVersion(t, ctx, backend, storage)

	require.Equal(t, v1.APIVersion, version.APIVersion)
	for _, route := range []string{
		routes.KeyPolicyPath,
		routes.EVMEIP712Sign,
		routes.EVMEIP712Verify,
		routes.EVMERC4337UserOperationSign,
		routes.EVMERC4337UserOperationVerify,
		routes.EVMEIP7702AuthorizationSign,
		routes.EVMEIP7702AuthorizationVerify,
		routes.EVMEIP7702TransactionSign,
		routes.EVMEIP7702TransactionRecover,
	} {
		require.Contains(t, version.SupportedRoutes, route)
	}
	require.Contains(t, version.SupportedEIP712Schemas, v1.EIP712SchemaCapability{
		ID:                v1.EIP712SchemaEIP2612Permit,
		Version:           v1.EIP712SchemaEIP2612PermitVersion,
		PrimaryType:       "Permit",
		SignatureEncoding: v1.SignatureEncodingRSV27,
	})
	require.Contains(t, version.SupportedEIP712Schemas, v1.EIP712SchemaCapability{
		ID:                registeredeip712.VerifyingPaymasterApprovalSchemaID,
		Version:           registeredeip712.VerifyingPaymasterApprovalSchemaVersion,
		PrimaryType:       "VerifyingPaymasterApproval",
		SignatureEncoding: v1.SignatureEncodingRSV27,
	})
	require.Contains(t, version.SupportedERC4337ProtocolVersions, v1.ERC4337ProtocolV09)
	require.Contains(t, version.SupportedAccountSigningSchemas, v1.ERC4337SimpleAccountSigningSchema)
	require.Contains(t, version.SupportedAccountImplementations, v1.ERC4337AccountCapability{
		ID:                v1.ERC4337AccountSimpleAccount,
		Version:           v1.ERC4337AccountSimpleAccountVersion,
		ProtocolVersions:  []string{v1.ERC4337ProtocolV09},
		SigningSchemas:    []string{v1.ERC4337SimpleAccountSigningSchema},
		SignatureEncoding: v1.ERC4337SimpleAccountSignatureEncoding,
	})
	require.Contains(t, version.SupportedEIP7702AuthorizationSchemas, v1.EIP7702AuthorizationSchemaV1)
	require.Contains(t, version.SupportedEIP7702TransactionTypes, v1.EIP7702TransactionCapability{
		ID:     v1.EIP7702TransactionTypeV1,
		Number: v1.EIP7702TransactionTypeNumber,
	})
}
