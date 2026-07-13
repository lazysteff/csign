package advancedregistry

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestDefaultRegistryBindsVersionedBehaviorAndCapabilities(t *testing.T) {
	registry := Default()
	schema, err := registry.EIP712Schema(eip712.SchemaID, eip712.SchemaVersion)
	require.NoError(t, err)
	require.NotNil(t, schema.HashPermit)
	require.Equal(t, v1.SignatureEncodingRSV27, schema.SignatureEncoding)

	account, err := registry.AccountAdapter(
		erc4337.ProtocolID,
		erc4337.SimpleAccountImplementation,
		erc4337.SimpleAccountImplementationVersion,
		erc4337.SimpleAccountSigningSchema,
	)
	require.NoError(t, err)
	require.NotNil(t, account.HashUserOperation)

	schemas, protocols, accounts, signingSchemas, authorizationSchemas, transactionTypes := registry.Capabilities()
	require.Equal(t, []v1.EIP712SchemaCapability{{
		ID: eip712.SchemaID, Version: eip712.SchemaVersion, PrimaryType: eip712.PrimaryType, SignatureEncoding: eip712.SignatureEncoding,
	}}, schemas)
	require.Equal(t, []string{erc4337.ProtocolID}, protocols)
	require.Len(t, accounts, 1)
	require.Equal(t, []string{erc4337.SimpleAccountSigningSchema}, signingSchemas)
	require.Equal(t, []string{v1.EIP7702AuthorizationSchemaV1}, authorizationSchemas)
	require.Equal(t, []v1.EIP7702TransactionCapability{{ID: v1.EIP7702TransactionTypeV1, Number: 4}}, transactionTypes)
}

func TestRegistryRejectsEachUnsupportedCompatibilityDimension(t *testing.T) {
	registry := Default()
	_, err := registry.EIP712Schema(eip712.SchemaID, "2")
	require.ErrorContains(t, err, "unsupported EIP-712 schema")

	_, err = registry.AccountAdapter(erc4337.ProtocolID, "unknown", "1", erc4337.SimpleAccountSigningSchema)
	require.ErrorContains(t, err, "unsupported account implementation")
	_, err = registry.AccountAdapter("erc4337-v1", erc4337.SimpleAccountImplementation, erc4337.SimpleAccountImplementationVersion, erc4337.SimpleAccountSigningSchema)
	require.ErrorContains(t, err, "unsupported ERC-4337 protocol")
	_, err = registry.AccountAdapter(erc4337.ProtocolID, erc4337.SimpleAccountImplementation, erc4337.SimpleAccountImplementationVersion, "unknown")
	require.ErrorContains(t, err, "unsupported account signing schema")
}

func TestCapabilitiesAggregateAccountCompatibilityDimensions(t *testing.T) {
	first := AccountAdapter{ID: "account", Version: "1", ProtocolVersion: "protocol-b", SigningSchema: "schema-b", SignatureEncoding: "rsv-v27"}
	second := AccountAdapter{ID: "account", Version: "1", ProtocolVersion: "protocol-a", SigningSchema: "schema-a", SignatureEncoding: "rsv-v27"}
	registry := Registry{
		eip712Schemas: map[string]EIP712Schema{},
		accountAdapters: map[string]AccountAdapter{
			accountKey(first.ProtocolVersion, first.ID, first.Version, first.SigningSchema):     first,
			accountKey(second.ProtocolVersion, second.ID, second.Version, second.SigningSchema): second,
		},
		authorizationSchemas: map[string]struct{}{},
		transactionTypes:     map[string]uint8{},
	}

	_, protocols, accounts, signingSchemas, _, _ := registry.Capabilities()
	require.Equal(t, []string{"protocol-a", "protocol-b"}, protocols)
	require.Equal(t, []string{"schema-a", "schema-b"}, signingSchemas)
	require.Equal(t, []v1.ERC4337AccountCapability{{
		ID:                "account",
		Version:           "1",
		ProtocolVersions:  []string{"protocol-a", "protocol-b"},
		SigningSchemas:    []string{"schema-a", "schema-b"},
		SignatureEncoding: "rsv-v27",
	}}, accounts)
}
