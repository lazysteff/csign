package vaultbackend

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestHandleVersionIncludesSupportedRoutes(t *testing.T) {
	backend := New(nil)
	resp, err := backend.handleVersion(context.Background(), nil, nil)
	require.NoError(t, err)

	var payload v1.VersionResponse
	require.NoError(t, decode(resp.Data, &payload))
	require.Equal(t, registeredPublicRoutes(backend.routes), payload.SupportedRoutes)
	require.Equal(t, backend.registry.OperationCapabilities(), payload.SupportedSigningOperations)
	require.Equal(t, []string{
		"v1/evm/contracts/eip1559/sign",
		"v1/evm/eip712/sign",
		"v1/evm/eip712/verify",
		"v1/evm/eip7702/authorizations/sign",
		"v1/evm/eip7702/authorizations/verify",
		"v1/evm/eip7702/transactions/recover",
		"v1/evm/eip7702/transactions/sign",
		"v1/evm/erc4337/user-operations/sign",
		"v1/evm/erc4337/user-operations/verify",
		"v1/evm/transfers/eip1559/sign",
		"v1/evm/transfers/legacy/sign",
		"v1/key-policy/{key_id}",
		"v1/key-status/{key_id}",
		"v1/keys",
		"v1/keys/{key_id}",
		"v1/recover",
		"v1/tron/governance/vote_witness/sign",
		"v1/tron/resources/delegate/sign",
		"v1/tron/resources/freeze_v2/sign",
		"v1/tron/resources/undelegate/sign",
		"v1/tron/resources/unfreeze_v2/sign",
		"v1/tron/resources/withdraw_expire_unfreeze/sign",
		"v1/tron/rewards/withdraw_balance/sign",
		"v1/tron/transfers/trc20/sign",
		"v1/tron/transfers/trx/sign",
		"v1/verify",
		"v1/version",
	}, payload.SupportedRoutes)
	require.Equal(t, v1.EIP712SchemaEIP2612Permit, payload.SupportedEIP712Schemas[0].ID)
	require.Equal(t, []string{v1.ERC4337ProtocolV09}, payload.SupportedERC4337ProtocolVersions)
}

func TestSigningRegistrationsMatchAuthoritativeCatalog(t *testing.T) {
	backend := New(nil)
	require.Same(t, backend.catalog, backend.registry.Catalog())
	registered := make(map[string]pathRegistration, len(backend.routes))
	for _, registration := range backend.routes {
		registered[registration.PublicRoute] = registration
	}

	entries := backend.catalog.Entries()
	for _, entry := range entries {
		registration, ok := registered[entry.Route]
		require.True(t, ok, entry.Route)
		require.Equal(t, entry.Route, registration.Path.Pattern)
		descriptor, err := backend.registry.Lookup(entry.Route)
		require.NoError(t, err)
		require.Equal(t, entry, descriptor.SigningOperationCapability)
	}
	require.Len(t, backend.registry.Routes(), len(entries))
}

func TestBackendStartupFailsForIncompleteCatalog(t *testing.T) {
	catalog := signingops.MustNew([]v1.SigningOperationCapability{{Route: "v1/test/sign", Operation: "test_operation"}})
	backend, err := newBackendWithCatalog(nil, catalog)
	require.Error(t, err)
	require.Nil(t, backend)
}

func TestBackendStartupFailsForExtraCatalogEntry(t *testing.T) {
	entries := signingops.Default().Entries()
	entries = append(entries, v1.SigningOperationCapability{Route: "v1/test/sign", Operation: "test_operation"})
	catalog := signingops.MustNew(entries)

	backend, err := newBackendWithCatalog(nil, catalog)
	require.Error(t, err)
	require.Nil(t, backend)
}
