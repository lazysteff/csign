package service

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestRegistryRejectsDuplicateRoutes(t *testing.T) {
	catalog := signingops.MustNew([]v1.SigningOperationCapability{{Route: "duplicate", Operation: "test_operation"}})
	_, err := NewRegistry(catalog, []OperationDescriptor{
		testDescriptor("duplicate"),
		testDescriptor("duplicate"),
	})
	require.Equal(t, faults.Internal, faults.KindOf(err))
}

func TestDefaultOperationDescriptorsAreUnique(t *testing.T) {
	catalog := signingops.Default()
	registry, err := NewRegistry(catalog, DefaultOperationDescriptors(catalog))
	require.NoError(t, err)
	require.Len(t, registry.Routes(), 16)

	_, err = registry.Lookup("missing")
	require.Equal(t, faults.Unsupported, faults.KindOf(err))
}

func TestRegistryRejectsCatalogDescriptorMismatch(t *testing.T) {
	catalog := signingops.MustNew([]v1.SigningOperationCapability{{Route: "route", Operation: "expected"}})
	descriptor := testDescriptor("route")
	descriptor.Operation = "wrong"
	_, err := NewRegistry(catalog, []OperationDescriptor{descriptor})
	require.Equal(t, faults.Internal, faults.KindOf(err))
	require.ErrorContains(t, err, "requires \"expected\"")
}

func TestRegistryRejectsCatalogEntriesWithoutDescriptors(t *testing.T) {
	entries := signingops.Default().Entries()
	entries = append(entries, v1.SigningOperationCapability{Route: "v1/test/sign", Operation: "test_operation"})
	catalog := signingops.MustNew(entries)

	_, err := NewRegistry(catalog, DefaultOperationDescriptors(catalog))
	require.Equal(t, faults.Internal, faults.KindOf(err))
	require.ErrorContains(t, err, "catalog has 17 entries")
}

func testDescriptor(route string) OperationDescriptor {
	return OperationDescriptor{
		Route:      route,
		Operation:  "test_operation",
		NewRequest: func() any { return &v1.EVMLegacyTransferSignRequest{} },
		Validate:   func(domain.Key, any) error { return nil },
		Execute: func(context.Context, custody.Material, any) (any, error) {
			return &v1.SignResponse{}, nil
		},
	}
}
