package service

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestRegistryRejectsDuplicateRoutes(t *testing.T) {
	_, err := NewRegistry([]OperationDescriptor{
		testDescriptor("duplicate"),
		testDescriptor("duplicate"),
	})
	require.Equal(t, faults.Internal, faults.KindOf(err))
}

func TestDefaultOperationDescriptorsAreUnique(t *testing.T) {
	registry, err := NewRegistry(DefaultOperationDescriptors())
	require.NoError(t, err)
	require.Len(t, registry.Routes(), 5)

	_, err = registry.Lookup("missing")
	require.Equal(t, faults.Unsupported, faults.KindOf(err))
}

func testDescriptor(route string) OperationDescriptor {
	return OperationDescriptor{
		Route:      route,
		NewRequest: func() any { return &v1.EVMLegacyTransferSignRequest{} },
		Validate:   func(domain.Key, any) error { return nil },
		Execute: func(context.Context, custody.Material, any) (*v1.SignResponse, error) {
			return &v1.SignResponse{}, nil
		},
	}
}
