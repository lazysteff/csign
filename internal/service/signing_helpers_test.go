package service

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

type fakeKeyLookup struct {
	key   *domain.Key
	err   error
	calls int
}

func (f *fakeKeyLookup) GetKey(_ context.Context, _ string) (*domain.Key, error) {
	f.calls++
	return f.key, f.err
}

type fakeCustodyResolver struct {
	fn func(context.Context, domain.Key) (custody.Material, error)
}

func (f fakeCustodyResolver) MaterialForKey(ctx context.Context, key domain.Key) (custody.Material, error) {
	return f.fn(ctx, key)
}

type fakeMaterial struct{}

func (fakeMaterial) PublicKey() *ecdsa.PublicKey                        { return nil }
func (fakeMaterial) SignDigest(context.Context, []byte) ([]byte, error) { return nil, nil }

func testOperationRegistry(t *testing.T, descriptors []OperationDescriptor) (*signingops.Catalog, *Registry) {
	t.Helper()
	entries := make([]v1.SigningOperationCapability, 0, len(descriptors))
	for index := range descriptors {
		descriptors[index].Operation = "test_operation"
		entries = append(entries, descriptors[index].SigningOperationCapability)
	}
	catalog, err := signingops.New(entries)
	require.NoError(t, err)
	registry, err := NewRegistry(catalog, descriptors)
	require.NoError(t, err)
	return catalog, registry
}

func allowedTestKey() *domain.Key {
	return &domain.Key{
		ID: "key-1", CustodyMode: v1.CustodyModeMVP,
		Policy: v1.Policy{AllowedSigningOperations: []string{"test_operation"}},
	}
}
