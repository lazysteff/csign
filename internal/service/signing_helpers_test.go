package service

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

type fakeKeyLookup struct {
	key   *domain.Key
	err   error
	calls int
}

func (f *fakeKeyLookup) GetKey(_ context.Context, _ string) (*domain.Key, error) {
	f.calls++
	if f.key == nil {
		return nil, f.err
	}
	key := f.key.Clone()
	if key.KeyType == "" {
		key.KeyType = cryptography.Secp256k1
	}
	if key.PublicKeyHex == "" {
		key.PublicKeyHex = custody.PublicKeyHex(&testPrivateKey().PublicKey)
	}
	return &key, f.err
}

type fakeCustodyResolver struct {
	fn func(context.Context, domain.Key) (custody.Material, error)
}

func (f fakeCustodyResolver) MaterialForKey(ctx context.Context, key domain.Key) (custody.Material, error) {
	return f.fn(ctx, key)
}

type fakeMaterial struct{}

func (fakeMaterial) PublicKey() *ecdsa.PublicKey { return &testPrivateKey().PublicKey }
func (fakeMaterial) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return ethcrypto.Sign(digest, testPrivateKey())
}

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
		ID: "key-1", Active: true, CustodyMode: v1.CustodyModeMVP,
		Policy: v1.Policy{AllowedSigningOperations: []string{"test_operation"}},
	}
}

func testPrivateKey() *ecdsa.PrivateKey {
	p, err := ethcrypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad")
	if err != nil {
		panic(err)
	}
	return p
}
func testCapabilities() []cryptography.Capability {
	return []cryptography.Capability{{Scheme: cryptography.ECDSASecp256k1, Input: cryptography.Digest}}
}
func testNormalize(request any) (any, error) { return request, nil }
func (f fakeCustodyResolver) DescribeCapabilities(context.Context, domain.Key) ([]cryptography.Capability, error) {
	return testCapabilities(), nil
}
func (f fakeCustodyResolver) ResolveSigningMaterial(ctx context.Context, key domain.Key) (custody.SigningMaterial, error) {
	m, err := f.MaterialForKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return custody.AdaptLegacy(m)
}
