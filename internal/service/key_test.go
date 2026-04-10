package service

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestKeyServiceCreateAndSetActive(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	repo := newMemoryKeyRepository()
	service := NewKeyService(repo, func() time.Time { return now })

	key, err := service.Create(ctx, v1.CreateKeyRequest{
		KeyID:            "evm-key",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad",
	})
	require.NoError(t, err)
	require.Equal(t, "evm-key", key.ID)
	require.True(t, key.Active)
	require.Equal(t, now, key.CreatedAt)
	require.Equal(t, now, key.UpdatedAt)

	privateKey, err := ethcrypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad")
	require.NoError(t, err)
	require.Equal(t, evm.DeriveAddress(&privateKey.PublicKey), key.SignerAddress)

	updated, err := service.SetActive(ctx, "evm-key", false)
	require.NoError(t, err)
	require.False(t, updated.Active)
}

func TestKeyServiceReadMissingKey(t *testing.T) {
	service := NewKeyService(newMemoryKeyRepository(), time.Now)
	_, err := service.Read(context.Background(), "missing")
	require.Equal(t, faults.NotFound, faults.KindOf(err))
}

type memoryKeyRepository struct {
	keys map[string]domain.Key
}

func newMemoryKeyRepository() *memoryKeyRepository {
	return &memoryKeyRepository{keys: make(map[string]domain.Key)}
}

func (r *memoryKeyRepository) GetKey(_ context.Context, keyID string) (*domain.Key, error) {
	key, ok := r.keys[keyID]
	if !ok {
		return nil, nil
	}
	copy := key
	return &copy, nil
}

func (r *memoryKeyRepository) PutKey(_ context.Context, key domain.Key) error {
	r.keys[key.ID] = key
	return nil
}

func (r *memoryKeyRepository) ListKeyIDs(_ context.Context) ([]string, error) {
	ids := make([]string, 0, len(r.keys))
	for id := range r.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
