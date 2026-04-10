package repository

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestVaultKeyRepositoryPutGetList(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage)

	require.NoError(t, repo.PutKey(ctx, domain.Key{ID: "key-b"}))
	require.NoError(t, repo.PutKey(ctx, domain.Key{ID: "key-a"}))

	key, err := repo.GetKey(ctx, "key-a")
	require.NoError(t, err)
	require.Equal(t, "key-a", key.ID)

	missing, err := repo.GetKey(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, missing)

	ids, err := repo.ListKeyIDs(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"key-a", "key-b"}, ids)
}

func TestVaultKeyRepositoryDecodeError(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage)

	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key:   keyPath("broken"),
		Value: []byte("{not-json"),
	}))

	_, err := repo.GetKey(ctx, "broken")
	require.ErrorContains(t, err, "decode key")
}
