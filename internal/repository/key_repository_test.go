package repository

import (
	"context"
	"testing"

	"github.com/lazysteff/csign/v2/internal/chain/evm"
	"github.com/lazysteff/csign/v2/internal/custody"
	"github.com/lazysteff/csign/v2/internal/domain"
	"github.com/lazysteff/csign/v2/internal/faults"
	"github.com/lazysteff/csign/v2/internal/signingops"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestVaultKeyRepositoryPutGetList(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage, signingops.Default())

	require.NoError(t, repo.PutKey(ctx, repositoryTestKey(t, "key-b")))
	require.NoError(t, repo.PutKey(ctx, repositoryTestKey(t, "key-a")))

	key, err := repo.GetKey(ctx, "key-a")
	require.NoError(t, err)
	require.Equal(t, "key-a", key.ID)

	missing, err := repo.GetKey(ctx, "missing")
	require.ErrorIs(t, err, ErrKeyNotFound)
	require.Nil(t, missing)

	ids, err := repo.ListKeyIDs(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"key-a", "key-b"}, ids)
}

func TestVaultKeyRepositoryListNestedKeyIDs(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage, signingops.Default())

	require.NoError(t, repo.PutKey(ctx, repositoryTestKey(t, "gateway/tron/main/hot")))
	require.NoError(t, repo.PutKey(ctx, repositoryTestKey(t, "gateway/ton/signing/default")))
	require.NoError(t, repo.PutKey(ctx, repositoryTestKey(t, "status/foo/bar")))

	ids, err := repo.ListKeyIDs(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{
		"gateway/ton/signing/default",
		"gateway/tron/main/hot",
		"status/foo/bar",
	}, ids)
}

func TestVaultKeyRepositoryDecodeError(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage, signingops.Default())

	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key:   keyPath("broken"),
		Value: []byte("{not-json"),
	}))

	_, err := repo.GetKey(ctx, "broken")
	require.ErrorIs(t, err, ErrInvalidPolicyRecord)
	require.ErrorContains(t, err, "decode key")
}

func TestVaultKeyRepositoryRejectsInvalidOperationPolicies(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage, signingops.Default())

	for _, allowed := range [][]string{
		{"unknown"},
		{v1.OperationEVMTransferLegacy, v1.OperationEVMTransferLegacy},
		{" evm_transfer_legacy"},
	} {
		err := repo.PutKey(ctx, domain.Key{ID: "invalid", Policy: v1.Policy{AllowedSigningOperations: allowed}})
		require.Equal(t, faults.Invalid, faults.KindOf(err))
		entry, readErr := storage.Get(ctx, keyPath("invalid"))
		require.NoError(t, readErr)
		require.Nil(t, entry)
	}
}

func repositoryTestKey(t *testing.T, id string) domain.Key {
	t.Helper()
	p, err := custody.ProvisionCreateRequest(v1.CreateKeyRequest{ChainFamily: "evm"})
	require.NoError(t, err)
	return domain.Key{ID: id, ChainFamily: "evm", CustodyMode: "mvp", PublicKeyHex: p.PublicKeyHex, PrivateKeyHex: p.PrivateKeyHex, SignerAddress: evm.DeriveAddress(p.PublicKey)}
}
