package service

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/repository"
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

func TestKeyServiceRejectsInvalidKeyIDsBeforeRepositoryAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("create", func(t *testing.T) {
		repo := newMemoryKeyRepository()
		service := NewKeyService(repo, time.Now)

		_, err := service.Create(ctx, v1.CreateKeyRequest{
			KeyID:            "a//b",
			ChainFamily:      v1.ChainFamilyEVM,
			CustodyMode:      v1.CustodyModeMVP,
			ImportPrivateKey: "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad",
		})
		require.Equal(t, faults.Invalid, faults.KindOf(err))
		require.Zero(t, repo.getCalls)
		require.Zero(t, repo.putCalls)
	})

	t.Run("read", func(t *testing.T) {
		repo := newMemoryKeyRepository()
		service := NewKeyService(repo, time.Now)

		_, err := service.Read(ctx, "/bad")
		require.Equal(t, faults.Invalid, faults.KindOf(err))
		require.Zero(t, repo.getCalls)
	})

	t.Run("set active", func(t *testing.T) {
		repo := newMemoryKeyRepository()
		service := NewKeyService(repo, time.Now)

		_, err := service.SetActive(ctx, "a/./b", false)
		require.Equal(t, faults.Invalid, faults.KindOf(err))
		require.Zero(t, repo.getCalls)
		require.Zero(t, repo.putCalls)
	})
}

func TestKeyServiceReadMissingKey(t *testing.T) {
	service := NewKeyService(newMemoryKeyRepository(), time.Now)
	_, err := service.Read(context.Background(), "missing")
	require.Equal(t, faults.NotFound, faults.KindOf(err))
}

func TestKeyServiceSetPolicyPreservesLegacyAdditionalPolicyContext(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryKeyRepository()
	repo.keys["legacy-policy-key"] = domain.Key{
		ID: "legacy-policy-key",
		Policy: v1.Policy{
			AllowedNetworks:         []string{"old-network"},
			AdditionalPolicyContext: map[string]string{"workflow": "legacy"},
		},
	}
	service := NewKeyService(repo, time.Now)

	updated, err := service.SetPolicy(ctx, "legacy-policy-key", v1.Policy{
		AllowedNetworks: []string{"new-network"},
		MaxGasLimit:     21_000,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"new-network"}, updated.Policy.AllowedNetworks)
	require.Equal(t, uint64(21_000), updated.Policy.MaxGasLimit)
	require.Equal(t, map[string]string{"workflow": "legacy"}, updated.Policy.AdditionalPolicyContext)
}

func TestKeyServiceDoesNotAliasMutableRequestOrRepositoryState(t *testing.T) {
	ctx := context.Background()
	repo := newMemoryKeyRepository()
	service := NewKeyService(repo, time.Now)
	request := v1.CreateKeyRequest{
		KeyID:            "isolated-key",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad",
		Labels:           map[string]string{"owner": "original"},
		Policy:           v1.Policy{AllowedNetworks: []string{"network-a"}},
	}
	created, err := service.Create(ctx, request)
	require.NoError(t, err)

	request.Labels["owner"] = "request-mutated"
	request.Policy.AllowedNetworks[0] = "request-mutated"
	created.Labels["owner"] = "response-mutated"
	created.Policy.AllowedNetworks[0] = "response-mutated"
	stored, err := service.Read(ctx, "isolated-key")
	require.NoError(t, err)
	require.Equal(t, "original", stored.Labels["owner"])
	require.Equal(t, []string{"network-a"}, stored.Policy.AllowedNetworks)

	newPolicy := v1.Policy{AllowedNetworks: []string{"network-b"}}
	updated, err := service.SetPolicy(ctx, "isolated-key", newPolicy)
	require.NoError(t, err)
	newPolicy.AllowedNetworks[0] = "request-mutated"
	updated.Policy.AllowedNetworks[0] = "response-mutated"
	stored, err = service.Read(ctx, "isolated-key")
	require.NoError(t, err)
	require.Equal(t, []string{"network-b"}, stored.Policy.AllowedNetworks)
}

type memoryKeyRepository struct {
	keys     map[string]domain.Key
	getCalls int
	putCalls int
}

func newMemoryKeyRepository() *memoryKeyRepository {
	return &memoryKeyRepository{keys: make(map[string]domain.Key)}
}

func (r *memoryKeyRepository) GetKey(_ context.Context, keyID string) (*domain.Key, error) {
	r.getCalls++
	key, ok := r.keys[keyID]
	if !ok {
		return nil, repository.ErrKeyNotFound
	}
	copy := key
	return &copy, nil
}

func (r *memoryKeyRepository) PutKey(_ context.Context, key domain.Key) error {
	r.putCalls++
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
