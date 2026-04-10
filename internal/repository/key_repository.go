package repository

import (
	"context"
	"fmt"
	"sort"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/hashicorp/vault/sdk/logical"
)

const keyPrefix = "keys/"

type KeyRepository interface {
	GetKey(context.Context, string) (*domain.Key, error)
	PutKey(context.Context, domain.Key) error
	ListKeyIDs(context.Context) ([]string, error)
}

type VaultKeyRepository struct {
	storage logical.Storage
}

func NewVaultKeyRepository(storage logical.Storage) *VaultKeyRepository {
	return &VaultKeyRepository{storage: storage}
}

func (r *VaultKeyRepository) PutKey(ctx context.Context, key domain.Key) error {
	entry, err := logical.StorageEntryJSON(keyPath(key.ID), key)
	if err != nil {
		return fmt.Errorf("encode key %q: %w", key.ID, err)
	}
	if err := r.storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("store key %q: %w", key.ID, err)
	}
	return nil
}

func (r *VaultKeyRepository) GetKey(ctx context.Context, keyID string) (*domain.Key, error) {
	entry, err := r.storage.Get(ctx, keyPath(keyID))
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", keyID, err)
	}
	if entry == nil {
		return nil, nil
	}
	var key domain.Key
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, fmt.Errorf("decode key %q: %w", keyID, err)
	}
	return &key, nil
}

func (r *VaultKeyRepository) ListKeyIDs(ctx context.Context) ([]string, error) {
	keys, err := r.storage.List(ctx, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}

func keyPath(keyID string) string {
	return keyPrefix + keyID
}
