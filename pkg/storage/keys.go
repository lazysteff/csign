package storage

import (
	"context"
	"fmt"
	"sort"

	"github.com/chain-signer/chain-signer/pkg/model"
	"github.com/hashicorp/vault/sdk/logical"
)

const keyPrefix = "keys/"

func PutKey(ctx context.Context, s logical.Storage, key model.Key) error {
	entry, err := logical.StorageEntryJSON(keyPath(key.ID), key)
	if err != nil {
		return fmt.Errorf("encode key %q: %w", key.ID, err)
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("store key %q: %w", key.ID, err)
	}
	return nil
}

func GetKey(ctx context.Context, s logical.Storage, keyID string) (*model.Key, error) {
	entry, err := s.Get(ctx, keyPath(keyID))
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", keyID, err)
	}
	if entry == nil {
		return nil, nil
	}
	var key model.Key
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, fmt.Errorf("decode key %q: %w", keyID, err)
	}
	return &key, nil
}

func ListKeys(ctx context.Context, s logical.Storage) ([]model.Key, error) {
	keys, err := s.List(ctx, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	out := make([]model.Key, 0, len(keys))
	for _, keyID := range keys {
		key, err := GetKey(ctx, s, keyID)
		if err != nil {
			return nil, err
		}
		if key != nil {
			out = append(out, *key)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func keyPath(keyID string) string {
	return keyPrefix + keyID
}
