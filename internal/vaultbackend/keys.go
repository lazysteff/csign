package vaultbackend

import (
	"context"
	"time"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) handleCreateKey(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.CreateKeyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	key, err := b.keyService(req.Storage).Create(ctx, payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleListKeys(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ids, err := b.keyService(req.Storage).ListKeyIDs(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return logical.ListResponse(ids), nil
}

func (b *Backend) handleReadKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, err := b.keyService(req.Storage).Read(ctx, fieldString(d, "key_id"))
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleUpdateKeyStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var payload v1.UpdateKeyStatusRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	key, err := b.keyService(req.Storage).SetActive(ctx, fieldString(d, "key_id"), payload.Active)
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleUpdateKeyPolicy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var payload v1.UpdateKeyPolicyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	if !payload.HasPolicy() {
		return nil, mapError(faults.New(faults.Invalid, "policy is required"))
	}
	key, err := b.keyService(req.Storage).SetPolicy(ctx, fieldString(d, "key_id"), payload.Policy)
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func keyResponse(key domain.Key) v1.KeyResponse {
	return v1.KeyResponse{
		APIVersion:    v1.APIVersion,
		KeyID:         key.ID,
		ChainFamily:   key.ChainFamily,
		CustodyMode:   key.CustodyMode,
		Active:        key.Active,
		Labels:        key.Labels,
		Policy:        key.Policy,
		SignerAddress: key.SignerAddress,
		PublicKeyHex:  key.PublicKeyHex,
		CreatedAt:     key.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:     key.UpdatedAt.Format(time.RFC3339Nano),
	}
}
