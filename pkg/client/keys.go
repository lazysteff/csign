package client

import (
	"context"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type KeysClient struct {
	client *Client
}

func (c *KeysClient) Create(ctx context.Context, req v1.CreateKeyRequest) (*v1.KeyResponse, error) {
	var out v1.KeyResponse
	if err := c.client.write(ctx, routes.Keys, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *KeysClient) Read(ctx context.Context, keyID string) (*v1.KeyResponse, error) {
	path, err := routes.Key(keyID)
	if err != nil {
		return nil, err
	}
	secret, err := c.client.logical.ReadWithContext(ctx, c.client.path(path))
	if err != nil {
		return nil, err
	}
	var out v1.KeyResponse
	if err := decodeSecret(secret, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *KeysClient) List(ctx context.Context) ([]string, error) {
	secret, err := c.client.logical.ListWithContext(ctx, c.client.path(routes.Keys))
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	rawKeys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected list response shape")
	}
	out := make([]string, 0, len(rawKeys))
	for _, raw := range rawKeys {
		key, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected list response shape")
		}
		out = append(out, key)
	}
	return out, nil
}

func (c *KeysClient) SetActive(ctx context.Context, keyID string, active bool) (*v1.KeyResponse, error) {
	path, err := routes.KeyStatus(keyID)
	if err != nil {
		return nil, err
	}
	var out v1.KeyResponse
	if err := c.client.write(ctx, path, v1.UpdateKeyStatusRequest{Active: active}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *KeysClient) SetPolicy(ctx context.Context, keyID string, policy v1.StructuredPolicy) (*v1.KeyResponse, error) {
	path, err := routes.KeyPolicy(keyID)
	if err != nil {
		return nil, err
	}
	var out v1.KeyResponse
	if err := c.client.write(ctx, path, v1.UpdateKeyPolicyRequest{Policy: policy}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
