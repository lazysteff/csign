package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
)

type LogicalTransport interface {
	ReadWithContext(context.Context, string) (*api.Secret, error)
	WriteWithContext(context.Context, string, map[string]interface{}) (*api.Secret, error)
	ListWithContext(context.Context, string) (*api.Secret, error)
}

type Client struct {
	logical  LogicalTransport
	mount    string
	Keys     *KeysClient
	Signing  *SigningClient
	Payloads *PayloadsClient
}

type KeysClient struct {
	client *Client
}

type SigningClient struct {
	client *Client
}

type PayloadsClient struct {
	client *Client
}

func New(logical LogicalTransport, mount string) *Client {
	mount = strings.Trim(mount, "/")
	client := &Client{
		logical: logical,
		mount:   mount,
	}
	client.Keys = &KeysClient{client: client}
	client.Signing = &SigningClient{client: client}
	client.Payloads = &PayloadsClient{client: client}
	return client
}

func NewFromVault(vaultClient *api.Client, mount string) *Client {
	return New(vaultClient.Logical(), mount)
}

func (c *Client) Version(ctx context.Context) (*v1.VersionResponse, error) {
	secret, err := c.logical.ReadWithContext(ctx, c.path(routes.Version))
	if err != nil {
		return nil, err
	}
	var out v1.VersionResponse
	if err := decodeSecret(secret, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *KeysClient) Create(ctx context.Context, req v1.CreateKeyRequest) (*v1.KeyResponse, error) {
	var out v1.KeyResponse
	if err := c.client.write(ctx, routes.Keys, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *KeysClient) Read(ctx context.Context, keyID string) (*v1.KeyResponse, error) {
	secret, err := c.client.logical.ReadWithContext(ctx, c.client.path(routes.Key(keyID)))
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
	var out v1.KeyResponse
	if err := c.client.write(ctx, routes.KeyStatus(keyID), v1.UpdateKeyStatusRequest{Active: active}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *SigningClient) SignEVMLegacyTransfer(ctx context.Context, req v1.EVMLegacyTransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.EVMLegacyTransferSign, req)
}

func (c *SigningClient) SignEVMEIP1559Transfer(ctx context.Context, req v1.EVMEIP1559TransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.EVMEIP1559TransferSign, req)
}

func (c *SigningClient) SignEVMContractCall(ctx context.Context, req v1.EVMContractCallSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.EVMContractCallSign, req)
}

func (c *SigningClient) SignTRXTransfer(ctx context.Context, req v1.TRXTransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRXTransferSign, req)
}

func (c *SigningClient) SignTRC20Transfer(ctx context.Context, req v1.TRC20TransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRC20TransferSign, req)
}

func (c *SigningClient) SignTRONFreezeBalanceV2(ctx context.Context, req v1.TRONFreezeBalanceV2SignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONFreezeBalanceV2Sign, req)
}

func (c *SigningClient) SignTRONUnfreezeBalanceV2(ctx context.Context, req v1.TRONUnfreezeBalanceV2SignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONUnfreezeBalanceV2Sign, req)
}

func (c *SigningClient) SignTRONDelegateResource(ctx context.Context, req v1.TRONDelegateResourceSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONDelegateResourceSign, req)
}

func (c *SigningClient) SignTRONUndelegateResource(ctx context.Context, req v1.TRONUndelegateResourceSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONUndelegateResourceSign, req)
}

func (c *SigningClient) SignTRONWithdrawExpireUnfreeze(ctx context.Context, req v1.TRONWithdrawExpireUnfreezeSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONWithdrawExpireUnfreezeSign, req)
}

func (c *SigningClient) sign(ctx context.Context, path string, payload any) (*v1.SignResponse, error) {
	var out v1.SignResponse
	if err := c.client.write(ctx, path, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *PayloadsClient) Verify(ctx context.Context, req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	var out v1.RecoverResponse
	if err := c.client.write(ctx, routes.Verify, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *PayloadsClient) Recover(ctx context.Context, req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	var out v1.RecoverResponse
	if err := c.client.write(ctx, routes.Recover, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) write(ctx context.Context, path string, payload any, out any) error {
	data, err := toMap(payload)
	if err != nil {
		return err
	}
	secret, err := c.logical.WriteWithContext(ctx, c.path(path), data)
	if err != nil {
		return err
	}
	return decodeSecret(secret, out)
}

func (c *Client) path(path string) string {
	return c.mount + "/" + strings.Trim(path, "/")
}

func toMap(payload any) (map[string]interface{}, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	out := make(map[string]interface{})
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeSecret(secret *api.Secret, out any) error {
	if secret == nil {
		return fmt.Errorf("vault returned an empty response")
	}
	raw, err := json.Marshal(secret.Data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode vault response: %w", err)
	}
	return nil
}
