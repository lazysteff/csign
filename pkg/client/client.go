package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
)

type Client struct {
	logical *api.Logical
	mount   string
}

func New(vaultClient *api.Client, mount string) *Client {
	mount = strings.Trim(mount, "/")
	return &Client{
		logical: vaultClient.Logical(),
		mount:   mount,
	}
}

func (c *Client) Version(ctx context.Context) (map[string]string, error) {
	secret, err := c.logical.ReadWithContext(ctx, c.path("v1/version"))
	if err != nil {
		return nil, err
	}
	var out map[string]string
	if err := decodeSecret(secret, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateKey(ctx context.Context, req v1.CreateKeyRequest) (*v1.KeyResponse, error) {
	var out v1.KeyResponse
	if err := c.write(ctx, "v1/keys", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ReadKey(ctx context.Context, keyID string) (*v1.KeyResponse, error) {
	secret, err := c.logical.ReadWithContext(ctx, c.path("v1/keys/"+keyID))
	if err != nil {
		return nil, err
	}
	var out v1.KeyResponse
	if err := decodeSecret(secret, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	secret, err := c.logical.ListWithContext(ctx, c.path("v1/keys"))
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
		if key, ok := raw.(string); ok {
			out = append(out, key)
		}
	}
	return out, nil
}

func (c *Client) SetKeyActive(ctx context.Context, keyID string, active bool) (*v1.KeyResponse, error) {
	var out v1.KeyResponse
	if err := c.write(ctx, "v1/keys/"+keyID+"/status", v1.UpdateKeyStatusRequest{Active: active}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SignEVMLegacyTransfer(ctx context.Context, req v1.EVMLegacyTransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, "v1/evm/transfers/legacy/sign", req)
}

func (c *Client) SignEVMEIP1559Transfer(ctx context.Context, req v1.EVMEIP1559TransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, "v1/evm/transfers/eip1559/sign", req)
}

func (c *Client) SignEVMContractCall(ctx context.Context, req v1.EVMContractCallSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, "v1/evm/contracts/eip1559/sign", req)
}

func (c *Client) SignTRXTransfer(ctx context.Context, req v1.TRXTransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, "v1/tron/transfers/trx/sign", req)
}

func (c *Client) SignTRC20Transfer(ctx context.Context, req v1.TRC20TransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, "v1/tron/transfers/trc20/sign", req)
}

func (c *Client) Verify(ctx context.Context, req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	var out v1.RecoverResponse
	if err := c.write(ctx, "v1/verify", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Recover(ctx context.Context, req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	var out v1.RecoverResponse
	if err := c.write(ctx, "v1/recover", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) sign(ctx context.Context, path string, payload interface{}) (*v1.SignResponse, error) {
	var out v1.SignResponse
	if err := c.write(ctx, path, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) write(ctx context.Context, path string, payload interface{}, out interface{}) error {
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

func toMap(payload interface{}) (map[string]interface{}, error) {
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

func decodeSecret(secret *api.Secret, out interface{}) error {
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
