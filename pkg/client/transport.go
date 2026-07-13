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

func (c *Client) write(ctx context.Context, path string, payload any, out any) error {
	data, err := toMap(payload)
	if err != nil {
		return err
	}
	secret, err := c.logical.WriteWithContext(ctx, c.path(path), data)
	if err != nil {
		return wrapAPIError(err)
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
