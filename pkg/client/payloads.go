package client

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

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
