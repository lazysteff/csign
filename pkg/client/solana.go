package client

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func (c *SigningClient) SignSolanaMessage(ctx context.Context, req v1.SolanaMessageSignRequest) (*v1.SolanaMessageSignResponse, error) {
	var out v1.SolanaMessageSignResponse
	if err := c.client.write(ctx, routes.SolanaMessageSign, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
