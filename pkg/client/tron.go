package client

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

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

func (c *SigningClient) SignTRONVoteWitness(ctx context.Context, req v1.TRONVoteWitnessSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONVoteWitnessSign, req)
}

func (c *SigningClient) SignTRONWithdrawBalance(ctx context.Context, req v1.TRONWithdrawBalanceSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.TRONWithdrawBalanceSign, req)
}

func (c *SigningClient) sign(ctx context.Context, path string, payload any) (*v1.SignResponse, error) {
	var out v1.SignResponse
	if err := c.client.write(ctx, path, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
