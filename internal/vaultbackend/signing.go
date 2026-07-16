package vaultbackend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) handleSign(route string) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		signing := b.signingService(req.Storage)
		payload, err := signing.NewRequest(ctx, route)
		if err != nil {
			return nil, mapError(err)
		}
		if err := decode(req.Data, payload); err != nil {
			return nil, mapError(structuredDecodeError(route, err))
		}
		result, err := signing.Execute(ctx, route, payload)
		if err != nil {
			return nil, mapError(err)
		}
		return response(result), nil
	}
}
