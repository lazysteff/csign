package vaultbackend

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) handleVerify(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	result, err := b.recovery.Verify(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) handleRecover(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	result, err := b.recovery.Recover(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) handleVerifyEVMEIP712(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMEIP712VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(advancedDecodeError(routes.EVMEIP712Verify, err))
	}
	result, err := b.recovery.VerifyEVMEIP712(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) handleVerifyEVMUserOperation(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMUserOperationVerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(advancedDecodeError(routes.EVMERC4337UserOperationVerify, err))
	}
	result, err := b.recovery.VerifyEVMUserOperation(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) handleVerifyEVMEIP7702Authorization(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMEIP7702AuthorizationVerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(advancedDecodeError(routes.EVMEIP7702AuthorizationVerify, err))
	}
	result, err := b.recovery.VerifyEVMEIP7702Authorization(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) handleRecoverEVMEIP7702Transaction(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMEIP7702TransactionRecoverRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(advancedDecodeError(routes.EVMEIP7702TransactionRecover, err))
	}
	result, err := b.recovery.RecoverEVMEIP7702Transaction(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}
