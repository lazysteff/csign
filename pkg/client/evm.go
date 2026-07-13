package client

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func (c *SigningClient) SignEVMLegacyTransfer(ctx context.Context, req v1.EVMLegacyTransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.EVMLegacyTransferSign, req)
}

func (c *SigningClient) SignEVMEIP1559Transfer(ctx context.Context, req v1.EVMEIP1559TransferSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.EVMEIP1559TransferSign, req)
}

func (c *SigningClient) SignEVMContractCall(ctx context.Context, req v1.EVMContractCallSignRequest) (*v1.SignResponse, error) {
	return c.sign(ctx, routes.EVMContractCallSign, req)
}

func (c *SigningClient) SignEVMEIP712(ctx context.Context, req v1.EVMEIP712SignRequest) (*v1.EVMEIP712SignResponse, error) {
	var out v1.EVMEIP712SignResponse
	if err := c.client.write(ctx, routes.EVMEIP712Sign, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *SigningClient) SignEVMUserOperation(ctx context.Context, req v1.EVMUserOperationSignRequest) (*v1.EVMUserOperationSignResponse, error) {
	var out v1.EVMUserOperationSignResponse
	if err := c.client.write(ctx, routes.EVMERC4337UserOperationSign, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *SigningClient) SignEVMEIP7702Authorization(ctx context.Context, req v1.EVMEIP7702AuthorizationSignRequest) (*v1.EVMEIP7702AuthorizationSignResponse, error) {
	var out v1.EVMEIP7702AuthorizationSignResponse
	if err := c.client.write(ctx, routes.EVMEIP7702AuthorizationSign, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *SigningClient) SignEVMEIP7702Transaction(ctx context.Context, req v1.EVMEIP7702TransactionSignRequest) (*v1.EVMEIP7702TransactionSignResponse, error) {
	var out v1.EVMEIP7702TransactionSignResponse
	if err := c.client.write(ctx, routes.EVMEIP7702TransactionSign, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *PayloadsClient) VerifyEVMEIP712(ctx context.Context, req v1.EVMEIP712VerifyRequest) (*v1.EVMEIP712VerifyResponse, error) {
	var out v1.EVMEIP712VerifyResponse
	if err := c.client.write(ctx, routes.EVMEIP712Verify, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *PayloadsClient) VerifyEVMUserOperation(ctx context.Context, req v1.EVMUserOperationVerifyRequest) (*v1.EVMUserOperationVerifyResponse, error) {
	var out v1.EVMUserOperationVerifyResponse
	if err := c.client.write(ctx, routes.EVMERC4337UserOperationVerify, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *PayloadsClient) VerifyEVMEIP7702Authorization(ctx context.Context, req v1.EVMEIP7702AuthorizationVerifyRequest) (*v1.EVMEIP7702AuthorizationVerifyResponse, error) {
	var out v1.EVMEIP7702AuthorizationVerifyResponse
	if err := c.client.write(ctx, routes.EVMEIP7702AuthorizationVerify, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *PayloadsClient) RecoverEVMEIP7702Transaction(ctx context.Context, req v1.EVMEIP7702TransactionRecoverRequest) (*v1.EVMEIP7702TransactionRecoverResponse, error) {
	var out v1.EVMEIP7702TransactionRecoverResponse
	if err := c.client.write(ctx, routes.EVMEIP7702TransactionRecover, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
