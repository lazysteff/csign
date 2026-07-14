package tron

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/custody"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
)

func SignTRONFreezeBalanceV2(ctx context.Context, material custody.Material, req *v1.TRONFreezeBalanceV2SignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	resource, err := tronResourceCode(req.Resource)
	if err != nil {
		return nil, err
	}
	contract := &core.FreezeBalanceV2Contract{
		OwnerAddress:  owner,
		FrozenBalance: req.Amount,
		Resource:      resource,
	}
	return signTRONOwnerTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONFreezeBalanceV2,
		core.Transaction_Contract_FreezeBalanceV2Contract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func SignTRONUnfreezeBalanceV2(ctx context.Context, material custody.Material, req *v1.TRONUnfreezeBalanceV2SignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	resource, err := tronResourceCode(req.Resource)
	if err != nil {
		return nil, err
	}
	contract := &core.UnfreezeBalanceV2Contract{
		OwnerAddress:    owner,
		UnfreezeBalance: req.Amount,
		Resource:        resource,
	}
	return signTRONOwnerTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONUnfreezeBalanceV2,
		core.Transaction_Contract_UnfreezeBalanceV2Contract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func SignTRONDelegateResource(ctx context.Context, material custody.Material, req *v1.TRONDelegateResourceSignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	receiver, err := base58Address(req.ReceiverAddress)
	if err != nil {
		return nil, err
	}
	resource, err := tronResourceCode(req.Resource)
	if err != nil {
		return nil, err
	}
	contract := &core.DelegateResourceContract{
		OwnerAddress:    owner,
		Resource:        resource,
		Balance:         req.Amount,
		ReceiverAddress: receiver,
		Lock:            req.Lock,
		LockPeriod:      req.LockPeriod,
	}
	return signTRONOwnerTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONDelegateResource,
		core.Transaction_Contract_DelegateResourceContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func SignTRONUndelegateResource(ctx context.Context, material custody.Material, req *v1.TRONUndelegateResourceSignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	receiver, err := base58Address(req.ReceiverAddress)
	if err != nil {
		return nil, err
	}
	resource, err := tronResourceCode(req.Resource)
	if err != nil {
		return nil, err
	}
	contract := &core.UnDelegateResourceContract{
		OwnerAddress:    owner,
		Resource:        resource,
		Balance:         req.Amount,
		ReceiverAddress: receiver,
	}
	return signTRONOwnerTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONUndelegateResource,
		core.Transaction_Contract_UnDelegateResourceContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func SignTRONWithdrawExpireUnfreeze(ctx context.Context, material custody.Material, req *v1.TRONWithdrawExpireUnfreezeSignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	contract := &core.WithdrawExpireUnfreezeContract{
		OwnerAddress: owner,
	}
	return signTRONOwnerTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONWithdrawExpireUnfreeze,
		core.Transaction_Contract_WithdrawExpireUnfreezeContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}
