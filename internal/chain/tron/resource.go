package tron

import (
	"context"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/custody"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
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
	return signTRONResourceTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
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
	return signTRONResourceTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
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
	return signTRONResourceTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
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
	return signTRONResourceTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
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
	return signTRONResourceTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		v1.OperationTRONWithdrawExpireUnfreeze,
		core.Transaction_Contract_WithdrawExpireUnfreezeContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func signTRONResourceTransaction(
	ctx context.Context,
	material custody.Material,
	keyID, network, operation string,
	contractType core.Transaction_Contract_ContractType,
	contract proto.Message,
	envelope v1.TRONRawDataEnvelope,
) (*v1.SignResponse, error) {
	typed, err := anypb.New(contract)
	if err != nil {
		return nil, fmt.Errorf("wrap tron resource contract: %w", err)
	}
	tx, err := buildTransaction(
		contractType,
		typed,
		envelope.RefBlockBytes,
		envelope.RefBlockHash,
		0,
		envelope.Timestamp,
		envelope.Expiration,
		envelope.FeeLimitOrZero(),
	)
	if err != nil {
		return nil, err
	}
	return signTransaction(ctx, material, keyID, network, operation, tx)
}
