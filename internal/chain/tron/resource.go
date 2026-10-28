package tron

import (
	"crypto/ecdsa"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
)

func PrepareTRONFreezeBalanceV2(pub *ecdsa.PublicKey, req *v1.TRONFreezeBalanceV2SignRequest) (*cryptography.Prepared, error) {
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
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONFreezeBalanceV2,
		core.Transaction_Contract_FreezeBalanceV2Contract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func PrepareTRONUnfreezeBalanceV2(pub *ecdsa.PublicKey, req *v1.TRONUnfreezeBalanceV2SignRequest) (*cryptography.Prepared, error) {
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
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONUnfreezeBalanceV2,
		core.Transaction_Contract_UnfreezeBalanceV2Contract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func PrepareTRONDelegateResource(pub *ecdsa.PublicKey, req *v1.TRONDelegateResourceSignRequest) (*cryptography.Prepared, error) {
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
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONDelegateResource,
		core.Transaction_Contract_DelegateResourceContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func PrepareTRONUndelegateResource(pub *ecdsa.PublicKey, req *v1.TRONUndelegateResourceSignRequest) (*cryptography.Prepared, error) {
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
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONUndelegateResource,
		core.Transaction_Contract_UnDelegateResourceContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}

func PrepareTRONWithdrawExpireUnfreeze(pub *ecdsa.PublicKey, req *v1.TRONWithdrawExpireUnfreezeSignRequest) (*cryptography.Prepared, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	contract := &core.WithdrawExpireUnfreezeContract{
		OwnerAddress: owner,
	}
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONWithdrawExpireUnfreeze,
		core.Transaction_Contract_WithdrawExpireUnfreezeContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}
