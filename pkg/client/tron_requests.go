package client

import v1 "github.com/chain-signer/chain-signer/pkg/api/v1"

func NewTRONOwnerSignRequestBase(keyID, network, requestID, ownerAddress string) v1.TRONOwnerSignRequestBase {
	return v1.TRONOwnerSignRequestBase{
		KeyID:        keyID,
		ChainFamily:  v1.ChainFamilyTRON,
		Network:      network,
		RequestID:    requestID,
		OwnerAddress: ownerAddress,
	}
}

func NewTRONFreezeBalanceV2Request(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope, resource string, amount int64) v1.TRONFreezeBalanceV2SignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
		Resource:                 resource,
		Amount:                   amount,
	}
}

func NewTRONUnfreezeBalanceV2Request(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope, resource string, amount int64) v1.TRONUnfreezeBalanceV2SignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONUnfreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
		Resource:                 resource,
		Amount:                   amount,
	}
}

func NewTRONDelegateResourceRequest(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope, receiverAddress, resource string, amount int64, lock bool, lockPeriod int64) v1.TRONDelegateResourceSignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONDelegateResourceSignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
		ReceiverAddress:          receiverAddress,
		Resource:                 resource,
		Amount:                   amount,
		Lock:                     lock,
		LockPeriod:               lockPeriod,
	}
}

func NewTRONUndelegateResourceRequest(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope, receiverAddress, resource string, amount int64) v1.TRONUndelegateResourceSignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONUndelegateResourceSignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
		ReceiverAddress:          receiverAddress,
		Resource:                 resource,
		Amount:                   amount,
	}
}

func NewTRONWithdrawExpireUnfreezeRequest(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope) v1.TRONWithdrawExpireUnfreezeSignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
	}
}
