package client

import v1 "github.com/chain-signer/chain-signer/pkg/api/v1"

func NewTRONWithdrawBalanceRequest(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope) v1.TRONWithdrawBalanceSignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONWithdrawBalanceSignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
	}
}
