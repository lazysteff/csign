package tron

import v1 "github.com/chain-signer/chain-signer/pkg/api/v1"

func tronOwnerBase(requestID, signer string) v1.TRONOwnerSignRequestBase {
	return v1.TRONOwnerSignRequestBase{
		KeyID:        "tron-key",
		ChainFamily:  v1.ChainFamilyTRON,
		Network:      "tron-nile",
		RequestID:    requestID,
		OwnerAddress: signer,
	}
}
