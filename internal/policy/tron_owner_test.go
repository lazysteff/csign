package policy

import v1 "github.com/chain-signer/chain-signer/pkg/api/v1"

func tronPolicyOwnerBase(signer string) v1.TRONOwnerSignRequestBase {
	return v1.TRONOwnerSignRequestBase{
		KeyID:        "tron-key",
		ChainFamily:  v1.ChainFamilyTRON,
		Network:      testTronNetwork,
		RequestID:    testRequestID,
		OwnerAddress: signer,
	}
}

func tronPolicyEnvelope() v1.TRONRawDataEnvelope {
	return v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}
}
