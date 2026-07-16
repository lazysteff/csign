package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateTRONResourceRoutes(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyTRON)
	key := baseTRONKey(signer)
	owner := v1.TRONOwnerSignRequestBase{
		KeyID: "tron-key", ChainFamily: v1.ChainFamilyTRON, Network: testTronNetwork,
		RequestID: testRequestID, OwnerAddress: signer,
	}
	rawData := v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2", RefBlockHash: "0102030405060708",
		Timestamp: 1710000000000, Expiration: 1710000060000,
	}

	freezeReq := &v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: owner, TRONRawDataEnvelope: rawData,
		Resource: v1.TRONResourceEnergy, Amount: 10,
	}
	require.NoError(t, ValidateTRONFreezeBalanceV2(key, freezeReq))
	freezeReq.Amount = 0
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONFreezeBalanceV2(key, freezeReq)))
	freezeReq.Amount = 10
	freezeReq.RefBlockBytes = "a1"
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONFreezeBalanceV2(key, freezeReq)))
	freezeReq.RefBlockBytes = "a1b2"
	freezeReq.Expiration = freezeReq.Timestamp
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONFreezeBalanceV2(key, freezeReq)))

	unfreezeReq := &v1.TRONUnfreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: owner, TRONRawDataEnvelope: rawData,
		Resource: v1.TRONResourceTRONPower, Amount: 10,
	}
	require.ErrorContains(t, ValidateTRONUnfreezeBalanceV2(key, unfreezeReq), "TRON_POWER")

	delegateReq := &v1.TRONDelegateResourceSignRequest{
		TRONOwnerSignRequestBase: owner, TRONRawDataEnvelope: rawData,
		ReceiverAddress: testTronRecipient, Resource: v1.TRONResourceBandwidth,
		Amount: 11, Lock: true, LockPeriod: 86400,
	}
	require.NoError(t, ValidateTRONDelegateResource(key, delegateReq))
	delegateReq.LockPeriod = 0
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONDelegateResource(key, delegateReq)))
	delegateReq.Lock = false
	delegateReq.LockPeriod = 1
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONDelegateResource(key, delegateReq)))

	undelegateReq := &v1.TRONUndelegateResourceSignRequest{
		TRONOwnerSignRequestBase: owner, TRONRawDataEnvelope: rawData,
		ReceiverAddress: testTronRecipient, Resource: v1.TRONResourceEnergy, Amount: 12,
	}
	require.NoError(t, ValidateTRONUndelegateResource(key, undelegateReq))

	withdrawReq := &v1.TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: owner, TRONRawDataEnvelope: rawData,
	}
	require.NoError(t, ValidateTRONWithdrawExpireUnfreeze(key, withdrawReq))
}
