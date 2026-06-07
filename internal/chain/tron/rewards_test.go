package tron

import (
	"context"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/stretchr/testify/require"
)

func TestSignAndRecoverTRONRewardOperations(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	withdrawBalanceResp, err := SignTRONWithdrawBalance(context.Background(), material, withdrawBalanceRequest(signer))
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, withdrawBalanceResp.SignedPayload, v1.OperationTRONWithdrawBalance)
}

func TestTRONRewardBuildersProduceExpectedContracts(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	withdrawBalanceResp, err := SignTRONWithdrawBalance(context.Background(), material, withdrawBalanceRequest(signer))
	require.NoError(t, err)
	tx := decodeSignedTransaction(t, withdrawBalanceResp.SignedPayload)
	require.Equal(t, int64(0), tx.RawData.FeeLimit)
	require.Equal(t, core.Transaction_Contract_WithdrawBalanceContract, tx.RawData.Contract[0].Type)
}

func withdrawBalanceRequest(signer string) *v1.TRONWithdrawBalanceSignRequest {
	return &v1.TRONWithdrawBalanceSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase("req-withdraw-balance", signer),
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
	}
}
