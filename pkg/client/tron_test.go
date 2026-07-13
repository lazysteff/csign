package client

import (
	"context"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestTRONResourceSigningUsesExpectedRoute(t *testing.T) {
	logical := &fakeLogical{
		writeSecret: &api.Secret{
			Data: map[string]interface{}{
				"api_version": v1.APIVersion,
				"key_id":      "tron-key",
			},
		},
	}
	client := New(logical, "chain-signer")
	_, err := client.Signing.SignTRONFreezeBalanceV2(context.Background(), v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: NewTRONOwnerSignRequestBase("tron-key", "tron-nile", "req-1", "TQ3f6xYfQudrM1J8XG2k6wN1KQkPqM7g7d"),
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
		Resource: v1.TRONResourceEnergy,
		Amount:   1,
	})
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/tron/resources/freeze_v2/sign", logical.lastWritePath)

	_, err = client.Signing.SignTRONVoteWitness(context.Background(), v1.TRONVoteWitnessSignRequest{
		TRONOwnerSignRequestBase: NewTRONOwnerSignRequestBase("tron-key", "tron-nile", "req-2", "TQ3f6xYfQudrM1J8XG2k6wN1KQkPqM7g7d"),
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
		Votes: []v1.TRONVoteWitnessVote{{
			VoteAddress: "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1",
			VoteCount:   1,
		}},
	})
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/tron/governance/vote_witness/sign", logical.lastWritePath)

	_, err = client.Signing.SignTRONWithdrawBalance(context.Background(), v1.TRONWithdrawBalanceSignRequest{
		TRONOwnerSignRequestBase: NewTRONOwnerSignRequestBase("tron-key", "tron-nile", "req-3", "TQ3f6xYfQudrM1J8XG2k6wN1KQkPqM7g7d"),
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/tron/rewards/withdraw_balance/sign", logical.lastWritePath)
}

func TestTRONRequestBuildersDefaultChainFamily(t *testing.T) {
	base := NewTRONOwnerSignRequestBase("tron-key", "tron-nile", "req-1", "TP4XxLr5K8NvL8nRc1rER6S1PqrgQ4QXbQ")
	req := NewTRONDelegateResourceRequest(base, v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}, "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1", v1.TRONResourceBandwidth, 10, false, 0)
	require.Equal(t, v1.ChainFamilyTRON, req.ChainFamily)
	require.Equal(t, int64(10), req.Amount)

	voteReq := NewTRONVoteWitnessRequest(base, v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}, []v1.TRONVoteWitnessVote{{VoteAddress: "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1", VoteCount: 1}})
	require.Equal(t, v1.ChainFamilyTRON, voteReq.ChainFamily)
	require.Equal(t, int64(1), voteReq.Votes[0].VoteCount)

	withdrawReq := NewTRONWithdrawBalanceRequest(base, v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	})
	require.Equal(t, v1.ChainFamilyTRON, withdrawReq.ChainFamily)
}
