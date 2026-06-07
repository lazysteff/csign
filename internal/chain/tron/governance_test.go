package tron

import (
	"context"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/stretchr/testify/require"
)

func TestSignAndRecoverTRONGovernanceOperations(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	voteResp, err := SignTRONVoteWitness(context.Background(), material, voteWitnessRequest(signer))
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, voteResp.SignedPayload, v1.OperationTRONVoteWitness)
}

func TestTRONGovernanceBuildersProduceExpectedContracts(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	voteResp, err := SignTRONVoteWitness(context.Background(), material, voteWitnessRequest(signer))
	require.NoError(t, err)
	expectedVoteAddress, err := base58Address(tronRecipient)
	require.NoError(t, err)
	assertContractFields[*core.VoteWitnessContract](t, voteResp.SignedPayload, core.Transaction_Contract_VoteWitnessContract, func(contract *core.VoteWitnessContract) {
		require.False(t, contract.Support)
		require.Len(t, contract.Votes, 1)
		require.Equal(t, expectedVoteAddress, contract.Votes[0].VoteAddress)
		require.Equal(t, int64(2), contract.Votes[0].VoteCount)
	})
}

func voteWitnessRequest(signer string) *v1.TRONVoteWitnessSignRequest {
	return &v1.TRONVoteWitnessSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase("req-vote", signer),
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
			FeeLimit:      int64Ptr(5000000),
		},
		Votes: []v1.TRONVoteWitnessVote{{
			VoteAddress: tronRecipient,
			VoteCount:   2,
		}},
	}
}
