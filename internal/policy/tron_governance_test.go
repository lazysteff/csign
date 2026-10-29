package policy

import (
	"testing"

	"github.com/lazysteff/csign/v2/internal/faults"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateTRONGovernanceRoutes(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyTRON)
	key := baseTRONKey(signer)

	voteReq := &v1.TRONVoteWitnessSignRequest{
		TRONOwnerSignRequestBase: tronPolicyOwnerBase(signer),
		TRONRawDataEnvelope:      tronPolicyEnvelope(),
		Votes: []v1.TRONVoteWitnessVote{{
			VoteAddress: testTronRecipient,
			VoteCount:   2,
		}},
	}
	require.NoError(t, ValidateTRONVoteWitness(key, voteReq))

	voteReq.Votes = nil
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONVoteWitness(key, voteReq)))
	voteReq.Votes = make([]v1.TRONVoteWitnessVote, 31)
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONVoteWitness(key, voteReq)))
	voteReq.Votes = []v1.TRONVoteWitnessVote{{VoteAddress: "not-a-tron-address", VoteCount: 1}}
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONVoteWitness(key, voteReq)))
	voteReq.Votes = []v1.TRONVoteWitnessVote{{VoteAddress: testTronRecipient, VoteCount: 0}}
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONVoteWitness(key, voteReq)))
	voteReq.Votes = []v1.TRONVoteWitnessVote{
		{VoteAddress: testTronRecipient, VoteCount: 1},
		{VoteAddress: testTronRecipient, VoteCount: 2},
	}
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateTRONVoteWitness(key, voteReq)))
}
