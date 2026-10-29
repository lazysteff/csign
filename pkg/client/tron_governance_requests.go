package client

import v1 "github.com/lazysteff/csign/v2/pkg/api/v1"

func NewTRONVoteWitnessRequest(base v1.TRONOwnerSignRequestBase, envelope v1.TRONRawDataEnvelope, votes []v1.TRONVoteWitnessVote) v1.TRONVoteWitnessSignRequest {
	base.ChainFamily = v1.ChainFamilyTRON
	return v1.TRONVoteWitnessSignRequest{
		TRONOwnerSignRequestBase: base,
		TRONRawDataEnvelope:      envelope,
		Votes:                    votes,
	}
}
