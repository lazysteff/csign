package tron

import (
	"crypto/ecdsa"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
)

func PrepareTRONVoteWitness(pub *ecdsa.PublicKey, req *v1.TRONVoteWitnessSignRequest) (*cryptography.Prepared, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	votes := make([]*core.VoteWitnessContract_Vote, 0, len(req.Votes))
	for _, requested := range req.Votes {
		voteAddress, err := base58Address(requested.VoteAddress)
		if err != nil {
			return nil, err
		}
		votes = append(votes, &core.VoteWitnessContract_Vote{
			VoteAddress: voteAddress,
			VoteCount:   requested.VoteCount,
		})
	}
	contract := &core.VoteWitnessContract{
		OwnerAddress: owner,
		Votes:        votes,
	}
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONVoteWitness,
		core.Transaction_Contract_VoteWitnessContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}
