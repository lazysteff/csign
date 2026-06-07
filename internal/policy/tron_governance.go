package policy

import (
	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

const maxTRONVoteWitnessEntries = 30

func ValidateTRONVoteWitness(key domain.Key, req *v1.TRONVoteWitnessSignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	if err := validateTRONResourceEnvelope(req.TRONRawDataEnvelope); err != nil {
		return err
	}
	if len(req.Votes) == 0 {
		return faults.New(faults.Invalid, "votes must contain at least 1 entry")
	}
	if len(req.Votes) > maxTRONVoteWitnessEntries {
		return faults.Newf(faults.Invalid, "votes must contain at most %d entries", maxTRONVoteWitnessEntries)
	}
	seen := make(map[string]struct{}, len(req.Votes))
	for i, vote := range req.Votes {
		normalized, err := chain.NormalizeAddress(v1.ChainFamilyTRON, vote.VoteAddress)
		if err != nil {
			return faults.Newf(faults.Invalid, "vote[%d] address is invalid: %v", i, err)
		}
		if _, exists := seen[normalized]; exists {
			return faults.Newf(faults.Invalid, "vote[%d] duplicates vote_address %q", i, vote.VoteAddress)
		}
		seen[normalized] = struct{}{}
		if vote.VoteCount <= 0 {
			return faults.Newf(faults.Invalid, "vote[%d].vote_count must be greater than 0", i)
		}
	}
	return nil
}
