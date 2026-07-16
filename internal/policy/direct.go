package policy

import (
	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func validateBase(key domain.Key, req v1.BaseSignRequest, expectedChainFamily string, chainID *int64) error {
	return validateBaseFields(key, req.ChainFamily, req.Network, req.SourceAddress, "source address", expectedChainFamily, chainID)
}

func validateBaseFields(key domain.Key, requestChainFamily, network, signerAddress, signerLabel, expectedChainFamily string, chainID *int64) error {
	if !key.Active {
		return faults.Newf(faults.PolicyDenied, "key %q is disabled", key.ID)
	}
	if domain.NormalizeChainFamily(requestChainFamily) != expectedChainFamily {
		return faults.Newf(faults.Invalid, "request chain family %q does not match endpoint", requestChainFamily)
	}
	if domain.NormalizeChainFamily(key.ChainFamily) != expectedChainFamily {
		return faults.Newf(faults.Invalid, "key %q is bound to chain family %q", key.ID, key.ChainFamily)
	}
	if !chain.EqualAddress(expectedChainFamily, signerAddress, key.SignerAddress) {
		return faults.Newf(faults.Invalid, "%s does not match key signer address", signerLabel)
	}
	return enforceNetwork(key.Policy, network, chainID)
}

func enforceNetwork(policy v1.Policy, network string, chainID *int64) error {
	if len(policy.AllowedNetworks) > 0 {
		found := false
		for _, candidate := range policy.AllowedNetworks {
			if candidate == network {
				found = true
				break
			}
		}
		if !found {
			return faults.Newf(faults.PolicyDenied, "network %q is not allowed", network)
		}
	}
	if chainID != nil && len(policy.AllowedChainIDs) > 0 {
		found := false
		for _, candidate := range policy.AllowedChainIDs {
			if candidate == *chainID {
				found = true
				break
			}
		}
		if !found {
			return faults.Newf(faults.PolicyDenied, "chain_id %d is not allowed", *chainID)
		}
	}
	return nil
}
