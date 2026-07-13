package policy

import (
	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

const (
	advancedPolicySigner     = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	advancedPolicyNetwork    = "ethereum-mainnet"
	advancedPolicyContract   = "0x1111111111111111111111111111111111111111"
	advancedPolicySpender    = "0x2222222222222222222222222222222222222222"
	advancedPolicySender     = "0x3333333333333333333333333333333333333333"
	advancedPolicyEntryPoint = v1.ERC4337EntryPointV09
)

func advancedPolicyKey(policy v1.Policy) domain.Key {
	return domain.Key{
		ID:            "advanced-key",
		ChainFamily:   v1.ChainFamilyEVM,
		Active:        true,
		SignerAddress: advancedPolicySigner,
		Policy:        policy,
	}
}
