package v1

// StructuredPolicyFromPolicy converts the enforced fields of a stored policy
// to the structured update contract. Legacy opaque context is not copied.
func StructuredPolicyFromPolicy(policy Policy) StructuredPolicy {
	policy = policy.Clone()
	return StructuredPolicy{
		AllowedNetworks:                 policy.AllowedNetworks,
		AllowedChainIDs:                 policy.AllowedChainIDs,
		MaxValue:                        policy.MaxValue,
		MaxGasLimit:                     policy.MaxGasLimit,
		MaxGasPrice:                     policy.MaxGasPrice,
		MaxFeePerGas:                    policy.MaxFeePerGas,
		MaxPriorityFeePerGas:            policy.MaxPriorityFeePerGas,
		MaxFeeLimit:                     policy.MaxFeeLimit,
		AllowedTokenContracts:           policy.AllowedTokenContracts,
		AllowedSelectors:                policy.AllowedSelectors,
		AllowedSigningOperations:        policy.AllowedSigningOperations,
		AllowedEIP712Schemas:            policy.AllowedEIP712Schemas,
		AllowedEIP712VerifyingContracts: policy.AllowedEIP712VerifyingContracts,
		AllowedERC4337Versions:          policy.AllowedERC4337Versions,
		AllowedEntryPoints:              policy.AllowedEntryPoints,
		AllowedAccountImplementations:   policy.AllowedAccountImplementations,
		AllowedAccountSigningSchemas:    policy.AllowedAccountSigningSchemas,
		AllowedEIP7702Delegates:         policy.AllowedEIP7702Delegates,
		AllowEIP7702Revocation:          policy.AllowEIP7702Revocation,
		AllowEIP7702ChainIDZero:         policy.AllowEIP7702ChainIDZero,
		AllowedTransactionTypes:         policy.AllowedTransactionTypes,
		AllowedContractDestinations:     policy.AllowedContractDestinations,
		MaxAuthorizationListEntries:     policy.MaxAuthorizationListEntries,
	}
}

// ToPolicy converts the structured update contract to the full stored policy.
// The service restores any legacy AdditionalPolicyContext already on the key.
func (p StructuredPolicy) ToPolicy() Policy {
	return (Policy{
		AllowedNetworks:                 p.AllowedNetworks,
		AllowedChainIDs:                 p.AllowedChainIDs,
		MaxValue:                        p.MaxValue,
		MaxGasLimit:                     p.MaxGasLimit,
		MaxGasPrice:                     p.MaxGasPrice,
		MaxFeePerGas:                    p.MaxFeePerGas,
		MaxPriorityFeePerGas:            p.MaxPriorityFeePerGas,
		MaxFeeLimit:                     p.MaxFeeLimit,
		AllowedTokenContracts:           p.AllowedTokenContracts,
		AllowedSelectors:                p.AllowedSelectors,
		AllowedSigningOperations:        p.AllowedSigningOperations,
		AllowedEIP712Schemas:            p.AllowedEIP712Schemas,
		AllowedEIP712VerifyingContracts: p.AllowedEIP712VerifyingContracts,
		AllowedERC4337Versions:          p.AllowedERC4337Versions,
		AllowedEntryPoints:              p.AllowedEntryPoints,
		AllowedAccountImplementations:   p.AllowedAccountImplementations,
		AllowedAccountSigningSchemas:    p.AllowedAccountSigningSchemas,
		AllowedEIP7702Delegates:         p.AllowedEIP7702Delegates,
		AllowEIP7702Revocation:          p.AllowEIP7702Revocation,
		AllowEIP7702ChainIDZero:         p.AllowEIP7702ChainIDZero,
		AllowedTransactionTypes:         p.AllowedTransactionTypes,
		AllowedContractDestinations:     p.AllowedContractDestinations,
		MaxAuthorizationListEntries:     p.MaxAuthorizationListEntries,
	}).Clone()
}

// Clone returns a policy whose mutable collections do not alias the source.
func (p Policy) Clone() Policy {
	clone := p
	clone.AllowedNetworks = append([]string(nil), p.AllowedNetworks...)
	clone.AllowedChainIDs = append([]int64(nil), p.AllowedChainIDs...)
	clone.AllowedTokenContracts = append([]string(nil), p.AllowedTokenContracts...)
	clone.AllowedSelectors = append([]string(nil), p.AllowedSelectors...)
	clone.AllowedSigningOperations = append([]string(nil), p.AllowedSigningOperations...)
	clone.AllowedEIP712Schemas = append([]string(nil), p.AllowedEIP712Schemas...)
	clone.AllowedEIP712VerifyingContracts = append([]string(nil), p.AllowedEIP712VerifyingContracts...)
	clone.AllowedERC4337Versions = append([]string(nil), p.AllowedERC4337Versions...)
	clone.AllowedEntryPoints = append([]string(nil), p.AllowedEntryPoints...)
	clone.AllowedAccountImplementations = append([]string(nil), p.AllowedAccountImplementations...)
	clone.AllowedAccountSigningSchemas = append([]string(nil), p.AllowedAccountSigningSchemas...)
	clone.AllowedEIP7702Delegates = append([]string(nil), p.AllowedEIP7702Delegates...)
	clone.AllowedTransactionTypes = append([]string(nil), p.AllowedTransactionTypes...)
	clone.AllowedContractDestinations = append([]string(nil), p.AllowedContractDestinations...)
	if p.AdditionalPolicyContext != nil {
		clone.AdditionalPolicyContext = make(map[string]string, len(p.AdditionalPolicyContext))
		for key, value := range p.AdditionalPolicyContext {
			clone.AdditionalPolicyContext[key] = value
		}
	}
	return clone
}
