package v1

// StructuredPolicyFromPolicy copies a stored policy for an update request.
// Deprecated opaque storage context is deliberately not copied.
func StructuredPolicyFromPolicy(policy Policy) StructuredPolicy {
	structured := policy.Clone()
	structured.AdditionalPolicyContext = nil
	return structured
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
