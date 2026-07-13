package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestEIP712PolicyDefaultsToDenyAndRequiresExplicitAllows(t *testing.T) {
	request := advancedPolicyPermitRequest()
	key := advancedPolicyKey(v1.Policy{})

	err := ValidateEVMEIP712(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "signing operation is not explicitly allowed")

	key.Policy = v1.Policy{
		AllowedSigningOperations:    []string{v1.OperationEVMEIP712Typed},
		AllowedNetworks:             []string{advancedPolicyNetwork},
		AllowedChainIDs:             []int64{1},
		AllowedEIP712Schemas:        []string{v1.EIP712SchemaEIP2612Permit},
		AllowedTokenContracts:       []string{advancedPolicyContract},
		AllowedContractDestinations: []string{advancedPolicySpender},
		MaxValue:                    "10",
	}
	require.NoError(t, ValidateEVMEIP712(key, &request))

	withoutSchema := key
	withoutSchema.Policy.AllowedEIP712Schemas = nil
	err = ValidateEVMEIP712(withoutSchema, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "EIP-712 schema is not explicitly allowed")

	wrongContract := key
	wrongContract.Policy.AllowedTokenContracts = []string{advancedPolicySpender}
	err = ValidateEVMEIP712(wrongContract, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "EIP-712 verifying contract")

	valueCap := key
	valueCap.Policy.MaxValue = "9"
	err = ValidateEVMEIP712(valueCap, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "permit value exceeds configured cap")
}

func advancedPolicyPermitRequest() v1.EVMEIP712SignRequest {
	return v1.EVMEIP712SignRequest{
		EVMAdvancedSignRequestBase: v1.EVMAdvancedSignRequestBase{
			EVMKeyRequestContext: v1.EVMKeyRequestContext{
				EVMRequestContext: v1.EVMRequestContext{
					ChainFamily: v1.ChainFamilyEVM,
					Network:     advancedPolicyNetwork,
					RequestID:   "permit-request",
				},
				KeyID: "advanced-key",
			},
			EVMSignerExpectation: v1.EVMSignerExpectation{
				ExpectedSignerAddress: advancedPolicySigner,
				ChainID:               "1",
			},
		},
		EIP712PermitPayload: v1.EIP712PermitPayload{
			SchemaID:      v1.EIP712SchemaEIP2612Permit,
			SchemaVersion: v1.EIP712SchemaEIP2612PermitVersion,
			Domain: v1.EIP712Domain{
				Name:              "Token",
				Version:           "1",
				ChainID:           "1",
				VerifyingContract: advancedPolicyContract,
			},
			Message: v1.EIP2612PermitMessage{
				Owner:    advancedPolicySigner,
				Spender:  advancedPolicySpender,
				Value:    "10",
				Nonce:    "0",
				Deadline: "100",
			},
		},
	}
}
