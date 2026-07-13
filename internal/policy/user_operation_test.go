package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestUserOperationPolicyDefaultsToDenyAndRequiresCompatibilityAllows(t *testing.T) {
	request := advancedPolicyUserOperationRequest()
	key := advancedPolicyKey(v1.Policy{})

	err := ValidateEVMUserOperation(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "signing operation is not explicitly allowed")

	key.Policy = v1.Policy{
		AllowedSigningOperations:      []string{v1.OperationEVMERC4337UserOperation},
		AllowedNetworks:               []string{advancedPolicyNetwork},
		AllowedChainIDs:               []int64{1},
		AllowedERC4337Versions:        []string{v1.ERC4337ProtocolV09},
		AllowedEntryPoints:            []string{advancedPolicyEntryPoint},
		AllowedAccountImplementations: []string{v1.ERC4337AccountSimpleAccount},
		AllowedAccountSigningSchemas:  []string{v1.ERC4337SimpleAccountSigningSchema},
		MaxFeePerGas:                  "100",
		MaxPriorityFeePerGas:          "2",
		MaxGasLimit:                   200000,
	}
	require.NoError(t, ValidateEVMUserOperation(key, &request))

	withoutEntryPoint := key
	withoutEntryPoint.Policy.AllowedEntryPoints = nil
	err = ValidateEVMUserOperation(withoutEntryPoint, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "EntryPoint is not explicitly allowed")

	withoutSigningSchema := key
	withoutSigningSchema.Policy.AllowedAccountSigningSchemas = nil
	err = ValidateEVMUserOperation(withoutSigningSchema, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "account signing schema is not explicitly allowed")

	feeCap := key
	feeCap.Policy.MaxFeePerGas = "99"
	err = ValidateEVMUserOperation(feeCap, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "max_fee_per_gas exceeds configured cap")

	gasCap := key
	gasCap.Policy.MaxGasLimit = 199999
	err = ValidateEVMUserOperation(gasCap, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "verification_gas_limit exceeds configured cap")

	shortCalldata := key
	shortCalldata.Policy.AllowedSelectors = []string{"aabbccdd"}
	err = ValidateEVMUserOperation(shortCalldata, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "4-byte selector")
	request.UserOperation.CallData = "0xaabbccdd"
	require.NoError(t, ValidateEVMUserOperation(shortCalldata, &request))

	request.UserOperation.Paymaster = &v1.ERC4337Paymaster{
		Address:              advancedPolicyContract,
		VerificationGasLimit: "200001",
		PostOpGasLimit:       "1",
		Data:                 "0x",
	}
	err = ValidateEVMUserOperation(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "paymaster.verification_gas_limit exceeds configured cap")

	request.UserOperation.CallGasLimit = "200001"
	request.UserOperation.VerificationGasLimit = "200002"
	for range 20 {
		err = ValidateEVMUserOperation(key, &request)
		require.EqualError(t, err, "call_gas_limit exceeds configured cap")
	}
}

func advancedPolicyUserOperationRequest() v1.EVMUserOperationSignRequest {
	return v1.EVMUserOperationSignRequest{
		EVMAdvancedSignRequestBase: v1.EVMAdvancedSignRequestBase{
			EVMKeyRequestContext: v1.EVMKeyRequestContext{
				EVMRequestContext: v1.EVMRequestContext{
					ChainFamily: v1.ChainFamilyEVM,
					Network:     advancedPolicyNetwork,
					RequestID:   "user-operation-request",
				},
				KeyID: "advanced-key",
			},
			EVMSignerExpectation: v1.EVMSignerExpectation{
				ExpectedSignerAddress: advancedPolicySigner,
				ChainID:               "1",
			},
		},
		ERC4337OperationDescriptor: v1.ERC4337OperationDescriptor{
			EntryPoint:                   advancedPolicyEntryPoint,
			ProtocolVersion:              v1.ERC4337ProtocolV09,
			AccountImplementation:        v1.ERC4337AccountSimpleAccount,
			AccountImplementationVersion: v1.ERC4337AccountSimpleAccountVersion,
			AccountSigningSchema:         v1.ERC4337SimpleAccountSigningSchema,
		},
		UserOperation: v1.ERC4337UserOperationV09{
			Sender:               advancedPolicySender,
			Nonce:                "7",
			CallData:             "0xaabb",
			CallGasLimit:         "100000",
			VerificationGasLimit: "200000",
			PreVerificationGas:   "50000",
			MaxFeePerGas:         "100",
			MaxPriorityFeePerGas: "2",
		},
	}
}
