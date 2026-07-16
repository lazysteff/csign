package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestSemanticallyEqualCanonicalizesControlPolicy(t *testing.T) {
	expected := v1.Policy{
		AllowedNetworks: []string{"network-b", "network-a"}, AllowedChainIDs: []int64{2, 1},
		AllowedSigningOperations:    []string{v1.OperationEVMContractEIP1559},
		AllowedContractDestinations: []string{"0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"},
		AllowedSelectors:            []string{"8456cb59", "3f4ba83a"}, MaxValue: "0",
		MaxGasLimit: 100000, MaxFeePerGas: "2000", MaxPriorityFeePerGas: "1000",
	}
	actual := expected.Clone()
	actual.AllowedNetworks = []string{"network-a", "network-b"}
	actual.AllowedChainIDs = []int64{1, 2}
	actual.AllowedContractDestinations = []string{"0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"}
	actual.AllowedSelectors = []string{"0X3F4BA83A", "0x8456CB59"}
	actual.MaxValue = "0x0"
	actual.MaxFeePerGas = "0x7d0"

	equal, err := SemanticallyEqual(signingops.Default(), v1.ChainFamilyEVM, expected, actual)
	require.NoError(t, err)
	require.True(t, equal)

	actual.MaxGasLimit = 0
	equal, err = SemanticallyEqual(signingops.Default(), v1.ChainFamilyEVM, expected, actual)
	require.NoError(t, err)
	require.False(t, equal, "an omitted gas cap must not equal a restricted cap")
}

func TestSemanticallyEqualRejectsDuplicateOrInvalidCanonicalValues(t *testing.T) {
	expected := v1.Policy{AllowedSigningOperations: []string{v1.OperationEVMContractEIP1559}}
	actual := expected.Clone()
	actual.AllowedSigningOperations = append(actual.AllowedSigningOperations, v1.OperationEVMContractEIP1559)
	_, err := SemanticallyEqual(signingops.Default(), v1.ChainFamilyEVM, expected, actual)
	require.Error(t, err)

	actual = expected.Clone()
	actual.AllowedSelectors = []string{"8456"}
	_, err = SemanticallyEqual(signingops.Default(), v1.ChainFamilyEVM, expected, actual)
	require.Error(t, err)
}
