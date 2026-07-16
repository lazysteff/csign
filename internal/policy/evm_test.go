package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateEVMLegacyTransfer(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyEVM)
	key := baseEVMKey(t)
	req := &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "key-1", ChainFamily: v1.ChainFamilyEVM, Network: testNetwork,
			RequestID: testRequestID, SourceAddress: signer,
		},
		ChainID: testEVMChainID, To: testRecipient, Value: "10",
		Nonce: 1, GasLimit: 21000, GasPrice: "1000",
	}
	require.NoError(t, ValidateEVMLegacyTransfer(key, req))

	key.Active = false
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMLegacyTransfer(key, req)))
	key = baseEVMKey(t)
	req.SourceAddress = testRecipient
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateEVMLegacyTransfer(key, req)))
	req.SourceAddress = signer
	req.Network = "mainnet"
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMLegacyTransfer(key, req)))
	req.Network = testNetwork
	req.ChainID = 1
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMLegacyTransfer(key, req)))
	req.ChainID = testEVMChainID
	req.GasPrice = "9999999999"
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMLegacyTransfer(key, req)))
}

func TestValidateEVMContractCall(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyEVM)
	key := baseEVMKey(t)
	key.Policy.AllowedTokenContracts = []string{testContract}
	key.Policy.AllowedSelectors = []string{domain.TRC20TransferSelector}
	req := contractCallRequest(signer)
	require.NoError(t, ValidateEVMContractCall(key, req))

	req.Data = ""
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateEVMContractCall(key, req)))
	req.Data = "0xdeadbeef"
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMContractCall(key, req)))
	req.Data = "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000"
	req.To = testRecipient
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMContractCall(key, req)))
}

func TestValidateEVMContractCallUsesNeutralDestinationAllowlist(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyEVM)
	key := baseEVMKey(t)
	key.Policy.AllowedContractDestinations = []string{testContract}
	key.Policy.AllowedSelectors = []string{domain.TRC20TransferSelector}
	req := contractCallRequest(signer)
	require.NoError(t, ValidateEVMContractCall(key, req))
	req.To = testRecipient
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMContractCall(key, req)))
}

func contractCallRequest(signer string) *v1.EVMContractCallSignRequest {
	return &v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "key-1", ChainFamily: v1.ChainFamilyEVM, Network: testNetwork,
			RequestID: testRequestID, SourceAddress: signer,
		},
		ChainID: testEVMChainID, To: testContract, Value: "0",
		Data:  "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000",
		Nonce: 1, GasLimit: 50000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	}
}
