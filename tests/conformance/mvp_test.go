package conformance_test

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestConformance_MVPEVMOperations(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)

	created, raw := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID:            "evm-mvp",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedSigningOperations: []string{
				v1.OperationEVMTransferLegacy,
				v1.OperationEVMTransferEIP1559,
				v1.OperationEVMContractEIP1559,
			},
			AllowedNetworks:      []string{testEVMNetwork},
			AllowedChainIDs:      []int64{testEVMChainID},
			MaxValue:             "1000000000000000000",
			MaxGasLimit:          250000,
			MaxGasPrice:          "1000000000",
			MaxFeePerGas:         "2000000000",
			MaxPriorityFeePerGas: "1000000000",
			AllowedTokenContracts: []string{
				testEVMContract,
			},
			AllowedSelectors: []string{domain.TRC20TransferSelector},
		},
	})
	require.NotContains(t, raw, "private_key_hex")

	read, raw := readKey(t, ctx, backend, storage, "evm-mvp")
	require.Equal(t, created.SignerAddress, read.SignerAddress)
	require.NotContains(t, raw, "private_key_hex")

	legacy := signEVMLegacy(t, ctx, backend, storage, v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "evm-mvp", ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
			RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMRecipient, Value: "1",
		Nonce: 1, GasLimit: 21000, GasPrice: "1000",
	})
	legacyVerification := verifyPayload(t, ctx, backend, storage, v1.VerifyRequest{
		ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
		Operation: v1.OperationEVMTransferLegacy, SignedPayload: legacy.SignedPayload,
		ExpectedSignerAddress: created.SignerAddress,
	})
	require.True(t, legacyVerification.MatchesExpected)
	require.Equal(t, v1.OperationEVMTransferLegacy, legacyVerification.Operation)
	require.Equal(t, legacy.TxHash, legacyVerification.TxHash)

	eip1559 := signEVMEIP1559(t, ctx, backend, storage, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "evm-mvp", ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
			RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMRecipient, Value: "2", Nonce: 2,
		GasLimit: 21000, MaxFeePerGas: "1500", MaxPriorityFeePerGas: "100",
	})
	eip1559Verification := verifyPayload(t, ctx, backend, storage, v1.VerifyRequest{
		ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
		Operation: v1.OperationEVMTransferEIP1559, SignedPayload: eip1559.SignedPayload,
		ExpectedSignerAddress: created.SignerAddress,
	})
	require.True(t, eip1559Verification.MatchesExpected)
	require.Equal(t, v1.OperationEVMTransferEIP1559, eip1559Verification.Operation)

	contract := signEVMContract(t, ctx, backend, storage, v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "evm-mvp", ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
			RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMContract, Value: "0",
		Data:  "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000",
		Nonce: 3, GasLimit: 90000, MaxFeePerGas: "1500", MaxPriorityFeePerGas: "100",
	})
	contractRecovery := recoverPayload(t, ctx, backend, storage, v1.VerifyRequest{
		ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
		SignedPayload: contract.SignedPayload, ExpectedSignerAddress: created.SignerAddress,
	})
	require.True(t, contractRecovery.MatchesExpected)
	require.Equal(t, v1.OperationEVMContractEIP1559, contractRecovery.Operation)
}
