package evm

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func TestAddressHelpers(t *testing.T) {
	privateKey := mustMaterial(t)
	address := DeriveAddress(privateKey.PublicKey())
	normalized, err := NormalizeAddress(address)
	require.NoError(t, err)
	require.Equal(t, address, normalized)
	require.True(t, EqualAddress(address, normalized))

	_, err = NormalizeAddress("not-an-address")
	require.ErrorContains(t, err, "invalid evm address")
}

func TestSignAndRecoverOperations(t *testing.T) {
	material := mustMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	legacy, err := SignLegacyTransfer(context.Background(), material, &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "key-1",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       "ethereum-sepolia",
			RequestID:     "req-1",
			SourceAddress: signer,
		},
		ChainID:  11155111,
		To:       "0x1111111111111111111111111111111111111111",
		Value:    "1",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "1000",
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationEVMTransferLegacy, legacy.Operation)

	recovered, err := Recover(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               legacy.Network,
		SignedPayload:         legacy.SignedPayload,
		ExpectedSignerAddress: signer,
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationEVMTransferLegacy, recovered.Operation)
	require.True(t, recovered.MatchesExpected)

	eip1559, err := SignEIP1559Transfer(context.Background(), material, &v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "key-1",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       "ethereum-sepolia",
			RequestID:     "req-2",
			SourceAddress: signer,
		},
		ChainID:              11155111,
		To:                   "0x1111111111111111111111111111111111111111",
		Value:                "1",
		Nonce:                2,
		GasLimit:             21000,
		MaxFeePerGas:         "1500",
		MaxPriorityFeePerGas: "100",
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationEVMTransferEIP1559, eip1559.Operation)

	contractCall, err := SignContractCall(context.Background(), material, &v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "key-1",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       "ethereum-sepolia",
			RequestID:     "req-3",
			SourceAddress: signer,
		},
		ChainID:              11155111,
		To:                   "0x2222222222222222222222222222222222222222",
		Value:                "0",
		Data:                 "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:                3,
		GasLimit:             90000,
		MaxFeePerGas:         "1500",
		MaxPriorityFeePerGas: "100",
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationEVMContractEIP1559, contractCall.Operation)

	recovered, err = Recover(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               contractCall.Network,
		SignedPayload:         contractCall.SignedPayload,
		ExpectedSignerAddress: signer,
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationEVMContractEIP1559, recovered.Operation)
}

func TestSignAndRecoverErrors(t *testing.T) {
	material := mustMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	_, err := SignLegacyTransfer(context.Background(), material, &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "key-1",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       "ethereum-sepolia",
			RequestID:     "req-1",
			SourceAddress: signer,
		},
		ChainID:  11155111,
		To:       "0x1111111111111111111111111111111111111111",
		Value:    "1",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "not-a-number",
	})
	require.ErrorContains(t, err, "invalid numeric value")

	_, err = Recover(v1.VerifyRequest{
		ChainFamily:   v1.ChainFamilyEVM,
		SignedPayload: "0xdeadbeef",
	})
	require.ErrorContains(t, err, "decode evm signed payload")
}

func TestClassifyOperationUnknown(t *testing.T) {
	tx := ethtypes.NewTx(&ethtypes.AccessListTx{})
	require.Equal(t, "unknown", classifyOperation(tx))
}

func mustMaterial(t *testing.T) custody.Material {
	t.Helper()
	material, err := custody.Resolver{}.MaterialForKey(context.Background(), domain.Key{
		ID:            "key-1",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad",
	})
	require.NoError(t, err)
	return material
}
