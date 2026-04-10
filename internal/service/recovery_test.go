package service

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestRecoveryServiceVerifyAppliesExpectedOperation(t *testing.T) {
	req, signerAddress := signedLegacyTransfer(t)
	service := NewRecoveryService()

	result, err := service.Verify(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               req.Network,
		Operation:             v1.OperationEVMTransferLegacy,
		SignedPayload:         req.SignedPayload,
		ExpectedSignerAddress: signerAddress,
	})
	require.NoError(t, err)
	require.True(t, result.MatchesExpected)

	result, err = service.Verify(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               req.Network,
		Operation:             v1.OperationTRXTransfer,
		SignedPayload:         req.SignedPayload,
		ExpectedSignerAddress: signerAddress,
	})
	require.NoError(t, err)
	require.False(t, result.MatchesExpected)
}

func TestRecoveryServiceRejectsUnsupportedChainFamily(t *testing.T) {
	service := NewRecoveryService()
	_, err := service.Recover(v1.VerifyRequest{ChainFamily: "unknown", SignedPayload: "0x00"})
	require.Equal(t, faults.Invalid, faults.KindOf(err))
}

func signedLegacyTransfer(t *testing.T) (*v1.SignResponse, string) {
	t.Helper()
	privateKeyHex := "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"
	resolver := custody.Resolver{}
	key := domain.Key{
		ID:            "evm-key",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: privateKeyHex,
	}
	material, err := resolver.MaterialForKey(context.Background(), key)
	require.NoError(t, err)

	signerAddress := evm.DeriveAddress(material.PublicKey())
	resp, err := evm.SignLegacyTransfer(context.Background(), material, &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-key",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       "ethereum-sepolia",
			RequestID:     "req-1",
			SourceAddress: signerAddress,
		},
		ChainID:  11155111,
		To:       "0x1111111111111111111111111111111111111111",
		Value:    "1",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "1000",
	})
	require.NoError(t, err)
	return resp, signerAddress
}
