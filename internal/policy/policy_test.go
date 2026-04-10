package policy

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

const (
	testPrivateKeyHex       = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"
	testRecipient           = "0x1111111111111111111111111111111111111111"
	testContract            = "0x2222222222222222222222222222222222222222"
	testTronRecipient       = "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1"
	testTronContract        = "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9"
	testNetwork             = "ethereum-sepolia"
	testTronNetwork         = "tron-nile"
	testRequestID           = "req-123"
	testEVMChainID    int64 = 11155111
)

func TestValidateCreateKeyRequest(t *testing.T) {
	require.NoError(t, ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: v1.ChainFamilyEVM,
	}))

	require.NoError(t, ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      testPublicKeyHex(t),
		ExternalSignerRef: "hsm-1",
	}))

	require.Equal(t, faults.Invalid, faults.KindOf(ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: "unknown",
	})))
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily:       v1.ChainFamilyEVM,
		ExternalSignerRef: "hsm-1",
	})))
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: v1.ChainFamilyEVM,
		CustodyMode: v1.CustodyModePKCS11,
	})))
}

func TestValidateEVMLegacyTransfer(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyEVM)
	key := baseEVMKey(t)
	req := &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "key-1",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testNetwork,
			RequestID:     testRequestID,
			SourceAddress: signer,
		},
		ChainID:  testEVMChainID,
		To:       testRecipient,
		Value:    "10",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "1000",
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

	req := &v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "key-1",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testNetwork,
			RequestID:     testRequestID,
			SourceAddress: signer,
		},
		ChainID:              testEVMChainID,
		To:                   testContract,
		Value:                "0",
		Data:                 "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:                1,
		GasLimit:             50000,
		MaxFeePerGas:         "1000",
		MaxPriorityFeePerGas: "100",
	}
	require.NoError(t, ValidateEVMContractCall(key, req))

	req.Data = ""
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateEVMContractCall(key, req)))
	req.Data = "0xdeadbeef"
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMContractCall(key, req)))
	req.Data = "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000"
	req.To = testRecipient
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateEVMContractCall(key, req)))
}

func TestValidateTRXAndTRC20Transfers(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyTRON)
	key := domain.Key{
		ID:            "tron-key",
		ChainFamily:   v1.ChainFamilyTRON,
		Active:        true,
		SignerAddress: signer,
		Policy: v1.Policy{
			AllowedNetworks:       []string{testTronNetwork},
			MaxValue:              "100",
			MaxFeeLimit:           20000000,
			AllowedTokenContracts: []string{testTronContract},
			AllowedSelectors:      []string{domain.TRC20TransferSelector},
		},
	}

	trxReq := &v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       testTronNetwork,
			RequestID:     testRequestID,
			SourceAddress: signer,
		},
		To:            testTronRecipient,
		Amount:        10,
		FeeLimit:      1000000,
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}
	require.NoError(t, ValidateTRXTransfer(key, trxReq))

	trxReq.Amount = 101
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateTRXTransfer(key, trxReq)))
	trxReq.Amount = 10
	trxReq.FeeLimit = 21000000
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateTRXTransfer(key, trxReq)))

	trc20Req := &v1.TRC20TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       testTronNetwork,
			RequestID:     testRequestID,
			SourceAddress: signer,
		},
		To:            testTronRecipient,
		TokenContract: testTronContract,
		Amount:        "25",
		FeeLimit:      1000000,
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}
	require.NoError(t, ValidateTRC20Transfer(key, trc20Req))

	trc20Req.TokenContract = testTronRecipient
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateTRC20Transfer(key, trc20Req)))
}

func baseEVMKey(t *testing.T) domain.Key {
	t.Helper()
	return domain.Key{
		ID:            "key-1",
		ChainFamily:   v1.ChainFamilyEVM,
		Active:        true,
		SignerAddress: testSignerAddress(t, v1.ChainFamilyEVM),
		Policy: v1.Policy{
			AllowedNetworks:      []string{testNetwork},
			AllowedChainIDs:      []int64{testEVMChainID},
			MaxValue:             "100",
			MaxGasLimit:          500000,
			MaxGasPrice:          "1000000000",
			MaxFeePerGas:         "2000000000",
			MaxPriorityFeePerGas: "1000000000",
		},
	}
}

func testSignerAddress(t *testing.T, chainFamily string) string {
	t.Helper()
	material := mustMaterial(t)
	address, err := chain.DeriveSignerAddress(chainFamily, material.PublicKey())
	require.NoError(t, err)
	return address
}

func testPublicKeyHex(t *testing.T) string {
	t.Helper()
	return custody.PublicKeyHex(mustMaterial(t).PublicKey())
}

func mustMaterial(t *testing.T) custody.Material {
	t.Helper()
	material, err := custody.Resolver{}.MaterialForKey(context.Background(), domain.Key{
		ID:            "test-key",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: testPrivateKeyHex,
	})
	require.NoError(t, err)
	return material
}
