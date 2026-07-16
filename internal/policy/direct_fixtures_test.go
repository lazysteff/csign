package policy

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
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

func baseTRONKey(signer string) domain.Key {
	return domain.Key{
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
}

func testSignerAddress(t *testing.T, chainFamily string) string {
	t.Helper()
	address, err := chain.DeriveSignerAddress(chainFamily, mustMaterial(t).PublicKey())
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
		ID: "test-key", CustodyMode: v1.CustodyModeMVP, PrivateKeyHex: testPrivateKeyHex,
	})
	require.NoError(t, err)
	return material
}
