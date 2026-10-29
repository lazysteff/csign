package chain

import (
	"context"
	"testing"

	"github.com/lazysteff/csign/v2/internal/custody"
	"github.com/lazysteff/csign/v2/internal/domain"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestChainSwitchHelpers(t *testing.T) {
	privateKeyHex := "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"
	material, err := custody.Resolver{}.MaterialForKey(context.Background(), domain.Key{
		ID:            "key-1",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: privateKeyHex,
	})
	require.NoError(t, err)

	evmAddress, err := DeriveSignerAddress(v1.ChainFamilyEVM, material.PublicKey())
	require.NoError(t, err)
	require.True(t, EqualAddress(v1.ChainFamilyEVM, evmAddress, evmAddress))

	tronAddress, err := DeriveSignerAddress(v1.ChainFamilyTRON, material.PublicKey())
	require.NoError(t, err)
	require.True(t, EqualAddress(v1.ChainFamilyTRON, tronAddress, tronAddress))

	_, err = NormalizeAddress("unknown", "value")
	require.ErrorContains(t, err, "unsupported chain family")
}

func TestRecoverRejectsUnsupportedChainFamily(t *testing.T) {
	_, err := Recover(v1.VerifyRequest{ChainFamily: "unknown"})
	require.ErrorContains(t, err, "unsupported chain family")
}
