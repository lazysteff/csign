package custody

import (
	"crypto/ecdsa"
	"testing"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

const testPrivHex = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"

func mustPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	keyBytes, err := enc.DecodeHex(testPrivHex)
	require.NoError(t, err)
	key, err := ethcrypto.ToECDSA(keyBytes)
	require.NoError(t, err)
	return key
}
