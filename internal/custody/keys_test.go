package custody

import (
	"testing"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestParsePublicKeyHexAndDecodeSignatureErrors(t *testing.T) {
	privateKey := mustPrivateKey(t)
	parsed, err := parsePublicKeyHex(PublicKeyHex(&privateKey.PublicKey))
	require.NoError(t, err)
	require.True(t, samePublicKey(&privateKey.PublicKey, parsed))

	compressed := enc.EncodeHex(ethcrypto.CompressPubkey(&privateKey.PublicKey))
	parsed, err = parsePublicKeyHex(compressed)
	require.NoError(t, err)
	require.True(t, samePublicKey(&privateKey.PublicKey, parsed))

	_, _, err = decodeSignature([]byte("bad"))
	require.ErrorContains(t, err, "unsupported format")
}
