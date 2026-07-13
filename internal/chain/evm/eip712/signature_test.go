package eip712

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestPermitSignatureFormattingAndRecovery(t *testing.T) {
	hashes, err := HashPermit(testDomain, testMessage)
	require.NoError(t, err)
	privateKey, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	require.NoError(t, err)

	raw, err := crypto.Sign(hashes.Digest[:], privateKey)
	require.NoError(t, err)
	require.Contains(t, []byte{0, 1}, raw[64])

	signature, err := FormatSignature(raw)
	require.NoError(t, err)
	require.Contains(t, []uint8{27, 28}, signature.V)
	require.Equal(t, signature.V, signature.Bytes()[64])
	require.Len(t, signature.Bytes(), 65)
	require.Len(t, signature.Hex(), 132)
	require.Equal(t, common.BytesToHash(raw[:32]), signature.R)
	require.Equal(t, common.BytesToHash(raw[32:64]), signature.S)

	recovered, err := RecoverSigner(hashes.Digest, signature.Bytes())
	require.NoError(t, err)
	require.Equal(t, testMessage.Owner, strings.ToLower(recovered.Hex()))
	recoveredFromParity, err := RecoverSigner(hashes.Digest, raw)
	require.NoError(t, err)
	require.Equal(t, recovered, recoveredFromParity)

	verified, err := VerifySigner(hashes.Digest, signature.Bytes(), testMessage.Owner)
	require.NoError(t, err)
	require.Equal(t, recovered, verified)

	returnedBytes := signature.Bytes()
	returnedBytes[0] ^= 0xff
	require.NotEqual(t, returnedBytes, signature.Bytes(), "Bytes must return a defensive copy")
	require.Equal(t,
		"0xfed4335ba95f5d2cc409baddc1b1af1feba60deccc9bae313556aaf3900381d00456983b59dc85e425fdfb5891134915925be15c095d5a47dc4d41d732248ad31c",
		signature.Hex(),
	)
}

func TestVerifySignerRejectsMismatch(t *testing.T) {
	hashes, err := HashPermit(testDomain, testMessage)
	require.NoError(t, err)
	privateKey, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	require.NoError(t, err)
	raw, err := crypto.Sign(hashes.Digest[:], privateKey)
	require.NoError(t, err)

	recovered, err := VerifySigner(hashes.Digest, raw, "0x3333333333333333333333333333333333333333")
	require.ErrorContains(t, err, "does not match expected signer")
	require.Equal(t, testMessage.Owner, strings.ToLower(recovered.Hex()))
}

func TestSignatureValidation(t *testing.T) {
	hashes, err := HashPermit(testDomain, testMessage)
	require.NoError(t, err)
	privateKey, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	require.NoError(t, err)
	raw, err := crypto.Sign(hashes.Digest[:], privateKey)
	require.NoError(t, err)

	_, err = FormatSignature(raw[:64])
	require.ErrorContains(t, err, "exactly 65 bytes")

	invalidV := append([]byte(nil), raw...)
	invalidV[64] = 2
	_, err = FormatSignature(invalidV)
	require.ErrorContains(t, err, "recovery value")

	zeroR := append([]byte(nil), raw...)
	clear(zeroR[:32])
	_, err = FormatSignature(zeroR)
	require.ErrorContains(t, err, "invalid or non-canonical")

	highS := append([]byte(nil), raw...)
	s := new(big.Int).SetBytes(highS[32:64])
	s.Sub(crypto.S256().Params().N, s).FillBytes(highS[32:64])
	highS[64] ^= 1
	_, err = FormatSignature(highS)
	require.ErrorContains(t, err, "invalid or non-canonical")

	_, err = VerifySigner(hashes.Digest, raw, "0x0000000000000000000000000000000000000000")
	require.ErrorContains(t, err, "expected signer must not be the zero address")
}
