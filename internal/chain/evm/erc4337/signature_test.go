package erc4337

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestSimpleAccountV090DirectDigestSignatureVector(t *testing.T) {
	privateKey, err := crypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad")
	require.NoError(t, err)
	owner := crypto.PubkeyToAddress(privateKey.PublicKey)
	require.Equal(t, common.HexToAddress("0x8bcf527cC930227F6907644921F1180936bed5f8"), owner)

	digest := common.HexToHash("0x5566644b8a0a191eb7572ce132ac3dbdbe4f0784fcc21d03280771bd1f007a03")
	signature, err := SignSimpleAccountDigest(privateKey, digest)
	require.NoError(t, err)
	require.Equal(t,
		"0x732c7561bc9860b86b581aee88c9ef9b1f90e9ed3e7b8f91020ee7de4aac7d8e486879256095819ad90981359f60a9722784e32d0ec882e32567f2f70ce378dd1c",
		hexBytes(signature),
	)

	recovered, err := RecoverSimpleAccountSigner(digest, signature)
	require.NoError(t, err)
	require.Equal(t, owner, recovered)
	valid, err := ValidateSimpleAccountSignature(digest, signature, owner)
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = ValidateSimpleAccountSignature(digest, signature, common.HexToAddress("0x1111111111111111111111111111111111111111"))
	require.NoError(t, err)
	require.False(t, valid)

	// Custody signers commonly return recovery parity 0/1. Encoding for the
	// account converts it to the 27/28 form OpenZeppelin accepts.
	recoverable := append([]byte(nil), signature...)
	recoverable[64] -= 27
	encoded, err := EncodeSimpleAccountSignature(recoverable)
	require.NoError(t, err)
	require.Equal(t, signature, encoded)
	_, err = RecoverSimpleAccountSigner(digest, recoverable)
	require.ErrorContains(t, err, "V must be 27 or 28")
}

func TestSimpleAccountSignatureRejectsMalleableOrMalformedValues(t *testing.T) {
	digest := common.HexToHash("0x5566644b8a0a191eb7572ce132ac3dbdbe4f0784fcc21d03280771bd1f007a03")
	valid := common.FromHex("0x732c7561bc9860b86b581aee88c9ef9b1f90e9ed3e7b8f91020ee7de4aac7d8e486879256095819ad90981359f60a9722784e32d0ec882e32567f2f70ce378dd1c")

	_, err := EncodeSimpleAccountSignature(valid[:64])
	require.ErrorContains(t, err, "must be 65 bytes")

	invalidV := append([]byte(nil), valid...)
	invalidV[64] = 29
	_, err = EncodeSimpleAccountSignature(invalidV)
	require.ErrorContains(t, err, "V must be")

	// N-S is the malleable high-S counterpart of the valid signature.
	highS := new(big.Int).Sub(crypto.S256().Params().N, new(big.Int).SetBytes(valid[32:64]))
	malleable := append([]byte(nil), valid...)
	highS.FillBytes(malleable[32:64])
	_, err = RecoverSimpleAccountSigner(digest, malleable)
	require.ErrorContains(t, err, "non-canonical high-S")

	_, err = SignSimpleAccountDigest(nil, digest)
	require.ErrorContains(t, err, "private key is required")
}
