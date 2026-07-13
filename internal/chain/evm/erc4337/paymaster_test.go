package erc4337

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestV090PaymasterSignatureExclusionVector(t *testing.T) {
	withFirstSignature, err := standardVectorOperation(common.FromHex("0x123456")).Pack()
	require.NoError(t, err)
	withSecondSignature, err := standardVectorOperation(common.FromHex("0xabcdef")).Pack()
	require.NoError(t, err)
	withoutSignature, err := standardVectorOperation(nil).Pack()
	require.NoError(t, err)

	require.Equal(t,
		"0x33333333333333333333333333333333333333330000000000000000000000000000003c00000000000000000000000000000046cafe123456000322e325a297439656",
		hexBytes(withFirstSignature.PaymasterAndData),
	)
	require.Equal(t, 3, mustPaymasterSignatureLength(t, withFirstSignature.PaymasterAndData))
	paymasterHash, hashErr := PaymasterDataHash(withFirstSignature.PaymasterAndData)
	require.NoError(t, hashErr)
	require.Equal(t, "0xb21f950e0a0630bbbe5ad72eb57ab9421a0d3085ab5e054c5f3e4910675ca045", paymasterHash.Hex())
	extracted, err := PaymasterSignature(withFirstSignature.PaymasterAndData)
	require.NoError(t, err)
	require.Equal(t, common.FromHex("0x123456"), extracted)

	firstHash, err := withFirstSignature.UserOperationHash(EntryPointAddress(), big.NewInt(1), nil)
	require.NoError(t, err)
	secondHash, err := withSecondSignature.UserOperationHash(EntryPointAddress(), big.NewInt(1), nil)
	require.NoError(t, err)
	unsignedHash, err := withoutSignature.UserOperationHash(EntryPointAddress(), big.NewInt(1), nil)
	require.NoError(t, err)

	require.Equal(t, "0xa5c3f3ad244763ec6a1a145c56f970652c3a81a6819890e9f09f0294143c69d2", firstHash.Hex())
	require.Equal(t, firstHash, secondHash, "the appended paymaster signature must not change the wallet hash")
	require.NotEqual(t, unsignedHash, firstHash, "opting into the suffix format appends magic to the signed preimage")
}

func TestV090PaymasterSignatureValidationMatchesContract(t *testing.T) {
	invalid := append(make([]byte, PaymasterStaticFieldsLength), 0, 1)
	invalid = append(invalid, paymasterSigMagic[:]...)
	_, err := PaymasterSignatureLength(invalid)
	require.ErrorContains(t, err, "invalid paymaster signature length 1 for data length 62")
	_, err = PaymasterDataHash(invalid)
	require.ErrorContains(t, err, "invalid paymaster signature length")

	valid := append(make([]byte, PaymasterStaticFieldsLength), 0xab, 0, 1)
	valid = append(valid, paymasterSigMagic[:]...)
	require.Equal(t, 1, mustPaymasterSignatureLength(t, valid))
	signature, err := PaymasterSignature(valid)
	require.NoError(t, err)
	require.Equal(t, []byte{0xab}, signature)

	zeroLengthSuffix := append(make([]byte, PaymasterStaticFieldsLength), 0, 0)
	zeroLengthSuffix = append(zeroLengthSuffix, paymasterSigMagic[:]...)
	require.Zero(t, mustPaymasterSignatureLength(t, zeroLengthSuffix))
	hash, err := PaymasterDataHash(zeroLengthSuffix)
	require.NoError(t, err)
	require.Equal(t, crypto.Keccak256Hash(zeroLengthSuffix), hash, "zero-length suffix is hashed verbatim by v0.9")
}

func mustPaymasterSignatureLength(t *testing.T, data []byte) int {
	t.Helper()
	length, err := PaymasterSignatureLength(data)
	require.NoError(t, err)
	return length
}
