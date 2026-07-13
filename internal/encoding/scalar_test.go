package encoding

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestNormalizeHex(t *testing.T) {
	require.Equal(t, "abcd", NormalizeHex("0xabcd"))
	require.Equal(t, "ABCD", NormalizeHex("0XABCD"))
	require.Equal(t, "abcd", NormalizeHex(" abcd "))
}

func TestDecodeAndEncodeHex(t *testing.T) {
	decoded, err := DecodeHex("0x6869")
	require.NoError(t, err)
	require.Equal(t, []byte("hi"), decoded)
	require.Equal(t, "0x6869", EncodeHex(decoded))
}

func TestDecodeHexRejectsInvalidInput(t *testing.T) {
	_, err := DecodeHex("0xzz")
	require.ErrorContains(t, err, "decode hex")
}

func TestParseBigIntSupportsDecimalAndHex(t *testing.T) {
	decimal, err := ParseBigInt("42")
	require.NoError(t, err)
	require.Equal(t, "42", decimal.String())

	hexValue, err := ParseBigInt("0x2a")
	require.NoError(t, err)
	require.Equal(t, "42", hexValue.String())
}

func TestParseBigIntRejectsEmptyAndInvalid(t *testing.T) {
	_, err := ParseBigInt("")
	require.ErrorContains(t, err, "numeric value is required")

	_, err = ParseBigInt("not-a-number")
	require.ErrorContains(t, err, "invalid numeric value")
}

func TestParseEVMAddressRequiresCanonicalWireForm(t *testing.T) {
	address, err := ParseEVMAddress("address", "0x1111111111111111111111111111111111111111", false)
	require.NoError(t, err)
	require.Equal(t, common.HexToAddress("0x1111111111111111111111111111111111111111"), address)

	for _, value := range []string{
		"0X1111111111111111111111111111111111111111",
		"0xAb11111111111111111111111111111111111111",
		"1111111111111111111111111111111111111111",
		"0x1111",
	} {
		_, err := ParseEVMAddress("address", value, false)
		require.ErrorContains(t, err, "canonical lowercase")
	}
	_, err = ParseEVMAddress("address", "0x0000000000000000000000000000000000000000", false)
	require.ErrorContains(t, err, "must not be the zero address")
}

func TestDecodeCanonicalHex(t *testing.T) {
	decoded, err := DecodeCanonicalHex("hash", "0x0011", 2)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0x11}, decoded)

	for _, value := range []string{"0011", "0X0011", "0xAA", "0x0", "0xzz"} {
		_, err := DecodeCanonicalHex("hash", value, -1)
		require.ErrorContains(t, err, "canonical lowercase")
	}
	_, err = DecodeCanonicalHex("hash", "0x00", 2)
	require.ErrorContains(t, err, "exactly 2 bytes")
}

func TestParseCanonicalUint(t *testing.T) {
	parsed, err := ParseCanonicalUint("value", "42", 256, false)
	require.NoError(t, err)
	require.Equal(t, int64(42), parsed.Int64())

	for _, value := range []string{"", "01", "+1", "-1", " 1", "0x1"} {
		_, err := ParseCanonicalUint("value", value, 256, true)
		require.ErrorContains(t, err, "canonical base-10")
	}
	_, err = ParseCanonicalUint("value", "0", 256, false)
	require.ErrorContains(t, err, "greater than zero")
	_, err = ParseCanonicalUint("value", new(big.Int).Lsh(big.NewInt(1), 128).String(), 128, true)
	require.ErrorContains(t, err, "outside the uint128 range")

	maximum := new(big.Int).SetUint64(^uint64(0)).String()
	value, err := ParseCanonicalUint64("nonce", maximum)
	require.NoError(t, err)
	require.Equal(t, ^uint64(0), value)
}
