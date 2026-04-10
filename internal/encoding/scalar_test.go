package encoding

import (
	"testing"

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
