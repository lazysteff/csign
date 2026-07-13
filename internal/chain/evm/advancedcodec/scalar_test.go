package advancedcodec

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestAdvancedCodecRejectsAmbiguousScalarEncodings(t *testing.T) {
	addressTests := []string{
		"1111111111111111111111111111111111111111",
		"0xA111111111111111111111111111111111111111",
		"0x111111111111111111111111111111111111111",
	}
	for _, value := range addressTests {
		_, err := parseAddress("address", value, false)
		require.ErrorContains(t, err, "canonical lowercase")
	}
	_, err := parseAddress("address", "0x0000000000000000000000000000000000000000", false)
	require.ErrorContains(t, err, "must not be the zero address")

	hexTests := []string{"aabb", "0xAabb", "0xabc", "0xzz"}
	for _, value := range hexTests {
		_, err := parseHex("data", value, -1)
		require.ErrorContains(t, err, "canonical lowercase")
	}
	_, err = parseHex("hash", "0x00", common.HashLength)
	require.ErrorContains(t, err, "exactly 32 bytes")

	uintTests := []string{"", "01", "+1", "-1", "0x1"}
	for _, value := range uintTests {
		_, err := parseUint("value", value, 256, true)
		require.ErrorContains(t, err, "canonical base-10")
	}
	_, err = parseUint("value", new(big.Int).Lsh(big.NewInt(1), 128).String(), 128, true)
	require.ErrorContains(t, err, "outside the uint128 range")
}
