package v1

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeTRONMemoHexPreservesBytes(t *testing.T) {
	t.Parallel()

	want := append([]byte("Zażółć 🛰️"), 0x00, 0xff)
	decoded, err := DecodeTRONMemoHex("0x" + hex.EncodeToString(want))
	require.NoError(t, err)
	require.Equal(t, want, decoded)

	empty, err := DecodeTRONMemoHex("")
	require.NoError(t, err)
	require.Nil(t, empty)
}

func TestDecodeTRONMemoHexRejectsInvalidAndExcessiveValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"0", "0x0", "zz"} {
		_, err := DecodeTRONMemoHex(value)
		require.ErrorContains(t, err, "memo_hex", value)
	}

	_, err := DecodeTRONMemoHex(strings.Repeat("00", TRONMaxTransactionBytes+1))
	require.ErrorContains(t, err, "exceeding")
}
