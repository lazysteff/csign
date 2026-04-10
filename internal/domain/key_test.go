package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeHelpers(t *testing.T) {
	require.Equal(t, "evm", NormalizeChainFamily(" EVM "))
	require.Equal(t, "pkcs11", NormalizeCustodyMode(" PKCS11 "))
	require.Equal(t, "a9059cbb", NormalizeSelector(" 0xA9059CBB "))
}

func TestGenerateKeyID(t *testing.T) {
	first, err := GenerateKeyID()
	require.NoError(t, err)
	second, err := GenerateKeyID()
	require.NoError(t, err)

	require.NotEqual(t, first, second)
	require.Len(t, first, len(DefaultGeneratedKeyIDPrefix)+16)
	require.Contains(t, first, DefaultGeneratedKeyIDPrefix)
}
