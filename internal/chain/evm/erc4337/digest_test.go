package erc4337

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// This vector was independently generated with ethers v5 from the exact
// EIP-712 types and helpers in eth-infinitism/account-abstraction v0.9.0
// (commit b36a1ed52ae00da6f8a4c8d50181e2877e4fa410).
func TestOfficialV090PackingAndHashVector(t *testing.T) {
	op := standardVectorOperation(nil)
	packed, err := op.Pack()
	require.NoError(t, err)

	require.Equal(t, "0x000000000000000000000000000000140000000000000000000000000000000a", packed.AccountGasLimits.Hex())
	require.Equal(t, "0x0000000000000000000000000000003200000000000000000000000000000028", packed.GasFees.Hex())
	require.Equal(t,
		"0x2222222222222222222222222222222222222222deadbeef",
		hexBytes(packed.InitCode),
	)
	require.Equal(t,
		"0x33333333333333333333333333333333333333330000000000000000000000000000003c00000000000000000000000000000046cafe",
		hexBytes(packed.PaymasterAndData),
	)
	require.Equal(t, "0x29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e", PackedUserOperationTypeHash().Hex())

	encoded, err := packed.EncodeForHash(nil)
	require.NoError(t, err)
	require.Equal(t,
		"0x29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e"+
			"0000000000000000000000001111111111111111111111111111111111111111"+
			"000000000000000000000000000000000000000000000000000000000000007b"+
			"90f4a2cfb8d428caaaa670c7fc276741ccd54a408f5a7a0977e3d61b23210622"+
			"d287dd697a3e3c4d476f6ced9981149a577c1419d5793ede4fafefaf9bb6203f"+
			"000000000000000000000000000000140000000000000000000000000000000a"+
			"000000000000000000000000000000000000000000000000000000000000001e"+
			"0000000000000000000000000000003200000000000000000000000000000028"+
			"217900ddab6b29a6070180866c80bae63360b19b67aa8f62d2bddd9f5b56f55a",
		hexBytes(encoded),
	)

	structHash, err := packed.StructHash(nil)
	require.NoError(t, err)
	require.Equal(t, "0x70ce8918d70ba053d29c8785125846e0e6a671fe41f6d1c548bea11fe6681946", structHash.Hex())

	domain, err := DomainSeparator(EntryPointAddress(), big.NewInt(1))
	require.NoError(t, err)
	require.Equal(t, "0xc3770890383ef71feb6849938be9093ba0de335ab68635a794748275c616d521", domain.Hex())

	hash, err := packed.UserOperationHash(EntryPointAddress(), big.NewInt(1), nil)
	require.NoError(t, err)
	require.Equal(t, "0x5566644b8a0a191eb7572ce132ac3dbdbe4f0784fcc21d03280771bd1f007a03", hash.Hex())

	digest, err := op.SimpleAccountSigningDigest(EntryPointAddress(), big.NewInt(1), nil)
	require.NoError(t, err)
	require.Equal(t, hash, digest)
}
