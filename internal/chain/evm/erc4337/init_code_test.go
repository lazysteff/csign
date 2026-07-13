package erc4337

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestOfficialV090EIP7702HashVector(t *testing.T) {
	op := UserOperation{
		Sender:               common.HexToAddress("0x4444444444444444444444444444444444444444"),
		Nonce:                big.NewInt(9),
		EIP7702:              &EIP7702Init{Data: common.FromHex("0xdeadbeef")},
		CallData:             common.FromHex("0x12345678"),
		VerificationGasLimit: big.NewInt(150000),
		CallGasLimit:         big.NewInt(90000),
		PreVerificationGas:   big.NewInt(21000),
		MaxPriorityFeePerGas: big.NewInt(1000000000),
		MaxFeePerGas:         big.NewInt(2000000000),
	}
	packed, err := op.Pack()
	require.NoError(t, err)
	require.Equal(t, "0x7702000000000000000000000000000000000000deadbeef", hexBytes(packed.InitCode))
	require.True(t, IsEIP7702InitCode(packed.InitCode))

	_, err = packed.UserOperationHash(EntryPointAddress(), big.NewInt(1), nil)
	require.ErrorContains(t, err, "EIP-7702 delegate is required")

	delegate := common.HexToAddress("0x5555555555555555555555555555555555555555")
	initCodeHash, err := InitCodeHash(packed.InitCode, &delegate)
	require.NoError(t, err)
	require.Equal(t, "0x5cc84ae7d1ee7f95b1ecc7127a6f12085c0d45010f4689bb2759b554e354c008", initCodeHash.Hex())

	encoded, err := packed.EncodeForHash(&delegate)
	require.NoError(t, err)
	require.Equal(t,
		"0x29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e"+
			"0000000000000000000000004444444444444444444444444444444444444444"+
			"0000000000000000000000000000000000000000000000000000000000000009"+
			"5cc84ae7d1ee7f95b1ecc7127a6f12085c0d45010f4689bb2759b554e354c008"+
			"30ca65d5da355227c97ff836c9c6719af9d3835fc6bc72bddc50eeecc1bb2b25"+
			"000000000000000000000000000249f000000000000000000000000000015f90"+
			"0000000000000000000000000000000000000000000000000000000000005208"+
			"0000000000000000000000003b9aca0000000000000000000000000077359400"+
			"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		hexBytes(encoded),
	)
	structHash, err := packed.StructHash(&delegate)
	require.NoError(t, err)
	require.Equal(t, "0xf945d8bb689bb0fb01714ae2e44f5495c652e4fb02d66d3149a83e9f28e35db8", structHash.Hex())
	hash, err := packed.UserOperationHash(EntryPointAddress(), big.NewInt(1), &delegate)
	require.NoError(t, err)
	require.Equal(t, "0x758608eb48a400f57115e93215edff185785cec0ede9aebc60b509fc39225bf0", hash.Hex())
}

func TestEIP7702MarkerDetectionMatchesCalldataPadding(t *testing.T) {
	require.False(t, IsEIP7702InitCode(nil))
	require.False(t, IsEIP7702InitCode([]byte{0x77}))
	require.True(t, IsEIP7702InitCode([]byte{0x77, 0x02}))
	require.True(t, IsEIP7702InitCode([]byte{0x77, 0x02, 0x00}))
	require.False(t, IsEIP7702InitCode([]byte{0x77, 0x02, 0x01}))
	require.True(t, IsEIP7702InitCode(append(append([]byte{0x77, 0x02}, make([]byte, 18)...), 0xff)))

	standard := []byte{0xde, 0xad}
	delegate := common.HexToAddress("0x5555555555555555555555555555555555555555")
	withDelegate, err := InitCodeHash(standard, &delegate)
	require.NoError(t, err)
	require.Equal(t, crypto.Keccak256Hash(standard), withDelegate, "delegate override is ignored for ordinary initCode")
}
