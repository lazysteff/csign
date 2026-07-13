package advancedcodec

import (
	"fmt"
	"math"
	"math/big"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestPrepareType4TransactionRecoversAuthorizationAuthority(t *testing.T) {
	privateKey, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	authorization := ethtypes.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(big.NewInt(1)),
		Address: common.HexToAddress(codecContract),
		Nonce:   7,
	}
	hash := authorization.SigHash()
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	require.NoError(t, err)

	input := v1.EIP7702SignedAuthorization{
		EIP7702Authorization: v1.EIP7702Authorization{ChainID: "1", Address: codecContract, Nonce: "7"},
		YParity:              signature[64],
		R:                    fmt.Sprintf("0x%x", signature[:32]),
		S:                    fmt.Sprintf("0x%x", signature[32:64]),
	}
	signed, recovered, err := PrepareSignedAuthorization(v1.EIP7702AuthorizationSchemaV1, input)
	require.NoError(t, err)
	require.Equal(t, crypto.PubkeyToAddress(privateKey.PublicKey), recovered)
	require.Equal(t, authorization.ChainID, signed.ChainID)
	require.Equal(t, authorization.Address, signed.Address)
	require.Equal(t, authorization.Nonce, signed.Nonce)

	transactionInput := v1.EVMEIP7702TransactionSignRequest{
		EIP7702TransactionFields: v1.EIP7702TransactionFields{
			ChainID:              "1",
			Nonce:                "0",
			To:                   codecSpender,
			Value:                "0",
			GasLimit:             "100000",
			MaxFeePerGas:         "100",
			MaxPriorityFeePerGas: "2",
			Data:                 "0x",
			AccessList:           []v1.EVMAccessTuple{},
		},
		SourceAddress:     codecSigner,
		AuthorizationList: []v1.EIP7702SignedAuthorization{input},
	}
	prepared, err := PrepareTransaction(transactionInput)
	require.NoError(t, err)
	require.Equal(t, []common.Address{recovered}, prepared.RecoveredAuthorities)

	malformed := input
	malformed.R = "0x00"
	_, _, err = PrepareSignedAuthorization(v1.EIP7702AuthorizationSchemaV1, malformed)
	require.ErrorContains(t, err, "r must contain exactly 32 bytes")
	require.NotContains(t, err.Error(), "authorization.r")

	transactionInput.AuthorizationList[0] = malformed
	_, err = PrepareTransaction(transactionInput)
	require.ErrorContains(t, err, "authorization_list[0].r must contain exactly 32 bytes")

	transactionInput.AuthorizationList[0] = input
	transactionInput.Nonce = fmt.Sprintf("%d", uint64(math.MaxUint64))
	_, err = PrepareTransaction(transactionInput)
	require.ErrorContains(t, err, "nonce must be less than 2^64-1")
}
