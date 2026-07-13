package eip7702

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestType4TransactionRecoveryRejectsMismatchesAndOtherTypes(t *testing.T) {
	transaction, authority := validTransaction(t)
	executor := executorKey(t)
	executorAddress := ethcrypto.PubkeyToAddress(executor.PublicKey)
	artifact, err := SignTransaction(context.Background(), deterministicMaterial(executor), transaction, TransactionOptions{
		ExpectedAuthorities: []common.Address{authority},
		ExpectedSigner:      &executorAddress,
	})
	require.NoError(t, err)

	wrongSigner := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err = RecoverTransaction(artifact.SignedPayload, TransactionOptions{ExpectedSigner: &wrongSigner})
	require.ErrorContains(t, err, "expected signer")

	wrongAuthority := common.HexToAddress("0x3333333333333333333333333333333333333333")
	_, err = RecoverTransaction(artifact.SignedPayload, TransactionOptions{ExpectedAuthorities: []common.Address{wrongAuthority}})
	require.ErrorContains(t, err, "expected authority")

	dynamic := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
		ChainID:   big.NewInt(1),
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       21000,
		Value:     new(big.Int),
	})
	dynamicPayload, err := dynamic.MarshalBinary()
	require.NoError(t, err)
	_, err = RecoverTransaction(dynamicPayload, TransactionOptions{})
	require.ErrorContains(t, err, "not EIP-7702")

	_, err = RecoverTransaction([]byte{TransactionType, 0xff}, TransactionOptions{})
	require.ErrorContains(t, err, "decode")
}
