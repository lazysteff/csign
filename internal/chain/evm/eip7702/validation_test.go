package eip7702

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestType4TransactionValidation(t *testing.T) {
	t.Run("empty authorization list", func(t *testing.T) {
		transaction, _ := validTransaction(t)
		transaction.AuthList = nil
		_, err := BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "must not be empty")
	})

	t.Run("chain bounds", func(t *testing.T) {
		transaction, _ := validTransaction(t)
		transaction.ChainID.Clear()
		_, err := BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "positive")

		transaction.ChainID = nil
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "positive")
	})

	t.Run("fee value and gas bounds", func(t *testing.T) {
		transaction, _ := validTransaction(t)
		transaction.Gas = 0
		_, err := BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "gas_limit")

		transaction, _ = validTransaction(t)
		transaction.GasTipCap = uint256.MustFromBig(new(big.Int).Add(transaction.GasFeeCap.ToBig(), big.NewInt(1)))
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "exceeds")

		transaction, _ = validTransaction(t)
		transaction.GasFeeCap = nil
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "required")

		transaction, _ = validTransaction(t)
		transaction.Value = nil
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "value is required")
	})

	t.Run("configured authorization bounds", func(t *testing.T) {
		transaction, authority := validTransaction(t)
		_, err := BuildTransaction(transaction, TransactionOptions{MaxAuthorizationListEntries: -1})
		require.ErrorContains(t, err, "must not be negative")

		_, err = BuildTransaction(transaction, TransactionOptions{MaxAuthorizationListEntries: 0})
		require.NoError(t, err)

		_, err = BuildTransaction(transaction, TransactionOptions{ExpectedAuthorities: []common.Address{authority, authority}})
		require.ErrorContains(t, err, "count")

		transaction.AuthList = append(transaction.AuthList, transaction.AuthList[0])
		_, err = BuildTransaction(transaction, TransactionOptions{MaxAuthorizationListEntries: 1})
		require.ErrorContains(t, err, "maximum")
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "duplicates")

		conflicting := testAuthorization()
		conflicting.Nonce++
		conflictArtifact, err := SignAuthorization(context.Background(), deterministicMaterial(authorityKey(t)), conflicting, AuthorizationOptions{ExpectedAuthority: &authority})
		require.NoError(t, err)
		transaction.AuthList = []ethtypes.SetCodeAuthorization{transaction.AuthList[0], conflictArtifact.Authorization}
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "duplicates or conflicts")
	})

	t.Run("authorization chain context", func(t *testing.T) {
		transaction, _ := validTransaction(t)
		mismatched, _ := signedAuthorizationForChain(t, big.NewInt(1), false)
		transaction.AuthList = []ethtypes.SetCodeAuthorization{mismatched}
		_, err := BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "does not match")

		wildcard, _ := signedAuthorizationForChain(t, new(big.Int), true)
		transaction.AuthList = []ethtypes.SetCodeAuthorization{wildcard}
		_, err = BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "wildcard")
		_, err = BuildTransaction(transaction, TransactionOptions{AllowWildcardAuthorizations: true})
		require.NoError(t, err)
	})

	t.Run("high-s authorization", func(t *testing.T) {
		transaction, _ := validTransaction(t)
		authorization := transaction.AuthList[0]
		authorization.S = *uint256.MustFromBig(new(big.Int).Sub(ethcrypto.S256().Params().N, authorization.S.ToBig()))
		authorization.V ^= 1
		transaction.AuthList = []ethtypes.SetCodeAuthorization{authorization}
		_, err := BuildTransaction(transaction, TransactionOptions{})
		require.ErrorContains(t, err, "invalid transaction v, r, s values")
	})
}
