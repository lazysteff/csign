package eip7702

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestType4TransactionDeterministicVector(t *testing.T) {
	transaction, authority := validTransaction(t)
	executor := executorKey(t)
	expectedSigner := ethcrypto.PubkeyToAddress(executor.PublicKey)
	options := TransactionOptions{
		ExpectedAuthorities:         []common.Address{authority},
		ExpectedSigner:              &expectedSigner,
		MaxAuthorizationListEntries: 4,
	}

	artifact, err := SignTransaction(context.Background(), deterministicMaterial(executor), transaction, options)
	require.NoError(t, err)
	reconstructedHash, err := TransactionSigningHash(transaction, options)
	require.NoError(t, err)
	require.Equal(t, artifact.SigningHash, reconstructedHash)
	require.Equal(t, uint8(TransactionType), artifact.Transaction.Type())
	require.Equal(t, "0xed774ab55e01008aaefadd95147311120232f54c331cbfce6ca47beca81e17c5", artifact.SigningHash.Hex())
	require.Equal(t, "0xc254cef403da0f2de976c79498d76ae9e322001c4ff336ba157ecc1e0d2b041b", artifact.TransactionHash.Hex())
	require.Equal(t, "04f9013183aa36a709843b9aca008477359400830186a094333333333333333333333333333333333333333382303984deadbeeff85bf859944444444444444444444444444444444444444444f842a00000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000002f85ff85d83aa36a79422222222222222222222222222222222222222220701a054300d550d2e154a8312cf14b32e14c06b643b1d0959dc029ae0f504663e59d3a017eeddd8802ca584ffed9d3dc6c31860df443acabd1e4108932d404ea6342c3101a020deab2bbb71b4e0d446ab0459265e6e3e680adca7c08ccf4d3c50924476be6aa01bb1f6458df60cb2130d54b03e285eec411dd5ad2270538eb5edc9873734bcd8", common.Bytes2Hex(artifact.SignedPayload))
	require.Equal(t, expectedSigner, artifact.Signer)
	require.Equal(t, []common.Address{authority}, artifact.Authorities)
	require.Equal(t, transaction.AccessList, artifact.Transaction.AccessList())
	require.Equal(t, transaction.AuthList[0].Address, artifact.Transaction.SetCodeAuthorizations()[0].Address)
	require.Equal(t, byte(TransactionType), artifact.SignedPayload[0])

	recovered, err := RecoverTransaction(artifact.SignedPayload, options)
	require.NoError(t, err)
	require.Equal(t, artifact.SigningHash, recovered.SigningHash)
	require.Equal(t, artifact.TransactionHash, recovered.TransactionHash)
	require.Equal(t, artifact.Signer, recovered.Signer)
	require.Equal(t, artifact.SignedPayload, recovered.SignedPayload)

	serialized, err := SerializeTransaction(artifact.Transaction)
	require.NoError(t, err)
	require.Equal(t, artifact.SignedPayload, serialized)
	_, err = SerializeTransaction(nil)
	require.ErrorContains(t, err, "required")
}
