package eip7702

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

const authorityPrivateKeyHex = "4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"

func authorityKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ethcrypto.HexToECDSA(authorityPrivateKeyHex)
	require.NoError(t, err)
	return key
}

func executorKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ethcrypto.HexToECDSA(strings.Repeat("0", 63) + "2")
	require.NoError(t, err)
	return key
}

func deterministicMaterial(key *ecdsa.PrivateKey) custody.Material {
	return custody.ExternalMaterial{
		Pub: &key.PublicKey,
		SignFunc: func(_ context.Context, digest []byte) ([]byte, error) {
			return ethcrypto.Sign(digest, key)
		},
	}
}

func materialReturning(key *ecdsa.PrivateKey, signature []byte) custody.Material {
	return custody.ExternalMaterial{
		Pub: &key.PublicKey,
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return append([]byte(nil), signature...), nil
		},
	}
}

func testAuthorization() ethtypes.SetCodeAuthorization {
	return ethtypes.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(big.NewInt(11155111)),
		Address: common.HexToAddress("0x2222222222222222222222222222222222222222"),
		Nonce:   7,
	}
}

func validTransaction(t *testing.T) (*ethtypes.SetCodeTx, common.Address) {
	t.Helper()
	authorization, authority := signedAuthorizationForChain(t, big.NewInt(11155111), false)
	return &ethtypes.SetCodeTx{
		ChainID:   uint256.MustFromBig(big.NewInt(11155111)),
		Nonce:     9,
		GasTipCap: uint256.MustFromBig(big.NewInt(1_000_000_000)),
		GasFeeCap: uint256.MustFromBig(big.NewInt(2_000_000_000)),
		Gas:       100_000,
		To:        common.HexToAddress("0x3333333333333333333333333333333333333333"),
		Value:     uint256.MustFromBig(big.NewInt(12_345)),
		Data:      common.FromHex("0xdeadbeef"),
		AccessList: ethtypes.AccessList{{
			Address: common.HexToAddress("0x4444444444444444444444444444444444444444"),
			StorageKeys: []common.Hash{
				common.HexToHash("0x01"),
				common.HexToHash("0x02"),
			},
		}},
		AuthList: []ethtypes.SetCodeAuthorization{authorization},
	}, authority
}

func signedAuthorizationForChain(t *testing.T, chainID *big.Int, allowWildcard bool) (ethtypes.SetCodeAuthorization, common.Address) {
	t.Helper()
	key := authorityKey(t)
	authority := ethcrypto.PubkeyToAddress(key.PublicKey)
	authorization := testAuthorization()
	authorization.ChainID = *uint256.MustFromBig(chainID)
	artifact, err := SignAuthorization(context.Background(), deterministicMaterial(key), authorization, AuthorizationOptions{
		AllowWildcard:     allowWildcard,
		ExpectedAuthority: &authority,
	})
	require.NoError(t, err)
	return artifact.Authorization, authority
}

func highSSignature(signature []byte) []byte {
	out := append([]byte(nil), signature...)
	s := new(big.Int).SetBytes(out[32:64])
	s.Sub(ethcrypto.S256().Params().N, s).FillBytes(out[32:64])
	out[64] ^= 1
	return out
}

func signatureRS(signature []byte) []byte {
	return append([]byte(nil), signature[:64]...)
}

func signatureASN1(t *testing.T, signature []byte) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
		R: new(big.Int).SetBytes(signature[:32]),
		S: new(big.Int).SetBytes(signature[32:64]),
	})
	require.NoError(t, err)
	return encoded
}
