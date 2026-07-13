package eip7702

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationDeterministicVector(t *testing.T) {
	key := authorityKey(t)
	expectedAuthority := ethcrypto.PubkeyToAddress(key.PublicKey)
	authorization := testAuthorization()
	artifact, err := SignAuthorization(context.Background(), deterministicMaterial(key), authorization, AuthorizationOptions{
		ExecutionChainID:  big.NewInt(11155111),
		ExpectedAuthority: &expectedAuthority,
	})
	require.NoError(t, err)

	signature := mustSignature(t, artifact.Authorization)
	require.Equal(t, "0xac68e295c52175a06b4f5b0ff777b36cf078a6fae71db41c3155def8b8add8dc", artifact.SigningHash.Hex())
	require.Equal(t, "54300d550d2e154a8312cf14b32e14c06b643b1d0959dc029ae0f504663e59d317eeddd8802ca584ffed9d3dc6c31860df443acabd1e4108932d404ea6342c3101", common.Bytes2Hex(signature))
	require.Equal(t, "f85d83aa36a79422222222222222222222222222222222222222220701a054300d550d2e154a8312cf14b32e14c06b643b1d0959dc029ae0f504663e59d3a017eeddd8802ca584ffed9d3dc6c31860df443acabd1e4108932d404ea6342c31", common.Bytes2Hex(artifact.Serialized))
	require.Equal(t, expectedAuthority, artifact.Authority)
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(ethcrypto.S256().Params().N), 1)
	require.LessOrEqual(t, artifact.Authorization.S.ToBig().Cmp(halfOrder), 0)

	parsed, recovered, err := ParseAuthorization(artifact.Serialized)
	require.NoError(t, err)
	require.Equal(t, expectedAuthority, recovered)
	require.Equal(t, authorization.ChainID, parsed.ChainID)
	require.Equal(t, authorization.Address, parsed.Address)
	require.Equal(t, authorization.Nonce, parsed.Nonce)
	require.Equal(t, signature, mustSignature(t, parsed))
}

func TestAuthorizationWildcardAndExpectedAuthority(t *testing.T) {
	key := authorityKey(t)
	authority := ethcrypto.PubkeyToAddress(key.PublicKey)
	wildcard := testAuthorization()
	wildcard.ChainID.Clear()

	_, err := SignAuthorization(context.Background(), deterministicMaterial(key), wildcard, AuthorizationOptions{
		ExecutionChainID: big.NewInt(1),
	})
	require.ErrorContains(t, err, "wildcard")

	artifact, err := SignAuthorization(context.Background(), deterministicMaterial(key), wildcard, AuthorizationOptions{
		ExecutionChainID:  big.NewInt(1),
		AllowWildcard:     true,
		ExpectedAuthority: &authority,
	})
	require.NoError(t, err)
	_, err = ValidateSignedAuthorization(artifact.Authorization, AuthorizationOptions{
		ExecutionChainID:  big.NewInt(137),
		AllowWildcard:     true,
		ExpectedAuthority: &authority,
	})
	require.NoError(t, err)

	nonWildcard := testAuthorization()
	_, err = SignAuthorization(context.Background(), deterministicMaterial(key), nonWildcard, AuthorizationOptions{
		ExecutionChainID: big.NewInt(1),
	})
	require.ErrorContains(t, err, "does not match")

	wrongAuthority := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err = SignAuthorization(context.Background(), deterministicMaterial(key), nonWildcard, AuthorizationOptions{
		ExpectedAuthority: &wrongAuthority,
	})
	require.ErrorContains(t, err, "expected authority")
}

func TestAuthorizationCanonicalSignatureHandling(t *testing.T) {
	key := authorityKey(t)
	authority := ethcrypto.PubkeyToAddress(key.PublicKey)
	authorization := testAuthorization()
	hash := authorization.SigHash()
	canonical, err := ethcrypto.Sign(hash[:], key)
	require.NoError(t, err)
	highS := highSSignature(canonical)

	_, err = AssembleAuthorization(authorization, highS, AuthorizationOptions{ExpectedAuthority: &authority})
	require.ErrorContains(t, err, "invalid transaction v, r, s values")

	normalized, err := SignAuthorization(context.Background(), materialReturning(key, highS), authorization, AuthorizationOptions{ExpectedAuthority: &authority})
	require.NoError(t, err)
	require.Equal(t, canonical, mustSignature(t, normalized.Authorization))

	invalidParity := append([]byte(nil), canonical...)
	invalidParity[64] = 2
	_, err = AssembleAuthorization(authorization, invalidParity, AuthorizationOptions{})
	require.ErrorContains(t, err, "parity")

	otherKey := executorKey(t)
	wrongSignature, err := ethcrypto.Sign(hash[:], otherKey)
	require.NoError(t, err)
	wrongMaterial := custody.ExternalMaterial{
		Pub: &key.PublicKey,
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return wrongSignature, nil
		},
	}
	_, err = SignAuthorization(context.Background(), wrongMaterial, authorization, AuthorizationOptions{})
	require.ErrorContains(t, err, "could not determine recovery id")

	for name, encoded := range map[string][]byte{
		"rs":   signatureRS(canonical),
		"asn1": signatureASN1(t, canonical),
		"v27_28": func() []byte {
			encoded := append([]byte(nil), canonical...)
			encoded[64] += 27
			return encoded
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			artifact, err := SignAuthorization(context.Background(), materialReturning(key, encoded), authorization, AuthorizationOptions{ExpectedAuthority: &authority})
			require.NoError(t, err)
			require.Equal(t, canonical, mustSignature(t, artifact.Authorization))
		})
	}
}

func TestAuthorizationRejectsInvalidCustodyResults(t *testing.T) {
	authorization := testAuthorization()
	_, err := SignAuthorization(context.Background(), nil, authorization, AuthorizationOptions{})
	require.ErrorContains(t, err, "signer material")

	_, err = SignAuthorization(context.Background(), custody.ExternalMaterial{
		SignFunc: func(context.Context, []byte) ([]byte, error) { return nil, nil },
	}, authorization, AuthorizationOptions{})
	require.ErrorContains(t, err, "public key")

	key := authorityKey(t)
	_, err = SignAuthorization(context.Background(), custody.ExternalMaterial{
		Pub: &key.PublicKey,
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("hsm unavailable")
		},
	}, authorization, AuthorizationOptions{})
	require.ErrorContains(t, err, "sign digest")

	_, err = SignAuthorization(context.Background(), materialReturning(key, make([]byte, 65)), authorization, AuthorizationOptions{})
	require.ErrorContains(t, err, "out of range")
}

func TestAuthorizationRejectsInvalidBoundsAndSerialization(t *testing.T) {
	valid := testAuthorization()
	_, err := SerializeAuthorization(valid)
	require.ErrorContains(t, err, "authority")

	_, _, err = ParseAuthorization([]byte{0xff})
	require.ErrorContains(t, err, "decode authorization")
}

func mustSignature(t *testing.T, authorization ethtypes.SetCodeAuthorization) []byte {
	t.Helper()
	signature := make([]byte, ethcrypto.SignatureLength)
	authorization.R.WriteToSlice(signature[:32])
	authorization.S.WriteToSlice(signature[32:64])
	signature[ethcrypto.RecoveryIDOffset] = authorization.V
	return signature
}
