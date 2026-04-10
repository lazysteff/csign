package custody

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

const testPrivHex = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"

func TestProvisionCreateRequest(t *testing.T) {
	provisioned, err := ProvisionCreateRequest(v1.CreateKeyRequest{
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
	})
	require.NoError(t, err)
	require.Equal(t, v1.CustodyModeMVP, provisioned.CustodyMode)
	require.NotEmpty(t, provisioned.PrivateKeyHex)
	require.NotNil(t, provisioned.PublicKey)

	generated, err := ProvisionCreateRequest(v1.CreateKeyRequest{
		ChainFamily: v1.ChainFamilyEVM,
	})
	require.NoError(t, err)
	require.Equal(t, v1.CustodyModeMVP, generated.CustodyMode)
	require.NotEmpty(t, generated.PrivateKeyHex)

	privateKey := mustPrivateKey(t)
	publicKeyHex := PublicKeyHex(&privateKey.PublicKey)
	external, err := ProvisionCreateRequest(v1.CreateKeyRequest{
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      publicKeyHex,
		ExternalSignerRef: "hsm-1",
	})
	require.NoError(t, err)
	require.Equal(t, v1.CustodyModePKCS11, external.CustodyMode)
	require.Equal(t, "hsm-1", external.ExternalSignerRef)
	require.Empty(t, external.PrivateKeyHex)

	_, err = ProvisionCreateRequest(v1.CreateKeyRequest{
		CustodyMode: "unknown",
	})
	require.ErrorContains(t, err, "unsupported custody mode")
}

func TestResolverMaterialForKey(t *testing.T) {
	resolver := Resolver{}
	key := domain.Key{
		ID:            "mvp",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: testPrivHex,
	}
	material, err := resolver.MaterialForKey(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, material.PublicKey())

	externalResolver := Resolver{
		External: fakeExternalResolver{
			fn: func(context.Context, domain.Key) (Material, error) {
				return ExternalMaterial{Pub: mustPrivateKey(t).Public().(*ecdsa.PublicKey), SignFunc: func(context.Context, []byte) ([]byte, error) {
					return make([]byte, 65), nil
				}}, nil
			},
		},
	}
	_, err = externalResolver.MaterialForKey(context.Background(), domain.Key{
		ID:                "pkcs11",
		CustodyMode:       v1.CustodyModePKCS11,
		ExternalSignerRef: "hsm-1",
	})
	require.NoError(t, err)

	_, err = resolver.MaterialForKey(context.Background(), domain.Key{
		ID:          "pkcs11",
		CustodyMode: v1.CustodyModePKCS11,
	})
	require.ErrorContains(t, err, "no external signer resolver")
}

func TestRecoverableSignatureAndRecoverAddress(t *testing.T) {
	privateKey := mustPrivateKey(t)
	digest := ethcrypto.Keccak256([]byte("hello"))
	address := ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	sig65, err := RecoverableSignature(context.Background(), localMaterial{privateKey: privateKey}, digest)
	require.NoError(t, err)
	require.Len(t, sig65, 65)
	recovered, err := RecoverAddressFromDigest(func(pub *ecdsa.PublicKey) string {
		return ethcrypto.PubkeyToAddress(*pub).Hex()
	}, digest, sig65)
	require.NoError(t, err)
	require.Equal(t, address, recovered)

	sig64, err := signRS(privateKey, digest)
	require.NoError(t, err)
	sig, err := RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: privateKey.Public().(*ecdsa.PublicKey),
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return sig64, nil
		},
	}, digest)
	require.NoError(t, err)
	require.Len(t, sig, 65)

	asn1Sig, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	require.NoError(t, err)
	sig, err = RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: privateKey.Public().(*ecdsa.PublicKey),
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return asn1Sig, nil
		},
	}, digest)
	require.NoError(t, err)
	require.Len(t, sig, 65)
}

func TestParsePublicKeyHexAndDecodeSignatureErrors(t *testing.T) {
	privateKey := mustPrivateKey(t)
	uncompressed := PublicKeyHex(&privateKey.PublicKey)
	parsed, err := parsePublicKeyHex(uncompressed)
	require.NoError(t, err)
	require.True(t, samePublicKey(&privateKey.PublicKey, parsed))

	compressed := enc.EncodeHex(ethcrypto.CompressPubkey(&privateKey.PublicKey))
	parsed, err = parsePublicKeyHex(compressed)
	require.NoError(t, err)
	require.True(t, samePublicKey(&privateKey.PublicKey, parsed))

	_, _, err = decodeSignature([]byte("bad"))
	require.ErrorContains(t, err, "unsupported format")
}

func TestNormalizeLowSAndSignatureBytes(t *testing.T) {
	curveOrder := ethcrypto.S256().Params().N
	s := new(big.Int).Sub(curveOrder, big.NewInt(1))
	normalized := normalizeLowS(s)
	require.True(t, normalized.Cmp(s) < 0)

	out := signatureBytes(big.NewInt(1), big.NewInt(2))
	require.Len(t, out, 64)
}

type fakeExternalResolver struct {
	fn func(context.Context, domain.Key) (Material, error)
}

func (f fakeExternalResolver) ResolveExternal(ctx context.Context, key domain.Key) (Material, error) {
	return f.fn(ctx, key)
}

func mustPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	keyBytes, err := enc.DecodeHex(testPrivHex)
	require.NoError(t, err)
	key, err := ethcrypto.ToECDSA(keyBytes)
	require.NoError(t, err)
	return key
}

func signRS(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out, nil
}
