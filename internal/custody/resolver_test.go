package custody

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestResolverMaterialForKey(t *testing.T) {
	resolver := Resolver{}
	material, err := resolver.MaterialForKey(context.Background(), domain.Key{
		ID:            "mvp",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: testPrivHex,
	})
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

	_, err = resolver.MaterialForKey(context.Background(), domain.Key{ID: "pkcs11", CustodyMode: v1.CustodyModePKCS11})
	require.ErrorContains(t, err, "no external signer resolver")
}

type fakeExternalResolver struct {
	fn func(context.Context, domain.Key) (Material, error)
}

func TestGeneralizedResolverPreservesLegacyExternalPublicKeyEncoding(t *testing.T) {
	private := mustPrivateKey(t)
	compressed := enc.EncodeHex(ethcrypto.CompressPubkey(&private.PublicKey))
	key := domain.Key{ID: "external", RecordVersion: RecordVersion, KeyType: cryptography.Secp256k1, CustodyMode: v1.CustodyModePKCS11, PublicKeyHex: compressed, ExternalSignerRef: "original-ref", Labels: map[string]string{"owner": "original"}}
	before := key.Clone()
	resolver := Resolver{External: fakeExternalResolver{fn: func(_ context.Context, received domain.Key) (Material, error) {
		expected := before.Clone()
		expected.PublicKeyHex = PublicKeyHex(&private.PublicKey)
		require.Equal(t, expected, received)
		received.Labels["owner"] = "mutated by external resolver"
		return ExternalMaterial{Pub: &private.PublicKey}, nil
	}}}
	material, err := resolver.ResolveSigningMaterial(context.Background(), key)
	require.NoError(t, err)
	pub, err := material.CanonicalPublicKey()
	require.NoError(t, err)
	require.Equal(t, compressed, enc.EncodeHex(pub.Bytes))
	require.Equal(t, before, key)
}

func (f fakeExternalResolver) ResolveExternal(ctx context.Context, key domain.Key) (Material, error) {
	return f.fn(ctx, key)
}
