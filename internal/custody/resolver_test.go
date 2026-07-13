package custody

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
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

func (f fakeExternalResolver) ResolveExternal(ctx context.Context, key domain.Key) (Material, error) {
	return f.fn(ctx, key)
}
