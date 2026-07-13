package custody

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"reflect"

	"github.com/chain-signer/chain-signer/internal/domain"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type Material interface {
	PublicKey() *ecdsa.PublicKey
	SignDigest(context.Context, []byte) ([]byte, error)
}

type ExternalResolver interface {
	ResolveExternal(context.Context, domain.Key) (Material, error)
}

type ExternalMaterial struct {
	Pub      *ecdsa.PublicKey
	SignFunc func(context.Context, []byte) ([]byte, error)
}

func (m ExternalMaterial) PublicKey() *ecdsa.PublicKey {
	return m.Pub
}

func (m ExternalMaterial) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	if m.SignFunc == nil {
		return nil, fmt.Errorf("external signer callback is required")
	}
	return m.SignFunc(ctx, digest)
}

// PublicKeyOf returns a validated, immutable secp256k1 public-key snapshot.
// Material implementations may be supplied by external custody integrations,
// so callers must not trust the interface value or retain its mutable key.
func PublicKeyOf(material Material) (canonical *ecdsa.PublicKey, err error) {
	if material == nil || isNil(material) {
		return nil, fmt.Errorf("signer material is required")
	}
	defer func() {
		if recover() != nil {
			canonical = nil
			err = fmt.Errorf("signer public key is not a valid secp256k1 point")
		}
	}()
	publicKey := material.PublicKey()
	if publicKey == nil {
		return nil, fmt.Errorf("signer public key is required")
	}
	encoded := ethcrypto.FromECDSAPub(publicKey)
	if len(encoded) != 65 {
		return nil, fmt.Errorf("signer public key is required")
	}
	canonical, err = ethcrypto.UnmarshalPubkey(encoded)
	if err != nil {
		return nil, fmt.Errorf("signer public key is not a valid secp256k1 point")
	}
	return canonical, nil
}

// Snapshot binds a material implementation to the public key observed at the
// trust boundary. The signer remains external, but subsequent verification
// cannot be redirected by a mutable PublicKey implementation.
func Snapshot(material Material) (Material, error) {
	publicKey, err := PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	return snapshot{material: material, publicKey: ethcrypto.FromECDSAPub(publicKey)}, nil
}

type snapshot struct {
	material  Material
	publicKey []byte
}

func (s snapshot) PublicKey() *ecdsa.PublicKey {
	publicKey, _ := ethcrypto.UnmarshalPubkey(s.publicKey)
	return publicKey
}

func (s snapshot) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	return s.material.SignDigest(ctx, digest)
}

func isNil(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
