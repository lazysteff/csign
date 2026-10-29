package custody

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// SigningMaterial is the protocol-neutral custody boundary. Legacy Material
// remains an adapter surface for existing secp256k1 external integrations.
type SigningMaterial interface {
	CanonicalPublicKey() (cryptography.PublicKey, error)
	Sign(context.Context, cryptography.Capability, cryptography.Payload) ([]byte, error)
}
type CapabilityDescriber interface {
	DescribeCapabilities(context.Context, domain.Key) ([]cryptography.Capability, error)
}

var ecdsaCapability = cryptography.Capability{Scheme: cryptography.ECDSASecp256k1, Input: cryptography.Digest}

func (r Resolver) DescribeCapabilities(ctx context.Context, key domain.Key) ([]cryptography.Capability, error) {
	switch key.CustodyMode {
	case "", "mvp":
		return []cryptography.Capability{ecdsaCapability, ed25519Capability}, nil
	case "pkcs11":
		if r.External == nil {
			return nil, fmt.Errorf("external custody unavailable")
		}
		if d, ok := r.External.(CapabilityDescriber); ok {
			reported, err := d.DescribeCapabilities(ctx, key)
			if err != nil {
				return nil, err
			}
			for _, c := range reported {
				if c == ecdsaCapability {
					return []cryptography.Capability{ecdsaCapability}, nil
				}
			}
			return nil, nil
		}
		// The historical ExternalResolver contract can only execute ECDSA digests.
		return []cryptography.Capability{ecdsaCapability}, nil
	default:
		return nil, fmt.Errorf("unsupported custody mode")
	}
}
func (r Resolver) ResolveSigningMaterial(ctx context.Context, key domain.Key) (SigningMaterial, error) {
	if key.KeyType == cryptography.Ed25519Key {
		if key.CustodyMode != v1.CustodyModeMVP {
			return nil, fmt.Errorf("unsupported Ed25519 custody")
		}
		seed, err := parseEd25519Seed(key.PrivateKeyHex)
		if err != nil {
			return nil, err
		}
		return ed25519Material{private: ed25519.NewKeyFromSeed(seed)}, nil
	}
	m, err := r.MaterialForKey(ctx, key)
	if err != nil {
		return nil, err
	}
	return AdaptLegacy(m)
}
func AdaptLegacy(m Material) (SigningMaterial, error) {
	pub, err := PublicKeyOf(m)
	if err != nil {
		return nil, err
	}
	canonical, err := cryptography.CanonicalSecp256k1(ethcrypto.FromECDSAPub(pub))
	if err != nil {
		return nil, err
	}
	return legacySigningMaterial{material: m, public: canonical}, nil
}

type legacySigningMaterial struct {
	material Material
	public   cryptography.PublicKey
}

func (m legacySigningMaterial) CanonicalPublicKey() (cryptography.PublicKey, error) {
	return m.public.Clone(), nil
}
func (m legacySigningMaterial) Sign(ctx context.Context, c cryptography.Capability, p cryptography.Payload) ([]byte, error) {
	if c != ecdsaCapability || p.Kind() != cryptography.Digest || len(p.Bytes()) != 32 {
		return nil, fmt.Errorf("unsupported custody capability")
	}
	return m.material.SignDigest(ctx, p.Bytes())
}

// ExecutePreparedECDSA keeps package-level protocol helpers compatible while
// production service execution uses the same registry verification boundary.
func ExecutePreparedECDSA(ctx context.Context, m Material, p *cryptography.Prepared) (any, error) {
	adapted, err := AdaptLegacy(m)
	if err != nil {
		return nil, err
	}
	raw, err := adapted.Sign(ctx, ecdsaCapability, p.Payload)
	if err != nil {
		return nil, fmt.Errorf("sign digest: %w", err)
	}
	pub, err := adapted.CanonicalPublicKey()
	if err != nil {
		return nil, err
	}
	sig, err := cryptography.Default().Verify(ecdsaCapability, pub, p.Payload, raw)
	if err != nil {
		return nil, err
	}
	return p.Format(sig)
}
