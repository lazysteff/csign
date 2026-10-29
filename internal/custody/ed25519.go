package custody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

const Ed25519Seed = "ed25519_seed"

var ed25519Capability = cryptography.Capability{Scheme: cryptography.Ed25519Scheme, Input: cryptography.Message}

func parseEd25519Seed(value string) ([]byte, error) {
	raw, err := enc.DecodeHex(value)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 private material encoding")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return raw, nil
	case ed25519.PrivateKeySize:
		private := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(private[ed25519.SeedSize:], raw[ed25519.SeedSize:]) {
			return nil, fmt.Errorf("Ed25519 public-key suffix does not match seed")
		}
		return append([]byte(nil), raw[:ed25519.SeedSize]...), nil
	default:
		return nil, fmt.Errorf("Ed25519 private material must contain 32 or 64 bytes")
	}
}
func provisionEd25519(req v1.CreateKeyRequest) (ProvisionedKey, error) {
	mode := domain.NormalizeCustodyMode(req.CustodyMode)
	if mode != "" && mode != v1.CustodyModeMVP {
		return ProvisionedKey{}, fmt.Errorf("Ed25519 managed keys require managed custody")
	}
	var private ed25519.PrivateKey
	if req.ImportPrivateKey != "" {
		seed, err := parseEd25519Seed(req.ImportPrivateKey)
		if err != nil {
			return ProvisionedKey{}, err
		}
		private = ed25519.NewKeyFromSeed(seed)
	} else {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return ProvisionedKey{}, fmt.Errorf("key generation failed")
		}
		private = generated
	}
	pub, err := cryptography.CanonicalEd25519(private.Public().(ed25519.PublicKey))
	if err != nil {
		return ProvisionedKey{}, err
	}
	return ProvisionedKey{KeyType: cryptography.Ed25519Key, CanonicalPublic: pub, CustodyMode: v1.CustodyModeMVP, MaterialFormat: Ed25519Seed, PublicKeyHex: enc.EncodeHex(pub.Bytes), PrivateKeyHex: enc.EncodeHex(private.Seed())}, nil
}

type ed25519Material struct{ private ed25519.PrivateKey }

func (m ed25519Material) CanonicalPublicKey() (cryptography.PublicKey, error) {
	if len(m.private) != ed25519.PrivateKeySize {
		return cryptography.PublicKey{}, fmt.Errorf("invalid managed Ed25519 material")
	}
	return cryptography.CanonicalEd25519(m.private.Public().(ed25519.PublicKey))
}
func (m ed25519Material) Sign(_ context.Context, c cryptography.Capability, p cryptography.Payload) ([]byte, error) {
	if c != ed25519Capability || p.Kind() != cryptography.Message || len(m.private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unsupported custody capability")
	}
	return ed25519.Sign(m.private, p.Bytes()), nil
}
