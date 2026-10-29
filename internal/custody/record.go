package custody

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const RecordVersion = 2
const Secp256k1Scalar = "secp256k1_scalar"

// CreateKeyType is the isolated adapter for historical EVM/TRON create requests.
// Generic provisioning and runtime scheme resolution never infer type by protocol.
func CreateKeyType(req v1.CreateKeyRequest) (cryptography.KeyType, error) {
	if req.KeyType != "" {
		if cryptography.KeyType(req.KeyType) != cryptography.Secp256k1 && cryptography.KeyType(req.KeyType) != cryptography.Ed25519Key {
			return "", fmt.Errorf("unsupported key type")
		}
		return cryptography.KeyType(req.KeyType), nil
	}
	switch domain.NormalizeChainFamily(req.ChainFamily) {
	case v1.ChainFamilyEVM, v1.ChainFamilyTRON:
		return cryptography.Secp256k1, nil
	}
	return "", fmt.Errorf("key_type is required")
}

// NormalizeRecord validates and maps old records without rewriting storage.
func NormalizeRecord(key domain.Key) (domain.Key, error) {
	key = key.Clone()
	if key.RecordVersion == 0 {
		if key.KeyType != "" || key.MaterialFormat != "" {
			return domain.Key{}, fmt.Errorf("ambiguous legacy key record")
		}
		if key.ChainFamily != v1.ChainFamilyEVM && key.ChainFamily != v1.ChainFamilyTRON {
			return domain.Key{}, fmt.Errorf("unsupported legacy protocol binding")
		}
		key.KeyType = cryptography.Secp256k1
		if key.CustodyMode == "" {
			key.CustodyMode = v1.CustodyModeMVP
		}
		if key.CustodyMode == v1.CustodyModeMVP {
			key.MaterialFormat = Secp256k1Scalar
		}
		key.RecordVersion = RecordVersion
	}
	if key.RecordVersion != RecordVersion {
		return domain.Key{}, fmt.Errorf("unsupported key record version")
	}
	pub, err := CanonicalPublicKey(key)
	if err != nil {
		return domain.Key{}, err
	}
	switch key.CustodyMode {
	case v1.CustodyModeMVP:
		if key.ExternalSignerRef != "" {
			return domain.Key{}, fmt.Errorf("inconsistent managed custody metadata")
		}
		var derived cryptography.PublicKey
		switch key.KeyType {
		case cryptography.Secp256k1:
			if key.MaterialFormat != Secp256k1Scalar {
				return domain.Key{}, fmt.Errorf("invalid material format")
			}
			secret, err := parsePrivateKeyHex(key.PrivateKeyHex)
			if err != nil {
				return domain.Key{}, fmt.Errorf("invalid protected key material")
			}
			derived, err = cryptography.CanonicalSecp256k1(ethcrypto.FromECDSAPub(&secret.PublicKey))
			if err != nil {
				return domain.Key{}, err
			}
		case cryptography.Ed25519Key:
			if key.MaterialFormat != Ed25519Seed {
				return domain.Key{}, fmt.Errorf("invalid material format")
			}
			seed, err := parseEd25519Seed(key.PrivateKeyHex)
			if err != nil || len(seed) != ed25519.SeedSize {
				return domain.Key{}, fmt.Errorf("invalid protected key material")
			}
			derived, err = cryptography.CanonicalEd25519(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
			if err != nil {
				return domain.Key{}, err
			}
			key.PrivateKeyHex = enc.EncodeHex(seed)
		default:
			return domain.Key{}, fmt.Errorf("unsupported key type")
		}
		if !bytes.Equal(pub.Bytes, derived.Bytes) {
			return domain.Key{}, fmt.Errorf("protected key does not match public key")
		}

	case v1.CustodyModePKCS11:
		if key.ExternalSignerRef == "" || key.PrivateKeyHex != "" || key.MaterialFormat != "" {
			return domain.Key{}, fmt.Errorf("inconsistent external custody metadata")
		}
	default:
		return domain.Key{}, fmt.Errorf("unsupported custody mode")
	}
	key.PublicKeyHex = enc.EncodeHex(pub.Bytes)
	return key, nil
}
func CanonicalPublicKey(key domain.Key) (cryptography.PublicKey, error) {
	raw, err := enc.DecodeHex(key.PublicKeyHex)
	if err != nil {
		return cryptography.PublicKey{}, fmt.Errorf("invalid public key encoding")
	}
	return cryptography.Default().PublicKey(key.KeyType, raw)
}
