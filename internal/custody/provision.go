package custody

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type ProvisionedKey struct {
	KeyType           cryptography.KeyType
	CanonicalPublic   cryptography.PublicKey
	MaterialFormat    string
	CustodyMode       string
	PublicKey         *ecdsa.PublicKey
	PublicKeyHex      string
	PrivateKeyHex     string
	ExternalSignerRef string
}

func provisionSecp256k1(req v1.CreateKeyRequest) (ProvisionedKey, error) {
	custodyMode := domain.NormalizeCustodyMode(req.CustodyMode)
	if custodyMode == "" {
		custodyMode = v1.CustodyModeMVP
	}

	switch custodyMode {
	case v1.CustodyModeMVP:
		if strings.TrimSpace(req.ImportPrivateKey) != "" {
			privateKey, err := parsePrivateKeyHex(req.ImportPrivateKey)
			if err != nil {
				return ProvisionedKey{}, err
			}
			return ProvisionedKey{
				KeyType: cryptography.Secp256k1, MaterialFormat: Secp256k1Scalar,
				CustodyMode:   custodyMode,
				PublicKey:     &privateKey.PublicKey,
				PublicKeyHex:  PublicKeyHex(&privateKey.PublicKey),
				PrivateKeyHex: enc.EncodeHex(ethcrypto.FromECDSA(privateKey)),
			}, nil
		}

		privateKey, err := ethcrypto.GenerateKey()
		if err != nil {
			return ProvisionedKey{}, err
		}
		return ProvisionedKey{
			KeyType: cryptography.Secp256k1, MaterialFormat: Secp256k1Scalar,
			CustodyMode:   custodyMode,
			PublicKey:     &privateKey.PublicKey,
			PublicKeyHex:  PublicKeyHex(&privateKey.PublicKey),
			PrivateKeyHex: enc.EncodeHex(ethcrypto.FromECDSA(privateKey)),
		}, nil
	case v1.CustodyModePKCS11:
		publicKey, err := parsePublicKeyHex(req.PublicKeyHex)
		if err != nil {
			return ProvisionedKey{}, err
		}
		return ProvisionedKey{
			KeyType:           cryptography.Secp256k1,
			CustodyMode:       custodyMode,
			PublicKey:         publicKey,
			PublicKeyHex:      PublicKeyHex(publicKey),
			ExternalSignerRef: req.ExternalSignerRef,
		}, nil
	default:
		return ProvisionedKey{}, fmt.Errorf("unsupported custody mode %q", req.CustodyMode)
	}
}

func ProvisionCreateRequest(req v1.CreateKeyRequest) (ProvisionedKey, error) {
	keyType, err := CreateKeyType(req)
	if err != nil {
		return ProvisionedKey{}, err
	}
	mode := domain.NormalizeCustodyMode(req.CustodyMode)
	if req.KeyType != "" && (mode == "" || mode == v1.CustodyModeMVP) && req.PublicKeyHex != "" {
		return ProvisionedKey{}, fmt.Errorf("public_key_hex is only valid for external custody when key_type is explicit")
	}
	if keyType == cryptography.Ed25519Key {
		return provisionEd25519(req)
	}
	p, err := provisionSecp256k1(req)
	if err != nil {
		return ProvisionedKey{}, err
	}
	canonical, err := cryptography.CanonicalSecp256k1(ethcrypto.FromECDSAPub(p.PublicKey))
	if err != nil {
		return ProvisionedKey{}, err
	}
	p.CanonicalPublic = canonical
	p.PublicKeyHex = enc.EncodeHex(canonical.Bytes)
	return p, nil
}
