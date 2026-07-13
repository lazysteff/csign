package custody

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type ProvisionedKey struct {
	CustodyMode       string
	PublicKey         *ecdsa.PublicKey
	PublicKeyHex      string
	PrivateKeyHex     string
	ExternalSignerRef string
}

func ProvisionCreateRequest(req v1.CreateKeyRequest) (ProvisionedKey, error) {
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
			CustodyMode:       custodyMode,
			PublicKey:         publicKey,
			PublicKeyHex:      PublicKeyHex(publicKey),
			ExternalSignerRef: req.ExternalSignerRef,
		}, nil
	default:
		return ProvisionedKey{}, fmt.Errorf("unsupported custody mode %q", req.CustodyMode)
	}
}
