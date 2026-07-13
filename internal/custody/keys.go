package custody

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func PublicKeyHex(pub *ecdsa.PublicKey) string {
	return enc.EncodeHex(ethcrypto.FromECDSAPub(pub))
}

type localMaterial struct {
	privateKey *ecdsa.PrivateKey
}

func (m localMaterial) PublicKey() *ecdsa.PublicKey {
	if m.privateKey == nil {
		return nil
	}
	return &m.privateKey.PublicKey
}

func (m localMaterial) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, fmt.Errorf("local private key is required")
	}
	return ethcrypto.Sign(digest, m.privateKey)
}

func parsePrivateKeyHex(value string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := enc.DecodeHex(value)
	if err != nil {
		return nil, err
	}
	key, err := ethcrypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func parsePublicKeyHex(value string) (*ecdsa.PublicKey, error) {
	pubBytes, err := enc.DecodeHex(value)
	if err != nil {
		return nil, err
	}
	switch len(pubBytes) {
	case 33:
		pub, err := ethcrypto.DecompressPubkey(pubBytes)
		if err != nil {
			return nil, fmt.Errorf("parse compressed public key: %w", err)
		}
		return pub, nil
	case 65:
		pub, err := ethcrypto.UnmarshalPubkey(pubBytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key length %d", len(pubBytes))
	}
}
