package custody

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func RecoverableSignature(ctx context.Context, material Material, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("sign digest: expected 32 bytes, got %d", len(digest))
	}
	publicKey, err := PublicKeyOf(material)
	if err != nil {
		return nil, fmt.Errorf("sign digest: %w", err)
	}
	canonicalDigest := append([]byte(nil), digest...)
	rawSig, err := material.SignDigest(ctx, append([]byte(nil), canonicalDigest...))
	if err != nil {
		return nil, fmt.Errorf("sign digest: %w", err)
	}
	pub, err := cryptography.CanonicalSecp256k1(ethcrypto.FromECDSAPub(publicKey))
	if err != nil {
		return nil, err
	}
	return cryptography.Default().Verify(ecdsaCapability, pub, cryptography.NewPayload(cryptography.Digest, canonicalDigest), rawSig)
}

func RecoverAddressFromDigest(deriveAddress func(*ecdsa.PublicKey) string, digest []byte, signature []byte) (string, error) {
	if deriveAddress == nil {
		return "", fmt.Errorf("recover public key: address derivation is required")
	}
	if len(digest) != 32 {
		return "", fmt.Errorf("recover public key: expected 32-byte digest")
	}
	if len(signature) != ethcrypto.SignatureLength || (signature[64] != 0 && signature[64] != 1) {
		return "", fmt.Errorf("recover public key: invalid recoverable signature")
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	if !ethcrypto.ValidateSignatureValues(signature[64], r, s, true) {
		return "", fmt.Errorf("recover public key: invalid signature values")
	}
	pub, err := ethcrypto.SigToPub(digest, signature)
	if err != nil {
		return "", fmt.Errorf("recover public key: %w", err)
	}
	return deriveAddress(pub), nil
}

func samePublicKey(left, right *ecdsa.PublicKey) bool {
	if left == nil || right == nil {
		return false
	}
	return bytes.Equal(ethcrypto.FromECDSAPub(left), ethcrypto.FromECDSAPub(right))
}
