package custody

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"

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
	r, s, err := decodeSignature(rawSig)
	if err != nil {
		return nil, err
	}
	if err := validateSignatureScalars(r, s); err != nil {
		return nil, err
	}
	return recoverableFromRS(publicKey, canonicalDigest, r, s)
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

func recoverableFromRS(pub *ecdsa.PublicKey, digest []byte, r, s *big.Int) ([]byte, error) {
	r = new(big.Int).Set(r)
	s = new(big.Int).Set(s)

	rs := signatureBytes(r, normalizeLowS(s))
	for v := byte(0); v <= 1; v++ {
		sig := append(append([]byte(nil), rs...), v)
		recovered, err := ethcrypto.SigToPub(digest, sig)
		if err != nil {
			continue
		}
		if samePublicKey(recovered, pub) {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("could not determine recovery id for signature")
}

func decodeSignature(sig []byte) (*big.Int, *big.Int, error) {
	switch len(sig) {
	case 64:
		return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), nil
	case 65:
		return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), nil
	default:
		var parsed struct {
			R *big.Int
			S *big.Int
		}
		rest, err := asn1.Unmarshal(sig, &parsed)
		if err != nil || len(rest) != 0 {
			return nil, nil, fmt.Errorf("decode signature: unsupported format")
		}
		if parsed.R == nil || parsed.S == nil {
			return nil, nil, fmt.Errorf("decode signature: missing r or s")
		}
		return parsed.R, parsed.S, nil
	}
}

func validateSignatureScalars(r, s *big.Int) error {
	if r == nil || s == nil {
		return fmt.Errorf("decode signature: missing r or s")
	}
	order := ethcrypto.S256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
		return fmt.Errorf("decode signature: r or s is out of range")
	}
	return nil
}

func signatureBytes(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):], sBytes)
	return out
}

func normalizeLowS(s *big.Int) *big.Int {
	curveOrder := ethcrypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(curveOrder), 1)
	if s.Cmp(halfOrder) <= 0 {
		return new(big.Int).Set(s)
	}
	return new(big.Int).Sub(curveOrder, s)
}

func samePublicKey(left, right *ecdsa.PublicKey) bool {
	if left == nil || right == nil {
		return false
	}
	return bytes.Equal(ethcrypto.FromECDSAPub(left), ethcrypto.FromECDSAPub(right))
}
