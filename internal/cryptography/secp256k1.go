package cryptography

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func productionSchemes() []Scheme {
	return []Scheme{{ID: ECDSASecp256k1, KeyTypes: []KeyType{Secp256k1}, Inputs: []InputKind{Digest}, Verify: verifyECDSA}, {ID: Ed25519Scheme, KeyTypes: []KeyType{Ed25519Key}, Inputs: []InputKind{Message}, Verify: verifyEd25519}}
}
func CanonicalSecp256k1(encoded []byte) (PublicKey, error) {
	var pub *ecdsa.PublicKey
	var err error
	switch len(encoded) {
	case 33:
		pub, err = ethcrypto.DecompressPubkey(encoded)
	case 65:
		pub, err = ethcrypto.UnmarshalPubkey(encoded)
	default:
		return PublicKey{}, fmt.Errorf("invalid secp256k1 public key length")
	}
	if err != nil {
		return PublicKey{}, fmt.Errorf("invalid secp256k1 public key")
	}
	return PublicKey{Type: Secp256k1, Bytes: ethcrypto.CompressPubkey(pub)}, nil
}
func ECDSAPublicKey(pub PublicKey) (*ecdsa.PublicKey, error) {
	if pub.Type != Secp256k1 {
		return nil, fmt.Errorf("expected secp256k1 public key")
	}
	return ethcrypto.DecompressPubkey(pub.Bytes)
}
func verifyECDSA(pub PublicKey, payload Payload, raw []byte) ([]byte, error) {
	if len(payload.Bytes()) != 32 {
		return nil, fmt.Errorf("ECDSA requires a 32-byte digest")
	}
	p, err := ECDSAPublicKey(pub)
	if err != nil {
		return nil, err
	}
	r, s, err := decodeSignature(raw)
	if err != nil {
		return nil, err
	}
	if err = validateSignatureScalars(r, s); err != nil {
		return nil, err
	}
	return recoverableFromRS(p, payload.Bytes(), r, s)
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
