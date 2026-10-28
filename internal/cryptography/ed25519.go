package cryptography

import (
	"crypto/ed25519"
	"fmt"
	"slices"
)

const Ed25519Key KeyType = "ed25519"
const Ed25519Scheme SchemeID = "ed25519"

func CanonicalEd25519(raw []byte) (PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("invalid Ed25519 public key length")
	}
	return PublicKey{Type: Ed25519Key, Bytes: slices.Clone(raw)}, nil
}
func verifyEd25519(pub PublicKey, payload Payload, signature []byte) ([]byte, error) {
	if len(pub.Bytes) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub.Bytes), payload.Bytes(), signature) {
		return nil, fmt.Errorf("invalid Ed25519 signature")
	}
	return slices.Clone(signature), nil
}
