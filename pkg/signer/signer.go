package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/chain-signer/chain-signer/pkg/model"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type Material interface {
	PublicKey() *ecdsa.PublicKey
	SignDigest(context.Context, []byte) ([]byte, error)
}

type Resolver interface {
	ResolveExternal(context.Context, model.Key) (Material, error)
}

type Engine struct {
	External Resolver
}

type ExternalMaterial struct {
	Pub      *ecdsa.PublicKey
	SignFunc func(context.Context, []byte) ([]byte, error)
}

func (m ExternalMaterial) PublicKey() *ecdsa.PublicKey {
	return m.Pub
}

func (m ExternalMaterial) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	return m.SignFunc(ctx, digest)
}

func (e Engine) MaterialFor(ctx context.Context, key model.Key) (Material, error) {
	switch model.NormalizeCustodyMode(key.CustodyMode) {
	case model.CustodyModeMVP, "":
		privateKey, err := model.ParsePrivateKeyHex(key.PrivateKeyHex)
		if err != nil {
			return nil, err
		}
		return localMaterial{privateKey: privateKey}, nil
	case model.CustodyModePKCS11:
		if e.External == nil {
			return nil, fmt.Errorf("pkcs11 mode requested for key %q but no external signer resolver is configured", key.ID)
		}
		return e.External.ResolveExternal(ctx, key)
	default:
		return nil, fmt.Errorf("unsupported custody mode %q", key.CustodyMode)
	}
}

type localMaterial struct {
	privateKey *ecdsa.PrivateKey
}

func (m localMaterial) PublicKey() *ecdsa.PublicKey {
	return &m.privateKey.PublicKey
}

func (m localMaterial) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return ethcrypto.Sign(digest, m.privateKey)
}

func RecoverableSignature(ctx context.Context, material Material, digest []byte) ([]byte, error) {
	rawSig, err := material.SignDigest(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("sign digest: %w", err)
	}
	if len(rawSig) == ethcrypto.SignatureLength && (rawSig[64] == 0 || rawSig[64] == 1) {
		return append([]byte(nil), rawSig...), nil
	}
	r, s, err := decodeSignature(rawSig)
	if err != nil {
		return nil, err
	}
	return recoverableFromRS(material.PublicKey(), digest, r, s)
}

func RecoverAddressFromDigest(chainFamily string, digest []byte, signature []byte) (string, error) {
	pub, err := ethcrypto.SigToPub(digest, signature)
	if err != nil {
		return "", fmt.Errorf("recover public key: %w", err)
	}
	return model.DeriveSignerAddress(chainFamily, pub)
}

func recoverableFromRS(pub *ecdsa.PublicKey, digest []byte, r, s *big.Int) ([]byte, error) {
	r = new(big.Int).Set(r)
	s = new(big.Int).Set(s)

	normalizedS := normalizeLowS(s)
	candidates := [][]byte{signatureBytes(r, normalizedS)}
	if normalizedS.Cmp(s) != 0 {
		candidates = append(candidates, signatureBytes(r, s))
	}

	for _, rs := range candidates {
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
		if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
			return nil, nil, fmt.Errorf("decode signature: unsupported format")
		}
		if parsed.R == nil || parsed.S == nil {
			return nil, nil, fmt.Errorf("decode signature: missing r or s")
		}
		return parsed.R, parsed.S, nil
	}
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
	return bytes.Equal(ethcrypto.FromECDSAPub(left), ethcrypto.FromECDSAPub(right))
}
