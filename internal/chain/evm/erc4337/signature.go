package erc4337

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain/evm/rsv27"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EncodeSimpleAccountSignature validates a recoverable secp256k1 signature and
// returns the R || S || V representation accepted by OpenZeppelin ECDSA.recover.
// Inputs with recovery parity 0/1 are converted to Ethereum V 27/28.
func EncodeSimpleAccountSignature(signature []byte) ([]byte, error) {
	formatted, err := rsv27.Format(signature)
	switch {
	case errors.Is(err, rsv27.ErrInvalidLength):
		return nil, fmt.Errorf("simple account signature must be 65 bytes, got %d", len(signature))
	case errors.Is(err, rsv27.ErrInvalidRecoveryValue):
		return nil, fmt.Errorf("simple account signature V must be 0, 1, 27, or 28, got %d", signature[crypto.RecoveryIDOffset])
	case errors.Is(err, rsv27.ErrInvalidValues):
		return nil, fmt.Errorf("simple account signature has invalid R, S, or non-canonical high-S value")
	case err != nil:
		return nil, err
	default:
		return formatted.Bytes(), nil
	}
}

// SignSimpleAccountDigest signs a direct v0.9 SimpleAccount digest and returns
// the OpenZeppelin-compatible 65-byte encoding with V 27/28.
func SignSimpleAccountDigest(privateKey *ecdsa.PrivateKey, digest common.Hash) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	signature, err := crypto.Sign(digest.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign simple account digest: %w", err)
	}
	return EncodeSimpleAccountSignature(signature)
}

// RecoverSimpleAccountSigner reproduces the signature constraints of
// OpenZeppelin ECDSA.recover used by SimpleAccount v0.9: 65-byte R || S || V,
// low-S, and V equal to 27 or 28.
func RecoverSimpleAccountSigner(digest common.Hash, signature []byte) (common.Address, error) {
	if len(signature) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("simple account signature must be 65 bytes, got %d", len(signature))
	}
	if signature[crypto.RecoveryIDOffset] != 27 && signature[crypto.RecoveryIDOffset] != 28 {
		return common.Address{}, fmt.Errorf("simple account signature V must be 27 or 28, got %d", signature[crypto.RecoveryIDOffset])
	}
	formatted, err := rsv27.Format(signature)
	if errors.Is(err, rsv27.ErrInvalidValues) {
		return common.Address{}, fmt.Errorf("simple account signature has invalid R, S, or non-canonical high-S value")
	}
	if err != nil {
		return common.Address{}, err
	}

	recovered, err := rsv27.Recover(digest, formatted)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover simple account signer: %w", err)
	}
	return recovered, nil
}

// ValidateSimpleAccountSignature reports whether signature recovers owner.
// Malformed signatures return an error, matching OpenZeppelin's revert behavior.
func ValidateSimpleAccountSignature(digest common.Hash, signature []byte, owner common.Address) (bool, error) {
	recovered, err := RecoverSimpleAccountSigner(digest, signature)
	if err != nil {
		return false, err
	}
	return recovered == owner, nil
}
