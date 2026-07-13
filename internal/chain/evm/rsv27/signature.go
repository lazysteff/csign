// Package rsv27 implements the canonical 65-byte r || s || v signature
// encoding used by EVM contracts that expect v to be 27 or 28.
package rsv27

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	ErrInvalidLength        = errors.New("signature must be 65 bytes")
	ErrInvalidRecoveryValue = errors.New("signature recovery value must be 0, 1, 27, or 28")
	ErrInvalidValues        = errors.New("signature has invalid or non-canonical secp256k1 values")
)

// Signature is a validated, low-S signature with v normalized to 27 or 28.
type Signature struct {
	R common.Hash
	S common.Hash
	V uint8

	encoded [crypto.SignatureLength]byte
}

// Format validates a recoverable signature and normalizes parity 0/1 to the
// contract-oriented 27/28 representation.
func Format(raw []byte) (Signature, error) {
	if len(raw) != crypto.SignatureLength {
		return Signature{}, ErrInvalidLength
	}

	recoveryID := raw[crypto.RecoveryIDOffset]
	switch recoveryID {
	case 0, 1:
	case 27, 28:
		recoveryID -= 27
	default:
		return Signature{}, ErrInvalidRecoveryValue
	}

	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:crypto.RecoveryIDOffset])
	if !crypto.ValidateSignatureValues(recoveryID, r, s, true) {
		return Signature{}, ErrInvalidValues
	}

	var encoded [crypto.SignatureLength]byte
	copy(encoded[:crypto.RecoveryIDOffset], raw[:crypto.RecoveryIDOffset])
	encoded[crypto.RecoveryIDOffset] = recoveryID + 27
	return Signature{
		R:       common.BytesToHash(encoded[:32]),
		S:       common.BytesToHash(encoded[32:crypto.RecoveryIDOffset]),
		V:       encoded[crypto.RecoveryIDOffset],
		encoded: encoded,
	}, nil
}

// Recover returns the EVM address that produced a validated signature.
func Recover(digest common.Hash, signature Signature) (common.Address, error) {
	recoverable := signature.Bytes()
	recoverable[crypto.RecoveryIDOffset] -= 27
	publicKey, err := crypto.SigToPub(digest[:], recoverable)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*publicKey), nil
}

// Bytes returns a defensive copy of the normalized signature.
func (signature Signature) Bytes() []byte {
	return append([]byte(nil), signature.encoded[:]...)
}

// Hex returns the normalized signature as lowercase 0x-prefixed hexadecimal.
func (signature Signature) Hex() string {
	return "0x" + hex.EncodeToString(signature.encoded[:])
}
