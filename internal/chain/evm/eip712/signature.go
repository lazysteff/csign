package eip712

import (
	"errors"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain/evm/rsv27"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/ethereum/go-ethereum/common"
)

// Signature is a validated, canonical secp256k1 signature. Bytes returns its
// 65-byte r || s || v representation with v encoded as 27 or 28.
type Signature = rsv27.Signature

// FormatSignature validates a recoverable 65-byte secp256k1 signature,
// rejects non-canonical or high-s values, and formats v as 27 or 28. Input v
// may be either recovery parity (0/1) or Ethereum contract form (27/28).
func FormatSignature(raw []byte) (Signature, error) {
	signature, err := rsv27.Format(raw)
	switch {
	case errors.Is(err, rsv27.ErrInvalidLength):
		return Signature{}, fmt.Errorf("EIP-712 signature must be exactly 65 bytes")
	case errors.Is(err, rsv27.ErrInvalidRecoveryValue):
		return Signature{}, fmt.Errorf("EIP-712 signature recovery value must be 0, 1, 27, or 28")
	case errors.Is(err, rsv27.ErrInvalidValues):
		return Signature{}, fmt.Errorf("EIP-712 signature has invalid or non-canonical secp256k1 values")
	case err != nil:
		return Signature{}, err
	default:
		return signature, nil
	}
}

// RecoverSigner validates the signature and recovers its EOA signer for the
// supplied EIP-712 digest. Signature v may be encoded as 0/1 or 27/28.
func RecoverSigner(digest common.Hash, rawSignature []byte) (common.Address, error) {
	signature, err := FormatSignature(rawSignature)
	if err != nil {
		return common.Address{}, err
	}
	recovered, err := rsv27.Recover(digest, signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover EIP-712 signer: %w", err)
	}
	return recovered, nil
}

// VerifySigner recovers the signature and requires it to match the canonical
// lowercase expected signer address.
func VerifySigner(digest common.Hash, rawSignature []byte, expectedSigner string) (common.Address, error) {
	expected, err := enc.ParseEVMAddress("expected signer", expectedSigner, false)
	if err != nil {
		return common.Address{}, err
	}
	recovered, err := RecoverSigner(digest, rawSignature)
	if err != nil {
		return common.Address{}, err
	}
	if recovered != expected {
		return recovered, fmt.Errorf("recovered EIP-712 signer %s does not match expected signer %s", recovered.Hex(), expected.Hex())
	}
	return recovered, nil
}
