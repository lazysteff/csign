// Package solana implements protocol identity and opaque message preparation.
// It deliberately has no transaction parser, builder, RPC, or custody code.
package solana

import (
	"fmt"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/shengdoushi/base58"
)

func DeriveAddress(pub cryptography.PublicKey) (string, error) {
	if pub.Type != cryptography.Ed25519Key || len(pub.Bytes) != 32 {
		return "", fmt.Errorf("solana identity requires an Ed25519 public key")
	}
	return base58.Encode(pub.Bytes, base58.BitcoinAlphabet), nil
}
func NormalizeAddress(address string) (string, error) {
	raw, err := base58.Decode(address, base58.BitcoinAlphabet)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid Solana signer address")
	}
	canonical := base58.Encode(raw, base58.BitcoinAlphabet)
	if canonical != address {
		return "", fmt.Errorf("noncanonical Solana signer address")
	}
	return canonical, nil
}
func EqualAddress(a, b string) bool {
	left, err := NormalizeAddress(a)
	if err != nil {
		return false
	}
	right, err := NormalizeAddress(b)
	return err == nil && left == right
}

type Input struct {
	Context v1.SolanaMessageSignRequest
	Message []byte
}

func Normalize(req *v1.SolanaMessageSignRequest) (Input, error) {
	if len(req.MessageHex) > v1.SolanaMaxMessageHexCharacters {
		return Input{}, fmt.Errorf("message_hex exceeds API resource limit")
	}
	message, err := enc.DecodeHex(req.MessageHex)
	if err != nil {
		return Input{}, fmt.Errorf("message_hex must contain valid hexadecimal bytes")
	}
	if len(message) == 0 || len(message) > v1.SolanaMaxMessageBytes {
		return Input{}, fmt.Errorf("message must contain 1 to 65536 bytes")
	}
	context := *req
	context.Labels = nil
	context.MessageHex = "" // metadata snapshot, no shared maps or duplicate payload storage
	return Input{Context: context, Message: message}, nil
}
func Prepare(capability cryptography.Capability, pub cryptography.PublicKey, input Input) (*cryptography.Prepared, error) {
	if capability.Scheme != cryptography.Ed25519Scheme || capability.Input != cryptography.Message {
		return nil, fmt.Errorf("incompatible Solana message scheme")
	}
	identity, err := DeriveAddress(pub)
	if err != nil {
		return nil, err
	}
	context := input.Context
	publicHex := enc.EncodeHex(pub.Bytes)
	return &cryptography.Prepared{Payload: cryptography.NewPayload(cryptography.Message, input.Message), Format: func(signature []byte) (any, error) {
		return &v1.SolanaMessageSignResponse{APIVersion: v1.APIVersion, KeyID: context.KeyID, ChainFamily: v1.ChainFamilySolana, Network: context.Network, RequestID: context.RequestID, Operation: v1.OperationSolanaMessage, PublicKeyHex: publicHex, SignerAddress: identity, SigningScheme: v1.SigningSchemeEd25519, SignatureEncoding: v1.PayloadEncodingHex, SignatureHex: enc.EncodeHex(signature)}, nil
	}}, nil
}
