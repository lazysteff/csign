package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

const (
	DefaultGeneratedKeyIDPrefix = "key_"
	PayloadEncodingHex          = "hex"
	TRC20TransferSelector       = "a9059cbb"
)

type Key struct {
	ID                string            `json:"id"`
	ChainFamily       string            `json:"chain_family"`
	CustodyMode       string            `json:"custody_mode"`
	Active            bool              `json:"active"`
	Labels            map[string]string `json:"labels,omitempty"`
	Policy            v1.Policy         `json:"policy,omitempty"`
	SignerAddress     string            `json:"signer_address"`
	PublicKeyHex      string            `json:"public_key_hex"`
	PrivateKeyHex     string            `json:"private_key_hex,omitempty"`
	ExternalSignerRef string            `json:"external_signer_ref,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

func NormalizeChainFamily(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeCustodyMode(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeSelector(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "0x"))
}

func GenerateKeyID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return DefaultGeneratedKeyIDPrefix + hex.EncodeToString(buf), nil
}
