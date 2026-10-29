package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

const (
	DefaultGeneratedKeyIDPrefix = "key_"
	PayloadEncodingHex          = v1.PayloadEncodingHex
	TRC20TransferSelector       = "a9059cbb"
)

type Key struct {
	RecordVersion     int                  `json:"schema_version,omitempty"`
	KeyType           cryptography.KeyType `json:"key_type,omitempty"`
	MaterialFormat    string               `json:"material_format,omitempty"`
	ID                string               `json:"id"`
	ChainFamily       string               `json:"chain_family"`
	CustodyMode       string               `json:"custody_mode"`
	Active            bool                 `json:"active"`
	Labels            map[string]string    `json:"labels,omitempty"`
	Policy            v1.Policy            `json:"policy,omitempty"`
	SignerAddress     string               `json:"signer_address"`
	PublicKeyHex      string               `json:"public_key_hex"`
	PrivateKeyHex     string               `json:"private_key_hex,omitempty"`
	ExternalSignerRef string               `json:"external_signer_ref,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

// Clone isolates mutable request/repository collections at service boundaries.
func (k Key) Clone() Key {
	clone := k
	clone.Labels = maps.Clone(k.Labels)
	clone.Policy = k.Policy.Clone()
	return clone
}

func NormalizeChainFamily(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeCustodyMode(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeSelector(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimPrefix(value, "0x")
}

func GenerateKeyID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return DefaultGeneratedKeyIDPrefix + hex.EncodeToString(buf), nil
}
