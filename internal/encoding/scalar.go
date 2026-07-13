package encoding

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

var maxUint64 = new(big.Int).SetUint64(^uint64(0))

func NormalizeHex(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return value[2:]
	}
	return value
}

func DecodeHex(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(NormalizeHex(value))
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return decoded, nil
}

func EncodeHex(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func ParseBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("numeric value is required")
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
	}
	out, ok := new(big.Int).SetString(value, base)
	if !ok {
		return nil, fmt.Errorf("invalid numeric value %q", value)
	}
	return out, nil
}

// ParseEVMAddress accepts only the canonical lowercase wire representation
// used by the structured EVM API.
func ParseEVMAddress(field, value string, allowZero bool) (common.Address, error) {
	if len(value) != 2+2*common.AddressLength || !strings.HasPrefix(value, "0x") || value != strings.ToLower(value) || !common.IsHexAddress(value) {
		return common.Address{}, fmt.Errorf("%s must be a canonical lowercase 0x-prefixed address", field)
	}
	address := common.HexToAddress(value)
	if !allowZero && address == (common.Address{}) {
		return common.Address{}, fmt.Errorf("%s must not be the zero address", field)
	}
	return address, nil
}

// DecodeCanonicalHex accepts lowercase, even-length, 0x-prefixed bytes and
// optionally enforces an exact decoded length. Pass a negative length to
// accept any number of bytes.
func DecodeCanonicalHex(field, value string, exactLength int) ([]byte, error) {
	if !strings.HasPrefix(value, "0x") || value != strings.ToLower(value) || len(value)%2 != 0 {
		return nil, fmt.Errorf("%s must be canonical lowercase 0x-prefixed hexadecimal", field)
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, fmt.Errorf("%s must be canonical lowercase 0x-prefixed hexadecimal", field)
	}
	if exactLength >= 0 && len(decoded) != exactLength {
		return nil, fmt.Errorf("%s must contain exactly %d bytes", field, exactLength)
	}
	return decoded, nil
}

// ParseCanonicalUint parses the canonical decimal-string form used for wide
// EVM protocol quantities.
func ParseCanonicalUint(field, value string, bits int, allowZero bool) (*big.Int, error) {
	if bits <= 0 {
		return nil, fmt.Errorf("%s has invalid uint width %d", field, bits)
	}
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return nil, fmt.Errorf("%s must be a canonical base-10 uint%d string", field, bits)
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return nil, fmt.Errorf("%s must be a canonical base-10 uint%d string", field, bits)
		}
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Sign() < 0 || parsed.BitLen() > bits {
		return nil, fmt.Errorf("%s is outside the uint%d range", field, bits)
	}
	if !allowZero && parsed.Sign() == 0 {
		return nil, fmt.Errorf("%s must be greater than zero", field)
	}
	return parsed, nil
}

func ParseCanonicalUint64(field, value string) (uint64, error) {
	parsed, err := ParseCanonicalUint(field, value, 64, true)
	if err != nil {
		return 0, err
	}
	if parsed.Cmp(maxUint64) > 0 {
		return 0, fmt.Errorf("%s is outside the uint64 range", field)
	}
	return parsed.Uint64(), nil
}
