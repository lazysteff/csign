package encoding

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

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
