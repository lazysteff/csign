package v1

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// TRONMemoEncodingHex is the byte-preserving JSON encoding used by the
	// transfer signing contracts for TransactionRaw.data.
	TRONMemoEncodingHex = "hex"

	// TRONMaxTransactionBytes matches java-tron's TRANSACTION_MAX_BYTE_SIZE.
	// The limit applies to the serialized transaction, not just its memo.
	TRONMaxTransactionBytes = 500 * 1024
)

// TRONMemoCapability reports which signing operations accept an encoded
// TransactionRaw.data value and the network's serialized transaction ceiling.
type TRONMemoCapability struct {
	Encoding            string   `json:"encoding"`
	MaxTransactionBytes int      `json:"max_transaction_bytes"`
	SigningOperations   []string `json:"signing_operations"`
}

// DecodeTRONMemoHex decodes an optional, byte-preserving TRON memo. Both plain
// and 0x-prefixed hexadecimal are accepted; an empty value means no memo.
func DecodeTRONMemoHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		value = value[2:]
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("memo_hex must be even-length hexadecimal: %w", err)
	}
	if len(decoded) > TRONMaxTransactionBytes {
		return nil, fmt.Errorf("memo_hex decodes to %d bytes, exceeding the %d-byte TRON transaction limit", len(decoded), TRONMaxTransactionBytes)
	}
	return decoded, nil
}
