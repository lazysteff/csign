package advancedcodec

import (
	"math/big"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/ethereum/go-ethereum/common"
)

func parseAddress(field, value string, allowZero bool) (common.Address, error) {
	return enc.ParseEVMAddress(field, value, allowZero)
}

func parseHex(field, value string, exactLength int) ([]byte, error) {
	return enc.DecodeCanonicalHex(field, value, exactLength)
}

func parseUint(field, value string, bits int, allowZero bool) (*big.Int, error) {
	return enc.ParseCanonicalUint(field, value, bits, allowZero)
}

func parseUint64(field, value string) (uint64, error) {
	return enc.ParseCanonicalUint64(field, value)
}

func fieldPath(prefix, field string) string {
	if prefix == "" {
		return field
	}
	return prefix + "." + field
}
