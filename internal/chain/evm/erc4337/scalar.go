package erc4337

import (
	"fmt"
	"math/big"
)

func validateUint(name string, value *big.Int, bits int) error {
	if value == nil {
		return fmt.Errorf("%s is required", name)
	}
	if value.Sign() < 0 {
		return fmt.Errorf("%s must be unsigned", name)
	}
	if value.BitLen() > bits {
		return fmt.Errorf("%s exceeds uint%d", name, bits)
	}
	return nil
}

func cloneBig(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}
