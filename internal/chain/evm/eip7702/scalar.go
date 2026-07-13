package eip7702

import (
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
)

func uint256Value(name string, value *big.Int, allowZero bool) (*uint256.Int, error) {
	if value == nil {
		return nil, fmt.Errorf("%s is required", name)
	}
	if value.Sign() < 0 {
		return nil, fmt.Errorf("%s must not be negative", name)
	}
	if !allowZero && value.Sign() == 0 {
		return nil, fmt.Errorf("%s must be positive", name)
	}
	out, overflow := uint256.FromBig(value)
	if overflow {
		return nil, fmt.Errorf("%s exceeds uint256", name)
	}
	return out, nil
}
