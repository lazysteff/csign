package erc4337

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// UserOperation is the structured, unpacked representation used at the RPC
// boundary. Factory and EIP7702 are mutually exclusive.
type UserOperation struct {
	Sender               common.Address
	Nonce                *big.Int
	Factory              *Factory
	EIP7702              *EIP7702Init
	CallData             []byte
	VerificationGasLimit *big.Int
	CallGasLimit         *big.Int
	PreVerificationGas   *big.Int
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	Paymaster            *Paymaster
	Signature            []byte
}

// PackedUserOperation mirrors contracts/interfaces/PackedUserOperation.sol in
// account-abstraction v0.9.0. Signature is transported with the operation but
// is not included in its hash.
type PackedUserOperation struct {
	Sender             common.Address
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   common.Hash
	PreVerificationGas *big.Int
	GasFees            common.Hash
	PaymasterAndData   []byte
	Signature          []byte
}

// Pack converts the structured operation to the PackedUserOperation layout
// consumed by EntryPoint v0.9.
func (op UserOperation) Pack() (PackedUserOperation, error) {
	if err := validateUint("nonce", op.Nonce, 256); err != nil {
		return PackedUserOperation{}, err
	}
	if err := validateEntryPointGasValues(op); err != nil {
		return PackedUserOperation{}, err
	}

	accountGasLimits, err := PackAccountGasLimits(op.VerificationGasLimit, op.CallGasLimit)
	if err != nil {
		return PackedUserOperation{}, err
	}
	gasFees, err := PackGasFees(op.MaxPriorityFeePerGas, op.MaxFeePerGas)
	if err != nil {
		return PackedUserOperation{}, err
	}
	initCode, err := packInitCode(op.Factory, op.EIP7702)
	if err != nil {
		return PackedUserOperation{}, err
	}

	var paymasterAndData []byte
	if op.Paymaster != nil {
		paymasterAndData, err = op.Paymaster.Pack()
		if err != nil {
			return PackedUserOperation{}, err
		}
	}

	return PackedUserOperation{
		Sender:             op.Sender,
		Nonce:              cloneBig(op.Nonce),
		InitCode:           cloneBytes(initCode),
		CallData:           cloneBytes(op.CallData),
		AccountGasLimits:   accountGasLimits,
		PreVerificationGas: cloneBig(op.PreVerificationGas),
		GasFees:            gasFees,
		PaymasterAndData:   cloneBytes(paymasterAndData),
		Signature:          cloneBytes(op.Signature),
	}, nil
}

// EntryPoint v0.9 validates all gas and fee values as uint120 before adding
// and multiplying them. The packed wire fields are uint128, but accepting the
// wider range would create an operation that is guaranteed to fail with AA94.
func validateEntryPointGasValues(op UserOperation) error {
	values := []struct {
		name  string
		value *big.Int
	}{
		{name: "verificationGasLimit", value: op.VerificationGasLimit},
		{name: "callGasLimit", value: op.CallGasLimit},
		{name: "preVerificationGas", value: op.PreVerificationGas},
		{name: "maxPriorityFeePerGas", value: op.MaxPriorityFeePerGas},
		{name: "maxFeePerGas", value: op.MaxFeePerGas},
	}
	for _, field := range values {
		if err := validateUint(field.name, field.value, 120); err != nil {
			return err
		}
	}
	return nil
}

// PackAccountGasLimits returns uint128(verificationGasLimit) ||
// uint128(callGasLimit), matching UserOperationLib v0.9.
func PackAccountGasLimits(verificationGasLimit, callGasLimit *big.Int) (common.Hash, error) {
	return packUints128("verificationGasLimit", verificationGasLimit, "callGasLimit", callGasLimit)
}

// UnpackAccountGasLimits reverses PackAccountGasLimits.
func UnpackAccountGasLimits(packed common.Hash) (verificationGasLimit, callGasLimit *big.Int) {
	return new(big.Int).SetBytes(packed[:16]), new(big.Int).SetBytes(packed[16:])
}

// PackGasFees returns uint128(maxPriorityFeePerGas) ||
// uint128(maxFeePerGas), matching UserOperationLib v0.9.
func PackGasFees(maxPriorityFeePerGas, maxFeePerGas *big.Int) (common.Hash, error) {
	return packUints128("maxPriorityFeePerGas", maxPriorityFeePerGas, "maxFeePerGas", maxFeePerGas)
}

// UnpackGasFees reverses PackGasFees.
func UnpackGasFees(packed common.Hash) (maxPriorityFeePerGas, maxFeePerGas *big.Int) {
	return new(big.Int).SetBytes(packed[:16]), new(big.Int).SetBytes(packed[16:])
}

func packUints128(highName string, high *big.Int, lowName string, low *big.Int) (common.Hash, error) {
	if err := validateUint(highName, high, 128); err != nil {
		return common.Hash{}, err
	}
	if err := validateUint(lowName, low, 128); err != nil {
		return common.Hash{}, err
	}
	var ret common.Hash
	high.FillBytes(ret[:16])
	low.FillBytes(ret[16:])
	return ret, nil
}
