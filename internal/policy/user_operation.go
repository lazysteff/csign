package policy

import (
	"errors"
	"math/big"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func ValidateEVMUserOperation(key domain.Key, req *v1.EVMUserOperationSignRequest) error {
	if err := validateAdvancedBase(key, req.ChainFamily, req.Network, req.RequestID, req.ExpectedSignerAddress, req.ChainID, v1.OperationEVMERC4337UserOperation, false); err != nil {
		return err
	}
	if err := requireStringAllowed(key.Policy.AllowedERC4337Versions, req.ProtocolVersion, "ERC-4337 protocol version"); err != nil {
		return err
	}
	if err := requireAddressAllowed(key.Policy.AllowedEntryPoints, req.EntryPoint, "EntryPoint"); err != nil {
		return err
	}
	if err := requireStringAllowed(key.Policy.AllowedAccountImplementations, req.AccountImplementation, "account implementation"); err != nil {
		return err
	}
	if err := requireStringAllowed(key.Policy.AllowedAccountSigningSchemas, req.AccountSigningSchema, "account signing schema"); err != nil {
		return err
	}
	if err := enforceBigCap(req.UserOperation.MaxFeePerGas, key.Policy.MaxFeePerGas, "max_fee_per_gas"); err != nil {
		return err
	}
	if err := enforceBigCap(req.UserOperation.MaxPriorityFeePerGas, key.Policy.MaxPriorityFeePerGas, "max_priority_fee_per_gas"); err != nil {
		return err
	}
	if key.Policy.MaxGasLimit > 0 {
		type gasValue struct {
			field string
			value string
		}
		gasValues := []gasValue{
			{field: "call_gas_limit", value: req.UserOperation.CallGasLimit},
			{field: "verification_gas_limit", value: req.UserOperation.VerificationGasLimit},
			{field: "pre_verification_gas", value: req.UserOperation.PreVerificationGas},
		}
		if req.UserOperation.Paymaster != nil {
			gasValues = append(gasValues,
				gasValue{field: "paymaster.verification_gas_limit", value: req.UserOperation.Paymaster.VerificationGasLimit},
				gasValue{field: "paymaster.post_op_gas_limit", value: req.UserOperation.Paymaster.PostOpGasLimit},
			)
		}
		for _, gas := range gasValues {
			parsed, parseErr := enc.ParseCanonicalUint(gas.field, gas.value, 256, true)
			if parseErr != nil {
				return faults.Wrap(faults.Invalid, parseErr)
			}
			if parsed.Cmp(new(big.Int).SetUint64(key.Policy.MaxGasLimit)) > 0 {
				return faults.Newf(faults.PolicyDenied, "%s exceeds configured cap", gas.field)
			}
		}
	}
	prepared, err := advancedcodec.PrepareUserOperation(
		req.ProtocolVersion,
		req.AccountImplementation,
		req.AccountImplementationVersion,
		req.AccountSigningSchema,
		req.ChainID,
		req.EntryPoint,
		req.ExpectedSignerAddress,
		req.ExpectedUserOperationHash,
		req.UserOperation,
	)
	if err != nil {
		return classifyUserOperationError(err)
	}
	if prepared.Delegate != nil {
		if err := requireAddressAllowed(key.Policy.AllowedEIP7702Delegates, strings.ToLower(prepared.Delegate.Hex()), "EIP-7702 delegate"); err != nil {
			return err
		}
	}
	if len(key.Policy.AllowedSelectors) > 0 {
		selector, err := selectorFromCanonicalHex(prepared.Operation.CallData)
		if err != nil {
			return err
		}
		if err := enforceSelectorAllowlist(key.Policy, selector); err != nil {
			return err
		}
	}
	return nil
}

func classifyUserOperationError(err error) error {
	message := err.Error()
	var unsupported *advancedregistry.UnsupportedError
	switch {
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedERC4337Protocol:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedERC4337Version, message)
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedAccountImplementation:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedAccountImplementation, message)
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedAccountSigningSchema:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedAccountSigningSchema, message)
	case errors.Is(err, advancedcodec.ErrUserOperationHashMismatch):
		return faults.NewCode(faults.Invalid, faults.UserOperationHashMismatch, message)
	default:
		return faults.NewCode(faults.Invalid, faults.InvalidUserOperation, message)
	}
}
