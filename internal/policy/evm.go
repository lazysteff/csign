package policy

import (
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func ValidateEVMLegacyTransfer(key domain.Key, req *v1.EVMLegacyTransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyEVM, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceEVMValueCap(req.Value, key.Policy.MaxValue); err != nil {
		return err
	}
	if err := enforceBigCap(req.GasPrice, key.Policy.MaxGasPrice, "gas_price"); err != nil {
		return err
	}
	return enforceGasLimit(req.GasLimit, key.Policy.MaxGasLimit)
}

func ValidateEVMEIP1559Transfer(key domain.Key, req *v1.EVMEIP1559TransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyEVM, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceEVMValueCap(req.Value, key.Policy.MaxValue); err != nil {
		return err
	}
	if err := enforceGasLimit(req.GasLimit, key.Policy.MaxGasLimit); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxFeePerGas, key.Policy.MaxFeePerGas, "max_fee_per_gas"); err != nil {
		return err
	}
	return enforceBigCap(req.MaxPriorityFeePerGas, key.Policy.MaxPriorityFeePerGas, "max_priority_fee_per_gas")
}

func ValidateEVMContractCall(key domain.Key, req *v1.EVMContractCallSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyEVM, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if strings.TrimSpace(req.Data) == "" {
		return faults.New(faults.Invalid, "data is required for contract calls")
	}
	selector, err := selectorFromHexData(req.Data)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if len(key.Policy.AllowedContractDestinations) > 0 {
		if err := requireAddressAllowed(key.Policy.AllowedContractDestinations, req.To, "transaction destination"); err != nil {
			return err
		}
	} else if err := enforceTokenContractAllowlist(key.Policy, v1.ChainFamilyEVM, req.To); err != nil {
		return err
	}
	if err := enforceSelectorAllowlist(key.Policy, selector); err != nil {
		return err
	}
	if err := enforceEVMValueCap(req.Value, key.Policy.MaxValue); err != nil {
		return err
	}
	if err := enforceGasLimit(req.GasLimit, key.Policy.MaxGasLimit); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxFeePerGas, key.Policy.MaxFeePerGas, "max_fee_per_gas"); err != nil {
		return err
	}
	return enforceBigCap(req.MaxPriorityFeePerGas, key.Policy.MaxPriorityFeePerGas, "max_priority_fee_per_gas")
}

func enforceEVMValueCap(value, capValue string) error {
	actual, err := enc.ParseEVMUint256(value)
	if err != nil {
		return faults.Newf(faults.Invalid, "parse value: %v", err)
	}
	if strings.TrimSpace(capValue) == "" {
		return nil
	}
	capInt, err := enc.ParseEVMUint256(capValue)
	if err != nil {
		return faults.Newf(faults.Invalid, "parse value cap: %v", err)
	}
	if actual.Cmp(capInt) > 0 {
		return faults.New(faults.PolicyDenied, "value exceeds configured cap")
	}
	return nil
}
