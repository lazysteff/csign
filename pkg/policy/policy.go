package policy

import (
	"fmt"
	"strings"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/chain-signer/chain-signer/pkg/model"
)

func ValidateCreateKeyRequest(req v1.CreateKeyRequest) error {
	chainFamily := model.NormalizeChainFamily(req.ChainFamily)
	if chainFamily != model.ChainFamilyEVM && chainFamily != model.ChainFamilyTRON {
		return fmt.Errorf("unsupported chain family %q", req.ChainFamily)
	}
	custodyMode := model.NormalizeCustodyMode(req.CustodyMode)
	if custodyMode == "" {
		custodyMode = model.CustodyModeMVP
	}
	switch custodyMode {
	case model.CustodyModeMVP:
		if strings.TrimSpace(req.ExternalSignerRef) != "" {
			return fmt.Errorf("external_signer_ref is only valid in pkcs11 mode")
		}
	case model.CustodyModePKCS11:
		if strings.TrimSpace(req.ImportPrivateKey) != "" {
			return fmt.Errorf("import_private_key_hex is not allowed in pkcs11 mode")
		}
		if strings.TrimSpace(req.PublicKeyHex) == "" {
			return fmt.Errorf("public_key_hex is required in pkcs11 mode")
		}
		if strings.TrimSpace(req.ExternalSignerRef) == "" {
			return fmt.Errorf("external_signer_ref is required in pkcs11 mode")
		}
	default:
		return fmt.Errorf("unsupported custody mode %q", req.CustodyMode)
	}
	return nil
}

func ValidateEVMLegacyTransfer(key model.Key, req v1.EVMLegacyTransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, model.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(model.ChainFamilyEVM, req.To); err != nil {
		return err
	}
	if err := enforceBigCap(req.Value, key.Policy.MaxValue, "value"); err != nil {
		return err
	}
	if err := enforceBigCap(req.GasPrice, key.Policy.MaxGasPrice, "gas_price"); err != nil {
		return err
	}
	if err := enforceGasLimit(req.GasLimit, key.Policy.MaxGasLimit); err != nil {
		return err
	}
	return nil
}

func ValidateEVMEIP1559Transfer(key model.Key, req v1.EVMEIP1559TransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, model.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(model.ChainFamilyEVM, req.To); err != nil {
		return err
	}
	if err := enforceBigCap(req.Value, key.Policy.MaxValue, "value"); err != nil {
		return err
	}
	if err := enforceGasLimit(req.GasLimit, key.Policy.MaxGasLimit); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxFeePerGas, key.Policy.MaxFeePerGas, "max_fee_per_gas"); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxPriorityFeePerGas, key.Policy.MaxPriorityFeePerGas, "max_priority_fee_per_gas"); err != nil {
		return err
	}
	return nil
}

func ValidateEVMContractCall(key model.Key, req v1.EVMContractCallSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, model.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(model.ChainFamilyEVM, req.To); err != nil {
		return err
	}
	if strings.TrimSpace(req.Data) == "" {
		return fmt.Errorf("data is required for contract calls")
	}
	selector, err := model.SelectorFromHexData(req.Data)
	if err != nil {
		return err
	}
	if err := enforceTokenContractAllowlist(key.Policy, model.ChainFamilyEVM, req.To); err != nil {
		return err
	}
	if err := enforceSelectorAllowlist(key.Policy, selector); err != nil {
		return err
	}
	if err := enforceBigCap(req.Value, key.Policy.MaxValue, "value"); err != nil {
		return err
	}
	if err := enforceGasLimit(req.GasLimit, key.Policy.MaxGasLimit); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxFeePerGas, key.Policy.MaxFeePerGas, "max_fee_per_gas"); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxPriorityFeePerGas, key.Policy.MaxPriorityFeePerGas, "max_priority_fee_per_gas"); err != nil {
		return err
	}
	return nil
}

func ValidateTRXTransfer(key model.Key, req v1.TRXTransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, model.ChainFamilyTRON, nil); err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(model.ChainFamilyTRON, req.To); err != nil {
		return err
	}
	if err := enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount"); err != nil {
		return err
	}
	if err := enforceFeeLimit(req.FeeLimit, key.Policy.MaxFeeLimit); err != nil {
		return err
	}
	return nil
}

func ValidateTRC20Transfer(key model.Key, req v1.TRC20TransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, model.ChainFamilyTRON, nil); err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(model.ChainFamilyTRON, req.To); err != nil {
		return err
	}
	if _, err := model.NormalizeAddress(model.ChainFamilyTRON, req.TokenContract); err != nil {
		return err
	}
	if err := enforceBigCap(req.Amount, key.Policy.MaxValue, "amount"); err != nil {
		return err
	}
	if err := enforceFeeLimit(req.FeeLimit, key.Policy.MaxFeeLimit); err != nil {
		return err
	}
	if err := enforceTokenContractAllowlist(key.Policy, model.ChainFamilyTRON, req.TokenContract); err != nil {
		return err
	}
	if err := enforceSelectorAllowlist(key.Policy, model.TRC20TransferSelector); err != nil {
		return err
	}
	return nil
}

func validateBase(key model.Key, req v1.BaseSignRequest, expectedChainFamily string, chainID *int64) error {
	if !key.Active {
		return fmt.Errorf("key %q is disabled", key.ID)
	}
	if model.NormalizeChainFamily(req.ChainFamily) != expectedChainFamily {
		return fmt.Errorf("request chain family %q does not match endpoint", req.ChainFamily)
	}
	if model.NormalizeChainFamily(key.ChainFamily) != expectedChainFamily {
		return fmt.Errorf("key %q is bound to chain family %q", key.ID, key.ChainFamily)
	}
	if !model.EqualAddress(expectedChainFamily, req.SourceAddress, key.SignerAddress) {
		return fmt.Errorf("source address does not match key signer address")
	}
	if err := enforceNetwork(key.Policy, req.Network, chainID); err != nil {
		return err
	}
	return nil
}

func enforceNetwork(policy model.Policy, network string, chainID *int64) error {
	if len(policy.AllowedNetworks) > 0 {
		found := false
		for _, candidate := range policy.AllowedNetworks {
			if candidate == network {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("network %q is not allowed", network)
		}
	}
	if chainID != nil && len(policy.AllowedChainIDs) > 0 {
		found := false
		for _, candidate := range policy.AllowedChainIDs {
			if candidate == *chainID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("chain_id %d is not allowed", *chainID)
		}
	}
	return nil
}

func enforceBigCap(value, capValue, field string) error {
	if strings.TrimSpace(capValue) == "" {
		return nil
	}
	actual, err := model.ParseBigInt(value)
	if err != nil {
		return fmt.Errorf("parse %s: %w", field, err)
	}
	capInt, err := model.ParseBigInt(capValue)
	if err != nil {
		return fmt.Errorf("parse %s cap: %w", field, err)
	}
	if actual.Cmp(capInt) > 0 {
		return fmt.Errorf("%s exceeds configured cap", field)
	}
	return nil
}

func enforceGasLimit(actual, capValue uint64) error {
	if capValue == 0 {
		return nil
	}
	if actual > capValue {
		return fmt.Errorf("gas_limit exceeds configured cap")
	}
	return nil
}

func enforceFeeLimit(actual, capValue int64) error {
	if capValue == 0 {
		return nil
	}
	if actual > capValue {
		return fmt.Errorf("fee_limit exceeds configured cap")
	}
	return nil
}

func enforceTokenContractAllowlist(policy model.Policy, chainFamily, contract string) error {
	if len(policy.AllowedTokenContracts) == 0 {
		return nil
	}
	normalized, err := model.NormalizeAddress(chainFamily, contract)
	if err != nil {
		return err
	}
	for _, allowed := range policy.AllowedTokenContracts {
		candidate, err := model.NormalizeAddress(chainFamily, allowed)
		if err != nil {
			continue
		}
		if candidate == normalized {
			return nil
		}
	}
	return fmt.Errorf("token contract is not allowlisted")
}

func enforceSelectorAllowlist(policy model.Policy, selector string) error {
	if len(policy.AllowedSelectors) == 0 {
		return nil
	}
	selector = model.NormalizeSelector(selector)
	for _, allowed := range policy.AllowedSelectors {
		if model.NormalizeSelector(allowed) == selector {
			return nil
		}
	}
	return fmt.Errorf("selector %q is not allowlisted", selector)
}
