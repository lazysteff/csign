package policy

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type Validator func(domain.Key, any) error

type Evaluator interface {
	Validate(domain.Key, any, Validator) error
}

type DefaultEvaluator struct{}

func (DefaultEvaluator) Validate(key domain.Key, request any, validator Validator) error {
	if validator == nil {
		return faults.New(faults.Internal, "operation validator is required")
	}
	return validator(key, request)
}

func ValidateCreateKeyRequest(req v1.CreateKeyRequest) error {
	chainFamily := domain.NormalizeChainFamily(req.ChainFamily)
	if chainFamily != v1.ChainFamilyEVM && chainFamily != v1.ChainFamilyTRON {
		return faults.Newf(faults.Invalid, "unsupported chain family %q", req.ChainFamily)
	}

	custodyMode := domain.NormalizeCustodyMode(req.CustodyMode)
	if custodyMode == "" {
		custodyMode = v1.CustodyModeMVP
	}

	switch custodyMode {
	case v1.CustodyModeMVP:
		if strings.TrimSpace(req.ExternalSignerRef) != "" {
			return faults.New(faults.Invalid, "external_signer_ref is only valid in pkcs11 mode")
		}
	case v1.CustodyModePKCS11:
		if strings.TrimSpace(req.ImportPrivateKey) != "" {
			return faults.New(faults.Invalid, "import_private_key_hex is not allowed in pkcs11 mode")
		}
		if strings.TrimSpace(req.PublicKeyHex) == "" {
			return faults.New(faults.Invalid, "public_key_hex is required in pkcs11 mode")
		}
		if strings.TrimSpace(req.ExternalSignerRef) == "" {
			return faults.New(faults.Invalid, "external_signer_ref is required in pkcs11 mode")
		}
	default:
		return faults.Newf(faults.Invalid, "unsupported custody mode %q", req.CustodyMode)
	}

	return nil
}

func ValidateEVMLegacyTransfer(key domain.Key, req *v1.EVMLegacyTransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyEVM, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
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

func ValidateEVMEIP1559Transfer(key domain.Key, req *v1.EVMEIP1559TransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyEVM, &req.ChainID); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyEVM, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
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
	if err := enforceTokenContractAllowlist(key.Policy, v1.ChainFamilyEVM, req.To); err != nil {
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

func ValidateTRXTransfer(key domain.Key, req *v1.TRXTransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyTRON, nil); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount"); err != nil {
		return err
	}
	if err := enforceFeeLimit(req.FeeLimit, key.Policy.MaxFeeLimit); err != nil {
		return err
	}
	return nil
}

func ValidateTRC20Transfer(key domain.Key, req *v1.TRC20TransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyTRON, nil); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.TokenContract); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceBigCap(req.Amount, key.Policy.MaxValue, "amount"); err != nil {
		return err
	}
	if err := enforceFeeLimit(req.FeeLimit, key.Policy.MaxFeeLimit); err != nil {
		return err
	}
	if err := enforceTokenContractAllowlist(key.Policy, v1.ChainFamilyTRON, req.TokenContract); err != nil {
		return err
	}
	if err := enforceSelectorAllowlist(key.Policy, domain.TRC20TransferSelector); err != nil {
		return err
	}
	return nil
}

func validateBase(key domain.Key, req v1.BaseSignRequest, expectedChainFamily string, chainID *int64) error {
	return validateBaseFields(key, req.ChainFamily, req.Network, req.SourceAddress, "source address", expectedChainFamily, chainID)
}

func validateBaseFields(key domain.Key, requestChainFamily, network, signerAddress, signerLabel, expectedChainFamily string, chainID *int64) error {
	if !key.Active {
		return faults.Newf(faults.PolicyDenied, "key %q is disabled", key.ID)
	}
	if domain.NormalizeChainFamily(requestChainFamily) != expectedChainFamily {
		return faults.Newf(faults.Invalid, "request chain family %q does not match endpoint", requestChainFamily)
	}
	if domain.NormalizeChainFamily(key.ChainFamily) != expectedChainFamily {
		return faults.Newf(faults.Invalid, "key %q is bound to chain family %q", key.ID, key.ChainFamily)
	}
	if !chain.EqualAddress(expectedChainFamily, signerAddress, key.SignerAddress) {
		return faults.Newf(faults.Invalid, "%s does not match key signer address", signerLabel)
	}
	if err := enforceNetwork(key.Policy, network, chainID); err != nil {
		return err
	}
	return nil
}

func enforceNetwork(policy v1.Policy, network string, chainID *int64) error {
	if len(policy.AllowedNetworks) > 0 {
		found := false
		for _, candidate := range policy.AllowedNetworks {
			if candidate == network {
				found = true
				break
			}
		}
		if !found {
			return faults.Newf(faults.PolicyDenied, "network %q is not allowed", network)
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
			return faults.Newf(faults.PolicyDenied, "chain_id %d is not allowed", *chainID)
		}
	}
	return nil
}

func enforceBigCap(value, capValue, field string) error {
	if strings.TrimSpace(capValue) == "" {
		return nil
	}
	actual, err := enc.ParseBigInt(value)
	if err != nil {
		return faults.Newf(faults.Invalid, "parse %s: %v", field, err)
	}
	capInt, err := enc.ParseBigInt(capValue)
	if err != nil {
		return faults.Newf(faults.Invalid, "parse %s cap: %v", field, err)
	}
	if actual.Cmp(capInt) > 0 {
		return faults.Newf(faults.PolicyDenied, "%s exceeds configured cap", field)
	}
	return nil
}

func enforceGasLimit(actual, capValue uint64) error {
	if capValue == 0 {
		return nil
	}
	if actual > capValue {
		return faults.New(faults.PolicyDenied, "gas_limit exceeds configured cap")
	}
	return nil
}

func enforceFeeLimit(actual, capValue int64) error {
	if capValue == 0 {
		return nil
	}
	if actual > capValue {
		return faults.New(faults.PolicyDenied, "fee_limit exceeds configured cap")
	}
	return nil
}

func enforceTokenContractAllowlist(policy v1.Policy, chainFamily, contract string) error {
	if len(policy.AllowedTokenContracts) == 0 {
		return nil
	}
	normalized, err := chain.NormalizeAddress(chainFamily, contract)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	for _, allowed := range policy.AllowedTokenContracts {
		candidate, err := chain.NormalizeAddress(chainFamily, allowed)
		if err != nil {
			continue
		}
		if candidate == normalized {
			return nil
		}
	}
	return faults.New(faults.PolicyDenied, "token contract is not allowlisted")
}

func enforceSelectorAllowlist(policy v1.Policy, selector string) error {
	if len(policy.AllowedSelectors) == 0 {
		return nil
	}
	selector = domain.NormalizeSelector(selector)
	for _, allowed := range policy.AllowedSelectors {
		if domain.NormalizeSelector(allowed) == selector {
			return nil
		}
	}
	return faults.Newf(faults.PolicyDenied, "selector %q is not allowlisted", selector)
}

func selectorFromHexData(data string) (string, error) {
	raw, err := enc.DecodeHex(data)
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("call data must include a 4-byte selector")
	}
	return strings.ToLower(hex.EncodeToString(raw[:4])), nil
}
