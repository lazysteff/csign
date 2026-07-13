package policy

import (
	"fmt"
	"strings"

	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func validateAdvancedBase(key domain.Key, chainFamily, network, requestID, signerAddress, chainIDValue, operation string, allowZeroChainID bool) error {
	if !key.Active {
		return faults.Newf(faults.PolicyDenied, "key %q is disabled", key.ID)
	}
	if domain.NormalizeChainFamily(chainFamily) != v1.ChainFamilyEVM {
		return faults.Newf(faults.Invalid, "request chain family %q does not match endpoint", chainFamily)
	}
	if domain.NormalizeChainFamily(key.ChainFamily) != v1.ChainFamilyEVM {
		return faults.Newf(faults.Invalid, "key %q is bound to chain family %q", key.ID, key.ChainFamily)
	}
	if strings.TrimSpace(network) == "" {
		return faults.New(faults.Invalid, "network is required")
	}
	if strings.TrimSpace(requestID) == "" {
		return faults.New(faults.Invalid, "request_id is required")
	}
	parsedSigner, err := enc.ParseEVMAddress("expected signer address", signerAddress, false)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	storedSigner, err := enc.ParseEVMAddress("key signer address", strings.ToLower(key.SignerAddress), false)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if parsedSigner != storedSigner {
		if operation == v1.OperationEVMEIP7702Authorization {
			return faults.NewCode(faults.Invalid, faults.AuthorizationSignerMismatch, "authority_address does not match key signer address")
		}
		return faults.New(faults.Invalid, "expected signer address does not match key signer address")
	}
	if err := requireStringAllowed(key.Policy.AllowedSigningOperations, operation, "signing operation"); err != nil {
		return err
	}
	if err := requireStringAllowed(key.Policy.AllowedNetworks, network, "network"); err != nil {
		return err
	}
	chainID, err := enc.ParseCanonicalUint("chain_id", chainIDValue, 256, allowZeroChainID)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if chainID.Sign() == 0 && allowZeroChainID {
		return nil
	}
	if chainID.BitLen() > 63 {
		return faults.New(faults.PolicyDenied, "chain_id exceeds the range supported by allowed_chain_ids policy")
	}
	if len(key.Policy.AllowedChainIDs) == 0 {
		return faults.New(faults.PolicyDenied, "chain_id is not explicitly allowed")
	}
	for _, allowed := range key.Policy.AllowedChainIDs {
		if allowed > 0 && chainID.Int64() == allowed {
			return nil
		}
	}
	return faults.Newf(faults.PolicyDenied, "chain_id %s is not allowed", chainID.String())
}

func selectorFromCanonicalHex(data []byte) (string, error) {
	if len(data) < 4 {
		return "", faults.New(faults.PolicyDenied, "calldata must include a 4-byte selector when allowed_selectors is configured")
	}
	return fmt.Sprintf("%x", data[:4]), nil
}

func requireStringAllowed(allowed []string, value, label string) error {
	if len(allowed) == 0 {
		return disallowedValue(label, value, true)
	}
	for _, candidate := range allowed {
		if candidate == value {
			return nil
		}
	}
	return disallowedValue(label, value, false)
}

func requireAddressAllowed(allowed []string, value, label string) error {
	if len(allowed) == 0 {
		return disallowedValue(label, value, true)
	}
	parsed, err := enc.ParseEVMAddress(label, value, true)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	for _, candidate := range allowed {
		candidateAddress, err := enc.ParseEVMAddress(label+" policy value", strings.ToLower(candidate), true)
		if err == nil && candidateAddress == parsed {
			return nil
		}
	}
	return disallowedValue(label, value, false)
}

func disallowedValue(label, value string, omitted bool) error {
	message := fmt.Sprintf("%s %q is not allowed", label, value)
	if omitted {
		message = fmt.Sprintf("%s is not explicitly allowed", label)
	}
	switch label {
	case "signing operation":
		return faults.NewCode(faults.PolicyDenied, faults.SigningOperationNotAllowed, message)
	case "EIP-7702 delegate":
		return faults.NewCode(faults.PolicyDenied, faults.DelegateNotAllowed, message)
	default:
		return faults.New(faults.PolicyDenied, message)
	}
}
