package policy

import (
	"fmt"
	"maps"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

// SemanticallyEqual compares enforced policy values after canonicalizing fields
// whose wire representation is intentionally flexible. Omitted caps remain
// distinct from explicit zero caps; deprecated opaque context is ignored.
func SemanticallyEqual(catalog *signingops.Catalog, chainFamily string, expected, actual v1.Policy) (bool, error) {
	if catalog == nil {
		return false, fmt.Errorf("signing operation catalog is required")
	}
	if err := catalog.ValidateAllowlist(expected.AllowedSigningOperations); err != nil {
		return false, fmt.Errorf("expected allowed_signing_operations: %w", err)
	}
	if err := catalog.ValidateAllowlist(actual.AllowedSigningOperations); err != nil {
		return false, fmt.Errorf("actual allowed_signing_operations: %w", err)
	}
	comparisons := []struct {
		field     string
		expected  []string
		actual    []string
		normalize func(string) (string, error)
	}{
		{"allowed_networks", expected.AllowedNetworks, actual.AllowedNetworks, exactValue},
		{"allowed_signing_operations", expected.AllowedSigningOperations, actual.AllowedSigningOperations, exactValue},
		{"allowed_eip712_schemas", expected.AllowedEIP712Schemas, actual.AllowedEIP712Schemas, exactValue},
		{"allowed_erc4337_versions", expected.AllowedERC4337Versions, actual.AllowedERC4337Versions, exactValue},
		{"allowed_account_implementations", expected.AllowedAccountImplementations, actual.AllowedAccountImplementations, exactValue},
		{"allowed_account_signing_schemas", expected.AllowedAccountSigningSchemas, actual.AllowedAccountSigningSchemas, exactValue},
		{"allowed_transaction_types", expected.AllowedTransactionTypes, actual.AllowedTransactionTypes, exactValue},
		{"allowed_selectors", expected.AllowedSelectors, actual.AllowedSelectors, normalizeSelector},
		{"allowed_token_contracts", expected.AllowedTokenContracts, actual.AllowedTokenContracts, normalizeAddress(chainFamily)},
		{"allowed_eip712_verifying_contracts", expected.AllowedEIP712VerifyingContracts, actual.AllowedEIP712VerifyingContracts, normalizeAddress(v1.ChainFamilyEVM)},
		{"allowed_entry_points", expected.AllowedEntryPoints, actual.AllowedEntryPoints, normalizeAddress(v1.ChainFamilyEVM)},
		{"allowed_eip7702_delegates", expected.AllowedEIP7702Delegates, actual.AllowedEIP7702Delegates, normalizeAddress(v1.ChainFamilyEVM)},
		{"allowed_contract_destinations", expected.AllowedContractDestinations, actual.AllowedContractDestinations, normalizeAddress(v1.ChainFamilyEVM)},
	}
	for _, comparison := range comparisons {
		equal, err := equalStringSets(comparison.field, comparison.expected, comparison.actual, comparison.normalize)
		if err != nil || !equal {
			return equal, err
		}
	}
	equal, err := equalInt64Sets("allowed_chain_ids", expected.AllowedChainIDs, actual.AllowedChainIDs)
	if err != nil || !equal {
		return equal, err
	}

	for _, values := range []struct {
		field    string
		expected string
		actual   string
	}{
		{"max_value", expected.MaxValue, actual.MaxValue},
		{"max_gas_price", expected.MaxGasPrice, actual.MaxGasPrice},
		{"max_fee_per_gas", expected.MaxFeePerGas, actual.MaxFeePerGas},
		{"max_priority_fee_per_gas", expected.MaxPriorityFeePerGas, actual.MaxPriorityFeePerGas},
	} {
		equal, err := equalNumericCaps(values.field, values.expected, values.actual)
		if err != nil || !equal {
			return equal, err
		}
	}

	return expected.MaxGasLimit == actual.MaxGasLimit &&
		expected.MaxFeeLimit == actual.MaxFeeLimit &&
		expected.AllowEIP7702Revocation == actual.AllowEIP7702Revocation &&
		expected.AllowEIP7702ChainIDZero == actual.AllowEIP7702ChainIDZero &&
		expected.MaxAuthorizationListEntries == actual.MaxAuthorizationListEntries, nil
}

func equalStringSets(field string, left, right []string, normalize func(string) (string, error)) (bool, error) {
	leftSet, err := canonicalStringSet(field, left, normalize)
	if err != nil {
		return false, fmt.Errorf("expected %s: %w", field, err)
	}
	rightSet, err := canonicalStringSet(field, right, normalize)
	if err != nil {
		return false, fmt.Errorf("actual %s: %w", field, err)
	}
	return maps.Equal(leftSet, rightSet), nil
}

func canonicalStringSet(field string, values []string, normalize func(string) (string, error)) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		canonical, err := normalize(value)
		if err != nil {
			return nil, err
		}
		if _, exists := out[canonical]; exists {
			return nil, fmt.Errorf("%s contains duplicate value %q", field, value)
		}
		out[canonical] = struct{}{}
	}
	return out, nil
}

func exactValue(value string) (string, error) {
	return value, nil
}

func normalizeAddress(chainFamily string) func(string) (string, error) {
	return func(value string) (string, error) {
		return chain.NormalizeAddress(chainFamily, value)
	}
}

func normalizeSelector(value string) (string, error) {
	decoded, err := enc.DecodeHex(value)
	if err != nil || len(decoded) != 4 {
		return "", fmt.Errorf("selector %q must contain exactly four hexadecimal bytes", value)
	}
	return enc.EncodeHex(decoded), nil
}

func equalInt64Sets(field string, left, right []int64) (bool, error) {
	leftSet, err := canonicalInt64Set(field, left)
	if err != nil {
		return false, fmt.Errorf("expected %s: %w", field, err)
	}
	rightSet, err := canonicalInt64Set(field, right)
	if err != nil {
		return false, fmt.Errorf("actual %s: %w", field, err)
	}
	return maps.Equal(leftSet, rightSet), nil
}

func canonicalInt64Set(field string, values []int64) (map[int64]struct{}, error) {
	out := make(map[int64]struct{}, len(values))
	for _, value := range values {
		if _, exists := out[value]; exists {
			return nil, fmt.Errorf("%s contains duplicate value %d", field, value)
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func equalNumericCaps(field, left, right string) (bool, error) {
	leftOmitted := strings.TrimSpace(left) == ""
	rightOmitted := strings.TrimSpace(right) == ""
	if leftOmitted || rightOmitted {
		return leftOmitted == rightOmitted, nil
	}
	leftValue, err := enc.ParseEVMUint256(left)
	if err != nil {
		return false, fmt.Errorf("expected %s: %w", field, err)
	}
	rightValue, err := enc.ParseEVMUint256(right)
	if err != nil {
		return false, fmt.Errorf("actual %s: %w", field, err)
	}
	return leftValue.Cmp(rightValue) == 0, nil
}
