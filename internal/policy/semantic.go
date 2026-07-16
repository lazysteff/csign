package policy

import (
	"fmt"

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
