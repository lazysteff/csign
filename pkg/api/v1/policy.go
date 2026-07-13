package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Policy struct {
	AllowedNetworks       []string `json:"allowed_networks,omitempty"`
	AllowedChainIDs       []int64  `json:"allowed_chain_ids,omitempty"`
	MaxValue              string   `json:"max_value,omitempty"`
	MaxGasLimit           uint64   `json:"max_gas_limit,omitempty"`
	MaxGasPrice           string   `json:"max_gas_price,omitempty"`
	MaxFeePerGas          string   `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas  string   `json:"max_priority_fee_per_gas,omitempty"`
	MaxFeeLimit           int64    `json:"max_fee_limit,omitempty"`
	AllowedTokenContracts []string `json:"allowed_token_contracts,omitempty"`
	AllowedSelectors      []string `json:"allowed_selectors,omitempty"`
	// Legacy compatibility: AdditionalPolicyContext is retained only for decoding
	// and returning older key records. Structured policy updates do not accept it.
	AdditionalPolicyContext       map[string]string `json:"additional_policy_context,omitempty"`
	AllowedSigningOperations      []string          `json:"allowed_signing_operations,omitempty"`
	AllowedEIP712Schemas          []string          `json:"allowed_eip712_schemas,omitempty"`
	AllowedERC4337Versions        []string          `json:"allowed_erc4337_versions,omitempty"`
	AllowedEntryPoints            []string          `json:"allowed_entry_points,omitempty"`
	AllowedAccountImplementations []string          `json:"allowed_account_implementations,omitempty"`
	AllowedAccountSigningSchemas  []string          `json:"allowed_account_signing_schemas,omitempty"`
	AllowedEIP7702Delegates       []string          `json:"allowed_eip7702_delegates,omitempty"`
	AllowEIP7702Revocation        bool              `json:"allow_eip7702_revocation,omitempty"`
	AllowEIP7702ChainIDZero       bool              `json:"allow_eip7702_chain_id_zero,omitempty"`
	AllowedTransactionTypes       []string          `json:"allowed_transaction_types,omitempty"`
	AllowedContractDestinations   []string          `json:"allowed_contract_destinations,omitempty"`
	MaxAuthorizationListEntries   uint64            `json:"max_authorization_list_entries,omitempty"`
}

// StructuredPolicy is the typed policy contract accepted by policy-update
// requests. It intentionally excludes opaque application policy context.
type StructuredPolicy struct {
	AllowedNetworks               []string `json:"allowed_networks,omitempty"`
	AllowedChainIDs               []int64  `json:"allowed_chain_ids,omitempty"`
	MaxValue                      string   `json:"max_value,omitempty"`
	MaxGasLimit                   uint64   `json:"max_gas_limit,omitempty"`
	MaxGasPrice                   string   `json:"max_gas_price,omitempty"`
	MaxFeePerGas                  string   `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas          string   `json:"max_priority_fee_per_gas,omitempty"`
	MaxFeeLimit                   int64    `json:"max_fee_limit,omitempty"`
	AllowedTokenContracts         []string `json:"allowed_token_contracts,omitempty"`
	AllowedSelectors              []string `json:"allowed_selectors,omitempty"`
	AllowedSigningOperations      []string `json:"allowed_signing_operations,omitempty"`
	AllowedEIP712Schemas          []string `json:"allowed_eip712_schemas,omitempty"`
	AllowedERC4337Versions        []string `json:"allowed_erc4337_versions,omitempty"`
	AllowedEntryPoints            []string `json:"allowed_entry_points,omitempty"`
	AllowedAccountImplementations []string `json:"allowed_account_implementations,omitempty"`
	AllowedAccountSigningSchemas  []string `json:"allowed_account_signing_schemas,omitempty"`
	AllowedEIP7702Delegates       []string `json:"allowed_eip7702_delegates,omitempty"`
	AllowEIP7702Revocation        bool     `json:"allow_eip7702_revocation,omitempty"`
	AllowEIP7702ChainIDZero       bool     `json:"allow_eip7702_chain_id_zero,omitempty"`
	AllowedTransactionTypes       []string `json:"allowed_transaction_types,omitempty"`
	AllowedContractDestinations   []string `json:"allowed_contract_destinations,omitempty"`
	MaxAuthorizationListEntries   uint64   `json:"max_authorization_list_entries,omitempty"`
}

func (p Policy) IsZero() bool {
	return len(p.AllowedNetworks) == 0 &&
		len(p.AllowedChainIDs) == 0 &&
		p.MaxValue == "" &&
		p.MaxGasLimit == 0 &&
		p.MaxGasPrice == "" &&
		p.MaxFeePerGas == "" &&
		p.MaxPriorityFeePerGas == "" &&
		p.MaxFeeLimit == 0 &&
		len(p.AllowedTokenContracts) == 0 &&
		len(p.AllowedSelectors) == 0 &&
		len(p.AdditionalPolicyContext) == 0 &&
		len(p.AllowedSigningOperations) == 0 &&
		len(p.AllowedEIP712Schemas) == 0 &&
		len(p.AllowedERC4337Versions) == 0 &&
		len(p.AllowedEntryPoints) == 0 &&
		len(p.AllowedAccountImplementations) == 0 &&
		len(p.AllowedAccountSigningSchemas) == 0 &&
		len(p.AllowedEIP7702Delegates) == 0 &&
		!p.AllowEIP7702Revocation &&
		!p.AllowEIP7702ChainIDZero &&
		len(p.AllowedTransactionTypes) == 0 &&
		len(p.AllowedContractDestinations) == 0 &&
		p.MaxAuthorizationListEntries == 0
}

type UpdateKeyPolicyRequest struct {
	Policy    StructuredPolicy `json:"policy"`
	policySet bool
}

func (r *UpdateKeyPolicyRequest) UnmarshalJSON(data []byte) error {
	type alias UpdateKeyPolicyRequest
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = UpdateKeyPolicyRequest(decoded)
	policy, ok := raw["policy"]
	if ok && bytes.Equal(bytes.TrimSpace(policy), []byte("null")) {
		return fmt.Errorf("policy must not be null")
	}
	r.policySet = ok
	return nil
}

// HasPolicy reports whether a policy member was present during JSON decoding.
// It is a transport presence check, not a test for a non-zero Policy value.
func (r UpdateKeyPolicyRequest) HasPolicy() bool {
	return r.policySet
}
