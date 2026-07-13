package v1

import ethtypes "github.com/ethereum/go-ethereum/core/types"

const (
	EIP7702AuthorizationSchemaV1     = "eip7702-v1"
	EIP7702TransactionTypeV1         = "eip7702-type-4"
	EIP7702TransactionTypeNumber     = ethtypes.SetCodeTxType
	OperationEVMEIP7702Authorization = "evm_eip7702_authorization"
	OperationEVMEIP7702Transaction   = "evm_eip7702_transaction"
)

type EIP7702Authorization struct {
	ChainID string `json:"chain_id"`
	Address string `json:"address"`
	Nonce   string `json:"nonce"`
}

type EIP7702SignedAuthorization struct {
	EIP7702Authorization
	YParity uint8  `json:"y_parity"`
	R       string `json:"r"`
	S       string `json:"s"`
}

type EVMEIP7702AuthorizationSignRequest struct {
	EIP7702Authorization
	EVMKeyRequestContext
	AuthorityAddress    string `json:"authority_address"`
	AuthorizationSchema string `json:"authorization_schema"`
}

func (r *EVMEIP7702AuthorizationSignRequest) UnmarshalJSON(data []byte) error {
	type alias EVMEIP7702AuthorizationSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMEIP7702AuthorizationSignRequest(decoded)
	return nil
}

type EVMEIP7702AuthorizationSignResponse struct {
	EVMOperationResponseBase
	EIP7702SignedAuthorization
	AuthorizationSchema     string `json:"authorization_schema"`
	AuthorityAddress        string `json:"authority_address"`
	AuthorizationHash       string `json:"authorization_hash"`
	SerializedAuthorization string `json:"serialized_authorization"`
}

type EVMEIP7702AuthorizationVerifyRequest struct {
	EIP7702SignedAuthorization
	EVMRequestContext
	ExpectedAuthorityAddress string `json:"expected_authority_address"`
	AuthorizationSchema      string `json:"authorization_schema"`
}

func (r *EVMEIP7702AuthorizationVerifyRequest) UnmarshalJSON(data []byte) error {
	type alias EVMEIP7702AuthorizationVerifyRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMEIP7702AuthorizationVerifyRequest(decoded)
	return nil
}

type EVMEIP7702AuthorizationVerifyResponse struct {
	EVMResponseContext
	AuthorizationHash  string `json:"authorization_hash"`
	RecoveredAuthority string `json:"recovered_authority"`
	AuthorizationValid bool   `json:"authorization_valid"`
}

type EVMAccessTuple struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storage_keys"`
}

type EIP7702TransactionFields struct {
	ChainID              string           `json:"chain_id"`
	Nonce                string           `json:"nonce"`
	To                   string           `json:"to"`
	Value                string           `json:"value"`
	GasLimit             string           `json:"gas_limit"`
	MaxFeePerGas         string           `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string           `json:"max_priority_fee_per_gas"`
	Data                 string           `json:"data"`
	AccessList           []EVMAccessTuple `json:"access_list"`
}

type EVMEIP7702TransactionSignRequest struct {
	EVMKeyRequestContext
	EIP7702TransactionFields
	SourceAddress     string                       `json:"source_address"`
	AuthorizationList []EIP7702SignedAuthorization `json:"authorization_list"`
}

func (r *EVMEIP7702TransactionSignRequest) UnmarshalJSON(data []byte) error {
	type alias EVMEIP7702TransactionSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMEIP7702TransactionSignRequest(decoded)
	return nil
}

type EVMEIP7702TransactionSignResponse struct {
	EVMOperationResponseBase
	TransactionType        string `json:"transaction_type"`
	TransactionHash        string `json:"transaction_hash"`
	TransactionSigningHash string `json:"transaction_signing_hash"`
	SignedPayload          string `json:"signed_payload"`
	PayloadEncoding        string `json:"payload_encoding"`
}

type EVMEIP7702TransactionRecoverRequest struct {
	EVMRequestContext
	SignedPayload         string `json:"signed_payload"`
	ExpectedSignerAddress string `json:"expected_signer_address,omitempty"`
}

func (r *EVMEIP7702TransactionRecoverRequest) UnmarshalJSON(data []byte) error {
	type alias EVMEIP7702TransactionRecoverRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMEIP7702TransactionRecoverRequest(decoded)
	return nil
}

type EIP7702DecodedAuthorization struct {
	EIP7702SignedAuthorization
	AuthorityAddress string `json:"authority_address"`
}

type EIP7702DecodedTransaction struct {
	EIP7702TransactionFields
	AuthorizationList []EIP7702DecodedAuthorization `json:"authorization_list"`
}

type EVMEIP7702TransactionRecoverResponse struct {
	EVMResponseContext
	TransactionHash    string                    `json:"transaction_hash"`
	TransactionType    string                    `json:"transaction_type"`
	RecoveredSigner    string                    `json:"recovered_signer"`
	ExpectedSigner     string                    `json:"expected_signer,omitempty"`
	MatchesExpected    bool                      `json:"matches_expected"`
	DecodedTransaction EIP7702DecodedTransaction `json:"decoded_transaction"`
}
