package v1

import "github.com/chain-signer/chain-signer/pkg/model"

const APIVersion = model.APIVersion

type CreateKeyRequest struct {
	KeyID             string            `json:"key_id,omitempty"`
	ChainFamily       string            `json:"chain_family"`
	CustodyMode       string            `json:"custody_mode,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Policy            model.Policy      `json:"policy,omitempty"`
	ImportPrivateKey  string            `json:"import_private_key_hex,omitempty"`
	PublicKeyHex      string            `json:"public_key_hex,omitempty"`
	ExternalSignerRef string            `json:"external_signer_ref,omitempty"`
}

type UpdateKeyStatusRequest struct {
	Active bool `json:"active"`
}

type KeyResponse struct {
	APIVersion    string            `json:"api_version"`
	KeyID         string            `json:"key_id"`
	ChainFamily   string            `json:"chain_family"`
	CustodyMode   string            `json:"custody_mode"`
	Active        bool              `json:"active"`
	Labels        map[string]string `json:"labels,omitempty"`
	Policy        model.Policy      `json:"policy,omitempty"`
	SignerAddress string            `json:"signer_address"`
	PublicKeyHex  string            `json:"public_key_hex"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

type BaseSignRequest struct {
	KeyID         string            `json:"key_id"`
	ChainFamily   string            `json:"chain_family"`
	Network       string            `json:"network"`
	RequestID     string            `json:"request_id"`
	Labels        map[string]string `json:"labels,omitempty"`
	ApprovalRef   string            `json:"approval_ref,omitempty"`
	SourceAddress string            `json:"source_address"`
}

type EVMLegacyTransferSignRequest struct {
	BaseSignRequest
	ChainID  int64  `json:"chain_id"`
	To       string `json:"to"`
	Value    string `json:"value"`
	Nonce    uint64 `json:"nonce"`
	GasLimit uint64 `json:"gas_limit"`
	GasPrice string `json:"gas_price"`
}

type EVMEIP1559TransferSignRequest struct {
	BaseSignRequest
	ChainID              int64  `json:"chain_id"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Nonce                uint64 `json:"nonce"`
	GasLimit             uint64 `json:"gas_limit"`
	MaxFeePerGas         string `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"`
}

type EVMContractCallSignRequest struct {
	BaseSignRequest
	ChainID              int64  `json:"chain_id"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Data                 string `json:"data"`
	Nonce                uint64 `json:"nonce"`
	GasLimit             uint64 `json:"gas_limit"`
	MaxFeePerGas         string `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"`
}

type TRXTransferSignRequest struct {
	BaseSignRequest
	To            string `json:"to"`
	Amount        int64  `json:"amount"`
	FeeLimit      int64  `json:"fee_limit"`
	RefBlockBytes string `json:"ref_block_bytes"`
	RefBlockHash  string `json:"ref_block_hash"`
	RefBlockNum   int64  `json:"ref_block_num,omitempty"`
	Timestamp     int64  `json:"timestamp"`
	Expiration    int64  `json:"expiration"`
}

type TRC20TransferSignRequest struct {
	BaseSignRequest
	To            string `json:"to"`
	TokenContract string `json:"token_contract"`
	Amount        string `json:"amount"`
	FeeLimit      int64  `json:"fee_limit"`
	RefBlockBytes string `json:"ref_block_bytes"`
	RefBlockHash  string `json:"ref_block_hash"`
	RefBlockNum   int64  `json:"ref_block_num,omitempty"`
	Timestamp     int64  `json:"timestamp"`
	Expiration    int64  `json:"expiration"`
}

type SignResponse struct {
	APIVersion      string `json:"api_version"`
	KeyID           string `json:"key_id"`
	ChainFamily     string `json:"chain_family"`
	Network         string `json:"network"`
	Operation       string `json:"operation"`
	SignerAddress   string `json:"signer_address"`
	TxHash          string `json:"tx_hash"`
	SignedPayload   string `json:"signed_payload"`
	PayloadEncoding string `json:"payload_encoding"`
}

type VerifyRequest struct {
	ChainFamily           string `json:"chain_family"`
	Network               string `json:"network"`
	Operation             string `json:"operation,omitempty"`
	SignedPayload         string `json:"signed_payload"`
	ExpectedSignerAddress string `json:"expected_signer_address,omitempty"`
}

type RecoverResponse struct {
	APIVersion      string `json:"api_version"`
	ChainFamily     string `json:"chain_family"`
	Network         string `json:"network"`
	Operation       string `json:"operation"`
	RecoveredSigner string `json:"recovered_signer"`
	ExpectedSigner  string `json:"expected_signer,omitempty"`
	MatchesExpected bool   `json:"matches_expected"`
	TxHash          string `json:"tx_hash"`
}
