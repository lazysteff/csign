package v1

import "encoding/json"

const (
	APIVersion = "v1"

	ChainFamilyEVM  = "evm"
	ChainFamilyTRON = "tron"

	CustodyModeMVP    = "mvp"
	CustodyModePKCS11 = "pkcs11"

	OperationEVMTransferLegacy          = "evm_transfer_legacy"
	OperationEVMTransferEIP1559         = "evm_transfer_eip1559"
	OperationEVMContractEIP1559         = "evm_contract_call_eip1559"
	OperationTRXTransfer                = "tron_transfer_trx"
	OperationTRC20Transfer              = "tron_transfer_trc20"
	OperationTRONFreezeBalanceV2        = "tron_freeze_balance_v2"
	OperationTRONUnfreezeBalanceV2      = "tron_unfreeze_balance_v2"
	OperationTRONDelegateResource       = "tron_delegate_resource"
	OperationTRONUndelegateResource     = "tron_undelegate_resource"
	OperationTRONWithdrawExpireUnfreeze = "tron_withdraw_expire_unfreeze"
	OperationTRONVoteWitness            = "tron_vote_witness"
	OperationTRONWithdrawBalance        = "tron_withdraw_balance"
)

type CreateKeyRequest struct {
	KeyID             string            `json:"key_id,omitempty"`
	ChainFamily       string            `json:"chain_family"`
	CustodyMode       string            `json:"custody_mode,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Policy            Policy            `json:"policy,omitempty"`
	ImportPrivateKey  string            `json:"import_private_key_hex,omitempty"`
	PublicKeyHex      string            `json:"public_key_hex,omitempty"`
	ExternalSignerRef string            `json:"external_signer_ref,omitempty"`
	keyIDSet          bool
}

func (r CreateKeyRequest) MarshalJSON() ([]byte, error) {
	type alias CreateKeyRequest
	return marshalWithoutEmptyPolicy(alias(r), r.Policy)
}

func (r *CreateKeyRequest) UnmarshalJSON(data []byte) error {
	type alias CreateKeyRequest
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*r = CreateKeyRequest(decoded)
	_, r.keyIDSet = raw["key_id"]
	return nil
}

func (r CreateKeyRequest) HasKeyID() bool {
	return r.keyIDSet
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
	Policy        Policy            `json:"policy,omitempty"`
	SignerAddress string            `json:"signer_address"`
	PublicKeyHex  string            `json:"public_key_hex"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

func (r KeyResponse) MarshalJSON() ([]byte, error) {
	type alias KeyResponse
	return marshalWithoutEmptyPolicy(alias(r), r.Policy)
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

func (r BaseSignRequest) GetKeyID() string {
	return r.KeyID
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
	RequestID       string `json:"request_id,omitempty"`
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

func marshalWithoutEmptyPolicy[T any](value T, policy Policy) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if !policy.IsZero() {
		return raw, nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	delete(out, "policy")
	return json.Marshal(out)
}
