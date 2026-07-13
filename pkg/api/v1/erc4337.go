package v1

const (
	ERC4337ProtocolV09                    = "erc4337-v0.9"
	ERC4337EntryPointV09                  = "0x433709009b8330fda32311df1c2afa402ed8d009"
	ERC4337AccountSimpleAccount           = "simple-account"
	ERC4337AccountSimpleAccountVersion    = "0.9"
	ERC4337SimpleAccountSigningSchema     = "simple-account-eip712-v1"
	ERC4337SimpleAccountSignatureEncoding = SignatureEncodingRSV27
	OperationEVMERC4337UserOperation      = "evm_erc4337_user_operation"
)

type ERC4337Factory struct {
	Address string `json:"address"`
	Data    string `json:"data"`
}

type ERC4337Paymaster struct {
	Address              string `json:"address"`
	VerificationGasLimit string `json:"verification_gas_limit"`
	PostOpGasLimit       string `json:"post_op_gas_limit"`
	Data                 string `json:"data"`
	Signature            string `json:"signature,omitempty"`
}

type ERC4337EIP7702Context struct {
	DelegateAddress string `json:"delegate_address"`
	Data            string `json:"data"`
}

type ERC4337UserOperationV09 struct {
	Sender               string                 `json:"sender"`
	Nonce                string                 `json:"nonce"`
	Factory              *ERC4337Factory        `json:"factory,omitempty"`
	EIP7702              *ERC4337EIP7702Context `json:"eip7702,omitempty"`
	CallData             string                 `json:"call_data"`
	CallGasLimit         string                 `json:"call_gas_limit"`
	VerificationGasLimit string                 `json:"verification_gas_limit"`
	PreVerificationGas   string                 `json:"pre_verification_gas"`
	MaxFeePerGas         string                 `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string                 `json:"max_priority_fee_per_gas"`
	Paymaster            *ERC4337Paymaster      `json:"paymaster,omitempty"`
}

type ERC4337OperationDescriptor struct {
	EntryPoint                   string `json:"entry_point"`
	ProtocolVersion              string `json:"protocol_version"`
	AccountImplementation        string `json:"account_implementation"`
	AccountImplementationVersion string `json:"account_implementation_version"`
	AccountSigningSchema         string `json:"account_signing_schema"`
}

type EVMUserOperationSignRequest struct {
	EVMAdvancedSignRequestBase
	ERC4337OperationDescriptor
	UserOperation             ERC4337UserOperationV09 `json:"user_operation"`
	ExpectedUserOperationHash string                  `json:"expected_user_operation_hash,omitempty"`
}

func (r *EVMUserOperationSignRequest) UnmarshalJSON(data []byte) error {
	type alias EVMUserOperationSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMUserOperationSignRequest(decoded)
	return nil
}

type EVMUserOperationSignResponse struct {
	EVMOperationResponseBase
	ProtocolVersion              string `json:"protocol_version"`
	AccountImplementation        string `json:"account_implementation"`
	AccountImplementationVersion string `json:"account_implementation_version"`
	AccountSigningSchema         string `json:"account_signing_schema"`
	UserOperationHash            string `json:"user_operation_hash"`
	AccountSigningDigest         string `json:"account_signing_digest"`
	Signature                    string `json:"signature"`
	SignatureEncoding            string `json:"signature_encoding"`
}

type EVMUserOperationVerifyRequest struct {
	EVMRequestContext
	EVMSignerExpectation
	ERC4337OperationDescriptor
	UserOperation ERC4337UserOperationV09 `json:"user_operation"`
	Signature     string                  `json:"signature"`
}

func (r *EVMUserOperationVerifyRequest) UnmarshalJSON(data []byte) error {
	type alias EVMUserOperationVerifyRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMUserOperationVerifyRequest(decoded)
	return nil
}

type EVMUserOperationVerifyResponse struct {
	EVMResponseContext
	ProtocolVersion       string `json:"protocol_version"`
	AccountImplementation string `json:"account_implementation"`
	UserOperationHash     string `json:"user_operation_hash"`
	AccountSigningDigest  string `json:"account_signing_digest"`
	RecoveredSigner       string `json:"recovered_signer"`
	SignatureValid        bool   `json:"signature_valid"`
}
