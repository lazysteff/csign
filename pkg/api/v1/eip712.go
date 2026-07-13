package v1

const (
	EIP712SchemaEIP2612Permit        = "eip2612-permit-v1"
	EIP712SchemaEIP2612PermitVersion = "1"
	OperationEVMEIP712Typed          = "evm_eip712_typed"
)

type EIP712Domain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	ChainID           string `json:"chain_id"`
	VerifyingContract string `json:"verifying_contract"`
}

type EIP2612PermitMessage struct {
	Owner    string `json:"owner"`
	Spender  string `json:"spender"`
	Value    string `json:"value"`
	Nonce    string `json:"nonce"`
	Deadline string `json:"deadline"`
}

type EIP712PermitPayload struct {
	SchemaID      string               `json:"schema_id"`
	SchemaVersion string               `json:"schema_version"`
	Domain        EIP712Domain         `json:"domain"`
	Message       EIP2612PermitMessage `json:"message"`
}

type EVMEIP712SignRequest struct {
	EVMAdvancedSignRequestBase
	EIP712PermitPayload
}

func (r *EVMEIP712SignRequest) UnmarshalJSON(data []byte) error {
	type alias EVMEIP712SignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMEIP712SignRequest(decoded)
	return nil
}

type EVMEIP712SignResponse struct {
	EVMOperationResponseBase
	SchemaID          string `json:"schema_id"`
	SchemaVersion     string `json:"schema_version"`
	DomainSeparator   string `json:"domain_separator"`
	StructHash        string `json:"struct_hash"`
	EIP712Digest      string `json:"eip712_digest"`
	Signature         string `json:"signature"`
	SignatureEncoding string `json:"signature_encoding"`
	R                 string `json:"r"`
	S                 string `json:"s"`
	V                 uint8  `json:"v"`
}

type EVMEIP712VerifyRequest struct {
	EVMRequestContext
	EVMSignerExpectation
	EIP712PermitPayload
	Signature string `json:"signature"`
}

func (r *EVMEIP712VerifyRequest) UnmarshalJSON(data []byte) error {
	type alias EVMEIP712VerifyRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = EVMEIP712VerifyRequest(decoded)
	return nil
}

type EVMEIP712VerifyResponse struct {
	EVMResponseContext
	SchemaID        string `json:"schema_id"`
	SchemaVersion   string `json:"schema_version"`
	Digest          string `json:"digest"`
	RecoveredSigner string `json:"recovered_signer"`
	SignatureValid  bool   `json:"signature_valid"`
}
