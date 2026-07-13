package v1

const (
	SignatureEncodingRSV27 = "rsv-v27"
	PayloadEncodingHex     = "hex"
)

type EVMRequestContext struct {
	ChainFamily string `json:"chain_family"`
	Network     string `json:"network"`
	RequestID   string `json:"request_id"`
}

type EVMKeyRequestContext struct {
	EVMRequestContext
	KeyID string `json:"key_id"`
}

func (r EVMKeyRequestContext) GetKeyID() string { return r.KeyID }

type EVMSignerExpectation struct {
	ExpectedSignerAddress string `json:"expected_signer_address"`
	ChainID               string `json:"chain_id"`
}

// EVMAdvancedSignRequestBase is shared by digest-oriented EVM operations whose
// signer is not necessarily a transaction source account.
type EVMAdvancedSignRequestBase struct {
	EVMKeyRequestContext
	EVMSignerExpectation
}

type EVMResponseContext struct {
	APIVersion  string `json:"api_version"`
	ChainFamily string `json:"chain_family"`
	Network     string `json:"network"`
	Operation   string `json:"operation"`
	RequestID   string `json:"request_id"`
}

type EVMOperationResponseBase struct {
	EVMResponseContext
	KeyID         string `json:"key_id"`
	SignerAddress string `json:"signer_address"`
}
