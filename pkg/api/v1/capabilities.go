package v1

type EIP712SchemaCapability struct {
	ID                string `json:"id"`
	Version           string `json:"version"`
	PrimaryType       string `json:"primary_type"`
	SignatureEncoding string `json:"signature_encoding"`
}

type ERC4337AccountCapability struct {
	ID                string   `json:"id"`
	Version           string   `json:"version"`
	ProtocolVersions  []string `json:"protocol_versions"`
	SigningSchemas    []string `json:"signing_schemas"`
	SignatureEncoding string   `json:"signature_encoding"`
}

type EIP7702TransactionCapability struct {
	ID     string `json:"id"`
	Number uint8  `json:"number"`
}

type VersionResponse struct {
	APIVersion                           string                         `json:"api_version"`
	BuildVersion                         string                         `json:"build_version"`
	SupportedRoutes                      []string                       `json:"supported_routes,omitempty"`
	SupportedEIP712Schemas               []EIP712SchemaCapability       `json:"supported_eip712_schemas,omitempty"`
	SupportedERC4337ProtocolVersions     []string                       `json:"supported_erc4337_protocol_versions,omitempty"`
	SupportedAccountImplementations      []ERC4337AccountCapability     `json:"supported_account_implementations,omitempty"`
	SupportedAccountSigningSchemas       []string                       `json:"supported_account_signing_schemas,omitempty"`
	SupportedEIP7702AuthorizationSchemas []string                       `json:"supported_eip7702_authorization_schemas,omitempty"`
	SupportedEIP7702TransactionTypes     []EIP7702TransactionCapability `json:"supported_eip7702_transaction_types,omitempty"`
}
