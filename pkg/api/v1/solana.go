package v1

const (
	ChainFamilySolana             = "solana"
	OperationSolanaMessage        = "solana_message"
	KeyTypeSecp256k1              = "secp256k1"
	KeyTypeEd25519                = "ed25519"
	SigningSchemeECDSASecp256k1   = "ecdsa_secp256k1"
	SigningSchemeEd25519          = "ed25519"
	SolanaMaxMessageBytes         = 65536
	SolanaMaxMessageHexCharacters = 2*SolanaMaxMessageBytes + 2
)

type SolanaMessageSignRequest struct {
	KeyID                 string            `json:"key_id"`
	ChainFamily           string            `json:"chain_family"`
	Network               string            `json:"network"`
	RequestID             string            `json:"request_id"`
	MessageHex            string            `json:"message_hex"`
	ExpectedSignerAddress string            `json:"expected_signer_address,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	ApprovalRef           string            `json:"approval_ref,omitempty"`
}

func (r SolanaMessageSignRequest) GetKeyID() string { return r.KeyID }
func (r *SolanaMessageSignRequest) UnmarshalJSON(data []byte) error {
	type plain SolanaMessageSignRequest
	return strictUnmarshalJSON(data, (*plain)(r))
}

type SolanaMessageSignResponse struct {
	APIVersion        string `json:"api_version"`
	KeyID             string `json:"key_id"`
	ChainFamily       string `json:"chain_family"`
	Network           string `json:"network"`
	RequestID         string `json:"request_id"`
	Operation         string `json:"operation"`
	PublicKeyHex      string `json:"public_key_hex"`
	SignerAddress     string `json:"signer_address"`
	SigningScheme     string `json:"signing_scheme"`
	SignatureEncoding string `json:"signature_encoding"`
	SignatureHex      string `json:"signature_hex"`
}
