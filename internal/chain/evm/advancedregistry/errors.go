package advancedregistry

type UnsupportedDimension string

const (
	UnsupportedEIP712Schema          UnsupportedDimension = "eip712_schema"
	UnsupportedERC4337Protocol       UnsupportedDimension = "erc4337_protocol"
	UnsupportedAccountImplementation UnsupportedDimension = "account_implementation"
	UnsupportedAccountSigningSchema  UnsupportedDimension = "account_signing_schema"
)

// UnsupportedError preserves the compatibility dimension independently of
// human-readable wording used at the API boundary.
type UnsupportedError struct {
	Dimension UnsupportedDimension
	Message   string
}

func (e *UnsupportedError) Error() string { return e.Message }
