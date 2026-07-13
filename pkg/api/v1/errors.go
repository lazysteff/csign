package v1

// ErrorCode is the stable machine-readable classification used by advanced
// operation failures. Human-readable error messages are not part of this
// compatibility contract.
type ErrorCode string

const (
	ErrorUnsupportedEIP712Schema          ErrorCode = "unsupported_eip712_schema"
	ErrorInvalidEIP712Domain              ErrorCode = "invalid_eip712_domain"
	ErrorInvalidEIP712Message             ErrorCode = "invalid_eip712_message"
	ErrorUnsupportedERC4337Version        ErrorCode = "unsupported_erc4337_version"
	ErrorUnsupportedAccountImplementation ErrorCode = "unsupported_account_implementation"
	ErrorUnsupportedAccountSigningSchema  ErrorCode = "unsupported_account_signing_schema"
	ErrorInvalidUserOperation             ErrorCode = "invalid_user_operation"
	ErrorUserOperationHashMismatch        ErrorCode = "user_operation_hash_mismatch"
	ErrorInvalidEIP7702Authorization      ErrorCode = "invalid_eip7702_authorization"
	ErrorAuthorizationSignerMismatch      ErrorCode = "authorization_signer_mismatch"
	ErrorDelegateNotAllowed               ErrorCode = "delegate_not_allowed"
	ErrorEIP7702RevocationNotAllowed      ErrorCode = "eip7702_revocation_not_allowed"
	ErrorInvalidAuthorizationList         ErrorCode = "invalid_authorization_list"
	ErrorUnsupportedTransactionType       ErrorCode = "unsupported_transaction_type"
	ErrorType4TransactionNotSupported     ErrorCode = "type4_transaction_not_supported"
	ErrorSigningOperationNotAllowed       ErrorCode = "signing_operation_not_allowed"
	ErrorSignatureVerificationFailed      ErrorCode = "signature_verification_failed"
)
