package service

import (
	"errors"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/routes"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

func classifyAdvancedExecutionError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "sign digest:") || strings.Contains(message, "custody sign digest:") {
		return faults.New(faults.CustodyFailed, "custody signing failed")
	}
	return faults.NewCode(faults.Invalid, faults.SignatureVerificationFailed, "signed artifact verification failed")
}

func classifyEIP712InspectionError(err error) error {
	message := err.Error()
	var unsupported *advancedregistry.UnsupportedError
	switch {
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedEIP712Schema:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedEIP712Schema, message)
	case isSignatureFailure(message):
		return faults.NewCode(faults.Invalid, faults.SignatureVerificationFailed, "EIP-712 signature verification failed")
	case strings.Contains(message, "domain") || strings.Contains(message, "chain_id"):
		return faults.NewCode(faults.Invalid, faults.InvalidEIP712Domain, message)
	default:
		return faults.NewCode(faults.Invalid, faults.InvalidEIP712Message, message)
	}
}

func classifyUserOperationInspectionError(err error) error {
	message := err.Error()
	var unsupported *advancedregistry.UnsupportedError
	switch {
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedERC4337Protocol:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedERC4337Version, message)
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedAccountImplementation:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedAccountImplementation, message)
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedAccountSigningSchema:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedAccountSigningSchema, message)
	case strings.Contains(message, "user_operation."):
		return faults.NewCode(faults.Invalid, faults.InvalidUserOperation, message)
	case isSignatureFailure(message):
		return faults.NewCode(faults.Invalid, faults.SignatureVerificationFailed, "UserOperation signature verification failed")
	default:
		return faults.NewCode(faults.Invalid, faults.InvalidUserOperation, message)
	}
}

func classifyAuthorizationInspectionError(err error) error {
	message := err.Error()
	if errors.Is(err, ethtypes.ErrInvalidSig) || isSignatureFailure(message) {
		return faults.NewCode(faults.Invalid, faults.SignatureVerificationFailed, "EIP-7702 authorization signature verification failed")
	}
	return faults.NewCode(faults.Invalid, faults.InvalidEIP7702Authorization, message)
}

func classifyType4InspectionError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "not EIP-7702 type") || strings.Contains(message, "transaction type"):
		return faults.NewCode(faults.Unsupported, faults.UnsupportedTransactionType, "signed payload is not an EIP-7702 type-4 transaction")
	case strings.Contains(message, "decode type-4 transaction"):
		return faults.NewCode(faults.Invalid, faults.InvalidAuthorizationList, "invalid EIP-7702 type-4 transaction payload")
	case strings.Contains(message, "authorization_list"):
		return faults.NewCode(faults.Invalid, faults.InvalidAuthorizationList, message)
	case isSignatureFailure(message):
		return faults.NewCode(faults.Invalid, faults.SignatureVerificationFailed, "EIP-7702 transaction signature verification failed")
	default:
		return faults.NewCode(faults.Invalid, faults.InvalidAuthorizationList, message)
	}
}

func isAdvancedSignRoute(route string) bool {
	switch route {
	case routes.EVMEIP712Sign,
		routes.EVMERC4337UserOperationSign,
		routes.EVMEIP7702AuthorizationSign,
		routes.EVMEIP7702TransactionSign:
		return true
	default:
		return false
	}
}

func isSignatureFailure(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "signature") || strings.Contains(message, "recover") || strings.Contains(message, "r or s") || strings.Contains(message, "low-s") || strings.Contains(message, "y parity")
}
