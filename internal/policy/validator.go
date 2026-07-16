package policy

import (
	"strings"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type Validator func(domain.Key, any) error

type Evaluator interface {
	Validate(domain.Key, any, Validator) error
}

type DefaultEvaluator struct{}

func (DefaultEvaluator) Validate(key domain.Key, request any, validator Validator) error {
	if validator == nil {
		return faults.New(faults.Internal, "operation validator is required")
	}
	return validator(key, request)
}

func ValidateCreateKeyRequest(req v1.CreateKeyRequest) error {
	chainFamily := domain.NormalizeChainFamily(req.ChainFamily)
	if chainFamily != v1.ChainFamilyEVM && chainFamily != v1.ChainFamilyTRON {
		return faults.Newf(faults.Invalid, "unsupported chain family %q", req.ChainFamily)
	}

	custodyMode := domain.NormalizeCustodyMode(req.CustodyMode)
	if custodyMode == "" {
		custodyMode = v1.CustodyModeMVP
	}

	switch custodyMode {
	case v1.CustodyModeMVP:
		if strings.TrimSpace(req.ExternalSignerRef) != "" {
			return faults.New(faults.Invalid, "external_signer_ref is only valid in pkcs11 mode")
		}
	case v1.CustodyModePKCS11:
		if strings.TrimSpace(req.ImportPrivateKey) != "" {
			return faults.New(faults.Invalid, "import_private_key_hex is not allowed in pkcs11 mode")
		}
		if strings.TrimSpace(req.PublicKeyHex) == "" {
			return faults.New(faults.Invalid, "public_key_hex is required in pkcs11 mode")
		}
		if strings.TrimSpace(req.ExternalSignerRef) == "" {
			return faults.New(faults.Invalid, "external_signer_ref is required in pkcs11 mode")
		}
	default:
		return faults.Newf(faults.Invalid, "unsupported custody mode %q", req.CustodyMode)
	}

	return nil
}
