package policy

import (
	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func ValidateTRONWithdrawBalance(key domain.Key, req *v1.TRONWithdrawBalanceSignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	return validateTRONResourceEnvelope(req.TRONRawDataEnvelope)
}
