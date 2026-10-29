package policy

import (
	"github.com/lazysteff/csign/v2/internal/domain"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

func ValidateTRONWithdrawBalance(key domain.Key, req *v1.TRONWithdrawBalanceSignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	return validateTRONResourceEnvelope(req.TRONRawDataEnvelope)
}
