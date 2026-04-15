package policy

import (
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func ValidateTRONFreezeBalanceV2(key domain.Key, req *v1.TRONFreezeBalanceV2SignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	if err := validateTRONResourceEnvelope(req.TRONRawDataEnvelope); err != nil {
		return err
	}
	if _, err := validateTRONResource(req.Resource); err != nil {
		return err
	}
	if err := enforcePositiveAmount(req.Amount, "amount"); err != nil {
		return err
	}
	return enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount")
}

func ValidateTRONUnfreezeBalanceV2(key domain.Key, req *v1.TRONUnfreezeBalanceV2SignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	if err := validateTRONResourceEnvelope(req.TRONRawDataEnvelope); err != nil {
		return err
	}
	if _, err := validateTRONUnfreezeResource(req.Resource); err != nil {
		return err
	}
	if err := enforcePositiveAmount(req.Amount, "amount"); err != nil {
		return err
	}
	return enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount")
}

func ValidateTRONDelegateResource(key domain.Key, req *v1.TRONDelegateResourceSignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	if err := validateTRONResourceEnvelope(req.TRONRawDataEnvelope); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.ReceiverAddress); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if _, err := validateTRONResource(req.Resource); err != nil {
		return err
	}
	if err := enforcePositiveAmount(req.Amount, "amount"); err != nil {
		return err
	}
	if req.Lock && req.LockPeriod <= 0 {
		return faults.New(faults.Invalid, "lock_period must be greater than 0 when lock is enabled")
	}
	if !req.Lock && req.LockPeriod != 0 {
		return faults.New(faults.Invalid, "lock_period must be 0 when lock is disabled")
	}
	return enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount")
}

func ValidateTRONUndelegateResource(key domain.Key, req *v1.TRONUndelegateResourceSignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	if err := validateTRONResourceEnvelope(req.TRONRawDataEnvelope); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.ReceiverAddress); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if _, err := validateTRONResource(req.Resource); err != nil {
		return err
	}
	if err := enforcePositiveAmount(req.Amount, "amount"); err != nil {
		return err
	}
	return enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount")
}

func ValidateTRONWithdrawExpireUnfreeze(key domain.Key, req *v1.TRONWithdrawExpireUnfreezeSignRequest) error {
	if err := validateTRONOwnerBase(key, req.TRONOwnerSignRequestBase); err != nil {
		return err
	}
	return validateTRONResourceEnvelope(req.TRONRawDataEnvelope)
}

func validateTRONOwnerBase(key domain.Key, req v1.TRONOwnerSignRequestBase) error {
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.OwnerAddress); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	return validateBaseFields(key, req.ChainFamily, req.Network, req.OwnerAddress, "owner address", v1.ChainFamilyTRON, nil)
}

func validateTRONResourceEnvelope(envelope v1.TRONRawDataEnvelope) error {
	if envelope.Timestamp <= 0 {
		return faults.New(faults.Invalid, "timestamp must be greater than 0")
	}
	if envelope.Expiration <= envelope.Timestamp {
		return faults.New(faults.Invalid, "expiration must be greater than timestamp")
	}
	if err := enforceDecodedLength(envelope.RefBlockBytes, 2, "ref_block_bytes"); err != nil {
		return err
	}
	if err := enforceDecodedLength(envelope.RefBlockHash, 8, "ref_block_hash"); err != nil {
		return err
	}
	return nil
}

func validateTRONResource(resource string) (string, error) {
	switch v1.NormalizeTRONResource(resource) {
	case v1.TRONResourceBandwidth:
		return v1.TRONResourceBandwidth, nil
	case v1.TRONResourceEnergy:
		return v1.TRONResourceEnergy, nil
	default:
		return "", faults.Newf(faults.Invalid, "unsupported resource %q", resource)
	}
}

func validateTRONUnfreezeResource(resource string) (string, error) {
	normalized := v1.NormalizeTRONResource(resource)
	if normalized == v1.TRONResourceTRONPower {
		return "", faults.New(faults.Invalid, "TRON_POWER is not supported on unfreeze_v2 in v0.4.0")
	}
	return validateTRONResource(normalized)
}

func enforcePositiveAmount(value int64, field string) error {
	if value <= 0 {
		return faults.Newf(faults.Invalid, "%s must be greater than 0", field)
	}
	return nil
}

func enforceDecodedLength(value string, expected int, field string) error {
	raw, err := enc.DecodeHex(value)
	if err != nil {
		return faults.Newf(faults.Invalid, "decode %s: %v", field, err)
	}
	if len(raw) != expected {
		return faults.Newf(faults.Invalid, "%s must decode to %d bytes", field, expected)
	}
	return nil
}
