package policy

import (
	"strings"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
)

func enforceBigCap(value, capValue, field string) error {
	if strings.TrimSpace(capValue) == "" {
		return nil
	}
	actual, err := enc.ParseBigInt(value)
	if err != nil {
		return faults.Newf(faults.Invalid, "parse %s: %v", field, err)
	}
	capInt, err := enc.ParseBigInt(capValue)
	if err != nil {
		return faults.Newf(faults.Invalid, "parse %s cap: %v", field, err)
	}
	if actual.Cmp(capInt) > 0 {
		return faults.Newf(faults.PolicyDenied, "%s exceeds configured cap", field)
	}
	return nil
}

func enforceGasLimit(actual, capValue uint64) error {
	if capValue == 0 {
		return nil
	}
	if actual > capValue {
		return faults.New(faults.PolicyDenied, "gas_limit exceeds configured cap")
	}
	return nil
}

func enforceFeeLimit(actual, capValue int64) error {
	if capValue == 0 {
		return nil
	}
	if actual > capValue {
		return faults.New(faults.PolicyDenied, "fee_limit exceeds configured cap")
	}
	return nil
}
