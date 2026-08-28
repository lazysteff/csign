package policy

import (
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func ValidateTRXTransfer(key domain.Key, req *v1.TRXTransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyTRON, nil); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceBigCap(fmt.Sprintf("%d", req.Amount), key.Policy.MaxValue, "amount"); err != nil {
		return err
	}
	if _, err := v1.DecodeTRONMemoHex(req.MemoHex); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	return enforceFeeLimit(req.FeeLimit, key.Policy.MaxFeeLimit)
}

func ValidateTRC20Transfer(key domain.Key, req *v1.TRC20TransferSignRequest) error {
	if err := validateBase(key, req.BaseSignRequest, v1.ChainFamilyTRON, nil); err != nil {
		return err
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.To); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if _, err := chain.NormalizeAddress(v1.ChainFamilyTRON, req.TokenContract); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceBigCap(req.Amount, key.Policy.MaxValue, "amount"); err != nil {
		return err
	}
	if err := enforceFeeLimit(req.FeeLimit, key.Policy.MaxFeeLimit); err != nil {
		return err
	}
	if _, err := v1.DecodeTRONMemoHex(req.MemoHex); err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if err := enforceTokenContractAllowlist(key.Policy, v1.ChainFamilyTRON, req.TokenContract); err != nil {
		return err
	}
	return enforceSelectorAllowlist(key.Policy, domain.TRC20TransferSelector)
}
