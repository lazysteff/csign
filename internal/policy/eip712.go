package policy

import (
	"errors"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

func ValidateEVMEIP712(key domain.Key, req *v1.EVMEIP712SignRequest) error {
	if err := validateAdvancedBase(key, req.ChainFamily, req.Network, req.RequestID, req.ExpectedSignerAddress, req.ChainID, v1.OperationEVMEIP712Typed, false); err != nil {
		return err
	}
	if err := requireStringAllowed(key.Policy.AllowedEIP712Schemas, req.SchemaID, "EIP-712 schema"); err != nil {
		return err
	}
	if err := requireAddressAllowed(key.Policy.AllowedTokenContracts, req.Domain.VerifyingContract, "EIP-712 verifying contract"); err != nil {
		return err
	}
	if err := requireAddressAllowed(key.Policy.AllowedContractDestinations, req.Message.Spender, "permit spender"); err != nil {
		return err
	}
	if err := enforceBigCap(req.Message.Value, key.Policy.MaxValue, "permit value"); err != nil {
		return err
	}
	prepared, err := advancedcodec.PreparePermit(req.SchemaID, req.SchemaVersion, req.ChainID, req.ExpectedSignerAddress, req.Domain, req.Message)
	if err != nil {
		return classifyEIP712Error(err)
	}
	if prepared.Expected == (common.Address{}) {
		return faults.New(faults.Invalid, "expected signer is required")
	}
	return nil
}

func classifyEIP712Error(err error) error {
	message := err.Error()
	var unsupported *advancedregistry.UnsupportedError
	switch {
	case errors.As(err, &unsupported) && unsupported.Dimension == advancedregistry.UnsupportedEIP712Schema:
		return faults.NewCode(faults.Unsupported, faults.UnsupportedEIP712Schema, message)
	case strings.Contains(message, "domain") || strings.Contains(message, "chain_id"):
		return faults.NewCode(faults.Invalid, faults.InvalidEIP712Domain, message)
	default:
		return faults.NewCode(faults.Invalid, faults.InvalidEIP712Message, message)
	}
}
