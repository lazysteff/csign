package service

import (
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func (s *RecoveryService) VerifyEVMEIP712(req v1.EVMEIP712VerifyRequest) (*v1.EVMEIP712VerifyResponse, error) {
	if err := validateInspectionBase(req.ChainFamily, req.Network, req.RequestID); err != nil {
		return nil, err
	}
	result, err := evm.VerifyEIP712(req)
	if err != nil {
		return nil, classifyEIP712InspectionError(err)
	}
	return result, nil
}

func (s *RecoveryService) VerifyEVMUserOperation(req v1.EVMUserOperationVerifyRequest) (*v1.EVMUserOperationVerifyResponse, error) {
	if err := validateInspectionBase(req.ChainFamily, req.Network, req.RequestID); err != nil {
		return nil, err
	}
	result, err := evm.VerifyUserOperation(req)
	if err != nil {
		return nil, classifyUserOperationInspectionError(err)
	}
	return result, nil
}

func (s *RecoveryService) VerifyEVMEIP7702Authorization(req v1.EVMEIP7702AuthorizationVerifyRequest) (*v1.EVMEIP7702AuthorizationVerifyResponse, error) {
	if err := validateInspectionBase(req.ChainFamily, req.Network, req.RequestID); err != nil {
		return nil, err
	}
	result, err := evm.VerifyEIP7702Authorization(req)
	if err != nil {
		return nil, classifyAuthorizationInspectionError(err)
	}
	return result, nil
}

func (s *RecoveryService) RecoverEVMEIP7702Transaction(req v1.EVMEIP7702TransactionRecoverRequest) (*v1.EVMEIP7702TransactionRecoverResponse, error) {
	if err := validateInspectionBase(req.ChainFamily, req.Network, req.RequestID); err != nil {
		return nil, err
	}
	result, err := evm.RecoverEIP7702Transaction(req)
	if err != nil {
		return nil, classifyType4InspectionError(err)
	}
	return result, nil
}

func validateInspectionBase(chainFamily, network, requestID string) error {
	if domain.NormalizeChainFamily(chainFamily) != v1.ChainFamilyEVM {
		return faults.New(faults.Invalid, "chain_family must be evm")
	}
	if strings.TrimSpace(network) == "" {
		return faults.New(faults.Invalid, "network is required")
	}
	if strings.TrimSpace(requestID) == "" {
		return faults.New(faults.Invalid, "request_id is required")
	}
	return nil
}
