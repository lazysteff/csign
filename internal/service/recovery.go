package service

import (
	"github.com/lazysteff/csign/v2/internal/chain"
	"github.com/lazysteff/csign/v2/internal/faults"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

type RecoveryService struct{}

func NewRecoveryService() *RecoveryService {
	return &RecoveryService{}
}

func (s *RecoveryService) Recover(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	result, err := chain.Recover(req)
	if err != nil {
		return nil, faults.Wrap(faults.Invalid, err)
	}
	return result, nil
}

func (s *RecoveryService) Verify(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	result, err := s.Recover(req)
	if err != nil {
		return nil, err
	}
	matchSigner := true
	if req.ExpectedSignerAddress != "" {
		matchSigner = result.MatchesExpected
	}
	matchOperation := true
	if req.Operation != "" {
		matchOperation = result.Operation == req.Operation
	}
	result.MatchesExpected = matchSigner && matchOperation
	return result, nil
}
