package tron

import (
	"crypto/ecdsa"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
)

func PrepareTRONWithdrawBalance(pub *ecdsa.PublicKey, req *v1.TRONWithdrawBalanceSignRequest) (*cryptography.Prepared, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	contract := &core.WithdrawBalanceContract{
		OwnerAddress: owner,
	}
	return prepareTRONOwnerTransaction(
		pub,
		req.KeyID,
		req.Network,
		req.RequestID,
		v1.OperationTRONWithdrawBalance,
		core.Transaction_Contract_WithdrawBalanceContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}
