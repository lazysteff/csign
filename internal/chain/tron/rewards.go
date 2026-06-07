package tron

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/custody"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
)

func SignTRONWithdrawBalance(ctx context.Context, material custody.Material, req *v1.TRONWithdrawBalanceSignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.OwnerAddress)
	if err != nil {
		return nil, err
	}
	contract := &core.WithdrawBalanceContract{
		OwnerAddress: owner,
	}
	return signTRONOwnerTransaction(
		ctx,
		material,
		req.KeyID,
		req.Network,
		v1.OperationTRONWithdrawBalance,
		core.Transaction_Contract_WithdrawBalanceContract,
		contract,
		req.TRONRawDataEnvelope,
	)
}
