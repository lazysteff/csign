package tron

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/fbsobreira/gotron-sdk/pkg/standards/trc20enc"
	"google.golang.org/protobuf/types/known/anypb"
)

func SignTRXTransfer(ctx context.Context, material custody.Material, req *v1.TRXTransferSignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.SourceAddress)
	if err != nil {
		return nil, err
	}
	to, err := base58Address(req.To)
	if err != nil {
		return nil, err
	}
	contract := &core.TransferContract{
		OwnerAddress: owner,
		ToAddress:    to,
		Amount:       req.Amount,
	}
	typed, err := anypb.New(contract)
	if err != nil {
		return nil, fmt.Errorf("wrap trx transfer contract: %w", err)
	}
	tx, err := buildTransaction(
		core.Transaction_Contract_TransferContract,
		typed,
		req.RefBlockBytes,
		req.RefBlockHash,
		req.RefBlockNum,
		req.Timestamp,
		req.Expiration,
		req.FeeLimit,
	)
	if err != nil {
		return nil, err
	}
	return signTransaction(ctx, material, req.KeyID, req.Network, v1.OperationTRXTransfer, tx)
}

func SignTRC20Transfer(ctx context.Context, material custody.Material, req *v1.TRC20TransferSignRequest) (*v1.SignResponse, error) {
	owner, err := base58Address(req.SourceAddress)
	if err != nil {
		return nil, err
	}
	tokenContract, err := base58Address(req.TokenContract)
	if err != nil {
		return nil, err
	}
	to, err := base58Address(req.To)
	if err != nil {
		return nil, err
	}
	amount, err := enc.ParseBigInt(req.Amount)
	if err != nil {
		return nil, err
	}
	callDataHex, err := trc20enc.EncodeTransferCall(to, amount)
	if err != nil {
		return nil, fmt.Errorf("encode trc20 transfer call: %w", err)
	}
	callData, err := hex.DecodeString(callDataHex)
	if err != nil {
		return nil, fmt.Errorf("decode trc20 transfer call: %w", err)
	}
	contract := &core.TriggerSmartContract{
		OwnerAddress:    owner,
		ContractAddress: tokenContract,
		Data:            callData,
		CallValue:       0,
	}
	typed, err := anypb.New(contract)
	if err != nil {
		return nil, fmt.Errorf("wrap trc20 transfer contract: %w", err)
	}
	tx, err := buildTransaction(
		core.Transaction_Contract_TriggerSmartContract,
		typed,
		req.RefBlockBytes,
		req.RefBlockHash,
		req.RefBlockNum,
		req.Timestamp,
		req.Expiration,
		req.FeeLimit,
	)
	if err != nil {
		return nil, err
	}
	return signTransaction(ctx, material, req.KeyID, req.Network, v1.OperationTRC20Transfer, tx)
}
