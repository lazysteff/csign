package signer

import (
	"context"
	"fmt"
	"math/big"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/chain-signer/chain-signer/pkg/model"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

func SignEVMLegacyTransfer(ctx context.Context, material Material, req v1.EVMLegacyTransferSignRequest) (*v1.SignResponse, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := model.ParseBigInt(req.Value)
	if err != nil {
		return nil, err
	}
	gasPrice, err := model.ParseBigInt(req.GasPrice)
	if err != nil {
		return nil, err
	}
	tx := ethtypes.NewTx(&ethtypes.LegacyTx{
		Nonce:    req.Nonce,
		GasPrice: gasPrice,
		Gas:      req.GasLimit,
		To:       &to,
		Value:    value,
	})
	return signEVMTransaction(ctx, material, req.KeyID, req.Network, model.OperationEVMTransferLegacy, big.NewInt(req.ChainID), tx)
}

func SignEVMEIP1559Transfer(ctx context.Context, material Material, req v1.EVMEIP1559TransferSignRequest) (*v1.SignResponse, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := model.ParseBigInt(req.Value)
	if err != nil {
		return nil, err
	}
	feeCap, err := model.ParseBigInt(req.MaxFeePerGas)
	if err != nil {
		return nil, err
	}
	tipCap, err := model.ParseBigInt(req.MaxPriorityFeePerGas)
	if err != nil {
		return nil, err
	}
	tx := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
		ChainID:   big.NewInt(req.ChainID),
		Nonce:     req.Nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       req.GasLimit,
		To:        &to,
		Value:     value,
	})
	return signEVMTransaction(ctx, material, req.KeyID, req.Network, model.OperationEVMTransferEIP1559, big.NewInt(req.ChainID), tx)
}

func SignEVMContractCall(ctx context.Context, material Material, req v1.EVMContractCallSignRequest) (*v1.SignResponse, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := model.ParseBigInt(req.Value)
	if err != nil {
		return nil, err
	}
	feeCap, err := model.ParseBigInt(req.MaxFeePerGas)
	if err != nil {
		return nil, err
	}
	tipCap, err := model.ParseBigInt(req.MaxPriorityFeePerGas)
	if err != nil {
		return nil, err
	}
	data, err := model.DecodeHex(req.Data)
	if err != nil {
		return nil, err
	}
	tx := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
		ChainID:   big.NewInt(req.ChainID),
		Nonce:     req.Nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       req.GasLimit,
		To:        &to,
		Value:     value,
		Data:      data,
	})
	return signEVMTransaction(ctx, material, req.KeyID, req.Network, model.OperationEVMContractEIP1559, big.NewInt(req.ChainID), tx)
}

func RecoverEVM(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	raw, err := model.DecodeHex(req.SignedPayload)
	if err != nil {
		return nil, err
	}
	var tx ethtypes.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("decode evm signed payload: %w", err)
	}
	signer := ethtypes.LatestSignerForChainID(tx.ChainId())
	recovered, err := ethtypes.Sender(signer, &tx)
	if err != nil {
		return nil, fmt.Errorf("recover evm sender: %w", err)
	}
	operation := classifyEVMOperation(&tx)
	expected := req.ExpectedSignerAddress
	matches := false
	if expected != "" {
		matches = model.EqualAddress(model.ChainFamilyEVM, expected, recovered.Hex())
	}
	return &v1.RecoverResponse{
		APIVersion:      v1.APIVersion,
		ChainFamily:     model.ChainFamilyEVM,
		Network:         req.Network,
		Operation:       operation,
		RecoveredSigner: recovered.Hex(),
		ExpectedSigner:  expected,
		MatchesExpected: matches,
		TxHash:          tx.Hash().Hex(),
	}, nil
}

func signEVMTransaction(ctx context.Context, material Material, keyID, network, operation string, chainID *big.Int, tx *ethtypes.Transaction) (*v1.SignResponse, error) {
	signer := ethtypes.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx)
	signature, err := RecoverableSignature(ctx, material, digest.Bytes())
	if err != nil {
		return nil, err
	}
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		return nil, fmt.Errorf("attach evm signature: %w", err)
	}
	raw, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal evm signed payload: %w", err)
	}
	signerAddress, err := model.DeriveSignerAddress(model.ChainFamilyEVM, material.PublicKey())
	if err != nil {
		return nil, err
	}
	return &v1.SignResponse{
		APIVersion:      v1.APIVersion,
		KeyID:           keyID,
		ChainFamily:     model.ChainFamilyEVM,
		Network:         network,
		Operation:       operation,
		SignerAddress:   signerAddress,
		TxHash:          signedTx.Hash().Hex(),
		SignedPayload:   model.EncodeHex(raw),
		PayloadEncoding: model.DefaultPayloadEncoding,
	}, nil
}

func classifyEVMOperation(tx *ethtypes.Transaction) string {
	switch tx.Type() {
	case ethtypes.LegacyTxType:
		if len(tx.Data()) == 0 {
			return model.OperationEVMTransferLegacy
		}
	case ethtypes.DynamicFeeTxType:
		if len(tx.Data()) == 0 {
			return model.OperationEVMTransferEIP1559
		}
		return model.OperationEVMContractEIP1559
	}
	return "unknown"
}
