package evm

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func DeriveAddress(pub *ecdsa.PublicKey) string {
	return ethcrypto.PubkeyToAddress(*pub).Hex()
}

func NormalizeAddress(value string) (string, error) {
	if !ethcommon.IsHexAddress(value) {
		return "", fmt.Errorf("invalid evm address %q", value)
	}
	return ethcommon.HexToAddress(value).Hex(), nil
}

func EqualAddress(left, right string) bool {
	nl, err := NormalizeAddress(left)
	if err != nil {
		return false
	}
	nr, err := NormalizeAddress(right)
	if err != nil {
		return false
	}
	return nl == nr
}

func SignLegacyTransfer(ctx context.Context, material custody.Material, req *v1.EVMLegacyTransferSignRequest) (*v1.SignResponse, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := enc.ParseBigInt(req.Value)
	if err != nil {
		return nil, err
	}
	gasPrice, err := enc.ParseBigInt(req.GasPrice)
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
	return signTransaction(ctx, material, req.KeyID, req.Network, v1.OperationEVMTransferLegacy, big.NewInt(req.ChainID), tx)
}

func SignEIP1559Transfer(ctx context.Context, material custody.Material, req *v1.EVMEIP1559TransferSignRequest) (*v1.SignResponse, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := enc.ParseBigInt(req.Value)
	if err != nil {
		return nil, err
	}
	feeCap, err := enc.ParseBigInt(req.MaxFeePerGas)
	if err != nil {
		return nil, err
	}
	tipCap, err := enc.ParseBigInt(req.MaxPriorityFeePerGas)
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
	return signTransaction(ctx, material, req.KeyID, req.Network, v1.OperationEVMTransferEIP1559, big.NewInt(req.ChainID), tx)
}

func SignContractCall(ctx context.Context, material custody.Material, req *v1.EVMContractCallSignRequest) (*v1.SignResponse, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := enc.ParseBigInt(req.Value)
	if err != nil {
		return nil, err
	}
	feeCap, err := enc.ParseBigInt(req.MaxFeePerGas)
	if err != nil {
		return nil, err
	}
	tipCap, err := enc.ParseBigInt(req.MaxPriorityFeePerGas)
	if err != nil {
		return nil, err
	}
	data, err := enc.DecodeHex(req.Data)
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
	return signTransaction(ctx, material, req.KeyID, req.Network, v1.OperationEVMContractEIP1559, big.NewInt(req.ChainID), tx)
}

func Recover(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	raw, err := enc.DecodeHex(req.SignedPayload)
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
	expected := req.ExpectedSignerAddress
	matches := false
	if expected != "" {
		matches = EqualAddress(expected, recovered.Hex())
	}
	return &v1.RecoverResponse{
		APIVersion:      v1.APIVersion,
		ChainFamily:     v1.ChainFamilyEVM,
		Network:         req.Network,
		Operation:       classifyOperation(&tx),
		RecoveredSigner: recovered.Hex(),
		ExpectedSigner:  expected,
		MatchesExpected: matches,
		TxHash:          tx.Hash().Hex(),
	}, nil
}

func signTransaction(ctx context.Context, material custody.Material, keyID, network, operation string, chainID *big.Int, tx *ethtypes.Transaction) (*v1.SignResponse, error) {
	signer := ethtypes.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx)
	signature, err := custody.RecoverableSignature(ctx, material, digest.Bytes())
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
	return &v1.SignResponse{
		APIVersion:      v1.APIVersion,
		KeyID:           keyID,
		ChainFamily:     v1.ChainFamilyEVM,
		Network:         network,
		Operation:       operation,
		SignerAddress:   DeriveAddress(material.PublicKey()),
		TxHash:          signedTx.Hash().Hex(),
		SignedPayload:   enc.EncodeHex(raw),
		PayloadEncoding: domain.PayloadEncodingHex,
	}, nil
}

func classifyOperation(tx *ethtypes.Transaction) string {
	switch tx.Type() {
	case ethtypes.LegacyTxType:
		if len(tx.Data()) == 0 {
			return v1.OperationEVMTransferLegacy
		}
	case ethtypes.DynamicFeeTxType:
		if len(tx.Data()) == 0 {
			return v1.OperationEVMTransferEIP1559
		}
		return v1.OperationEVMContractEIP1559
	}
	return "unknown"
}
