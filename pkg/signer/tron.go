package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/chain-signer/chain-signer/pkg/model"
	tronaddress "github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/fbsobreira/gotron-sdk/pkg/standards/trc20enc"
	"github.com/fbsobreira/gotron-sdk/pkg/txcore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func SignTRXTransfer(ctx context.Context, material Material, req v1.TRXTransferSignRequest) (*v1.SignResponse, error) {
	owner, err := tronaddress.Base58ToAddress(req.SourceAddress)
	if err != nil {
		return nil, err
	}
	to, err := tronaddress.Base58ToAddress(req.To)
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
	tx, err := buildTRONTransaction(
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
	return signTRONTransaction(ctx, material, req.KeyID, req.Network, model.OperationTRXTransfer, tx)
}

func SignTRC20Transfer(ctx context.Context, material Material, req v1.TRC20TransferSignRequest) (*v1.SignResponse, error) {
	owner, err := tronaddress.Base58ToAddress(req.SourceAddress)
	if err != nil {
		return nil, err
	}
	tokenContract, err := tronaddress.Base58ToAddress(req.TokenContract)
	if err != nil {
		return nil, err
	}
	to, err := tronaddress.Base58ToAddress(req.To)
	if err != nil {
		return nil, err
	}
	amount, err := model.ParseBigInt(req.Amount)
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
	tx, err := buildTRONTransaction(
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
	return signTRONTransaction(ctx, material, req.KeyID, req.Network, model.OperationTRC20Transfer, tx)
}

func RecoverTRON(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	raw, err := model.DecodeHex(req.SignedPayload)
	if err != nil {
		return nil, err
	}
	var tx core.Transaction
	if err := proto.Unmarshal(raw, &tx); err != nil {
		return nil, fmt.Errorf("decode tron signed payload: %w", err)
	}
	if len(tx.Signature) == 0 {
		return nil, fmt.Errorf("signed tron payload does not include a signature")
	}
	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return nil, fmt.Errorf("marshal tron raw data: %w", err)
	}
	digest := sha256.Sum256(rawData)
	recoveredSigner, err := RecoverAddressFromDigest(model.ChainFamilyTRON, digest[:], tx.Signature[0])
	if err != nil {
		return nil, err
	}
	txID, err := txcore.TransactionID(&tx)
	if err != nil {
		return nil, err
	}
	expected := req.ExpectedSignerAddress
	matches := false
	if expected != "" {
		matches = model.EqualAddress(model.ChainFamilyTRON, expected, recoveredSigner)
	}
	operation, err := classifyTRONOperation(&tx)
	if err != nil {
		return nil, err
	}
	return &v1.RecoverResponse{
		APIVersion:      v1.APIVersion,
		ChainFamily:     model.ChainFamilyTRON,
		Network:         req.Network,
		Operation:       operation,
		RecoveredSigner: recoveredSigner,
		ExpectedSigner:  expected,
		MatchesExpected: matches,
		TxHash:          txID,
	}, nil
}

func buildTRONTransaction(
	contractType core.Transaction_Contract_ContractType,
	parameter *anypb.Any,
	refBlockBytes string,
	refBlockHash string,
	refBlockNum int64,
	timestamp int64,
	expiration int64,
	feeLimit int64,
) (*core.Transaction, error) {
	refBytes, err := model.DecodeHex(refBlockBytes)
	if err != nil {
		return nil, fmt.Errorf("decode ref_block_bytes: %w", err)
	}
	refHash, err := model.DecodeHex(refBlockHash)
	if err != nil {
		return nil, fmt.Errorf("decode ref_block_hash: %w", err)
	}
	return &core.Transaction{
		RawData: &core.TransactionRaw{
			RefBlockBytes: refBytes,
			RefBlockHash:  refHash,
			RefBlockNum:   refBlockNum,
			Timestamp:     timestamp,
			Expiration:    expiration,
			FeeLimit:      feeLimit,
			Contract: []*core.Transaction_Contract{
				{
					Type:      contractType,
					Parameter: parameter,
				},
			},
		},
	}, nil
}

func signTRONTransaction(ctx context.Context, material Material, keyID, network, operation string, tx *core.Transaction) (*v1.SignResponse, error) {
	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return nil, fmt.Errorf("marshal tron raw data: %w", err)
	}
	digest := sha256.Sum256(rawData)
	signature, err := RecoverableSignature(ctx, material, digest[:])
	if err != nil {
		return nil, err
	}
	tx.Signature = append(tx.Signature, signature)
	signedPayload, err := proto.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("marshal tron signed payload: %w", err)
	}
	txID, err := txcore.TransactionID(tx)
	if err != nil {
		return nil, err
	}
	signerAddress, err := model.DeriveSignerAddress(model.ChainFamilyTRON, material.PublicKey())
	if err != nil {
		return nil, err
	}
	return &v1.SignResponse{
		APIVersion:      v1.APIVersion,
		KeyID:           keyID,
		ChainFamily:     model.ChainFamilyTRON,
		Network:         network,
		Operation:       operation,
		SignerAddress:   signerAddress,
		TxHash:          txID,
		SignedPayload:   model.EncodeHex(signedPayload),
		PayloadEncoding: model.DefaultPayloadEncoding,
	}, nil
}

func classifyTRONOperation(tx *core.Transaction) (string, error) {
	if tx == nil || tx.RawData == nil || len(tx.RawData.Contract) == 0 {
		return "", fmt.Errorf("tron transaction has no contracts")
	}
	contract := tx.RawData.Contract[0]
	switch contract.Type {
	case core.Transaction_Contract_TransferContract:
		return model.OperationTRXTransfer, nil
	case core.Transaction_Contract_TriggerSmartContract:
		trigger := new(core.TriggerSmartContract)
		if err := contract.Parameter.UnmarshalTo(trigger); err != nil {
			return "", fmt.Errorf("decode trigger smart contract: %w", err)
		}
		if len(trigger.Data) < 4 {
			return "", fmt.Errorf("trigger smart contract call data is too short")
		}
		if hex.EncodeToString(trigger.Data[:4]) == model.TRC20TransferSelector {
			return model.OperationTRC20Transfer, nil
		}
		return "", fmt.Errorf("unsupported trigger smart contract selector")
	default:
		return "", fmt.Errorf("unsupported tron contract type %v", contract.Type)
	}
}
