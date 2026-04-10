package tron

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	tronaddress "github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/fbsobreira/gotron-sdk/pkg/standards/trc20enc"
	"github.com/fbsobreira/gotron-sdk/pkg/txcore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func DeriveAddress(pub *ecdsa.PublicKey) string {
	return tronaddress.PubkeyToAddress(*pub).String()
}

func NormalizeAddress(value string) (string, error) {
	addr, err := tronaddress.Base58ToAddress(value)
	if err != nil {
		return "", fmt.Errorf("invalid tron address %q: %w", value, err)
	}
	return addr.String(), nil
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

func SignTRXTransfer(ctx context.Context, material custody.Material, req *v1.TRXTransferSignRequest) (*v1.SignResponse, error) {
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

func Recover(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	raw, err := enc.DecodeHex(req.SignedPayload)
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
	recoveredSigner, err := custody.RecoverAddressFromDigest(DeriveAddress, digest[:], tx.Signature[0])
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
		matches = EqualAddress(expected, recoveredSigner)
	}
	operation, err := classifyOperation(&tx)
	if err != nil {
		return nil, err
	}
	return &v1.RecoverResponse{
		APIVersion:      v1.APIVersion,
		ChainFamily:     v1.ChainFamilyTRON,
		Network:         req.Network,
		Operation:       operation,
		RecoveredSigner: recoveredSigner,
		ExpectedSigner:  expected,
		MatchesExpected: matches,
		TxHash:          txID,
	}, nil
}

func buildTransaction(
	contractType core.Transaction_Contract_ContractType,
	parameter *anypb.Any,
	refBlockBytes string,
	refBlockHash string,
	refBlockNum int64,
	timestamp int64,
	expiration int64,
	feeLimit int64,
) (*core.Transaction, error) {
	refBytes, err := enc.DecodeHex(refBlockBytes)
	if err != nil {
		return nil, fmt.Errorf("decode ref_block_bytes: %w", err)
	}
	refHash, err := enc.DecodeHex(refBlockHash)
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

func signTransaction(ctx context.Context, material custody.Material, keyID, network, operation string, tx *core.Transaction) (*v1.SignResponse, error) {
	rawData, err := proto.Marshal(tx.GetRawData())
	if err != nil {
		return nil, fmt.Errorf("marshal tron raw data: %w", err)
	}
	digest := sha256.Sum256(rawData)
	signature, err := custody.RecoverableSignature(ctx, material, digest[:])
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
	return &v1.SignResponse{
		APIVersion:      v1.APIVersion,
		KeyID:           keyID,
		ChainFamily:     v1.ChainFamilyTRON,
		Network:         network,
		Operation:       operation,
		SignerAddress:   DeriveAddress(material.PublicKey()),
		TxHash:          txID,
		SignedPayload:   enc.EncodeHex(signedPayload),
		PayloadEncoding: domain.PayloadEncodingHex,
	}, nil
}

func classifyOperation(tx *core.Transaction) (string, error) {
	if tx == nil || tx.RawData == nil || len(tx.RawData.Contract) == 0 {
		return "", fmt.Errorf("tron transaction has no contracts")
	}
	contract := tx.RawData.Contract[0]
	switch contract.Type {
	case core.Transaction_Contract_TransferContract:
		return v1.OperationTRXTransfer, nil
	case core.Transaction_Contract_TriggerSmartContract:
		trigger := new(core.TriggerSmartContract)
		if err := contract.Parameter.UnmarshalTo(trigger); err != nil {
			return "", fmt.Errorf("decode trigger smart contract: %w", err)
		}
		if len(trigger.Data) < 4 {
			return "", fmt.Errorf("trigger smart contract call data is too short")
		}
		if hex.EncodeToString(trigger.Data[:4]) == domain.TRC20TransferSelector {
			return v1.OperationTRC20Transfer, nil
		}
		return "", fmt.Errorf("unsupported trigger smart contract selector")
	default:
		return "", fmt.Errorf("unsupported tron contract type %v", contract.Type)
	}
}
