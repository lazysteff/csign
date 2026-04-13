package tron

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/fbsobreira/gotron-sdk/pkg/txcore"
	"google.golang.org/protobuf/proto"
)

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
	case core.Transaction_Contract_FreezeBalanceV2Contract:
		return v1.OperationTRONFreezeBalanceV2, nil
	case core.Transaction_Contract_UnfreezeBalanceV2Contract:
		return v1.OperationTRONUnfreezeBalanceV2, nil
	case core.Transaction_Contract_DelegateResourceContract:
		return v1.OperationTRONDelegateResource, nil
	case core.Transaction_Contract_UnDelegateResourceContract:
		return v1.OperationTRONUndelegateResource, nil
	case core.Transaction_Contract_WithdrawExpireUnfreezeContract:
		return v1.OperationTRONWithdrawExpireUnfreeze, nil
	default:
		return "", fmt.Errorf("unsupported tron contract type %v", contract.Type)
	}
}
