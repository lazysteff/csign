package evm

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
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

func PrepareLegacyTransfer(pub *ecdsa.PublicKey, req *v1.EVMLegacyTransferSignRequest) (*cryptography.Prepared, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := enc.ParseEVMUint256(req.Value)
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
	return prepareTransaction(pub, req.KeyID, req.Network, req.RequestID, v1.OperationEVMTransferLegacy, big.NewInt(req.ChainID), tx)
}

func PrepareEIP1559Transfer(pub *ecdsa.PublicKey, req *v1.EVMEIP1559TransferSignRequest) (*cryptography.Prepared, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := enc.ParseEVMUint256(req.Value)
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
	return prepareTransaction(pub, req.KeyID, req.Network, req.RequestID, v1.OperationEVMTransferEIP1559, big.NewInt(req.ChainID), tx)
}

func PrepareContractCall(pub *ecdsa.PublicKey, req *v1.EVMContractCallSignRequest) (*cryptography.Prepared, error) {
	to := ethcommon.HexToAddress(req.To)
	value, err := enc.ParseEVMUint256(req.Value)
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
	return prepareTransaction(pub, req.KeyID, req.Network, req.RequestID, v1.OperationEVMContractEIP1559, big.NewInt(req.ChainID), tx)
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

func prepareTransaction(pub *ecdsa.PublicKey, keyID, network, requestID, operation string, chainID *big.Int, tx *ethtypes.Transaction) (*cryptography.Prepared, error) {
	signer := ethtypes.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx)
	return &cryptography.Prepared{Payload: cryptography.NewPayload(cryptography.Digest, digest.Bytes()), Format: func(signature []byte) (any, error) {
		signedTx, err := tx.WithSignature(signer, signature)
		if err != nil {
			return nil, fmt.Errorf("attach evm signature: %w", err)
		}
		recovered, err := ethtypes.Sender(signer, signedTx)
		if err != nil {
			return nil, fmt.Errorf("verify evm signature: %w", err)
		}
		expectedSigner := DeriveAddress(pub)
		if !EqualAddress(recovered.Hex(), expectedSigner) {
			return nil, fmt.Errorf("verify evm signature: recovered signer mismatch")
		}
		raw, err := signedTx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal evm signed payload: %w", err)
		}
		return &v1.SignResponse{
			APIVersion:      v1.APIVersion,
			RequestID:       requestID,
			KeyID:           keyID,
			ChainFamily:     v1.ChainFamilyEVM,
			Network:         network,
			Operation:       operation,
			SignerAddress:   recovered.Hex(),
			TxHash:          signedTx.Hash().Hex(),
			SignedPayload:   enc.EncodeHex(raw),
			PayloadEncoding: domain.PayloadEncodingHex,
		}, nil
	}}, nil
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
	case ethtypes.SetCodeTxType:
		return v1.OperationEVMEIP7702Transaction
	}
	return "unknown"
}
