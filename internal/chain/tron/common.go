package tron

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	tronaddress "github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
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

func base58Address(value string) ([]byte, error) {
	return tronaddress.Base58ToAddress(value)
}

func tronResourceCode(resource string) (core.ResourceCode, error) {
	switch v1.NormalizeTRONResource(resource) {
	case v1.TRONResourceBandwidth:
		return core.ResourceCode_BANDWIDTH, nil
	case v1.TRONResourceEnergy:
		return core.ResourceCode_ENERGY, nil
	default:
		return 0, fmt.Errorf("unsupported tron resource %q", resource)
	}
}
