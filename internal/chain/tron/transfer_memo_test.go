package tron

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTransferMemosAreSignedByteForByte(t *testing.T) {
	t.Parallel()

	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())
	tests := []struct {
		name string
		sign func(string) (*v1.SignResponse, error)
		kind core.Transaction_Contract_ContractType
	}{
		{
			name: "trx",
			kind: core.Transaction_Contract_TransferContract,
			sign: func(memoHex string) (*v1.SignResponse, error) {
				return SignTRXTransfer(context.Background(), material, trxMemoRequest(signer, memoHex))
			},
		},
		{
			name: "trc20",
			kind: core.Transaction_Contract_TriggerSmartContract,
			sign: func(memoHex string) (*v1.SignResponse, error) {
				return SignTRC20Transfer(context.Background(), material, trc20MemoRequest(signer, memoHex))
			},
		},
	}

	wantMemo := append([]byte("Zażółć 🛰️"), 0x00, 0xff)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resp, err := test.sign(hex.EncodeToString(wantMemo))
			require.NoError(t, err)

			tx := decodeSignedTransaction(t, resp.SignedPayload)
			require.Equal(t, wantMemo, tx.GetRawData().GetData())
			require.Len(t, tx.GetRawData().GetContract(), 1)
			require.Equal(t, test.kind, tx.GetRawData().GetContract()[0].GetType())

			rawData, err := proto.Marshal(tx.GetRawData())
			require.NoError(t, err)
			digest := sha256.Sum256(rawData)
			require.Equal(t, hex.EncodeToString(digest[:]), strings.TrimPrefix(resp.TxHash, "0x"))
			requireRecoveredOperation(t, signer, resp.SignedPayload, resp.Operation)
		})
	}
}

func TestEmptyTransferMemoPreservesSerializedTransaction(t *testing.T) {
	t.Parallel()

	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	withoutMemo, err := SignTRXTransfer(context.Background(), material, trxMemoRequest(signer, ""))
	require.NoError(t, err)
	explicitEmpty, err := SignTRXTransfer(context.Background(), material, trxMemoRequest(signer, "0x"))
	require.NoError(t, err)

	require.Equal(t, withoutMemo.TxHash, explicitEmpty.TxHash)
	require.Equal(t, withoutMemo.SignedPayload, explicitEmpty.SignedPayload)
	require.Empty(t, decodeSignedTransaction(t, withoutMemo.SignedPayload).GetRawData().GetData())
}

func TestTransferMemoRejectsTransactionOverNetworkSizeLimit(t *testing.T) {
	t.Parallel()

	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())
	_, err := SignTRC20Transfer(context.Background(), material, trc20MemoRequest(
		signer,
		strings.Repeat("00", v1.TRONMaxTransactionBytes),
	))
	require.ErrorContains(t, err, "network limit")
}

func trxMemoRequest(signer, memoHex string) *v1.TRXTransferSignRequest {
	return &v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "tron-key", ChainFamily: v1.ChainFamilyTRON, Network: "tron-nile",
			RequestID: "req-trx-memo", SourceAddress: signer,
		},
		To: tronRecipient, Amount: 10, MemoHex: memoHex, FeeLimit: 1_000_000,
		RefBlockBytes: "a1b2", RefBlockHash: "0102030405060708", RefBlockNum: 1,
		Timestamp: 1_710_000_000_000, Expiration: 1_710_000_060_000,
	}
}

func trc20MemoRequest(signer, memoHex string) *v1.TRC20TransferSignRequest {
	return &v1.TRC20TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "tron-key", ChainFamily: v1.ChainFamilyTRON, Network: "tron-nile",
			RequestID: "req-trc20-memo", SourceAddress: signer,
		},
		To: tronRecipient, TokenContract: tronContract, Amount: "25", MemoHex: memoHex, FeeLimit: 15_000_000,
		RefBlockBytes: "a1b2", RefBlockHash: "0102030405060708", RefBlockNum: 1,
		Timestamp: 1_710_000_000_000, Expiration: 1_710_000_060_000,
	}
}
