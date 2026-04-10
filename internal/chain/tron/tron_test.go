package tron

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	tronaddress "github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	tronPrivHex   = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"
	tronRecipient = "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1"
	tronContract  = "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9"
)

func TestAddressHelpers(t *testing.T) {
	material := mustTRONMaterial(t)
	address := DeriveAddress(material.PublicKey())
	normalized, err := NormalizeAddress(address)
	require.NoError(t, err)
	require.Equal(t, address, normalized)
	require.True(t, EqualAddress(address, normalized))

	_, err = NormalizeAddress("not-a-tron-address")
	require.ErrorContains(t, err, "invalid tron address")
}

func TestSignAndRecoverTRONOperations(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	trxResp, err := SignTRXTransfer(context.Background(), material, &v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       "tron-nile",
			RequestID:     "req-1",
			SourceAddress: signer,
		},
		To:            tronRecipient,
		Amount:        10,
		FeeLimit:      1000000,
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		RefBlockNum:   1,
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationTRXTransfer, trxResp.Operation)

	recovered, err := Recover(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               "tron-nile",
		SignedPayload:         trxResp.SignedPayload,
		ExpectedSignerAddress: signer,
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationTRXTransfer, recovered.Operation)
	require.True(t, recovered.MatchesExpected)

	trc20Resp, err := SignTRC20Transfer(context.Background(), material, &v1.TRC20TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       "tron-nile",
			RequestID:     "req-2",
			SourceAddress: signer,
		},
		To:            tronRecipient,
		TokenContract: tronContract,
		Amount:        "25",
		FeeLimit:      15000000,
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		RefBlockNum:   1,
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationTRC20Transfer, trc20Resp.Operation)

	recovered, err = Recover(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               "tron-nile",
		SignedPayload:         trc20Resp.SignedPayload,
		ExpectedSignerAddress: signer,
	})
	require.NoError(t, err)
	require.Equal(t, v1.OperationTRC20Transfer, recovered.Operation)
}

func TestTRONErrorsAndClassification(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	_, err := SignTRXTransfer(context.Background(), material, &v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       "tron-nile",
			RequestID:     "req-1",
			SourceAddress: signer,
		},
		To:            tronRecipient,
		Amount:        10,
		FeeLimit:      1000000,
		RefBlockBytes: "zz",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	})
	require.ErrorContains(t, err, "decode ref_block_bytes")

	owner, err := tronaddress.Base58ToAddress(signer)
	require.NoError(t, err)
	to, err := tronaddress.Base58ToAddress(tronRecipient)
	require.NoError(t, err)
	typed, err := anypb.New(&core.TransferContract{
		OwnerAddress: owner,
		ToAddress:    to,
		Amount:       1,
	})
	require.NoError(t, err)
	unsigned, err := buildTransaction(
		core.Transaction_Contract_TransferContract,
		typed,
		"a1b2",
		"0102030405060708",
		1,
		1710000000000,
		1710000060000,
		1000000,
	)
	require.NoError(t, err)
	raw, err := proto.Marshal(unsigned)
	require.NoError(t, err)
	_, err = Recover(v1.VerifyRequest{
		ChainFamily:   v1.ChainFamilyTRON,
		SignedPayload: enc.EncodeHex(raw),
	})
	require.ErrorContains(t, err, "does not include a signature")

	_, err = Recover(v1.VerifyRequest{
		ChainFamily:   v1.ChainFamilyTRON,
		SignedPayload: "0xdeadbeef",
	})
	require.ErrorContains(t, err, "decode tron signed payload")

	_, err = classifyOperation(&core.Transaction{})
	require.ErrorContains(t, err, "has no contracts")

	trigger := &core.TriggerSmartContract{Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	typed, err = anypb.New(trigger)
	require.NoError(t, err)
	_, err = classifyOperation(&core.Transaction{
		RawData: &core.TransactionRaw{
			Contract: []*core.Transaction_Contract{{
				Type:      core.Transaction_Contract_TriggerSmartContract,
				Parameter: typed,
			}},
		},
	})
	require.ErrorContains(t, err, "unsupported trigger smart contract selector")
}

func mustTRONMaterial(t *testing.T) custody.Material {
	t.Helper()
	material, err := custody.Resolver{}.MaterialForKey(context.Background(), domain.Key{
		ID:            "tron-key",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: tronPrivHex,
	})
	require.NoError(t, err)
	return material
}
