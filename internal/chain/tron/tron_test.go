package tron

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
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

func TestTRONResourceCodeNormalizesInput(t *testing.T) {
	code, err := tronResourceCode(" energy ")
	require.NoError(t, err)
	require.Equal(t, core.ResourceCode_ENERGY, code)

	_, err = tronResourceCode("not-a-resource")
	require.ErrorContains(t, err, "unsupported tron resource")
}

func TestSignAndRecoverTRONOperations(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())

	trxResp, err := SignTRXTransfer(context.Background(), material, &v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       "tron-nile",
			RequestID:     "req-trx",
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
	requireRecoveredOperation(t, signer, trxResp.SignedPayload, v1.OperationTRXTransfer)

	trc20Resp, err := SignTRC20Transfer(context.Background(), material, &v1.TRC20TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-key",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       "tron-nile",
			RequestID:     "req-trc20",
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
	requireRecoveredOperation(t, signer, trc20Resp.SignedPayload, v1.OperationTRC20Transfer)

	resourceEnvelope := v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
		FeeLimit:      int64Ptr(5000000),
	}

	freezeResp, err := SignTRONFreezeBalanceV2(context.Background(), material, &v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-freeze",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		Resource:            v1.TRONResourceEnergy,
		Amount:              12,
	})
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, freezeResp.SignedPayload, v1.OperationTRONFreezeBalanceV2)

	unfreezeResp, err := SignTRONUnfreezeBalanceV2(context.Background(), material, &v1.TRONUnfreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-unfreeze",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		Resource:            v1.TRONResourceBandwidth,
		Amount:              8,
	})
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, unfreezeResp.SignedPayload, v1.OperationTRONUnfreezeBalanceV2)

	delegateResp, err := SignTRONDelegateResource(context.Background(), material, &v1.TRONDelegateResourceSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-delegate",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		ReceiverAddress:     tronRecipient,
		Resource:            v1.TRONResourceEnergy,
		Amount:              7,
		Lock:                true,
		LockPeriod:          86400,
	})
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, delegateResp.SignedPayload, v1.OperationTRONDelegateResource)

	undelegateResp, err := SignTRONUndelegateResource(context.Background(), material, &v1.TRONUndelegateResourceSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-undelegate",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		ReceiverAddress:     tronRecipient,
		Resource:            v1.TRONResourceBandwidth,
		Amount:              6,
	})
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, undelegateResp.SignedPayload, v1.OperationTRONUndelegateResource)

	withdrawResp, err := SignTRONWithdrawExpireUnfreeze(context.Background(), material, &v1.TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-withdraw",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
	})
	require.NoError(t, err)
	requireRecoveredOperation(t, signer, withdrawResp.SignedPayload, v1.OperationTRONWithdrawExpireUnfreeze)
}

func TestTRONResourceBuildersProduceExpectedContracts(t *testing.T) {
	material := mustTRONMaterial(t)
	signer := DeriveAddress(material.PublicKey())
	envelope := v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
		FeeLimit:      int64Ptr(5000000),
	}

	freezeResp, err := SignTRONFreezeBalanceV2(context.Background(), material, &v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-freeze",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: envelope,
		Resource:            v1.TRONResourceEnergy,
		Amount:              12,
	})
	require.NoError(t, err)
	assertContractFields[*core.FreezeBalanceV2Contract](t, freezeResp.SignedPayload, core.Transaction_Contract_FreezeBalanceV2Contract, func(contract *core.FreezeBalanceV2Contract) {
		require.Equal(t, int64(12), contract.FrozenBalance)
		require.Equal(t, core.ResourceCode_ENERGY, contract.Resource)
	})

	delegateResp, err := SignTRONDelegateResource(context.Background(), material, &v1.TRONDelegateResourceSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-delegate",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: envelope,
		ReceiverAddress:     tronRecipient,
		Resource:            v1.TRONResourceBandwidth,
		Amount:              7,
		Lock:                true,
		LockPeriod:          86400,
	})
	require.NoError(t, err)
	assertContractFields[*core.DelegateResourceContract](t, delegateResp.SignedPayload, core.Transaction_Contract_DelegateResourceContract, func(contract *core.DelegateResourceContract) {
		require.Equal(t, int64(7), contract.Balance)
		require.Equal(t, core.ResourceCode_BANDWIDTH, contract.Resource)
		require.True(t, contract.Lock)
		require.Equal(t, int64(86400), contract.LockPeriod)
	})

	withdrawResp, err := SignTRONWithdrawExpireUnfreeze(context.Background(), material, &v1.TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-withdraw",
			OwnerAddress: signer,
		},
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
	})
	require.NoError(t, err)
	tx := decodeSignedTransaction(t, withdrawResp.SignedPayload)
	require.Equal(t, int64(0), tx.RawData.FeeLimit)
	require.Equal(t, core.Transaction_Contract_WithdrawExpireUnfreezeContract, tx.RawData.Contract[0].Type)
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

	typed, err := anypb.New(&core.TransferContract{
		OwnerAddress: []byte{0x41, 0x01},
		ToAddress:    []byte{0x41, 0x02},
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

func requireRecoveredOperation(t *testing.T, signer, signedPayload, expectedOperation string) {
	t.Helper()
	recovered, err := Recover(v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               "tron-nile",
		SignedPayload:         signedPayload,
		ExpectedSignerAddress: signer,
	})
	require.NoError(t, err)
	require.Equal(t, expectedOperation, recovered.Operation)
	require.True(t, recovered.MatchesExpected)
}

func decodeSignedTransaction(t *testing.T, signedPayload string) *core.Transaction {
	t.Helper()
	raw, err := enc.DecodeHex(signedPayload)
	require.NoError(t, err)
	var tx core.Transaction
	require.NoError(t, proto.Unmarshal(raw, &tx))
	return &tx
}

func assertContractFields[T proto.Message](t *testing.T, signedPayload string, expectedType core.Transaction_Contract_ContractType, assertFn func(T)) {
	t.Helper()
	tx := decodeSignedTransaction(t, signedPayload)
	require.Len(t, tx.RawData.Contract, 1)
	require.Equal(t, expectedType, tx.RawData.Contract[0].Type)
	contract := newMessage[T](t)
	require.NoError(t, tx.RawData.Contract[0].Parameter.UnmarshalTo(contract))
	assertFn(contract)
}

func newMessage[T proto.Message](t *testing.T) T {
	t.Helper()
	var zero T
	return zero.ProtoReflect().New().Interface().(T)
}

func int64Ptr(value int64) *int64 {
	return &value
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
