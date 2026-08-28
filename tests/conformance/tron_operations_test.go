package conformance_test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/vaultbackend"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestConformance_MVPTRONOperations(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "tron-mvp",
		ChainFamily:      v1.ChainFamilyTRON,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedSigningOperations: []string{
				v1.OperationTRXTransfer,
				v1.OperationTRC20Transfer,
				v1.OperationTRONFreezeBalanceV2,
				v1.OperationTRONUnfreezeBalanceV2,
				v1.OperationTRONDelegateResource,
				v1.OperationTRONUndelegateResource,
				v1.OperationTRONWithdrawExpireUnfreeze,
				v1.OperationTRONVoteWitness,
				v1.OperationTRONWithdrawBalance,
			},
			AllowedNetworks: []string{testTRONNetwork},
			MaxValue:        "1000000000",
			MaxFeeLimit:     20000000,
			AllowedTokenContracts: []string{
				testTRONContract,
			},
			AllowedSelectors: []string{domain.TRC20TransferSelector},
		},
	})

	versionResp := readVersion(t, ctx, b, storage)
	require.Contains(t, versionResp.SupportedRoutes, "v1/tron/resources/freeze_v2/sign")
	require.Contains(t, versionResp.SupportedRoutes, "v1/tron/resources/withdraw_expire_unfreeze/sign")
	require.Contains(t, versionResp.SupportedRoutes, "v1/tron/governance/vote_witness/sign")
	require.Contains(t, versionResp.SupportedRoutes, "v1/tron/rewards/withdraw_balance/sign")
	require.Contains(t, versionResp.SupportedTRONMemoCapabilities, v1.TRONMemoCapability{
		Encoding:            v1.TRONMemoEncodingHex,
		MaxTransactionBytes: v1.TRONMaxTransactionBytes,
		SigningOperations:   []string{v1.OperationTRXTransfer, v1.OperationTRC20Transfer},
	})

	trxMemo := append([]byte("TRX-zażółć"), 0x00, 0xff)

	trxSign := signTRX(t, ctx, b, storage, v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-mvp",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       testTRONNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		To:            testTRONRecipient,
		Amount:        10,
		MemoHex:       hex.EncodeToString(trxMemo),
		FeeLimit:      1000000,
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		RefBlockNum:   1,
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	})
	trxRecover := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         trxSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, trxRecover.MatchesExpected)
	require.Equal(t, v1.OperationTRXTransfer, trxRecover.Operation)
	require.Equal(t, trxSign.TxHash, trxRecover.TxHash)
	require.Equal(t, trxMemo, decodeTRONPayload(t, trxSign.SignedPayload).GetRawData().GetData())

	trc20Memo := []byte("TRC20-🛰️")

	trc20Sign := signTRC20(t, ctx, b, storage, v1.TRC20TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-mvp",
			ChainFamily:   v1.ChainFamilyTRON,
			Network:       testTRONNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		To:            testTRONRecipient,
		TokenContract: testTRONContract,
		Amount:        "25",
		MemoHex:       hex.EncodeToString(trc20Memo),
		FeeLimit:      15000000,
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		RefBlockNum:   1,
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	})
	trc20Verify := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		Operation:             v1.OperationTRC20Transfer,
		SignedPayload:         trc20Sign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, trc20Verify.MatchesExpected)
	require.Equal(t, v1.OperationTRC20Transfer, trc20Verify.Operation)
	require.Equal(t, trc20Memo, decodeTRONPayload(t, trc20Sign.SignedPayload).GetRawData().GetData())

	resourceEnvelope := v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
		FeeLimit:      int64Ptr(5000000),
	}

	requireTRONOperation(t, ctx, b, storage, signTRONFreezeBalanceV2(t, ctx, b, storage, v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      resourceEnvelope,
		Resource:                 v1.TRONResourceEnergy,
		Amount:                   10,
	}), createResp.SignerAddress, v1.OperationTRONFreezeBalanceV2)

	requireTRONOperation(t, ctx, b, storage, signTRONUnfreezeBalanceV2(t, ctx, b, storage, v1.TRONUnfreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      resourceEnvelope,
		Resource:                 v1.TRONResourceBandwidth,
		Amount:                   5,
	}), createResp.SignerAddress, v1.OperationTRONUnfreezeBalanceV2)

	requireTRONOperation(t, ctx, b, storage, signTRONDelegateResource(t, ctx, b, storage, v1.TRONDelegateResourceSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      resourceEnvelope,
		ReceiverAddress:          testTRONRecipient,
		Resource:                 v1.TRONResourceEnergy,
		Amount:                   4,
		Lock:                     true,
		LockPeriod:               86400,
	}), createResp.SignerAddress, v1.OperationTRONDelegateResource)

	requireTRONOperation(t, ctx, b, storage, signTRONUndelegateResource(t, ctx, b, storage, v1.TRONUndelegateResourceSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      resourceEnvelope,
		ReceiverAddress:          testTRONRecipient,
		Resource:                 v1.TRONResourceBandwidth,
		Amount:                   3,
	}), createResp.SignerAddress, v1.OperationTRONUndelegateResource)

	zeroFeeEnvelope := v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}
	requireTRONOperation(t, ctx, b, storage, signTRONWithdrawExpireUnfreeze(t, ctx, b, storage, v1.TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      zeroFeeEnvelope,
	}), createResp.SignerAddress, v1.OperationTRONWithdrawExpireUnfreeze)

	requireTRONOperation(t, ctx, b, storage, signTRONVoteWitness(t, ctx, b, storage, v1.TRONVoteWitnessSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      resourceEnvelope,
		Votes: []v1.TRONVoteWitnessVote{{
			VoteAddress: testTRONRecipient,
			VoteCount:   2,
		}},
	}), createResp.SignerAddress, v1.OperationTRONVoteWitness)

	requireTRONOperation(t, ctx, b, storage, signTRONWithdrawBalance(t, ctx, b, storage, v1.TRONWithdrawBalanceSignRequest{
		TRONOwnerSignRequestBase: tronOwnerBase(createResp.SignerAddress),
		TRONRawDataEnvelope:      zeroFeeEnvelope,
	}), createResp.SignerAddress, v1.OperationTRONWithdrawBalance)
}

func decodeTRONPayload(t *testing.T, payload string) *core.Transaction {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(payload, "0x"))
	require.NoError(t, err)
	tx := new(core.Transaction)
	require.NoError(t, proto.Unmarshal(raw, tx))
	return tx
}

func TestConformance_TRONMemoValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b, storage := newTestBackend(t, nil)
	created, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID: "tron-memo-validation", ChainFamily: v1.ChainFamilyTRON,
		CustodyMode: v1.CustodyModeMVP, ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationTRXTransfer}},
	})
	request := v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "tron-memo-validation", ChainFamily: v1.ChainFamilyTRON,
			Network: testTRONNetwork, RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		To: testTRONRecipient, Amount: 1, FeeLimit: 1_000_000,
		RefBlockBytes: "a1b2", RefBlockHash: "0102030405060708",
		Timestamp: 1_710_000_000_000, Expiration: 1_710_000_060_000,
	}

	request.MemoHex = "not-hex"
	_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trx/sign", mustMap(t, request))
	require.ErrorContains(t, err, "memo_hex")

	request.MemoHex = strings.Repeat("00", v1.TRONMaxTransactionBytes+1)
	_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trx/sign", mustMap(t, request))
	require.ErrorContains(t, err, "exceeding")
}

func requireTRONOperation(
	t *testing.T,
	ctx context.Context,
	b *vaultbackend.Backend,
	storage logical.Storage,
	signResp v1.SignResponse,
	signer,
	expectedOperation string,
) {
	t.Helper()
	recovered := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         signResp.SignedPayload,
		ExpectedSignerAddress: signer,
	})
	require.True(t, recovered.MatchesExpected)
	require.Equal(t, expectedOperation, recovered.Operation)
}

func tronOwnerBase(signer string) v1.TRONOwnerSignRequestBase {
	return v1.TRONOwnerSignRequestBase{
		KeyID:        "tron-mvp",
		ChainFamily:  v1.ChainFamilyTRON,
		Network:      testTRONNetwork,
		RequestID:    testRequestID,
		OwnerAddress: signer,
	}
}
