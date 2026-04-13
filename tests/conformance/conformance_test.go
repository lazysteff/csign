package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/vaultbackend"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	testPrivHex             = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"
	testTRONRecipient       = "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1"
	testTRONContract        = "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9"
	testEVMRecipient        = "0x1111111111111111111111111111111111111111"
	testEVMContract         = "0x2222222222222222222222222222222222222222"
	testRequestID           = "req-123"
	testEVMNetwork          = "ethereum-sepolia"
	testTRONNetwork         = "tron-nile"
	testEVMChainID    int64 = 11155111
)

func TestConformance_MVPEVMOperations(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, createRaw := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "evm-mvp",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedNetworks:      []string{testEVMNetwork},
			AllowedChainIDs:      []int64{testEVMChainID},
			MaxValue:             "1000000000000000000",
			MaxGasLimit:          250000,
			MaxGasPrice:          "1000000000",
			MaxFeePerGas:         "2000000000",
			MaxPriorityFeePerGas: "1000000000",
			AllowedTokenContracts: []string{
				testEVMContract,
			},
			AllowedSelectors: []string{domain.TRC20TransferSelector},
		},
	})
	require.NotContains(t, createRaw, "private_key_hex")

	readResp, readRaw := readKey(t, ctx, b, storage, "evm-mvp")
	require.Equal(t, createResp.SignerAddress, readResp.SignerAddress)
	require.NotContains(t, readRaw, "private_key_hex")

	legacyReq := v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:  testEVMChainID,
		To:       testEVMRecipient,
		Value:    "1",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "1000",
	}
	legacySign := signEVMLegacy(t, ctx, b, storage, legacyReq)
	legacyVerify := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             v1.OperationEVMTransferLegacy,
		SignedPayload:         legacySign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, legacyVerify.MatchesExpected)
	require.Equal(t, v1.OperationEVMTransferLegacy, legacyVerify.Operation)
	require.Equal(t, legacySign.TxHash, legacyVerify.TxHash)

	eip1559Req := v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:              testEVMChainID,
		To:                   testEVMRecipient,
		Value:                "2",
		Nonce:                2,
		GasLimit:             21000,
		MaxFeePerGas:         "1500",
		MaxPriorityFeePerGas: "100",
	}
	eip1559Sign := signEVMEIP1559(t, ctx, b, storage, eip1559Req)
	eip1559Verify := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             v1.OperationEVMTransferEIP1559,
		SignedPayload:         eip1559Sign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, eip1559Verify.MatchesExpected)
	require.Equal(t, v1.OperationEVMTransferEIP1559, eip1559Verify.Operation)

	contractReq := v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:              testEVMChainID,
		To:                   testEVMContract,
		Value:                "0",
		Data:                 "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:                3,
		GasLimit:             90000,
		MaxFeePerGas:         "1500",
		MaxPriorityFeePerGas: "100",
	}
	contractSign := signEVMContract(t, ctx, b, storage, contractReq)
	contractVerify := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		SignedPayload:         contractSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, contractVerify.MatchesExpected)
	require.Equal(t, v1.OperationEVMContractEIP1559, contractVerify.Operation)
}

func TestConformance_MVPTRONOperations(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "tron-mvp",
		ChainFamily:      v1.ChainFamilyTRON,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
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

	resourceEnvelope := v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
		FeeLimit:      int64Ptr(5000000),
	}

	freezeSign := signTRONFreezeBalanceV2(t, ctx, b, storage, v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-mvp",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      testTRONNetwork,
			RequestID:    testRequestID,
			OwnerAddress: createResp.SignerAddress,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		Resource:            v1.TRONResourceEnergy,
		Amount:              10,
	})
	freezeRecover := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         freezeSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, freezeRecover.MatchesExpected)
	require.Equal(t, v1.OperationTRONFreezeBalanceV2, freezeRecover.Operation)

	unfreezeSign := signTRONUnfreezeBalanceV2(t, ctx, b, storage, v1.TRONUnfreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-mvp",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      testTRONNetwork,
			RequestID:    testRequestID,
			OwnerAddress: createResp.SignerAddress,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		Resource:            v1.TRONResourceBandwidth,
		Amount:              5,
	})
	unfreezeRecover := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         unfreezeSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, unfreezeRecover.MatchesExpected)
	require.Equal(t, v1.OperationTRONUnfreezeBalanceV2, unfreezeRecover.Operation)

	delegateSign := signTRONDelegateResource(t, ctx, b, storage, v1.TRONDelegateResourceSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-mvp",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      testTRONNetwork,
			RequestID:    testRequestID,
			OwnerAddress: createResp.SignerAddress,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		ReceiverAddress:     testTRONRecipient,
		Resource:            v1.TRONResourceEnergy,
		Amount:              4,
		Lock:                true,
		LockPeriod:          86400,
	})
	delegateVerify := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		Operation:             v1.OperationTRONDelegateResource,
		SignedPayload:         delegateSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, delegateVerify.MatchesExpected)
	require.Equal(t, v1.OperationTRONDelegateResource, delegateVerify.Operation)

	undelegateSign := signTRONUndelegateResource(t, ctx, b, storage, v1.TRONUndelegateResourceSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-mvp",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      testTRONNetwork,
			RequestID:    testRequestID,
			OwnerAddress: createResp.SignerAddress,
		},
		TRONRawDataEnvelope: resourceEnvelope,
		ReceiverAddress:     testTRONRecipient,
		Resource:            v1.TRONResourceBandwidth,
		Amount:              3,
	})
	undelegateRecover := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         undelegateSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, undelegateRecover.MatchesExpected)
	require.Equal(t, v1.OperationTRONUndelegateResource, undelegateRecover.Operation)

	withdrawSign := signTRONWithdrawExpireUnfreeze(t, ctx, b, storage, v1.TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
			KeyID:        "tron-mvp",
			ChainFamily:  v1.ChainFamilyTRON,
			Network:      testTRONNetwork,
			RequestID:    testRequestID,
			OwnerAddress: createResp.SignerAddress,
		},
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
	})
	withdrawRecover := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         withdrawSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, withdrawRecover.MatchesExpected)
	require.Equal(t, v1.OperationTRONWithdrawExpireUnfreeze, withdrawRecover.Operation)
}

func TestConformance_PKCS11StyleExternalSigner(t *testing.T) {
	ctx := context.Background()
	privateKey := mustPrivateKey(t, testPrivHex)
	resolver := staticResolver{
		materials: map[string]custody.Material{
			"hsm-1": custody.ExternalMaterial{
				Pub: &privateKey.PublicKey,
				SignFunc: func(_ context.Context, digest []byte) ([]byte, error) {
					r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
					if err != nil {
						return nil, err
					}
					return sig64(r, s), nil
				},
			},
		},
	}
	b, storage := newTestBackend(t, resolver)

	createResp, createRaw := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:             "evm-pkcs11",
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      enc.EncodeHex(ethcrypto.FromECDSAPub(&privateKey.PublicKey)),
		ExternalSignerRef: "hsm-1",
	})
	require.NotContains(t, createRaw, "private_key_hex")

	signResp := signEVMEIP1559(t, ctx, b, storage, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-pkcs11",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:              testEVMChainID,
		To:                   testEVMRecipient,
		Value:                "1",
		Nonce:                7,
		GasLimit:             21000,
		MaxFeePerGas:         "1000",
		MaxPriorityFeePerGas: "100",
	})
	verifyResp := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             v1.OperationEVMTransferEIP1559,
		SignedPayload:         signResp.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, verifyResp.MatchesExpected)
}

func TestConformance_NegativeCases(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "negatives",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedNetworks: []string{testEVMNetwork},
			AllowedChainIDs: []int64{testEVMChainID},
			MaxValue:        "1",
		},
	})

	t.Run("policy denial on cap violation", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": createResp.SignerAddress,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "2",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cap")
	})

	t.Run("address mismatch", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": testEVMRecipient,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "1",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "source address")
	})

	t.Run("disabled key", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys/negatives/status", map[string]interface{}{
			"active": false,
		})
		require.NoError(t, err)
		_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": createResp.SignerAddress,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "1",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "disabled")
	})

	t.Run("malformed request", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"chain_family": v1.ChainFamilyEVM,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")
	})

	t.Run("unsupported operation", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/unsupported/sign", map[string]interface{}{})
		require.Error(t, err)
		require.True(t, errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation))
	})
}

type staticResolver struct {
	materials map[string]custody.Material
}

func (r staticResolver) ResolveExternal(_ context.Context, key domain.Key) (custody.Material, error) {
	material, ok := r.materials[key.ExternalSignerRef]
	if !ok {
		return nil, errors.New("external signer not found")
	}
	return material, nil
}

func newTestBackend(t *testing.T, resolver custody.ExternalResolver) (*vaultbackend.Backend, logical.Storage) {
	t.Helper()
	b := vaultbackend.New(resolver)
	conf := logical.TestBackendConfig()
	require.NoError(t, b.Setup(context.Background(), conf))
	return b, new(logical.InmemStorage)
}

func createKey(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.CreateKeyRequest) (v1.KeyResponse, map[string]interface{}) {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.KeyResponse](t, resp), resp.Data
}

func readKey(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, keyID string) (v1.KeyResponse, map[string]interface{}) {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.ReadOperation, "v1/keys/"+keyID, nil)
	require.NoError(t, err)
	return decodeResponse[v1.KeyResponse](t, resp), resp.Data
}

func signEVMLegacy(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.EVMLegacyTransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signEVMEIP1559(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.EVMEIP1559TransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/eip1559/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signEVMContract(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.EVMContractCallSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/contracts/eip1559/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRX(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRXTransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trx/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRC20(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRC20TransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trc20/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONFreezeBalanceV2(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONFreezeBalanceV2SignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/freeze_v2/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONUnfreezeBalanceV2(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONUnfreezeBalanceV2SignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/unfreeze_v2/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONDelegateResource(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONDelegateResourceSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/delegate/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONUndelegateResource(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONUndelegateResourceSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/undelegate/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONWithdrawExpireUnfreeze(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONWithdrawExpireUnfreezeSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/withdraw_expire_unfreeze/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func readVersion(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage) v1.VersionResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.ReadOperation, "v1/version", nil)
	require.NoError(t, err)
	return decodeResponse[v1.VersionResponse](t, resp)
}

func verifyPayload(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.VerifyRequest) v1.RecoverResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/verify", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.RecoverResponse](t, resp)
}

func recoverPayload(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.VerifyRequest) v1.RecoverResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/recover", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.RecoverResponse](t, resp)
}

func handle(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	req := logical.TestRequest(t, op, path)
	req.Storage = storage
	req.Data = data
	return b.HandleRequest(ctx, req)
}

func decodeResponse[T any](t *testing.T, resp *logical.Response) T {
	t.Helper()
	var out T
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func mustMap(t *testing.T, payload interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func mustPrivateKey(t *testing.T, raw string) *ecdsa.PrivateKey {
	t.Helper()
	keyBytes, err := enc.DecodeHex(raw)
	require.NoError(t, err)
	key, err := ethcrypto.ToECDSA(keyBytes)
	require.NoError(t, err)
	return key
}

func sig64(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out
}

func int64Ptr(value int64) *int64 {
	return &value
}
