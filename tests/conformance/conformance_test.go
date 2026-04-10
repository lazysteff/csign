package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/chain-signer/chain-signer/pkg/backend"
	"github.com/chain-signer/chain-signer/pkg/model"
	signerpkg "github.com/chain-signer/chain-signer/pkg/signer"
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
		ChainFamily:      model.ChainFamilyEVM,
		CustodyMode:      model.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: model.Policy{
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
			AllowedSelectors: []string{model.TRC20TransferSelector},
		},
	})
	require.NotContains(t, createRaw, "private_key_hex")

	readResp, readRaw := readKey(t, ctx, b, storage, "evm-mvp")
	require.Equal(t, createResp.SignerAddress, readResp.SignerAddress)
	require.NotContains(t, readRaw, "private_key_hex")

	legacyReq := v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   model.ChainFamilyEVM,
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
		ChainFamily:           model.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             model.OperationEVMTransferLegacy,
		SignedPayload:         legacySign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, legacyVerify.MatchesExpected)
	require.Equal(t, model.OperationEVMTransferLegacy, legacyVerify.Operation)
	require.Equal(t, legacySign.TxHash, legacyVerify.TxHash)

	eip1559Req := v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   model.ChainFamilyEVM,
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
		ChainFamily:           model.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             model.OperationEVMTransferEIP1559,
		SignedPayload:         eip1559Sign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, eip1559Verify.MatchesExpected)
	require.Equal(t, model.OperationEVMTransferEIP1559, eip1559Verify.Operation)

	contractReq := v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   model.ChainFamilyEVM,
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
		ChainFamily:           model.ChainFamilyEVM,
		Network:               testEVMNetwork,
		SignedPayload:         contractSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, contractVerify.MatchesExpected)
	require.Equal(t, model.OperationEVMContractEIP1559, contractVerify.Operation)
}

func TestConformance_MVPTRONOperations(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "tron-mvp",
		ChainFamily:      model.ChainFamilyTRON,
		CustodyMode:      model.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: model.Policy{
			AllowedNetworks: []string{testTRONNetwork},
			MaxValue:        "1000000000",
			MaxFeeLimit:     20000000,
			AllowedTokenContracts: []string{
				testTRONContract,
			},
			AllowedSelectors: []string{model.TRC20TransferSelector},
		},
	})

	trxSign := signTRX(t, ctx, b, storage, v1.TRXTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-mvp",
			ChainFamily:   model.ChainFamilyTRON,
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
		ChainFamily:           model.ChainFamilyTRON,
		Network:               testTRONNetwork,
		SignedPayload:         trxSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, trxRecover.MatchesExpected)
	require.Equal(t, model.OperationTRXTransfer, trxRecover.Operation)
	require.Equal(t, trxSign.TxHash, trxRecover.TxHash)

	trc20Sign := signTRC20(t, ctx, b, storage, v1.TRC20TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "tron-mvp",
			ChainFamily:   model.ChainFamilyTRON,
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
		ChainFamily:           model.ChainFamilyTRON,
		Network:               testTRONNetwork,
		Operation:             model.OperationTRC20Transfer,
		SignedPayload:         trc20Sign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, trc20Verify.MatchesExpected)
	require.Equal(t, model.OperationTRC20Transfer, trc20Verify.Operation)
}

func TestConformance_PKCS11StyleExternalSigner(t *testing.T) {
	ctx := context.Background()
	privateKey := mustPrivateKey(t, testPrivHex)
	resolver := staticResolver{
		materials: map[string]signerpkg.Material{
			"hsm-1": signerpkg.ExternalMaterial{
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
		ChainFamily:       model.ChainFamilyEVM,
		CustodyMode:       model.CustodyModePKCS11,
		PublicKeyHex:      model.PublicKeyHex(&privateKey.PublicKey),
		ExternalSignerRef: "hsm-1",
	})
	require.NotContains(t, createRaw, "private_key_hex")

	signResp := signEVMEIP1559(t, ctx, b, storage, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-pkcs11",
			ChainFamily:   model.ChainFamilyEVM,
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
		ChainFamily:           model.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             model.OperationEVMTransferEIP1559,
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
		ChainFamily:      model.ChainFamilyEVM,
		CustodyMode:      model.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: model.Policy{
			AllowedNetworks: []string{testEVMNetwork},
			AllowedChainIDs: []int64{testEVMChainID},
			MaxValue:        "1",
		},
	})

	t.Run("policy denial on cap violation", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   model.ChainFamilyEVM,
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
			"chain_family":   model.ChainFamilyEVM,
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
			"chain_family":   model.ChainFamilyEVM,
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
			"chain_family": model.ChainFamilyEVM,
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
	materials map[string]signerpkg.Material
}

func (r staticResolver) ResolveExternal(_ context.Context, key model.Key) (signerpkg.Material, error) {
	material, ok := r.materials[key.ExternalSignerRef]
	if !ok {
		return nil, errors.New("external signer not found")
	}
	return material, nil
}

func newTestBackend(t *testing.T, resolver signerpkg.Resolver) (*backend.Backend, logical.Storage) {
	t.Helper()
	b := backend.New(resolver)
	conf := logical.TestBackendConfig()
	require.NoError(t, b.Setup(context.Background(), conf))
	return b, new(logical.InmemStorage)
}

func createKey(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.CreateKeyRequest) (v1.KeyResponse, map[string]interface{}) {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.KeyResponse](t, resp), resp.Data
}

func readKey(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, keyID string) (v1.KeyResponse, map[string]interface{}) {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.ReadOperation, "v1/keys/"+keyID, nil)
	require.NoError(t, err)
	return decodeResponse[v1.KeyResponse](t, resp), resp.Data
}

func signEVMLegacy(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.EVMLegacyTransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signEVMEIP1559(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.EVMEIP1559TransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/eip1559/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signEVMContract(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.EVMContractCallSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/contracts/eip1559/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRX(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.TRXTransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trx/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRC20(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.TRC20TransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trc20/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func verifyPayload(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.VerifyRequest) v1.RecoverResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/verify", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.RecoverResponse](t, resp)
}

func recoverPayload(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, payload v1.VerifyRequest) v1.RecoverResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/recover", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.RecoverResponse](t, resp)
}

func handle(t *testing.T, ctx context.Context, b *backend.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
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
	key, err := model.ParsePrivateKeyHex(raw)
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
